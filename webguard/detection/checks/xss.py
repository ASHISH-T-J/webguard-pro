"""Context-aware reflected XSS detection.

1. Send a unique canary and locate every reflection in the parsed DOM (text, attribute
   value, URL attribute, <script> block, comment).
2. For each reflection context send a context-specific break-out payload and confirm by
   *parsing* the response: a new element / attribute with our random name must exist in
   the DOM, or the script block must contain our unescaped statement. Mere string reflection
   is never reported as XSS.
"""

from __future__ import annotations

from bs4 import BeautifulSoup, Comment

from webguard.detection.context import Context, token
from webguard.models import SIGNATURE, Confidence, Finding, InjectionPoint, Severity

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poc"}
DESCRIPTION = (
    "User input is reflected into the HTML response without context-appropriate output encoding, "
    "allowing an attacker to inject markup/script that executes in a victim's browser (session "
    "hijacking, account takeover, phishing within the trusted origin)."
)
REMEDIATION = (
    "Contextually encode all untrusted output (HTML body, attribute, JavaScript, URL contexts) using "
    "a templating engine with auto-escaping, validate URL schemes, and deploy a strict Content-Security-Policy."
)
REFS = [
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
]


def _soup(text: str) -> BeautifulSoup:
    return BeautifulSoup(text, "html.parser")


def contexts(html: str, canary: str) -> set[str]:
    soup = _soup(html)
    found: set[str] = set()
    for el in soup.find_all(True):
        for attr, val in el.attrs.items():
            val = " ".join(val) if isinstance(val, list) else str(val)
            if canary in val:
                if attr.lower() in URL_ATTRS and val.lower().startswith(canary.lower()):
                    found.add("url-attr")
                elif attr.lower().startswith("on") or attr.lower() == "style":
                    found.add("js-attr")
                else:
                    found.add("attr")
        if el.name in ("script",) and el.string and canary in el.string:
            found.add("script")
        if el.name in ("textarea", "title", "noscript", "style", "xmp") and canary in el.get_text():
            found.add(f"rcdata:{el.name}")
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if canary in c:
            found.add("comment")
    for s in soup.find_all(string=True):
        if canary in s and not isinstance(s, Comment) and s.parent and s.parent.name not in (
            "script", "textarea", "title", "noscript", "style", "xmp"
        ):
            found.add("html")
    return found


def _has_tag(html: str, tag: str) -> bool:
    return _soup(html).find(tag) is not None


def _has_attr(html: str, attr: str) -> bool:
    return _soup(html).find(attrs={attr: True}) is not None


def _script_contains(html: str, needle: str) -> bool:
    return any(s.string and needle in s.string for s in _soup(html).find_all("script"))


async def run(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("xss", point):
        return
    canary = token()
    r = await ctx.send(point, canary)
    if r is None or canary not in r.text or not r.is_html:
        return
    ctxs = contexts(r.text, canary)
    if not ctxs:
        return
    c2 = token(6)
    attempts: list[tuple[str, str, callable, Severity]] = []
    if "html" in ctxs or "comment" in ctxs or any(x.startswith("rcdata") for x in ctxs):
        prefix = "-->" if "comment" in ctxs else ""
        for x in ctxs:
            if x.startswith("rcdata:"):
                prefix = f"</{x.split(':', 1)[1]}>"
        attempts.append(("html", f"{prefix}<{c2} {c2}=1>", lambda h: _has_tag(h, c2), Severity.HIGH))
        attempts.append(("html", f"{prefix}<img src=x onerror=alert({c2[2:]!r})>",
                         lambda h: any(i.get("onerror") == f"alert({c2[2:]!r})" for i in _soup(h).find_all("img")),
                         Severity.HIGH))
    if "attr" in ctxs or "url-attr" in ctxs or "js-attr" in ctxs:
        for q in ('"', "'", ""):
            attempts.append(("attr", f"{canary}{q} {c2}=1 x={q}", lambda h: _has_attr(h, c2), Severity.HIGH))
        attempts.append(("attr", f'{canary}"><{c2}>', lambda h: _has_tag(h, c2), Severity.HIGH))
    if "url-attr" in ctxs:
        attempts.append(("url", f"javascript:alert(1)//{c2}",
                         lambda h: any(
                             str(v).lower().startswith("javascript:alert(1)//" + c2)
                             for el in _soup(h).find_all(True) for k, v in el.attrs.items() if k in URL_ATTRS),
                         Severity.MEDIUM))
    if "script" in ctxs:
        for brk in ("';", '";', "`;", ";", "</script>"):
            stmt = f"{c2}=1"
            if brk == "</script>":
                attempts.append(("script", f"</script><{c2}>", lambda h: _has_tag(h, c2), Severity.HIGH))
            else:
                payload = f"{canary}{brk}{stmt};//"
                attempts.append(("script", payload,
                                 lambda h, p=payload: _script_contains(h, p) and f"\\{p[len(canary)]}" not in h,
                                 Severity.HIGH))

    for kind, payload, check, sev in attempts:
        resp = await ctx.send(point, payload)
        if resp is None or not resp.is_html:
            continue
        if check(resp.text):
            conf = Confidence.CERTAIN if kind in ("html", "attr") else Confidence.FIRM
            poc = _exec_payload(kind, payload, canary, c2)
            context = {}
            if poc and point.method.upper() == "GET" and point.location in ("query", "form"):
                context["poc_url"] = str(ctx.client._client.build_request(
                    "GET", point.url, params=point.with_value(poc)).url)
                context["poc_payload"] = poc
            ctx.report(Finding(
                context=context,
                check="xss",
                title=f"Reflected cross-site scripting ({kind} context)",
                severity=sev,
                confidence=conf,
                url=point.url,
                method=point.method,
                parameter=point.name,
                location=point.location,
                payload=payload,
                evidence=f"Reflection contexts: {', '.join(sorted(ctxs))}. Injected markup was parsed as live DOM "
                         f"({kind} break-out confirmed).",
                description=DESCRIPTION,
                remediation=REMEDIATION,
                cwe="CWE-79",
                owasp="A03:2021-Injection",
                detection=SIGNATURE,
                references=REFS,
                tags=["xss", "injection", kind],
                request=ctx.curl(point, payload),
                features={"contexts": float(len(ctxs))},
            ))
            return


def _exec_payload(kind: str, confirmed: str, canary: str, marker: str) -> str | None:
    """Turn the harmless confirmation payload into a visibly executing PoC for the same context."""
    alert = "alert(document.domain)"
    if kind == "html":
        prefix = confirmed.split("<", 1)[0]  # '-->' / '</textarea>' break-outs are kept
        return f"{prefix}<img src=x onerror={alert}>"
    if kind == "attr":
        quote = confirmed[len(canary):len(canary) + 1] if confirmed.startswith(canary) else '"'
        quote = quote if quote in "\"'" else ""
        return f"{canary}{quote}><img src=x onerror={alert}>"
    if kind == "script" and confirmed.startswith(canary):
        brk = confirmed[len(canary):].split(f"{marker}=1", 1)[0]
        return f"{canary}{brk}{alert};//"
    if kind == "script" and confirmed.startswith("</script>"):
        return f"</script><img src=x onerror={alert}>"
    return None
