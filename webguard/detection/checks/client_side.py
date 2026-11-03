"""Open redirect and CRLF / header injection."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from webguard.detection.context import Context, token
from webguard.models import SIGNATURE, Confidence, Finding, InjectionPoint, Severity

REDIRECT_PARAMS = re.compile(
    r"(?i)^(?:next|url|target|rurl|dest|destination|redir|redirect(?:_?ur[il])?|redirect_to|return(?:_?to|url|_url)?|"
    r"continue|goto|go|forward|out|view|to|image_url|checkout_url|callback|success_url|fail(?:ure)?_url|ref|r|u|link)$"
)


async def open_redirect(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("redirect", point):
        return
    if not (REDIRECT_PARAMS.search(point.name) or point.original.startswith(("http", "/"))):
        return
    c = token()
    evil = f"{c}.example.org"
    own = urlsplit(point.url).netloc
    payloads = [f"https://{evil}/", f"//{evil}/", f"/\\{evil}/", f"https:/\\{evil}", f"https://{own}@{evil}/",
                f"https://{evil}%2f{own}/", f"\\/\\/{evil}/"]
    if point.original.startswith(("http://", "https://")):
        # allow-list bypasses: validators that use substring / prefix matching on the trusted URL
        trusted = point.original
        payloads = [f"https://{evil}/?wg={trusted}", f"https://{evil}/#{trusted}",
                    f"{trusted.split('://')[0]}://{urlsplit(trusted).netloc}.{evil}/", *payloads]
    for payload in payloads:
        r = await ctx.send(point, payload)
        if r is None:
            continue
        where = None
        loc = r.headers.get("location")
        if r.status in (301, 302, 303, 307, 308) and loc:
            target = urljoin(r.url, loc.replace("\\", "/"))
            if (urlsplit(target).hostname or "").endswith(evil):
                where = f"Location: {loc}"
        if not where and r.is_html:
            m = re.search(r"(?i)<meta[^>]+http-equiv=[\"']?refresh[^>]+url=([^\"'>]+)", r.text)
            if m and (urlsplit(urljoin(r.url, m.group(1).strip().replace("\\", "/"))).hostname or "").endswith(evil):
                where = f"meta refresh to {m.group(1)}"
            m2 = re.search(r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*[\"'](?:https?:)?//" + re.escape(evil), r.text)
            if not where and m2:
                where = f"JavaScript redirect: {m2.group(0)}"
        if where:
            ctx.report(Finding(
                check="redirect", title="Open redirect",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                url=point.url, method=point.method, parameter=point.name, location=point.location,
                payload=payload, evidence=f"Redirects to attacker-controlled host: {where}",
                description="The application redirects users to arbitrary external URLs. This is used for "
                            "phishing and can chain into OAuth token theft or SSRF filter bypasses.",
                remediation="Only redirect to relative paths or an allow-list of destinations; validate the "
                            "parsed host, not a string prefix.",
                cwe="CWE-601", owasp="A01:2021-Broken Access Control", detection=SIGNATURE,
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                tags=["redirect"], request=ctx.curl(point, payload),
            ))
            return


async def crlf(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("crlf", point) or point.location not in ("query", "form"):
        return
    c = token(6)
    header = f"X-Wg-{c}"
    for sep in ("\r\n", "\n", "\r", "嘍嘊"):  # last: unicode CRLF smuggling (UTF-8 truncation)
        payload = f"{point.original}{sep}{header}: 1"
        r = await ctx.send(point, payload)
        if r is not None and header.lower() in {k.lower() for k in r.headers.keys()}:
            ctx.report(Finding(
                check="crlf", title="CRLF injection / HTTP response header injection",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                url=point.url, method=point.method, parameter=point.name, location=point.location,
                payload=payload, evidence=f"Injected response header '{header}' present in response.",
                description="Line-break characters in input are written into response headers, enabling header "
                            "injection, cookie setting, cache poisoning and response splitting (XSS).",
                remediation="Strip/reject CR and LF in any value placed into HTTP headers; use framework header APIs.",
                cwe="CWE-113", owasp="A03:2021-Injection", detection=SIGNATURE,
                references=["https://owasp.org/www-community/vulnerabilities/CRLF_Injection"],
                tags=["crlf", "injection"], request=ctx.curl(point, payload),
            ))
            return
