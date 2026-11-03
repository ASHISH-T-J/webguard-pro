"""Server-side injection checks: SSTI, path traversal / LFI, OS command injection, SSRF.

All confirmations rely on values the server must *compute* or *fetch* (products of random
numbers, file contents, remote page content) so a plain reflection cannot cause a false positive.
"""

from __future__ import annotations

import random
import re

from webguard.detection.context import Context, token
from webguard.models import SIGNATURE, TIMING, Confidence, Finding, InjectionPoint, Severity

# --------------------------------------------------------------------------------- SSTI

SSTI_TEMPLATES = [
    ("{{{{{a}*{b}}}}}", "Jinja2/Twig/Nunjucks/Handlebars-like"),
    ("${{{a}*{b}}}", "FreeMarker/Velocity/Thymeleaf/JSP EL/Mako"),
    ("#{{{a}*{b}}}", "Ruby ERB-interp/Pug/Thymeleaf"),
    ("<%= {a}*{b} %>", "ERB/EJS"),
    ("{{{{={a}*{b}}}}}", "doT.js"),
    ("*{{{a}*{b}}}", "Thymeleaf"),
    ("@({a}*{b})", "Razor"),
    ("[[${{{a}*{b}}}]]", "Thymeleaf inline"),
    ("{{{a}*{b}}}", "Smarty"),
    ("${{{{{a}*{b}}}}}", "Spring/Angular-expression"),
]


async def ssti(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("ssti", point):
        return
    base = await ctx.baseline(point)
    if base is None:
        return
    a, b = random.randint(1000, 9999), random.randint(1000, 9999)
    product = str(a * b)
    for tpl, engines in SSTI_TEMPLATES:
        payload = point.original + tpl.format(a=a, b=b)
        r = await ctx.send(point, payload)
        if r is None or product not in r.text or base.contains(product):
            continue
        engine = engines
        if tpl.startswith("{{"):
            probe = await ctx.send(point, point.original + "{{7*'7'}}")
            if probe is not None:
                if "7777777" in probe.text:
                    engine = "Jinja2"
                elif re.search(r"(?<!\d)49(?!\d)", probe.text) and not base.contains("49"):
                    engine = "Twig"
        ctx.report(Finding(
            check="ssti",
            title=f"Server-side template injection ({engine})",
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            url=point.url, method=point.method, parameter=point.name, location=point.location,
            payload=payload,
            evidence=f"Template expression {a}*{b} was evaluated server-side: response contains {product}.",
            description="User input is embedded into a server-side template and evaluated. SSTI usually "
                        "leads to remote code execution on the server.",
            remediation="Never build templates from user input; pass input as template *data*. Use a "
                        "logic-less or sandboxed template engine.",
            cwe="CWE-1336", owasp="A03:2021-Injection", detection=SIGNATURE,
            references=["https://portswigger.net/research/server-side-template-injection"],
            tags=["ssti", "rce", "injection"], request=ctx.curl(point, payload),
        ))
        return

# --------------------------------------------------------------------------------- LFI

LFI_PAYLOADS = [
    ("../../../../../../../../etc/passwd", "unix"),
    ("/etc/passwd", "unix"),
    ("....//....//....//....//....//etc/passwd", "unix"),
    ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "unix"),
    ("../../../../../../../../etc/passwd\x00", "unix"),
    ("file:///etc/passwd", "unix"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "windows"),
    ("C:\\Windows\\win.ini", "windows"),
    ("php://filter/convert.base64-encode/resource=index.php", "php"),
]
LFI_SIGS = {
    "unix": re.compile(r"root:[^:\n]*:0:0:"),
    "windows": re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I),
    "php": re.compile(r"PD9waHA[A-Za-z0-9+/=]{20,}"),
}
FILE_PARAMS = re.compile(r"(?i)(file|path|page|doc|folder|dir|include|inc|template|tpl|view|load|read|lang|name|src|style|layout|conf)")


async def lfi(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("lfi", point):
        return
    # limit to plausible parameters (name or value looks file-like) to save requests
    if not (FILE_PARAMS.search(point.name) or re.search(r"[./\\]", point.original) or not point.original):
        return
    base = await ctx.baseline(point)
    if base is None:
        return
    for payload, kind in LFI_PAYLOADS:
        r = await ctx.send(point, payload)
        if r is None:
            continue
        m = LFI_SIGS[kind].search(r.text)
        if m and not any(LFI_SIGS[kind].search(s.text) for s in base.samples):
            ctx.report(Finding(
                check="lfi",
                title="Path traversal / local file inclusion",
                severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                url=point.url, method=point.method, parameter=point.name, location=point.location,
                payload=payload,
                evidence=f"Server file contents returned: {m.group(0)[:80]}",
                description="The parameter is used to build a filesystem path without validation, allowing "
                            "arbitrary files on the server to be read (source code, credentials, keys). "
                            "With PHP wrappers or log poisoning this may escalate to code execution.",
                remediation="Map user choices to an allow-list of files/IDs; never pass raw input to file APIs. "
                            "Canonicalise paths and verify they stay inside the intended directory.",
                cwe="CWE-22", owasp="A01:2021-Broken Access Control", detection=SIGNATURE,
                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                tags=["lfi", "path-traversal", kind], request=ctx.curl(point, payload),
            ))
            return

# --------------------------------------------------------------------------------- CMDi

CMD_ECHO = ["{o};echo {c}$(({a}*{b}))", "{o}|echo {c}$(({a}*{b}))", "{o}$(echo {c}$(({a}*{b})))",
            "{o}`echo {c}$(({a}*{b}))`", "{o}&&echo {c}$(({a}*{b}))", "{o}\necho {c}$(({a}*{b}))",
            "{o}&set /a {a}*{b}&"]
CMD_SLEEP = ["{o};sleep {d};", "{o}|sleep {d}", "{o}$(sleep {d})", "{o}`sleep {d}`", "{o}&&sleep {d}",
             "{o}& ping -n {d1} 127.0.0.1 &"]


async def cmdi(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("cmdi", point):
        return
    base = await ctx.baseline(point)
    if base is None:
        return
    o = point.original
    a, b = random.randint(1000, 9999), random.randint(1000, 9999)
    c = token(5)
    for tpl in CMD_ECHO:
        payload = tpl.format(o=o, c=c, a=a, b=b)
        expect = str(a * b) if "set /a" in tpl else f"{c}{a * b}"
        r = await ctx.send(point, payload)
        if r is not None and expect in r.text and not base.contains(expect):
            _report_cmdi(ctx, point, payload, f"Shell arithmetic was evaluated: response contains '{expect}'.",
                         Confidence.CERTAIN, SIGNATURE)
            return
    if not ctx.config.timing_checks:
        return
    for tpl in CMD_SLEEP:
        ok, ev = await ctx.timing_confirm(point, lambda d, t=tpl: t.format(o=o, d=d, d1=d + 1), base)
        if ok:
            d = ctx.config.time_delay
            _report_cmdi(ctx, point, tpl.format(o=o, d=d, d1=d + 1),
                         f"Response delay follows injected sleep duration: {ev}", Confidence.FIRM, TIMING, ev)
            return


def _report_cmdi(ctx, point, payload, evidence, conf, detection, feats=None):
    ctx.report(Finding(
        check="cmdi",
        title="OS command injection",
        severity=Severity.CRITICAL, confidence=conf,
        url=point.url, method=point.method, parameter=point.name, location=point.location,
        payload=payload, evidence=evidence,
        description="User input is passed to a system shell, allowing arbitrary command execution on the server.",
        remediation="Avoid shell invocation; call programs with argument arrays (no shell) and strict "
                    "allow-list validation of every argument.",
        cwe="CWE-78", owasp="A03:2021-Injection", detection=detection,
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["cmdi", "rce", "injection"], request=ctx.curl(point, payload), features=feats or {},
    ))

# --------------------------------------------------------------------------------- SSRF

URL_PARAMS = re.compile(r"(?i)(url|uri|link|src|source|dest|redirect|feed|fetch|proxy|host|site|callback|"
                        r"webhook|endpoint|image|img|avatar|domain|load|file|path|next|target|ref)")
SSRF_MARKER = re.compile(r"<title>Example Domain</title>|This domain is for use in (?:illustrative|documentation) examples")


async def ssrf(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("ssrf", point):
        return
    looks_url = point.original.startswith(("http://", "https://", "//", "/"))
    if not (looks_url or URL_PARAMS.search(point.name)):
        return
    base = await ctx.baseline(point)
    if base is None:
        return
    # in-band: does the server fetch and return remote content?
    payload = "http://example.com/"
    r = await ctx.send(point, payload)
    if r is not None and SSRF_MARKER.search(r.text) and not any(SSRF_MARKER.search(s.text) for s in base.samples):
        ctx.report(Finding(
            check="ssrf", title="Server-side request forgery (in-band)",
            severity=Severity.HIGH, confidence=Confidence.CERTAIN,
            url=point.url, method=point.method, parameter=point.name, location=point.location,
            payload=payload,
            evidence="The response contains the content of http://example.com/, fetched by the server.",
            description="The server fetches attacker-controlled URLs, which can be abused to reach internal "
                        "services, cloud metadata endpoints (credentials) and to bypass network ACLs.",
            remediation="Allow-list destination hosts/schemes, resolve and block private/link-local ranges "
                        "after DNS resolution, disable redirects, and isolate the fetcher network-wise.",
            cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery", detection=SIGNATURE,
            references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
            tags=["ssrf"], request=ctx.curl(point, payload),
        ))
        return
    # out-of-band: correlate later with the user's interaction server (interactsh/Collaborator)
    if ctx.config.oob_domain:
        t = token(10)
        oob_payload = f"http://{t}.{ctx.config.oob_domain}/"
        await ctx.send(point, oob_payload)
        ctx.oob_log.append({"token": t, "url": point.url, "parameter": point.name,
                            "location": point.location, "payload": oob_payload})
