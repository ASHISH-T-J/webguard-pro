"""Host-level checks: security headers, CORS, sensitive file exposure, HTTP methods."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from webguard.detection.baseline import similarity
from webguard.detection.context import Context, token
from webguard.http import Resp
from webguard.models import PASSIVE, SIGNATURE, Confidence, Finding, Severity


def _root(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


# ------------------------------------------------------------------------- security headers

async def security_headers(ctx: Context, resp: Resp) -> None:
    h = {k.lower(): v for k, v in resp.headers.items()}
    https = resp.url.startswith("https://")
    missing = []
    if https and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security")
    if "content-security-policy" not in h:
        missing.append("Content-Security-Policy")
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options")
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options / CSP frame-ancestors")
    if "referrer-policy" not in h:
        missing.append("Referrer-Policy")
    if missing:
        ctx.report(Finding(
            check="headers", title="Missing security headers", severity=Severity.INFO if len(missing) < 3 else Severity.LOW,
            confidence=Confidence.CERTAIN, url=_root(resp.url) + "/", evidence="Missing: " + ", ".join(missing),
            description="Browser security headers that mitigate XSS, clickjacking, MIME sniffing and protocol "
                        "downgrade are absent.",
            remediation="Add the missing headers at the web server / CDN layer.",
            cwe="CWE-693", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE,
            references=["https://owasp.org/www-project-secure-headers/"], tags=["headers", "hardening"],
        ))
    if csp:
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'", "data:", " * ", "http:") if w in f" {csp} "]
        if "script-src" not in csp and "default-src" not in csp:
            weak.append("no script-src/default-src")
        if weak:
            ctx.report(Finding(
                check="headers", title="Weak Content-Security-Policy", severity=Severity.LOW,
                confidence=Confidence.CERTAIN, url=_root(resp.url) + "/#csp", evidence=f"Weak directives: {', '.join(weak)}",
                description="The CSP allows constructs that let injected scripts execute, so it does not mitigate XSS.",
                remediation="Use nonce- or hash-based script-src with 'strict-dynamic'; remove unsafe-inline/unsafe-eval.",
                cwe="CWE-693", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE, tags=["headers", "csp"],
            ))
    disclosed = {k: h[k] for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version") if k in h}
    versioned = {k: v for k, v in disclosed.items() if re.search(r"\d+\.\d+", v)}
    if versioned:
        ctx.report(Finding(
            check="headers", title="Software version disclosure in headers", severity=Severity.INFO,
            confidence=Confidence.CERTAIN, url=_root(resp.url) + "/#version",
            evidence="; ".join(f"{k}: {v}" for k, v in versioned.items()),
            description="Exact software versions help attackers match known CVEs.",
            remediation="Suppress version banners (e.g. server_tokens off; expose_php = Off).",
            cwe="CWE-200", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE, tags=["disclosure"],
        ))


# ------------------------------------------------------------------------- cookies

SESSION_COOKIE = re.compile(r"(?i)(sess|sid|auth|token|jwt|login|remember)")


def cookie_flags(ctx: Context, resp: Resp) -> None:
    for raw in resp.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        problems = []
        if resp.url.startswith("https://") and "; secure" not in attrs:
            problems.append("Secure")
        if SESSION_COOKIE.search(name) and "httponly" not in attrs:
            problems.append("HttpOnly")
        if "samesite" not in attrs:
            problems.append("SameSite")
        if problems and SESSION_COOKIE.search(name):
            ctx.report(Finding(
                check="headers", title=f"Session cookie '{name}' missing flags",
                severity=Severity.LOW, confidence=Confidence.CERTAIN,
                url=_root(resp.url) + f"/#cookie-{name}", evidence=f"Set-Cookie: {raw[:200]} (missing {', '.join(problems)})",
                description="Cookie attributes protect session cookies from theft over plaintext, script access and CSRF.",
                remediation="Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies.",
                cwe="CWE-614", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE, tags=["cookies"],
            ))


# ------------------------------------------------------------------------- CORS

async def cors(ctx: Context, url: str) -> None:
    host = urlsplit(url).hostname or ""
    scheme = urlsplit(url).scheme
    c = token(6)
    origins = [
        (f"https://{c}.example.org", "arbitrary origin reflected"),
        ("null", "null origin trusted"),
        (f"{scheme}://{host}.{c}.example.org", "suffix-match bypass (prefix check only)"),
        (f"{scheme}://{c}{host}", "prefix-match bypass (suffix check only)"),
        (f"http://{host}", "plaintext HTTP origin trusted") if scheme == "https" else (None, None),
    ]
    for origin, desc in origins:
        if not origin:
            continue
        try:
            r = await ctx.client.request("GET", url, headers={"Origin": origin})
        except Exception:
            return
        if r is None:
            return
        acao = r.headers.get("access-control-allow-origin", "")
        creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao != origin:
            continue
        if origin.startswith("http://") and origin.endswith(host) and not creds:
            continue
        sev = Severity.HIGH if creds else Severity.LOW
        if origin == f"http://{host}":
            sev = Severity.LOW
        ctx.report(Finding(
            check="cors", title=f"CORS misconfiguration: {desc}", severity=sev,
            confidence=Confidence.CERTAIN, url=url, payload=f"Origin: {origin}",
            evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {creds}",
            description="The server trusts attacker-controlled origins for cross-origin reads"
                        + (" including credentials, so a malicious site can read authenticated responses "
                           "(account data, CSRF tokens, API keys)." if creds else "."),
            remediation="Validate Origin against an exact allow-list; never reflect arbitrary origins or trust "
                        "'null' with credentials.",
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
            references=["https://portswigger.net/web-security/cors"], tags=["cors"],
            request=ctx.client.curl("GET", url, headers={"Origin": origin}),
        ))
        return


# ------------------------------------------------------------------------- exposures

async def soft404(ctx: Context, root: str) -> list[Resp]:
    """Fingerprints of the site's 'not found' responses (many sites return 200 for everything)."""
    out = []
    for path in (f"/{token()}", f"/{token()}.php", f"/.{token()}"):
        r = await ctx.client.safe_get(root + path)
        if r is not None:
            out.append(r)
    return out


async def exposures(ctx: Context, root: str) -> None:
    fps = await soft404(ctx, root)

    async def probe(key: str, sig: dict) -> None:
        r = await ctx.client.safe_get(root + sig["path"])
        if r is None:
            return
        if r.status != 200 and not (sig.get("allow_404") and r.status in (404, 500)):
            return
        if not re.search(sig["match"], r.text[:200000], re.M):
            return
        if sig.get("negative") and re.search(sig["negative"], r.text[:2000], re.I):
            return
        for fp in fps:
            if fp.status == r.status and similarity(fp.text, r.text) > 0.9:
                return
            if re.search(sig["match"], fp.text[:200000], re.M) and not sig.get("allow_404"):
                return
        snippet = re.search(sig["match"], r.text, re.M).group(0)[:120]
        ctx.report(Finding(
            check="exposure", title=sig["name"], severity=Severity.parse(sig["severity"]),
            confidence=Confidence.CERTAIN, url=root + sig["path"].split("?")[0],
            evidence=f"HTTP {r.status}, matched: {snippet!r}",
            description=f"{sig['name']} is publicly accessible at {sig['path']}.",
            remediation="Remove the file/endpoint from the web root or restrict access (deny rules, auth, network ACL).",
            cwe=sig.get("cwe"), owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
            tags=["exposure", key], request=ctx.client.curl("GET", root + sig["path"]),
        ))

    await asyncio.gather(*(probe(k, s) for k, s in ctx.sigdb.exposures.items()))


async def http_methods(ctx: Context, root: str) -> None:
    try:
        r = await ctx.client.request("TRACE", root + "/", headers={"X-Wg-Trace": "wgtrace1"})
    except Exception:
        return
    if r is not None and r.status == 200 and "wgtrace1" in r.text and "message/http" in r.content_type:
        ctx.report(Finding(
            check="headers", title="HTTP TRACE method enabled", severity=Severity.LOW, confidence=Confidence.CERTAIN,
            url=root + "/#trace", evidence="TRACE request echoed back with message/http content-type.",
            description="TRACE echoes requests (including headers), historically abused for cross-site tracing.",
            remediation="Disable TRACE at the web server (e.g. TraceEnable off).",
            cwe="CWE-16", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE, tags=["methods"],
        ))
