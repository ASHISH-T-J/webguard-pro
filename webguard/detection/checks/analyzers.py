"""Passive analyzers (no extra requests): JWT weaknesses, sensitive data in API responses, CSRF,
serialized objects, credentials in URLs, missing Subresource Integrity."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import parse_qsl, urlsplit

from bs4 import BeautifulSoup

from webguard.detection.context import Context
from webguard.http import Resp
from webguard.models import PASSIVE, Confidence, Finding, Severity

JWT_RX = re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,})\.(eyJ[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{0,})")
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt", "jwtsecret", "jwt_secret", "secretkey", "secret_key",
    "your-256-bit-secret", "your_jwt_secret", "mysecret", "key", "private", "admin", "test", "default", "s3cr3t",
    "supersecret", "super-secret", "topsecret", "qwerty", "letmein", "token", "auth", "hmac", "app", "dev",
    "development", "production", "secret123", "password123", "12345678", "abc123", "shhhhh", "keyboard cat",
    "my-secret", "my_secret", "jwt-secret", "secretKey", "SECRET", "Secret", "gfg_jwt_secret_key", "hello",
]


def _b64json(part: str) -> dict | None:
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return None


def crack_hs(token: str, words: list[str] = WEAK_SECRETS) -> str | None:
    head, payload, sig = token.split(".")
    alg = (_b64json(head) or {}).get("alg", "")
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    msg = f"{head}.{payload}".encode()
    for w in words:
        mac = base64.urlsafe_b64encode(hmac.new(w.encode(), msg, digest).digest()).rstrip(b"=").decode()
        if hmac.compare_digest(mac, sig):
            return w
    return None


SENSITIVE_CLAIMS = re.compile(r"(?i)^(?:password|passwd|pwd|hash|secret|ssn|credit_?card|card_?number|totp_?secret|"
                              r"api_?key|private_?key)$")


def _walk_keys(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{prefix}{k}", k, v
            yield from _walk_keys(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for item in obj[:50]:
            yield from _walk_keys(item, prefix)


def jwt(ctx: Context, resp: Resp) -> None:
    sources = [resp.text[:500000]] + list(resp.headers.get_list("set-cookie"))
    seen = set()
    for src in sources:
        for m in JWT_RX.finditer(src):
            tok = m.group(0)
            if tok in seen:
                continue
            seen.add(tok)
            header, claims = _b64json(m.group(1)) or {}, _b64json(m.group(2)) or {}
            alg = str(header.get("alg", "?"))
            issues, sev = [], Severity.INFO
            if alg.lower() == "none" or not m.group(3):
                issues.append("unsigned token (alg=none)")
                sev = Severity.HIGH
            secret = crack_hs(tok) if alg.upper().startswith("HS") else None
            if secret is not None:
                issues.append(f"HMAC secret cracked offline: '{secret}'")
                sev = Severity.CRITICAL
            leaked = sorted({path for path, k, v in _walk_keys(claims) if SENSITIVE_CLAIMS.match(str(k)) and v})
            if leaked:
                issues.append(f"sensitive claims in payload: {', '.join(leaked)}")
                sev = max(sev, Severity.MEDIUM)
            if "exp" not in claims:
                issues.append("no expiry (exp) claim")
                sev = max(sev, Severity.LOW)
            for k in ("jku", "x5u", "kid"):
                if k in header:
                    issues.append(f"header '{k}' present - test for key-injection ({k}={str(header[k])[:60]})")
            if not issues:
                continue
            issues.append(f"seen at {resp.url.split('#')[0]}")
            ctx.report(Finding(
                check="jwt", title="JWT weaknesses: " + issues[0].split(":")[0], severity=sev,
                confidence=Confidence.CERTAIN if secret or alg.lower() == "none" or leaked else Confidence.FIRM,
                # one finding per token, not per page that happens to carry it
                url="{0.scheme}://{0.netloc}/#jwt-".format(urlsplit(resp.url)) + hashlib.sha1(tok.encode()).hexdigest()[:8],
                evidence=f"alg={alg}; " + "; ".join(issues),
                description="JSON Web Tokens must be signed with a strong key, expire, and must not carry secrets "
                            "(the payload is only base64-encoded, not encrypted). A cracked HMAC secret lets anyone "
                            "forge tokens for any user.",
                remediation="Use a long random signing key (or asymmetric keys), enforce an algorithm allow-list, "
                            "set short expiries and keep sensitive data out of claims.",
                cwe="CWE-347" if secret or alg.lower() == "none" else "CWE-200",
                owasp="A02:2021-Cryptographic Failures", detection=PASSIVE, tags=["jwt", "auth"],
            ))


HASH_TYPES = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt"),
    (re.compile(r"^\$argon2"), "argon2"),
    (re.compile(r"^\$6\$"), "sha512-crypt"),
    (re.compile(r"^[a-f0-9]{32}$", re.I), "MD5"),
    (re.compile(r"^[a-f0-9]{40}$", re.I), "SHA-1"),
    (re.compile(r"^[a-f0-9]{64}$", re.I), "SHA-256"),
]
SECRET_KEYS = re.compile(r"(?i)^(?:password|passwd|pwd|password_?hash|hash|secret|api_?key|private_?key|"
                         r"totp_?secret|deluxe_?token|reset_?token|access_?token|refresh_?token)$")
PII_KEYS = re.compile(r"(?i)^(?:e?mail|email_?address|phone|mobile|ssn|dob|date_?of_?birth|card_?num(?:ber)?|"
                      r"credit_?card|iban|address|street)$")


def data_exposure(ctx: Context, resp: Resp) -> None:
    """Sensitive fields (password hashes, secrets, bulk PII) in JSON API responses - aggregated per URL."""
    if "json" not in resp.content_type or resp.status >= 400:
        return
    try:
        data = json.loads(resp.text)
    except ValueError:
        return
    secrets: dict[str, set[str]] = {}
    pii_values: set[str] = set()
    for _path, key, value in _walk_keys(data):
        if not isinstance(value, str) or not value or value in ("null", "undefined"):
            continue
        if SECRET_KEYS.match(str(key)):
            kind = next((name for rx, name in HASH_TYPES if rx.match(value)), "plaintext/unknown")
            secrets.setdefault(f"{key} ({kind})", set()).add(value)
        elif PII_KEYS.match(str(key)):
            pii_values.add(value)
    url = resp.url.split("#")[0]
    if secrets:
        weak = any(("MD5" in k or "SHA-1" in k or "plaintext" in k) and "token" not in k.lower() for k in secrets)
        n = sum(len(v) for v in secrets.values())
        ctx.report(Finding(
            check="data_exposure", title="Credentials / password hashes exposed in API response",
            severity=Severity.HIGH, confidence=Confidence.CERTAIN, url=url,
            evidence=f"{n} value(s) in fields: {', '.join(sorted(secrets))}" + ("; weak/unsalted hash format" if weak else ""),
            description="The API returns password hashes or secrets. Unsalted fast hashes (MD5/SHA-1) are cracked "
                        "in seconds with public wordlists, leading to account takeover.",
            remediation="Never serialise credential fields to clients (use explicit response DTOs/serialisers); "
                        "store passwords with bcrypt/argon2.",
            cwe="CWE-200", owasp="A01:2021-Broken Access Control", detection=PASSIVE,
            tags=["data-exposure", "credentials"],
        ))
    if len(pii_values) >= 5:
        ctx.report(Finding(
            check="data_exposure", title="Bulk personal data exposed in API response", severity=Severity.MEDIUM,
            confidence=Confidence.FIRM, url=url + "#pii", evidence=f"{len(pii_values)} distinct PII values (emails/phones/addresses).",
            description="The response contains personal data for many users; verify that the caller is authorised.",
            remediation="Restrict the endpoint to authorised roles and return only the fields the client needs.",
            cwe="CWE-359", owasp="A01:2021-Broken Access Control", detection=PASSIVE, tags=["data-exposure", "pii"],
        ))


CSRF_FIELD = re.compile(r"(?i)csrf|xsrf|_token|authenticity|nonce|__requestverificationtoken|state")


def csrf(ctx: Context, resp: Resp, samesite_cookies: bool) -> None:
    if not resp.is_html or "<form" not in resp.text.lower():
        return
    soup = BeautifulSoup(resp.text, "html.parser")
    for form in soup.find_all("form"):
        if (form.get("method") or "get").lower() != "post":
            continue
        names = [i.get("name") or "" for i in form.find_all(["input", "textarea", "select"])]
        if any(CSRF_FIELD.search(n) for n in names) or any(i.get("type") == "password" for i in form.find_all("input")):
            continue  # protected, or a login form (login CSRF is low value)
        action = form.get("action") or urlsplit(resp.url).path
        ctx.report(Finding(
            check="csrf", title="State-changing form without anti-CSRF token", severity=Severity.LOW if samesite_cookies else Severity.MEDIUM,
            confidence=Confidence.TENTATIVE, url=resp.url.split("#")[0] + f"#form-{action}", method="POST",
            evidence=f"POST form to '{action}' with fields {', '.join(n for n in names if n)[:120]} has no token; "
                     f"session cookies {'use' if samesite_cookies else 'lack'} SameSite.",
            description="Without a CSRF token (or SameSite cookies) another site can submit this form on behalf of a "
                        "logged-in user. Confirm the action changes state and relies on cookie authentication.",
            remediation="Add synchroniser/double-submit CSRF tokens and set SameSite=Lax/Strict on session cookies.",
            cwe="CWE-352", owasp="A01:2021-Broken Access Control", detection=PASSIVE, tags=["csrf"],
        ))


SERIALIZED = [
    (re.compile(r"\brO0AB[A-Za-z0-9+/=]{10,}"), "Java serialized object (base64)"),
    (re.compile(r"\baced0005[0-9a-f]{8,}", re.I), "Java serialized object (hex)"),
    (re.compile(r"\bAAEAAAD/////[A-Za-z0-9+/=]{8,}"), ".NET BinaryFormatter (base64)"),
    (re.compile(r"(?:^|[=;&\"'])(?:O|a):\d+:[{\"]"), "PHP serialized object"),
    (re.compile(r"\bgAS[VW][A-Za-z0-9+/=]{8,}"), "Python pickle (base64)"),
]


def deserialization(ctx: Context, resp: Resp, request_url: str) -> None:
    hay = [("cookie", c) for c in resp.headers.get_list("set-cookie")]
    hay += [("query", f"{k}={v}") for k, v in parse_qsl(urlsplit(request_url).query)]
    if resp.is_html:
        hay += [("hidden field", m.group(0)) for m in re.finditer(r"<input[^>]+type=[\"']?hidden[^>]+>", resp.text[:300000], re.I)]
    for where, value in hay:
        for rx, name in SERIALIZED:
            if rx.search(value):
                ctx.report(Finding(
                    check="deserialization", title=f"Serialized object in {where}: {name}", severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE, url=resp.url.split("#")[0] + f"#ser-{where.replace(' ', '-')}",
                    evidence=f"{where}: {value[:120]}",
                    description="Client-controlled serialized objects are a classic remote-code-execution vector if "
                                "they are deserialised server-side without integrity protection.",
                    remediation="Use data-only formats (JSON) for client state, or sign and verify it (HMAC) before "
                                "deserialisation; enable type allow-lists.",
                    cwe="CWE-502", owasp="A08:2021-Software and Data Integrity Failures", detection=PASSIVE,
                    tags=["deserialization", "hunting"],
                ))
                return


SENSITIVE_PARAM = re.compile(r"(?i)^(?:password|passwd|pwd|token|access_token|api_?key|secret|session|sessionid|"
                             r"auth|jwt|key|otp|ssn)$")


def sensitive_url_params(ctx: Context, url: str) -> None:
    for k, v in parse_qsl(urlsplit(url).query):
        if SENSITIVE_PARAM.match(k) and len(v) >= 6:
            ctx.report(Finding(
                check="exposure", title="Sensitive value transmitted in URL", severity=Severity.LOW,
                confidence=Confidence.FIRM, url=url.split("?")[0] + f"#param-{k}", parameter=k, location="query",
                evidence=f"{k}=<{len(v)} chars> appears in a URL",
                description="Secrets in URLs leak through browser history, proxy/server logs and Referer headers.",
                remediation="Send secrets in headers or POST bodies; use short-lived single-use tokens where unavoidable.",
                cwe="CWE-598", owasp="A04:2021-Insecure Design", detection=PASSIVE, tags=["exposure", "url"],
            ))


def subresource_integrity(ctx: Context, resp: Resp) -> None:
    if not resp.is_html:
        return
    own = urlsplit(resp.url).netloc
    missing = []
    for m in re.finditer(r"<script[^>]+src=[\"'](https?:)?//([^/\"']+)[^\"']*[\"'][^>]*>", resp.text[:300000], re.I):
        if m.group(2) != own and "integrity=" not in m.group(0).lower():
            missing.append(m.group(2))
    if missing:
        ctx.report(Finding(
            check="headers", title="Third-party scripts without Subresource Integrity", severity=Severity.INFO,
            confidence=Confidence.CERTAIN, url=f"{urlsplit(resp.url).scheme}://{own}/#sri",
            evidence="Scripts from: " + ", ".join(sorted(set(missing))[:8]),
            description="If a third-party script host is compromised, the code runs with full access to this origin.",
            remediation="Add integrity= and crossorigin= attributes, or self-host critical scripts.",
            cwe="CWE-353", owasp="A08:2021-Software and Data Integrity Failures", detection=PASSIVE, tags=["sri"],
        ))


PRIVILEGED_PATH = re.compile(r"(?i)/(?:admin|administrator|internal|management|manage|private|debug|config|"
                             r"configuration|superuser|staff|ops|backoffice)(?:/|$|[-_.])")


def privileged_api(ctx: Context, resp: Resp, authenticated: bool) -> None:
    """Administrative/internal API endpoints that return data to an anonymous client."""
    if authenticated or resp.status != 200 or "json" not in resp.content_type:
        return
    path = urlsplit(resp.url).path
    if not PRIVILEGED_PATH.search(path) or len(resp.text) < 40:
        return
    try:
        data = json.loads(resp.text)
    except ValueError:
        return
    if not data or (isinstance(data, dict) and set(data) <= {"status", "error", "message", "ok"}):
        return
    keys = sorted(data)[:8] if isinstance(data, dict) else [f"list[{len(data)}]"]
    ctx.report(Finding(
        check="access", title="Administrative/internal API accessible without authentication",
        severity=Severity.MEDIUM, confidence=Confidence.FIRM, url=resp.url.split("#")[0],
        evidence=f"Anonymous GET {path} -> HTTP 200 JSON ({len(resp.text)} bytes; keys: {', '.join(map(str, keys))})",
        description="An endpoint under an administrative/internal path returns data without any session. Such "
                    "endpoints commonly leak configuration, user data or expose privileged functions.",
        remediation="Require authentication and an administrative role for the whole /admin (internal) API surface.",
        cwe="CWE-306", owasp="A01:2021-Broken Access Control", detection=PASSIVE, tags=["access-control", "admin"],
        request=ctx.client.curl("GET", resp.url),
    ))
