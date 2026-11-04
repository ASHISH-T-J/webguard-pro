"""TLS / HTTPS configuration audit (OWASP WSTG-CRYP-01, WSTG-CONF-07).

A handful of ordinary TLS handshakes per HTTPS origin (no data is sent after the handshake):

* protocol versions accepted (TLS 1.0 / 1.1 deprecated - RFC 8996)
* weak cipher suites accepted (NULL, anonymous, EXPORT, RC4, 3DES, static-RSA key exchange)
* certificate: expired / not yet valid / expiring soon, self-signed, untrusted or incomplete chain,
  host name mismatch, RSA key < 2048 bits, SHA-1 / MD5 signature
* HTTPS enforcement: plain-HTTP access without redirect, weak HSTS policy

Only *accepted* weak options are reported. If this machine's TLS library cannot offer a legacy protocol
or cipher, that item is listed as not tested, never as "not supported by the server".
Handshakes connect directly to the target, so they are skipped when ``--proxy`` is set.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
import socket
import ssl
import warnings
from urllib.parse import urlsplit

from webguard.detection.context import Context
from webguard.models import PASSIVE, SIGNATURE, Confidence, Finding, Severity

CRYPTO = "A02:2021-Cryptographic Failures"
LEGACY = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]
MODERN = [("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]
# (label, OpenSSL cipher string, severity) - probed with TLS 1.2 as the highest version
WEAK_CIPHERS = [
    ("NULL encryption", "eNULL", Severity.HIGH),
    ("anonymous key exchange", "aNULL", Severity.HIGH),
    ("EXPORT-grade", "EXPORT", Severity.HIGH),
    ("RC4", "RC4", Severity.MEDIUM),
    ("3DES (SWEET32)", "3DES", Severity.MEDIUM),
    ("static RSA key exchange (no forward secrecy)", "kRSA", Severity.LOW),
]
VERIFY_CODES = {
    9: ("not yet valid", Severity.HIGH), 10: ("expired", Severity.HIGH),
    18: ("self-signed", Severity.MEDIUM), 19: ("self-signed certificate in chain", Severity.MEDIUM),
    20: ("untrusted or incomplete chain (issuer not found)", Severity.MEDIUM),
    21: ("incomplete chain (cannot verify first certificate)", Severity.MEDIUM),
    62: ("host name mismatch", Severity.MEDIUM),
    66: ("certificate key too small", Severity.MEDIUM), 68: ("CA signature digest too weak", Severity.MEDIUM),
}
HSTS_MIN = 15552000  # 180 days


class Unsupported(Exception):
    """This client cannot offer the requested protocol / cipher (local TLS library policy)."""


def _context(version: ssl.TLSVersion | None = None, ciphers: str | None = None,
             max_version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        warnings.filterwarnings("ignore", "ssl.TLSVersion.TLSv1", DeprecationWarning)  # probing them on purpose
        if version is not None:
            ctx.minimum_version = ctx.maximum_version = version
        elif max_version is not None:
            ctx.maximum_version = max_version
        if ciphers or (version is not None and version < ssl.TLSVersion.TLSv1_2):
            ctx.set_ciphers((ciphers or "ALL") + ":@SECLEVEL=0")
    except (ValueError, ssl.SSLError) as exc:
        raise Unsupported(str(exc)) from exc
    return ctx


def handshake(host: str, port: int, ctx: ssl.SSLContext, sni: str | None = None, timeout: float = 6.0) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        try:
            tls = ctx.wrap_socket(sock, server_hostname=sni or host)
        except ssl.SSLError as exc:
            if re.search(r"NO_(?:PROTOCOLS|CIPHERS)_AVAILABLE|no cipher", str(exc), re.I):
                raise Unsupported(str(exc)) from exc  # refused locally, before talking to the server
            raise
        with tls:
            return {"version": tls.version(), "cipher": tls.cipher(), "der": tls.getpeercert(binary_form=True),
                    "cert": tls.getpeercert() if ctx.verify_mode != ssl.CERT_NONE else None}


def _cert_details(der: bytes | None) -> dict:
    """not_after, key type/size, signature hash, subject/issuer (cryptography optional)."""
    if not der:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError:
        return {}
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    out = {"not_after": getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc),
           "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string()}
    if isinstance(key, rsa.RSAPublicKey):
        out["key"] = ("RSA", key.key_size)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        out["key"] = ("EC", key.curve.key_size)
    try:
        out["sig_hash"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        out["sig_hash"] = None
    return out


def probe(host: str, port: int, sni: str) -> dict:
    """Blocking TLS survey of one endpoint (run in a thread)."""
    res: dict = {"accepted": [], "untested": [], "weak": [], "cert_error": None, "cert": {}, "error": None}
    for label, version in LEGACY + MODERN:
        try:
            info = handshake(host, port, _context(version), sni)
            if info["version"] in (label, label.replace("TLSv1.0", "TLSv1")):  # ssl reports 1.0 as "TLSv1"
                res["accepted"].append(label)
                res.setdefault("der", info["der"])
                res.setdefault("cipher", info["cipher"])
        except Unsupported:
            res["untested"].append(label)
        except (ssl.SSLError, ConnectionError, TimeoutError):
            pass
        except OSError as exc:
            res["error"] = f"{type(exc).__name__}: {exc}"
            return res
    if not res["accepted"]:
        res["error"] = res["error"] or "no TLS handshake succeeded"
        return res
    for label, spec, sev in WEAK_CIPHERS:
        try:
            info = handshake(host, port, _context(ciphers=spec, max_version=ssl.TLSVersion.TLSv1_2), sni)
            res["weak"].append((label, info["cipher"][0], sev))
        except Unsupported:
            res["untested"].append(label)
        except (ssl.SSLError, OSError):
            pass
    verifying = ssl.create_default_context()
    try:
        info = handshake(host, port, verifying, sni)
        res["cert"]["not_after_text"] = (info["cert"] or {}).get("notAfter")
    except ssl.SSLCertVerificationError as exc:
        res["cert_error"] = (exc.verify_code, exc.verify_message)
    except (ssl.SSLError, OSError):
        pass
    res["cert"].update(_cert_details(res.get("der")))
    return res


def _finding(url: str, title: str, sev: Severity, evidence: str, description: str, remediation: str,
             cwe: str = "CWE-326", tags: tuple[str, ...] = ()) -> Finding:
    return Finding(check="tls", title=title, severity=sev, confidence=Confidence.CERTAIN, url=url, evidence=evidence,
                   description=description, remediation=remediation, cwe=cwe, owasp=CRYPTO, detection=SIGNATURE,
                   references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_"
                               "Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_"
                               "Layer_Security"], tags=["tls", *tags])


def report(ctx: Context, origin: str, res: dict, now: dt.datetime | None = None) -> None:
    def url(part: str) -> str:  # one URL per issue so distinct TLS findings never deduplicate
        return f"{origin}/#tls-{re.sub(r'[^a-z0-9]+', '-', part.lower()).strip('-')}"

    legacy = [p for p in res["accepted"] if p in ("TLSv1.0", "TLSv1.1")]
    if legacy:
        ctx.report(_finding(url("protocol"), f"Deprecated TLS protocol enabled ({', '.join(legacy)})", Severity.MEDIUM,
                            f"Handshake completed with {', '.join(legacy)}; accepted: {', '.join(res['accepted'])}",
                            "TLS 1.0 and 1.1 are deprecated (RFC 8996) and lack modern cipher suites; PCI DSS and "
                            "most baselines prohibit them.",
                            "Allow only TLS 1.2 and 1.3 (e.g. nginx: ssl_protocols TLSv1.2 TLSv1.3;).", tags=("protocol",)))
    for label, cipher, sev in res["weak"]:
        ctx.report(_finding(url("cipher " + label), f"Weak TLS cipher suites accepted: {label}", sev, f"Negotiated {cipher} over TLS",
                            "The server agrees to cipher suites that are broken or lack forward secrecy.",
                            "Use an AEAD-only, ECDHE-based cipher list (e.g. the Mozilla 'intermediate' profile).",
                            cwe="CWE-327", tags=("cipher",)))
    if res.get("cert_error"):
        code, msg = res["cert_error"]
        what, sev = VERIFY_CODES.get(code, (msg, Severity.MEDIUM))
        ctx.report(_finding(url("certificate " + what), f"TLS certificate problem: {what}", sev, f"Verification failed: {msg} (code {code})",
                            "Browsers and API clients reject this certificate; users who click through are open "
                            "to interception, and automated clients may be configured to skip verification.",
                            "Install a certificate from a trusted CA that covers this host name, with the full "
                            "intermediate chain, and automate renewal.", cwe="CWE-295", tags=("certificate",)))
    cert = res.get("cert") or {}
    now = now or dt.datetime.now(dt.timezone.utc)
    not_after = cert.get("not_after")
    if not_after is None and cert.get("not_after_text"):
        not_after = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["not_after_text"]), dt.timezone.utc)
    if not_after is not None and not (res.get("cert_error") or (0, ""))[0] == 10:
        days = (not_after - now).days
        if 0 <= days < 30:
            ctx.report(_finding(url("certificate expiry"), f"TLS certificate expires in {days} day(s)", Severity.LOW,
                                f"notAfter {not_after:%Y-%m-%d}", "An expired certificate breaks access and "
                                "teaches users to ignore warnings.", "Renew now and automate renewal (ACME).",
                                cwe="CWE-298", tags=("certificate",)))
    key = cert.get("key")
    if key and key[0] == "RSA" and key[1] < 2048:
        ctx.report(_finding(url("certificate key"), f"Weak TLS certificate key (RSA {key[1]} bits)", Severity.MEDIUM,
                            f"Certificate public key: RSA {key[1]} bits", "RSA keys under 2048 bits are below "
                            "current minimums and can be factored with sufficient resources.",
                            "Re-issue the certificate with RSA 2048+ or ECDSA P-256.", tags=("certificate",)))
    if cert.get("sig_hash") in ("sha1", "md5"):
        ctx.report(_finding(url("certificate signature"), f"TLS certificate signed with {cert['sig_hash'].upper()}", Severity.MEDIUM,
                            f"Signature hash: {cert['sig_hash']}", "SHA-1/MD5 certificate signatures are vulnerable "
                            "to collision attacks and rejected by modern clients.",
                            "Re-issue the certificate with a SHA-256 signature.", cwe="CWE-328", tags=("certificate",)))


async def hsts_and_redirect(ctx: Context, origin: str) -> None:
    """Plain-HTTP access without redirect, and HSTS strength (from ordinary GETs)."""
    host = urlsplit(origin).netloc
    https = await ctx.client.safe_get(origin + "/")
    if https is not None:
        hsts = https.headers.get("strict-transport-security", "")
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        if hsts and (not m or int(m.group(1)) < HSTS_MIN):
            ctx.report(Finding(
                check="tls", title="Weak HSTS policy", severity=Severity.LOW, confidence=Confidence.CERTAIN,
                url=origin + "/#hsts", evidence=f"Strict-Transport-Security: {hsts[:160]}",
                description="A short max-age lets HSTS expire between visits, re-opening SSL-stripping attacks.",
                remediation="Use max-age=31536000; includeSubDomains (and consider preload).",
                cwe="CWE-523", owasp=CRYPTO, detection=PASSIVE, tags=["tls", "hsts"]))
    plain_url = f"http://{host.rsplit(':', 1)[0] if host.endswith(':443') else host}/"
    if not ctx.client.scope.in_scope(plain_url) or ":" in host and not host.endswith(":443"):
        return  # non-standard HTTPS port: there is no matching plain-HTTP origin to check
    plain = await ctx.client.safe_get(plain_url)
    if plain is None or plain.status != 200:
        return
    if plain.history or not plain.url.startswith("http://"):
        return
    ctx.report(Finding(
        check="tls", title="Site served over plain HTTP without redirect to HTTPS", severity=Severity.LOW,
        confidence=Confidence.CERTAIN, url=plain_url, evidence=f"GET {plain_url} -> HTTP 200 without redirect",
        description="Users who type the address or follow http:// links stay on an unencrypted connection that "
                    "can be read and modified in transit.",
        remediation="Redirect all plain-HTTP requests to HTTPS (301) and enable HSTS.",
        cwe="CWE-319", owasp=CRYPTO, detection=PASSIVE, tags=["tls", "redirect"],
        request=ctx.client.curl("GET", plain_url)))


async def audit(ctx: Context, origin: str) -> dict | None:
    """TLS audit of one https:// origin. Returns the raw survey (also stored as a fact by the caller)."""
    p = urlsplit(origin)
    if p.scheme != "https":
        return None
    await hsts_and_redirect(ctx, origin)
    if ctx.config.proxy:
        return {"skipped": "proxy configured - TLS handshakes would bypass it"}
    host, port = p.hostname or "", p.port or 443
    res = await asyncio.to_thread(probe, host, port, host)
    ctx.client.stats["tls_handshakes"] = ctx.client.stats.get("tls_handshakes", 0) + 13
    if res.get("error") and not res["accepted"]:
        return res
    report(ctx, origin, res)
    return res
