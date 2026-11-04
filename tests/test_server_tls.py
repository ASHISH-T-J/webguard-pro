"""Web server configuration and TLS audits: misconfigured targets vs hardened twins."""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from webguard.config import ScanConfig
from webguard.detection.checks import server, tls
from webguard.detection.context import Context
from webguard.http import HttpClient, Resp
from webguard.models import Severity
from webguard.scope import Scope
from webguard.signatures import default_db


def _run(handler, fn):
    async def go():
        async with HttpClient(ScanConfig(rate_limit=1000), Scope(include=["t.test"]),
                              transport=httpx.MockTransport(handler)) as client:
            ctx = Context(client, ScanConfig(), default_db())
            await fn(ctx)
            return list(ctx.findings.values())
    return asyncio.run(go())


def test_software_versions_from_headers_and_pages():
    r = Resp("https://t.test/", 200, httpx.Headers({"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.1f PHP/7.4.3",
                                                     "X-Jenkins": "2.441"}),
             '<meta name="generator" content="WordPress 5.8.1">', 0.1, "GET")
    found = {(p, v) for p, v, _, _ in server.software_versions(r)}
    assert {("apache_httpd", "2.4.49"), ("openssl", "1.0.1f"), ("php", "7.4.3"), ("jenkins", "2.441"),
            ("wordpress", "5.8.1")} <= found


def misconfigured(req: httpx.Request) -> httpx.Response:
    path = req.url.path
    hdr = {"Server": "Apache/2.4.49 (Unix) PHP/7.4.3"}
    if req.method == "OPTIONS":
        return httpx.Response(200, headers={**hdr, "Allow": "GET, HEAD, POST, PUT, DELETE, PROPFIND", "DAV": "1,2"})
    if path == "/":
        return httpx.Response(200, headers=hdr, text="<html><title>Welcome to nginx!</title></html>")
    if path == "/files/":
        return httpx.Response(200, headers=hdr, text='<title>Index of /files</title><a href="backup.sql">backup.sql</a>')
    if path == "/manager/html":
        return httpx.Response(401, headers={**hdr, "WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'})
    return httpx.Response(404, headers=hdr, text="not found")


def hardened(req: httpx.Request) -> httpx.Response:
    if req.method == "OPTIONS":
        return httpx.Response(204, headers={"Allow": "GET, HEAD, POST"})
    if req.url.path == "/":
        return httpx.Response(200, headers={"Server": "nginx"}, text="<html><title>Shop</title></html>")
    return httpx.Response(404, headers={"Server": "nginx"}, text="not found")


def test_server_audit_flags_misconfigurations():
    findings = _run(misconfigured, lambda ctx: server.audit(ctx, "https://t.test", {}))
    titles = {f.title for f in findings}
    checks = {f.check for f in findings}
    assert "cve:CVE-2021-41773" in checks and "cve:CVE-2021-42013" in checks
    assert any(t.startswith("End-of-life software: php 7.4.3") for t in titles)
    listing = next(f for f in findings if f.title.startswith("Directory listing"))
    assert listing.severity == Severity.MEDIUM and listing.url.endswith("/files/")  # backup.sql listed
    assert "Default nginx page" in titles
    tomcat = next(f for f in findings if "Tomcat Manager" in f.title)
    assert tomcat.severity == Severity.LOW and "login prompt" in tomcat.title
    assert any(t.startswith("WebDAV / write methods advertised") for t in titles)


def test_hardened_server_has_no_findings():
    assert _run(hardened, lambda ctx: server.audit(ctx, "https://t.test", {})) == []


def test_weak_hsts_and_plain_http_without_redirect():
    def handler(req):
        if req.url.scheme == "https":
            return httpx.Response(200, headers={"Strict-Transport-Security": "max-age=300"}, text="ok")
        return httpx.Response(200, text="plain")

    titles = {f.title for f in _run(handler, lambda ctx: tls.hsts_and_redirect(ctx, "https://t.test"))}
    assert titles == {"Weak HSTS policy", "Site served over plain HTTP without redirect to HTTPS"}

    def good(req):
        if req.url.scheme == "https":
            return httpx.Response(200, headers={"Strict-Transport-Security": "max-age=31536000"}, text="ok")
        return httpx.Response(301, headers={"Location": "https://t.test/"})

    assert _run(good, lambda ctx: tls.hsts_and_redirect(ctx, "https://t.test")) == []


def test_tls_report_from_survey():
    now = dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc)
    survey = {"accepted": ["TLSv1.0", "TLSv1.2"], "untested": [], "error": None,
              "weak": [("3DES (SWEET32)", "DES-CBC3-SHA", Severity.MEDIUM)], "cert_error": (18, "self-signed certificate"),
              "cert": {"not_after": now + dt.timedelta(days=10), "key": ("RSA", 1024), "sig_hash": "sha1"}}
    findings = _run(lambda r: httpx.Response(404), lambda ctx: asyncio.sleep(0, tls.report(ctx, "https://t.test", survey, now)))
    titles = {f.title for f in findings}
    assert titles == {"Deprecated TLS protocol enabled (TLSv1.0)", "Weak TLS cipher suites accepted: 3DES (SWEET32)",
                      "TLS certificate problem: self-signed", "TLS certificate expires in 10 day(s)",
                      "Weak TLS certificate key (RSA 1024 bits)", "TLS certificate signed with SHA1"}


# ----------------------------------------------------------------------------- live TLS handshakes

def _cert(tmp_path, bits: int, days: int):
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / f"c{bits}.pem", tmp_path / f"k{bits}.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class _TLSServer:
    def __init__(self, cert, key, legacy: bool):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass  # rejected legacy handshakes are expected

        self.httpd = Quiet(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if legacy:
            import warnings

            warnings.filterwarnings("ignore", "ssl.TLSVersion.TLSv1", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def test_live_tls_probe_weak_vs_hardened(tmp_path):
    weak_srv = _TLSServer(*_cert(tmp_path, 1024, 10), legacy=True)
    good_srv = _TLSServer(*_cert(tmp_path, 2048, 365), legacy=False)
    try:
        weak = tls.probe("127.0.0.1", weak_srv.port, "localhost")
        good = tls.probe("127.0.0.1", good_srv.port, "localhost")
    finally:
        weak_srv.close()
        good_srv.close()
    assert weak["cert_error"][0] in (18, 19, 66)  # self-signed, or rejected first for the 1024-bit key
    assert good["cert_error"][0] in (18, 19)
    assert weak["cert"]["key"] == ("RSA", 1024) and good["cert"]["key"] == ("RSA", 2048)
    assert "TLSv1.2" in good["accepted"] and not {"TLSv1.0", "TLSv1.1"} & set(good["accepted"])
    if "TLSv1.0" not in weak["untested"]:  # this client's OpenSSL can still speak TLS 1.0
        assert "TLSv1.0" in weak["accepted"]
    assert not [w for w in good["weak"] if w[2] >= Severity.MEDIUM]


def test_cve_version_ordering_and_backports():
    from webguard import cve

    assert cve.in_range("9.6p1", ">=8.5p1,<9.8p1") and not cve.in_range("9.8p1", ">=8.5p1,<9.8p1")
    assert cve.in_range("11.0.0-M1", "<11.0.0") and cve.in_range("1.0.1f", "<1.0.1g")
    assert cve.in_range("2.4", "==2.4.0") and not cve.in_range("2.4.51", "==2.4.49")
    assert cve.normalize_version("OpenSSH_9.6p1 Ubuntu-3ubuntu13") == "9.6p1"
    assert {c.id for c in cve.lookup("apache_httpd", "2.4.49")} >= {"CVE-2021-41773", "CVE-2021-42013"}
    assert cve.lookup("apache_httpd", "2.4.62") == []
    banner = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"  # distro back-ported the fix: lower confidence
    f = cve.findings_for("openssh", "8.9p1", "tcp://h:22", "SSH banner", banner)[0]
    assert f.check == "cve:CVE-2024-6387" and f.confidence.name == "TENTATIVE" and "back-ported" in f.evidence
    assert cve.eol_finding("php", "7.4.3", "https://t.test/", "header") is not None
    assert cve.eol_finding("php", "8.3.1", "https://t.test/", "header") is None
