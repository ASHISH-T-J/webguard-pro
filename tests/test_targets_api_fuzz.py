"""Targets, reflection-guided planning, API tests, fuzzing, fingerprints, service audit, NLP corpus."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from webguard.config import ScanConfig
from webguard.detection.context import Context
from webguard.http import HttpClient, Resp
from webguard.scope import Scope
from webguard.signatures import default_db


def _ctx_run(handler, fn, **cfg):
    async def go():
        config = ScanConfig(rate_limit=1000, **cfg)
        async with HttpClient(config, Scope(include=["t.test"]), transport=httpx.MockTransport(handler)) as client:
            ctx = Context(client, config, default_db())
            out = await fn(ctx)
            return out, list(ctx.findings.values())
    return asyncio.run(go())


# ----------------------------------------------------------------------------- targets

def test_target_parsing(tmp_path):
    from webguard.targets import parse

    f = tmp_path / "t.txt"
    f.write_text("# scope\nhttps://a.test/app\nb.test   # comment\n10.0.0.0/30\n\nb.test\n")
    targets, errors = parse(["@" + str(f), "10.0.0.9:8443,[2001:db8::1]", "bad!", "ftp://x.test"], [])
    assert [(t.kind, t.value) for t in targets] == [
        ("url", "https://a.test/app"), ("domain", "b.test"), ("ip", "10.0.0.1"), ("ip", "10.0.0.2"),
        ("host_port", "10.0.0.9:8443"), ("ip", "[2001:db8::1]")]
    assert len(errors) == 2
    with pytest.raises(ValueError):
        from webguard.targets import expand
        expand("10.0.0.0/8")


# ----------------------------------------------------------------------------- reflection

def test_reflection_contexts_and_plan():
    from webguard.detection import reflection as R

    m = "wgabc123"
    html = f'<p>{m}\'"<</p><input value="{m}&#39;"><script>var a="{m}";</script><!-- {m} -->'
    r = Resp("https://t.test/", 200, httpx.Headers({"Content-Type": "text/html", "Location": f"/x?{m}"}), html, 0, "GET")
    ref = R.classify(r, m)
    assert ref.contexts == {"html_text", "html_attr", "script", "comment", "location"} and ref.raw_specials
    order = ["sqli", "lfi", "xss", "ssti", "redirect", "crlf"]
    assert R.plan(order, ref, "GET", False)[:4] == ["redirect", "crlf", "xss", "ssti"]
    none = R.Reflection(m)
    assert R.plan(order, none, "GET", True) == ["sqli", "lfi", "ssti", "redirect", "crlf"]  # xss pruned
    assert R.plan(order, none, "POST", True)[-1] == "xss"  # stored XSS still possible: demoted, not dropped


def test_site_param_names():
    from webguard.recon.params import site_param_names

    pages = {"a": Resp("https://t.test/api", 200, httpx.Headers({"Content-Type": "application/json"}),
                       '{"data":{"debugMode":true,"items":[{"ownerId":1}]}}', 0, "GET"),
             "b": Resp("https://t.test/", 200, httpx.Headers({"Content-Type": "text/html"}),
                       '<input name="coupon"><script>new URLSearchParams(location.search).get("preview")'
                       '; fetch("/x?tenant=1")</script>', 0, "GET")}
    assert {"debugMode", "ownerId", "coupon", "preview", "tenant"} <= set(site_param_names(pages))


# ----------------------------------------------------------------------------- API tests

def test_api_unauthenticated_access_and_versions():
    from webguard.detection.checks import api

    def handler(req):
        if req.url.path in ("/api/v2/me", "/api/v1/me"):
            return httpx.Response(200, json={"email": "a@t.test", "role": "user", "id": 1})
        return httpx.Response(404, json={"error": "nf"})

    authed = Resp("https://t.test/api/v2/me", 200, httpx.Headers({"Content-Type": "application/json"}),
                  '{"email": "a@t.test", "role": "user", "id": 1}', 0, "GET")

    async def run(ctx):
        await api.unauthenticated_access(ctx, [authed.url], {authed.url: authed}, httpx.MockTransport(handler))
        await api.api_versions(ctx, authed.url, authed)

    _, findings = _ctx_run(handler, run, headers={"Authorization": "Bearer x"})
    titles = {f.title for f in findings}
    assert "API endpoint returns private data without authentication" in titles
    assert "Additional API version(s) reachable: v1" in titles


def test_api_content_type_confusion_vs_strict_api():
    from webguard.detection.checks import api

    def lax(req):
        if req.content.startswith(b"{wg-"):
            return httpx.Response(400, json={"error": "bad json"})
        return httpx.Response(200, json={"ok": True})

    def ignores_body(req):
        return httpx.Response(200, json={"ok": True})

    def strict(req):
        ok = req.headers.get("content-type", "").startswith("application/json")
        return httpx.Response(200 if ok else 415, json={"ok": ok})

    run = lambda ctx: api.content_type_confusion(ctx, "https://t.test/api/profile", "POST", {"name": "x"})  # noqa: E731
    assert [f.title for f in _ctx_run(lax, run, cookies={"sid": "1"})[1]] == ["JSON API also accepts form-encoded requests"]
    assert _ctx_run(strict, run, cookies={"sid": "1"})[1] == []
    assert _ctx_run(ignores_body, run, cookies={"sid": "1"})[1] == []


# ----------------------------------------------------------------------------- fuzzing

def test_fuzzer_calibrates_and_filters():
    from webguard.fuzz import Filters, Fuzzer

    def handler(req):
        if req.url.path in ("/admin", "/backup.zip"):
            return httpx.Response(200 if req.url.path == "/admin" else 403, text="real " + req.url.path * 20)
        return httpx.Response(200, text="<html>catch-all spa shell</html>")  # soft 404

    fz = Fuzzer("https://t.test/FUZZ", ["admin", "backup.zip", "nope", "zzz"], ScanConfig(rate_limit=1000),
                Scope(include=["t.test"]), filters=Filters(), transport=httpx.MockTransport(handler))
    hits = asyncio.run(fz.run())
    assert [(h.value, h.status) for h in hits] == [("admin", 200), ("backup.zip", 403)]
    with pytest.raises(ValueError):
        Fuzzer("https://FUZZ.t.test/", [], ScanConfig(), Scope(include=["t.test"]))


# ----------------------------------------------------------------------------- fingerprints & services

def test_http_fingerprints_with_wordpress_workflow():
    from webguard import fingerprints

    def handler(req):
        p = req.url.path
        if p == "/feed/":
            return httpx.Response(200, text="<generator>https://wordpress.org/?v=6.4.2</generator>")
        if p == "/wp-content/plugins/wp-file-manager/readme.txt":
            return httpx.Response(200, text="=== File Manager ===\nStable tag: 6.8\n")
        if p == "/":
            return httpx.Response(200, headers={"X-Jenkins": "2.441"}, text="<html>/wp-content/</html>")
        return httpx.Response(404)

    async def run(ctx):
        return await fingerprints.run_http(ctx.client, "https://t.test", set())

    dets, _ = _ctx_run(handler, run)
    got = {(d.product, d.version) for d in dets}
    assert {("jenkins", "2.441"), ("wordpress", "6.4.2"), ("wp-plugin:wp-file-manager", "6.8")} <= got


def test_service_audit_banners(tmp_path):
    from webguard.recon import services

    async def run():
        async def ssh(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            await writer.drain()
            writer.close()

        async def ftp(reader, writer):
            writer.write(b"220 (vsFTPd 2.3.4)\r\n")
            await writer.drain()
            writer.close()

        s1 = await asyncio.start_server(ssh, "127.0.0.1", 0)
        s2 = await asyncio.start_server(ftp, "127.0.0.1", 0)
        p1, p2 = s1.sockets[0].getsockname()[1], s2.sockets[0].getsockname()[1]
        services.PORT_SERVICE.update({p1: "ssh", p2: "ftp"})
        try:
            return await services.audit("127.0.0.1", [p1, p2]), (p1, p2)
        finally:
            s1.close()
            s2.close()

    (found, findings), _ = asyncio.run(run())
    by = {s.product: s for s in found}
    assert by["openssh"].version == "8.9p1" and by["vsftpd"].version == "2.3.4"
    checks = {f.check: f for f in findings}
    assert checks["cve:CVE-2024-6387"].confidence.name == "TENTATIVE"  # Ubuntu back-port tag
    assert "cve:CVE-2011-2523" in checks


def test_nlp_param_corpus_generalises():
    from webguard.nlp.models import classify_param

    held = {"customerNumber": "id", "attachmentPath": "file", "avatarLink": "url", "returnPath": "redirect",
            "pingHost": "command", "emailTemplate": "template", "searchQuery": "search", "notifyEmail": "email",
            "bearerToken": "auth", "orderDirection": "sort", "jsonPayload": "data", "isDebug": "flag",
            "pageSize": "number", "userLocale": "lang", "ticket_number": "id", "export_file": "file",
            "sortField": "sort", "apiSecret": "auth", "debugMode": "flag"}
    assert sum(classify_param(k)[0] == v for k, v in held.items()) >= 17
