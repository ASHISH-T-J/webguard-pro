"""Out-of-band detection, recursive content discovery + 403 bypass, NLP / ML identification."""

from __future__ import annotations

import asyncio
import base64
import json
import os

import httpx
import pytest
from vulnapp import VulnServer

from webguard import oob
from webguard.config import ScanConfig
from webguard.detection.checks import hunting
from webguard.detection.context import Context
from webguard.http import HttpClient
from webguard.models import Confidence, Finding, Severity
from webguard.scope import Scope
from webguard.signatures import default_db

# ----------------------------------------------------------------------------- OOB providers


def test_interactsh_register_poll_decrypt_roundtrip():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    state: dict = {}

    def server(req: httpx.Request) -> httpx.Response:  # minimal interactsh server
        if req.url.path == "/register":
            body = json.loads(req.content)
            state["pub"] = serialization.load_pem_public_key(base64.b64decode(body["public-key"]))
            state["corr"], state["secret"] = body["correlation-id"], body["secret-key"]
            return httpx.Response(200, json={"message": "registration successful"})
        if req.url.path == "/poll":
            assert req.url.params["id"] == state["corr"] and req.url.params["secret"] == state["secret"]
            key, iv = os.urandom(32), os.urandom(16)
            try:
                from cryptography.hazmat.decrepit.ciphers.modes import CFB
            except ImportError:
                CFB = modes.CFB
            enc = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
            item = {"protocol": "http", "unique-id": state["uid"], "remote-address": "203.0.113.7",
                    "timestamp": "2026-11-04T10:00:00Z", "raw-request": "GET / HTTP/1.1"}
            blob = iv + enc.update(json.dumps(item).encode()) + enc.finalize()
            aes = state["pub"].encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                         label=None))
            return httpx.Response(200, json={"data": [base64.b64encode(blob).decode()],
                                             "aes_key": base64.b64encode(aes).decode()})
        return httpx.Response(200, json={})

    async def run():
        p = await oob.spawn("interactsh:oast.test", transport=httpx.MockTransport(server))
        payload = p.new_payload({"check": "ssrf", "url": "https://t.test/x", "parameter": "u"})
        assert payload.host.endswith(".oast.test") and len(payload.id) == 33
        state["uid"] = payload.id
        pairs = await p.correlate()
        await p.close()
        return payload, pairs

    payload, pairs = asyncio.run(run())
    assert pairs and pairs[0][0] is payload and pairs[0][1].remote == "203.0.113.7"


def test_auto_falls_back_to_local_listener():
    async def run():
        p = await oob.spawn("auto", transport=httpx.MockTransport(lambda r: httpx.Response(503)))
        kind = type(p).__name__
        await p.close()
        return kind

    assert asyncio.run(run()) == "LocalListener"


def test_static_domain_records_payloads():
    async def run():
        return await oob.spawn("collab.example.net")

    p = asyncio.run(run())
    pl = p.new_payload({"check": "ssrf"})
    assert pl.host.endswith(".collab.example.net") and not p.polls


def test_blind_ssrf_detected_with_spawned_listener(tmp_path):
    from webguard.assessment.agent import AssessmentAgent

    cfg = ScanConfig(rate_limit=1000, timing_checks=False, browser=False, model_path=tmp_path / "m.json",
                     checks=("ssrf",), oob="local:127.0.0.1", oob_wait=2, discovery_wordlist=None)
    with VulnServer() as server:
        res = asyncio.run(AssessmentAgent(cfg, Scope.for_target(server.url), on_status=lambda m: None).run(server.url))
    blind = [f for f in res.findings if f.title.startswith("Blind server-side request forgery")]
    assert [(f.url.split("/", 3)[-1], f.parameter) for f in blind] == [("webhook", "callback")]  # not /safe/webhook
    assert blind[0].confidence == Confidence.CERTAIN and blind[0].context["oob"]["protocols"] == ["http"]
    assert any("Out-of-band detection via local listener" in x for x in res.facts)


# ----------------------------------------------------------------------------- recursive discovery + 403 bypass

def site(req: httpx.Request) -> httpx.Response:
    raw = (req.extensions.get("target") or b"").decode()
    path = req.url.path
    if raw == "/admin/secret/.":  # proxy rule matches the literal path only
        return httpx.Response(200, text="<h1>Secret admin panel</h1>" + "<p>user list and settings</p>" * 5)
    if path == "/":
        return httpx.Response(200, text="<html><title>Home</title>" + "<p>welcome to the shop</p>" * 5)
    if path in ("/admin", "/assets"):
        return httpx.Response(301, headers={"Location": path + "/"})
    if path == "/admin/secret":
        return httpx.Response(403, text="<h1>403 Forbidden</h1>")
    if path == "/assets/app.js":
        return httpx.Response(200, text="console.log(1)")
    return httpx.Response(404, text="not found")


def test_recursive_discovery_finds_nested_paths_and_bypasses_403():
    async def run():
        async with HttpClient(ScanConfig(rate_limit=1000), Scope(include=["t.test"]),
                              transport=httpx.MockTransport(site)) as client:
            ctx = Context(client, ScanConfig(), default_db())
            found = await hunting.content_discovery(ctx, "https://t.test", ["admin", "assets", "secret", "app.js"],
                                                    depth=1)
            return found, list(ctx.findings.values())

    found, findings = asyncio.run(run())
    urls = {u for u, _ in found}
    assert {"https://t.test/admin", "https://t.test/admin/secret", "https://t.test/assets/app.js"} <= urls
    bypass = next(f for f in findings if f.check == "access")
    assert bypass.url == "https://t.test/admin/secret" and "trailing /." in bypass.title
    assert "--path-as-is" in bypass.request
    disc = next(f for f in findings if f.title == "Unlinked content discovered")
    assert "admin:" in disc.evidence and "depth 1" in disc.evidence


def test_discovery_depth_zero_does_not_recurse():
    async def run():
        async with HttpClient(ScanConfig(rate_limit=1000), Scope(include=["t.test"]),
                              transport=httpx.MockTransport(site)) as client:
            ctx = Context(client, ScanConfig(), default_db())
            return await hunting.content_discovery(ctx, "https://t.test", ["admin", "secret"], depth=0)

    assert {u for u, _ in asyncio.run(run())} == {"https://t.test/admin"}


# ----------------------------------------------------------------------------- NLP / ML

def test_path_classifier_and_recursion_order():
    from webguard.nlp.paths import classify_path, recursion_priority

    assert classify_path("/wp-admin")[0] == "admin" and classify_path("/db_dump.sql")[0] == "backup"
    assert classify_path("/.git/HEAD")[0] == "source_control" and classify_path("/api/v2")[0] == "api"
    assert classify_path("/assets/app.js")[0] == "static" and classify_path("/settings.yml")[0] == "config"
    order = sorted(["/css", "/images", "/admin", "/api", "/backup"], key=recursion_priority)
    assert order[0] == "/admin" and order[-2:] in (["/css", "/images"], ["/images", "/css"])


def test_nlp_version_extraction_uses_context():
    from webguard.nlp.fingerprint import extract

    (product, version, conf), = extract("<footer>Powered by Atlassian Confluence 7.13.0</footer>")
    assert (product, version) == ("confluence", "7.13.0") and conf >= 0.8
    assert extract("<p>Webmin 1.910</p>")[0][:2] == ("webmin", "1.910")
    assert extract("<p>Requires PHP 7.4 or newer</p>") == []
    assert extract("<p>Upgrade to Jenkins 2.442 today</p>") == []
    assert extract("<p>our tomcat has 3 cats</p>") == []


def test_server_inventory_uses_nlp_for_long_tail():
    from webguard.detection.checks import server

    def handler(req):
        if req.url.path == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"},
                                  text="<html><body><footer>Powered by Atlassian Confluence 7.13.0</footer></body></html>")
        return httpx.Response(404, text="nf")

    async def run():
        async with HttpClient(ScanConfig(rate_limit=1000), Scope(include=["t.test"]),
                              transport=httpx.MockTransport(handler)) as client:
            ctx = Context(client, ScanConfig(), default_db())
            await server.inventory(ctx, "https://t.test", [])
            return list(ctx.findings.values())

    checks = {f.check for f in asyncio.run(run())}
    assert "cve:CVE-2022-26134" in checks


def test_triage_context_features_and_priors():
    from webguard import cve
    from webguard.ml.triage import TriageModel, context_features

    f = cve.findings_for("confluence", "7.13.0", "https://t.test/", "Server header")[0]
    feats = context_features(f)
    assert "ctx:version_only" in feats and "ctx:kev" in feats and "ctx:rce" in feats
    plain = Finding(check="xss", title="x", severity=Severity.HIGH, confidence=Confidence.FIRM, url="https://t.test/")
    m = TriageModel()
    assert m.prior(f) < m.prior(plain)  # banner-only CVE matches need a patch-level check
    blind = Finding(check="ssrf", title="Blind SSRF", severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                    url="https://t.test/w", detection="oob", context={"oob": {"protocols": ["http"]}})
    assert "ctx:oob:http" in context_features(blind) and m.prior(blind) >= 0.95
