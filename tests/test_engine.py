"""End-to-end detection tests against the local vulnerable app (and its safe twins)."""

from __future__ import annotations

import asyncio

import pytest
from vulnapp import VulnServer

from webguard.config import ScanConfig
from webguard.engine import ScanEngine
from webguard.scope import Scope


@pytest.fixture(scope="module")
def scan_result(tmp_path_factory):
    with VulnServer() as server:
        cfg = ScanConfig(time_delay=2, rate_limit=1000, concurrency=20,
                         model_path=tmp_path_factory.mktemp("m") / "none.json")
        engine = ScanEngine(cfg, Scope.for_target(server.url), on_status=lambda m: None)
        result = asyncio.run(engine.scan(server.url))
        yield server.url, result


def _found(result, base, check, path, param=None):
    return [f for f in result.findings
            if f.check == check and f.url.replace(base, "").split("#")[0] == path and (param is None or f.parameter == param)]


@pytest.mark.parametrize("check,path,param", [
    ("sqli", "/item", "id"),
    ("sqli", "/news", "id"),           # time-based
    ("xss", "/search", "q"),           # html context
    ("xss", "/profile", "color"),      # attribute context
    ("xss", "/comment", "body"),       # POST form
    ("ssti", "/greet", "name"),
    ("lfi", "/view", "file"),
    ("cmdi", "/ping", "host"),
    ("redirect", "/go", "next"),
    ("crlf", "/go", "next"),
    ("exposure", "/.git/HEAD", None),
    ("secrets", "/", None),                   # keyed per host; source page in evidence
    # classes added in v3
    ("auth", "/api/login", "email"),          # SQLi login bypass on a JSON API found in JS
    ("nosqli", "/users/search", "name"),
    ("xxe", "/api/xml", None),
    ("access", "/admin", None),               # X-Original-URL bypass
    ("host_header", "/reset", None),          # cache poisoning via X-Forwarded-Host
    ("idor", "/api/users/1", None),
    ("data_exposure", "/api/users/1", None),  # MD5 password hashes in API
    ("graphql", "/graphql", None),
    ("csrf", "/", None),
    ("dom_xss", "/dom", None),                # verified in headless Chromium
    ("jwt", "/", None),                       # HS256 token signed with "secret"
    ("access", "/api/admin/config", None),    # admin API answering anonymous requests
    ("sqli", "/track", "User-Agent"),         # header value logged into SQL
    ("sqli", "/filtered/item", "id"),         # app blacklist (spaces/quotes) defeated by auto-tamper
    # PortSwigger / HackTricks filter-bypass scenarios, defeated by per-class encoding variants
    ("lfi", "/lfi/ext", "file"),              # extension validation -> null byte
    ("lfi", "/lfi/start", "file"),            # start-of-path validation -> path prefix
    ("xss", "/xss/decode", "q"),              # sanitise-then-decode -> double URL encoding
    ("sqli", "/data", "data"),                # SQLi inside a base64-encoded parameter value
    ("cmdi", "/cmd/filter", "host"),          # spaces/';' blocked -> ${IFS}
    ("ssrf", "/fetch", "url"),                # substring allow-list -> userinfo
    ("ldapi", "/directory", "user"),
    ("xpathi", "/lookup", "name"),
    ("xxe", "/stock", "productId"),           # XInclude
    ("ssti", "/render", "tpl"),               # template-error polyglot lead
    ("xss", "/welcome", "Referer"),           # header value rendered into HTML
    ("xss", "/welcome", "theme"),             # cookie value rendered into an attribute
    ("exposure", "/static/legacy.js.map", None),  # source map exposed
    ("vulnerable_component", "/static/jquery-1.8.3.min.js", None),
    ("dom_flow", "/app", None),               # static source->sink + postMessage without origin check
    ("dom_xss", "/app", None),                # client-read ?msg= verified in the browser
    ("cache_deception", "/account", None),    # /account;x.css served dynamic page and got cached
    ("redirect", "/oauth/authorize", "redirect_uri"),  # prefix-only redirect_uri check
    ("prototype_pollution", "/pp", None),
])
def test_detects_vulnerability(scan_result, check, path, param):
    base, result = scan_result
    if check in ("dom_xss", "prototype_pollution"):
        pytest.importorskip("playwright")
    assert _found(result, base, check, path, param), f"{check} not detected at {path}"


@pytest.mark.parametrize("path", ["/safe/search", "/safe/item", "/safe/view", "/safe/greet", "/safe/go", "/safe/ping",
                                  "/safe/api/login", "/safe/users/search", "/safe/api/xml", "/safe/admin",
                                  "/safe/reset", "/safe/api/users/1", "/safe/dom", "/safe/api/admin/config",
                                  "/safe/track", "/safe/welcome", "/safe/app",
                                  "/safe/account", "/safe/oauth/authorize", "/safe/pp", "/safe/filtered/item",
                                  "/safe/lfi/ext", "/safe/xss/decode", "/safe/data", "/safe/cmd/filter",
                                  "/safe/fetch", "/safe/directory", "/safe/lookup", "/safe/stock"])
def test_no_false_positives_on_safe_twins(scan_result, path):
    base, result = scan_result
    hits = [f for f in result.findings if f.url.replace(base, "") == path]
    assert not hits, [f"{f.check}: {f.title}" for f in hits]


def test_cors_with_credentials_is_high(scan_result):
    base, result = scan_result
    cors = [f for f in result.findings if f.check == "cors"]
    assert cors and cors[0].severity.name == "HIGH"


def test_logout_never_requested(scan_result):
    base, result = scan_result
    assert not any("/logout" in u for u in result.urls)


def test_findings_have_reproduction_and_ml_score(scan_result):
    _, result = scan_result
    for f in result.findings:
        assert f.ml_score is not None
        if f.parameter:  # DOM XSS needs a browser to reproduce; everything else has a curl command
            assert f.request and f.request.startswith("open in browser: " if f.check == "dom_xss" else "curl ")


def test_active_findings_are_independently_verified(scan_result):
    _, result = scan_result
    active = [f for f in result.findings if f.check in ("sqli", "xss", "ssti", "lfi", "cmdi", "redirect", "nosqli")]
    assert active and all("verified" in f.tags for f in active)


def test_assessment_analysis_outputs(scan_result):
    _, result = scan_result
    titles = {c["title"] for c in result.chains}
    assert "Administrative access: authentication bypass" in titles
    assert "Privilege escalation: forge JWTs with cracked signing secret" in titles
    assert result.narrative["executive_summary"].startswith("The assessment of")
    assert result.coverage["WSTG-INPV-05"] == "vulnerable" and result.coverage["WSTG-ATHN-04"] == "vulnerable"
    assert [t.phase for t in result.trace][:2] == ["recon", "recon"] and result.trace[-1].phase == "analysis"
    assert len(result.issues) <= len(result.findings)


def test_secret_reported_once_per_host_with_source(scan_result):
    _, result = scan_result
    aws = [f for f in result.findings if f.title == "Exposed secret: AWS Access Key ID"]
    assert len(aws) == 1 and "/static/app.js" in aws[0].evidence


def test_js_analysis_mines_source_maps_and_chunks(scan_result):
    base, result = scan_result
    urls = {p.url.replace(base, "") for p in result.points}
    assert "/internal/export" in urls and "/internal/reports" in urls  # from source map + lazy chunk
    assert any(f.check == "secrets" and ".map" in f.evidence for f in result.findings)  # key in original source
    assert any("client-read params: msg" in fact for fact in result.facts)


def test_oauth_redirect_is_high_severity(scan_result):
    base, result = scan_result
    f = next(f for f in result.findings if f.url.endswith("/oauth/authorize") and f.check == "redirect")
    assert f.title == "OAuth redirect_uri validation bypass" and f.severity.name == "HIGH"


def test_waf_blocked_inputs_reported_as_not_tested(scan_result):
    base, result = scan_result
    assert not [f for f in result.findings if "/waf/search" in f.url and f.parameter == "q"]
    obstructed = [x for items in result.obstructed.values() for x in items]
    assert any("/waf/search" in x for x in obstructed)
    assert any("NOT TESTED" in fact for fact in result.facts)


def test_findings_carry_context_and_http_evidence(scan_result):
    base, result = scan_result
    sqli = next(f for f in result.findings if f.check == "sqli" and f.url == base + "/item")
    assert sqli.context["verification"].startswith("verified")
    assert sqli.context["http_request"].startswith("GET /item?id=")
    assert "SQL syntax" in sqli.context["http_response"]
    assert all(f.context.get("environment") == "development" for f in result.findings)  # 127.0.0.1


def test_auto_tamper_only_against_application_filters(scan_result):
    base, result = scan_result
    f = next(f for f in result.findings if f.check == "sqli" and f.url.endswith("/filtered/item"))
    assert "input filter bypassed with tamper space2comment" in f.title and "/**/" in f.payload
    assert "tamper:space2comment" in f.tags
    # behind the simulated WAF no tamper is attempted: still no finding, still NOT TESTED
    assert not [g for g in result.findings if "/waf/search" in g.url and g.check == "sqli"]


def test_poc_screenshots_and_evidence(scan_result, tmp_path):
    pytest.importorskip("playwright")
    from webguard.reporting import poc

    base, result = scan_result
    cfg = ScanConfig(rate_limit=1000)
    n = asyncio.run(poc.capture(result.findings, cfg, Scope.for_target(base), tmp_path))
    assert n >= 10
    by_kind = {}
    for f in result.findings:
        if f.context.get("poc_screenshot"):
            assert (tmp_path / f.context["poc_screenshot"]).stat().st_size > 2000
            by_kind.setdefault(f.context["poc_kind"], []).append(f)
    # reflected XSS: an executing PoC was observed in the browser, not just assumed
    assert any(f.check == "xss" and any("alert(" in d for d in f.context.get("poc_observed", []))
               for f in by_kind.get("browser-execution", []))
    assert any(f.check == "lfi" for f in by_kind.get("live-response", []))
    auth = next(f for f in result.findings if f.check == "auth")
    assert '"token"' in auth.context["http_response"]  # replayed request captured the real response
    # PII / tokens are blurred on screenshots (JWT + e-mail in the auth-bypass response)
    assert auth.context.get("poc_redactions", 0) >= 2


def test_bypass_findings_name_the_technique_and_verify(scan_result):
    base, result = scan_result
    byp = {f.url.replace(base, ""): f for f in result.findings if any(t.startswith("bypass:") for t in f.tags)}
    assert "null-byte-extension" in byp["/lfi/ext"].title
    assert "path-prefix" in byp["/lfi/start"].title
    assert "ifs-whitespace" in byp["/cmd/filter"].title and "${IFS}" in byp["/cmd/filter"].payload
    assert "allowlist-userinfo" in byp["/fetch"].title
    assert byp["/lfi/ext"].context["bypass"]["technique_source"].startswith("PortSwigger")
    for f in byp.values():  # independently re-verified with the same variant
        if f.check in ("lfi", "cmdi", "xss"):
            assert "verified" in f.tags, f.title
    enc = next(f for f in result.findings if f.url.endswith("/data") and f.check == "sqli")
    assert enc.context["value_encoding"] == "base64" and "inside base64-encoded value" in enc.title
