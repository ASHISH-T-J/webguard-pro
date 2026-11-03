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
    ("secrets", "/static/app.js", None),
])
def test_detects_vulnerability(scan_result, check, path, param):
    base, result = scan_result
    assert _found(result, base, check, path, param), f"{check} not detected at {path}"


@pytest.mark.parametrize("path", ["/safe/search", "/safe/item", "/safe/view", "/safe/greet", "/safe/go", "/safe/ping"])
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
        if f.parameter:
            assert f.request and f.request.startswith("curl ")
