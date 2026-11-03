"""HTTP resilience, response-context classification, profiles and WAF-obstruction reporting."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from webguard.analysis.context import classify, environment
from webguard.config import ScanConfig, apply_profile
from webguard.http import HttpClient, Resp, parse_retry_after
from webguard.scope import Scope


def _client(handler, **cfg):
    return HttpClient(ScanConfig(retries=2, rate_limit=1000, **cfg), Scope(include=["t.test"]),
                      transport=httpx.MockTransport(handler))


def test_retry_after_is_honoured_and_rate_backs_off():
    calls = []

    def handler(req):
        calls.append(req)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, text="ok")

    async def run():
        async with _client(handler) as c:
            r = await c.get("https://t.test/")
            st = c.host("https://t.test/")
            return r, c.stats, st

    r, stats, st = asyncio.run(run())
    assert r.status == 200 and len(calls) == 2
    assert stats["rate_limited"] == 1 and stats["retries"] == 1
    assert st.adjustments and "429" in st.adjustments[0]


def test_parse_retry_after_http_date():
    assert parse_retry_after("2") == 2.0
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
    assert parse_retry_after(None) is None


def test_circuit_breaker_gives_up_on_dead_host():
    def handler(req):
        raise httpx.ConnectError("Connection refused")

    async def run():
        async with _client(handler) as c:
            c.config.retries = 0
            for _ in range(40):
                await c.get("https://t.test/")
            return c

    c = asyncio.run(run())
    st = c.host("https://t.test/")
    assert c.stats["circuit_trips"] >= 1 and st.dead
    assert c.errors["refused"] >= 8 and c.errors["host_unavailable"] > 0  # later calls fail fast


def _resp(status, body, headers=None):
    return Resp("https://t.test/x", status, httpx.Headers(headers or {}), body, 0.1, "GET")


@pytest.mark.parametrize("status,body,headers,kind", [
    (403, "<title>Attention Required! | Cloudflare</title> Ray ID: 1", {}, "challenge"),
    (403, "<title>Just a moment...</title>", {"cf-mitigated": "challenge"}, "challenge"),
    (403, "The requested URL was rejected. Please consult with your administrator. Support ID: 1", {}, "waf_block"),
    (429, "Too many requests", {}, "rate_limited"),
    (500, "SQLITE_ERROR: near 'x': syntax error", {}, "server_error"),
    (302, "", {"location": "/login?next=/admin"}, "login_redirect"),
    (200, "<h1>hello</h1>", {}, "ok"),
])
def test_response_context(status, body, headers, kind):
    rc = classify(_resp(status, body, headers))
    assert rc.kind == kind
    if kind == "server_error":
        assert rc.error_type == "database" and "sqli" in rc.hints


def test_environment_detection():
    assert environment("staging.shop.example") == "staging"
    assert environment("api-dev.example.com") == "development"
    assert environment("www.example.com") == "production"


def test_profiles():
    safe = apply_profile(ScanConfig(), "safe")
    assert safe.rate_limit <= 5 and not safe.timing_checks and "anomaly" not in safe.checks
    thorough = apply_profile(ScanConfig(), "thorough")
    assert thorough.param_discovery and thorough.discovery_wordlist.name == "common.txt"
    with pytest.raises(ValueError):
        apply_profile(ScanConfig(), "yolo")
