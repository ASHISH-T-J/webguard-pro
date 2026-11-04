"""Confirmed-class short-circuiting, route templating, robust liveness, asset discovery, active subdomains."""

from __future__ import annotations

import asyncio

import httpx

from webguard.config import ScanConfig
from webguard.detection.context import ACTIVE_CHECK, VERIFYING, Context, route_key
from webguard.http import HttpClient
from webguard.models import Confidence, Finding, InjectionPoint, Severity
from webguard.scope import Scope
from webguard.signatures import default_db


def test_route_key_templates_ids():
    assert route_key("https://t.test/users/42/orders/7") == "t.test/users/{id}/orders/{id}"
    assert route_key("https://t.test/doc/0f8fad5b-d9cb-469f-a165-70867728950e") == "t.test/doc/{id}"
    assert route_key("https://t.test/search") == "t.test/search"


def test_confirmed_class_stops_same_class_on_same_route_only():
    sent: list[str] = []

    def handler(req):
        sent.append(str(req.url))
        return httpx.Response(200, text="ok")

    async def run():
        async with HttpClient(ScanConfig(rate_limit=1000), Scope(include=["t.test"]),
                              transport=httpx.MockTransport(handler)) as client:
            ctx = Context(client, ScanConfig(), default_db())
            p1 = InjectionPoint("https://t.test/item/1", "GET", "query", "q", {"q": "a"})
            p2 = InjectionPoint("https://t.test/item/2", "GET", "query", "q", {"q": "a"})  # same route
            other = InjectionPoint("https://t.test/item/2", "GET", "query", "sort", {"sort": "a"})
            ctx.report(Finding(check="xss", title="XSS", severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                               url=p1.url, parameter="q", location="query"))
            ACTIVE_CHECK.set("xss")
            blocked = await ctx.send(p2, "<x>")          # xss already proven for this route+param
            other_ok = await ctx.send(other, "<x>")      # other parameter: still tested
            ACTIVE_CHECK.set("sqli")
            sqli_ok = await ctx.send(p2, "'")            # other class on the same input: still tested
            ACTIVE_CHECK.set("xss")
            VERIFYING.set(True)
            verify_ok = await ctx.send(p2, "<x>")        # re-verification is never blocked
            return ctx, blocked, other_ok, sqli_ok, verify_ok

    ctx, blocked, other_ok, sqli_ok, verify_ok = asyncio.run(run())
    assert blocked is None and other_ok is not None and sqli_ok is not None and verify_ok is not None
    assert ctx.skipped_redundant == 1 and len(sent) == 3


def test_host_scoped_and_tentative_findings():
    ctx = Context.__new__(Context)
    ctx.confirmed = set()
    ctx._confirm(Finding(check="cors", title="CORS", severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                         url="https://t.test/api/a"))
    assert ctx.is_confirmed("cors", url="https://t.test/other/path")
    assert not ctx.is_confirmed("cors", url="https://u.test/")
    ctx._confirm(Finding(check="sqli", title="lead", severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
                         url="https://t.test/x", parameter="id"))
    assert not ctx.is_confirmed("sqli", InjectionPoint("https://t.test/x", "GET", "query", "id"))  # leads stay open


def test_injection_points_capped_per_route():
    from webguard.assessment.agent import injection_points
    from webguard.crawler import CrawlResult

    crawl = CrawlResult()
    crawl.urls_with_params = {f"https://t.test/item/{i}?view=full" for i in range(50)} | {"https://t.test/s?q=1"}
    pts = injection_points(crawl)
    assert sum(p.name == "view" for p in pts) == 2 and any(p.name == "q" for p in pts)


# ----------------------------------------------------------------------------- liveness

def test_liveness_statuses_and_second_chance(monkeypatch):
    from webguard.recon import liveness as lv

    async def run():
        async def fast(reader, writer):
            await reader.read(1024)
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
            await writer.drain()
            writer.close()

        async def slow(reader, writer):
            await reader.read(1024)
            await asyncio.sleep(1.2)  # slower than the first-pass timeout, within the second-chance one
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()

        s_fast = await asyncio.start_server(fast, "127.0.0.1", 0)
        s_slow = await asyncio.start_server(slow, "127.0.0.1", 0)
        closed = await asyncio.start_server(fast, "127.0.0.1", 0)
        closed_port = closed.sockets[0].getsockname()[1]
        closed.close()
        await closed.wait_closed()
        names = [f"127.0.0.1:{s_fast.sockets[0].getsockname()[1]}", f"127.0.0.1:{s_slow.sockets[0].getsockname()[1]}",
                 f"127.0.0.1:{closed_port}", "does-not-exist.invalid"]
        monkeypatch.setattr(lv, "TIMEOUTS", (0.4,))
        monkeypatch.setattr(lv, "SECOND_CHANCE_TIMEOUT", 4.0)
        monkeypatch.setattr(lv.check, "__defaults__", (lv.DEFAULT_PORTS, (0.4,), False))
        async with HttpClient(ScanConfig(rate_limit=1000, retries=0), Scope(include=["127.0.0.1", "does-not-exist.invalid"])) as c:
            res = await lv.check_many(c, names)
        s_fast.close()
        s_slow.close()
        return names, res

    names, res = asyncio.run(run())
    fast, slow, closed, nx = (res[n] for n in names)
    assert fast.status == "live" and fast.http_status == 503  # an error page is still a live service
    assert slow.status == "live" and "second-chance" in slow.reason
    assert closed.status == "refused" and nx.status == "dns-fail"


# ----------------------------------------------------------------------------- assets & subdomains

def test_asset_discovery_from_content():
    from webguard.recon.assets import hosts_in, registrable

    assert registrable("api.shop.example.co.uk") == "example.co.uk" and registrable("a.b.example.com") == "example.com"
    js = 'fetch("https://api.example.com/v1/users"); const s3="https://cdn.othercorp.net/x.js"; // admin.example.com'
    own, other = hosts_in([js, "<a href='//staging.example.com/'>x</a>"], "example.com")
    assert own == {"api.example.com", "admin.example.com", "staging.example.com"} and "cdn.othercorp.net" in other


def test_active_subdomains_filter_wildcards(monkeypatch):
    from webguard.recon import subdomains_active as sa

    async def fake_resolve(names, concurrency=50):
        real = {"dev.example.com": ["10.0.0.2"], "api.example.com": ["10.0.0.3"],
                "api-staging.example.com": ["10.0.0.4"]}
        return {n: real.get(n, ["10.9.9.9"] if n.startswith("wg") or "nope" in n else []) for n in names}

    async def no_axfr(domain):
        return [], None

    monkeypatch.setattr(sa, "resolve_many", fake_resolve)
    monkeypatch.setattr(sa, "zone_transfer", no_axfr)
    found, _ = asyncio.run(sa.enumerate_active("example.com", {"api.example.com"}, ["dev", "nope", "www"],
                                               status=lambda m: None))
    assert "dev.example.com" in found and "api-staging.example.com" in found  # brute force + permutation
    assert "nope.example.com" not in found  # resolves only to the wildcard address
