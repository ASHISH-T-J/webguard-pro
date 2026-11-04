"""CMS workflows, technology probes, WAF re-test pass, user configuration."""

from __future__ import annotations

import asyncio
import json

import httpx

from webguard.config import ScanConfig
from webguard.detection.context import ACTIVE_CHECK, Context
from webguard.http import HttpClient, Resp
from webguard.models import InjectionPoint
from webguard.scope import Scope
from webguard.signatures import default_db


def _run(handler, fn, **cfg):
    async def go():
        config = ScanConfig(rate_limit=1000, **cfg)
        async with HttpClient(config, Scope(include=["t.test"]), transport=httpx.MockTransport(handler)) as client:
            ctx = Context(client, config, default_db())
            out = await fn(ctx)
            return out, list(ctx.findings.values())
    return asyncio.run(go())


def _page(text: str, url: str = "https://t.test/") -> Resp:
    return Resp(url, 200, httpx.Headers({"Content-Type": "text/html"}), text, 0, "GET")


# ----------------------------------------------------------------------------- CMS

def test_cms_detection_markers():
    from webguard.detection.checks.cms import detect

    pages = {"a": _page('<link href="/wp-content/themes/x/style.css">'), "b": _page("<p>shop</p>")}
    assert detect(pages, []) == {"wordpress"}
    assert detect({}, ["Drupal 7"]) == {"drupal"}


def test_wordpress_workflow():
    from webguard.detection.checks import cms

    def wp(req):
        p = req.url.path
        if p == "/wp-content/themes/bricks/style.css":
            return httpx.Response(200, text="/*\nTheme Name: Bricks\nVersion: 1.9.5\n*/")
        if p == "/wp-json/wp/v2/users":
            return httpx.Response(200, json=[{"id": 1, "slug": "admin"}, {"id": 2, "slug": "editor"}])
        if p == "/xmlrpc.php":
            return httpx.Response(405, text="XML-RPC server accepts POST requests only.")
        if p == "/wp-json/":
            return httpx.Response(200, json={"namespaces": ["wp/v2", "contact-form-7/v1"]})
        return httpx.Response(404, text="nf")

    pages = {"https://t.test/": _page('<script src="/wp-content/plugins/wp-file-manager/lib/js/a.js?ver=6.0"></script>'
                                       '<link href="/wp-content/themes/bricks/style.css">')}
    info, findings = _run(wp, lambda ctx: cms.wordpress(ctx, "https://t.test", pages))
    checks = {f.check for f in findings}
    assert info["plugins"] == {"wp-file-manager": "6.0"} and info["themes"] == {"bricks": "1.9.5"}
    assert {"cve:CVE-2020-25213", "cve:CVE-2024-25600"} <= checks
    titles = {f.title for f in findings}
    assert "WordPress user enumeration via REST API" in titles and "WordPress XML-RPC interface enabled" in titles
    assert info["users"] == ["admin", "editor"] and "contact-form-7/v1" in info["namespaces"]


def test_drupal_and_joomla_versions():
    from webguard.detection.checks import cms

    def site(req):
        if req.url.path == "/CHANGELOG.txt":
            return httpx.Response(200, text="Drupal 7.57, 2018-02-21\n------\n")
        if req.url.path == "/administrator/manifests/files/joomla.xml":
            return httpx.Response(200, text="<extension type='file'><version>4.2.7</version></extension>")
        return httpx.Response(404, text="nf")

    _, d = _run(site, lambda ctx: cms.drupal(ctx, "https://t.test", {}))
    _, j = _run(site, lambda ctx: cms.joomla(ctx, "https://t.test", {}))
    assert "cve:CVE-2018-7600" in {f.check for f in d} and "cve:CVE-2023-23752" in {f.check for f in j}


def test_tech_probes_with_safe_twin():
    from webguard.detection.checks import cms

    def leaky(req):
        if req.url.path == "/index.php~":
            return httpx.Response(200, text="<?php $db_pass = 'x'; ?>")
        return httpx.Response(404, text="nf")

    def catch_all(req):  # SPA answers everything with the same shell
        return httpx.Response(200, text="<?php shell? no: <html>app</html>")

    run = lambda ctx: cms.tech_probes(ctx, "https://t.test", {"php 8.1"}, [])  # noqa: E731
    assert [f.title for f in _run(leaky, run)[1]] == ["PHP source backup (index.php~)"]

    async def calibrated(ctx):
        from webguard.detection.checks.host import soft404

        return await cms.tech_probes(ctx, "https://t.test", {"php"}, await soft404(ctx, "https://t.test"))

    assert _run(catch_all, calibrated)[1] == []


# ----------------------------------------------------------------------------- WAF

CF_BLOCK = httpx.Response(403, headers={"cf-ray": "8a1b2c3d4e5f-AMS", "server": "cloudflare"},
                          text="<title>Attention Required! | Cloudflare</title>Sorry, you have been blocked")


def test_blocked_tests_are_recorded_for_retest():
    def handler(req):
        return CF_BLOCK if "<" in req.url.params.get("q", "") else httpx.Response(200, text="ok")

    async def run(ctx):
        p = InjectionPoint("https://t.test/search", "GET", "query", "q", {"q": "a"})
        ACTIVE_CHECK.set("xss")
        await ctx.send(p, "<svg>")
        ACTIVE_CHECK.set("")
        return ctx.obstructed_tests

    tests, _ = _run(handler, run)
    assert list(tests) == [(("GET", "https://t.test/search", "query", "q"), "xss")]


def test_waf_blocked_inputs_are_retested_and_found(tmp_path):
    from webguard.assessment.agent import AssessmentAgent

    state = {"blocks": 0}

    def site(req):
        if req.url.path == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"},
                                  text='<html><a href="/search?q=hello">search</a></html>')
        if req.url.path == "/search":
            q = req.url.params.get("q", "")
            if any(c in q for c in "<>\"'") and state["blocks"] < 400:  # burst protection: blocks the first wave
                state["blocks"] += 1
                return CF_BLOCK
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=f"<html><p>Results for {q}</p></html>")
        return httpx.Response(404, text="nf")

    class Retry400(dict):
        pass

    cfg = ScanConfig(rate_limit=1000, timing_checks=False, browser=False, model_path=tmp_path / "m.json",
                     checks=("xss",), waf_cooldown=0, discovery_wordlist=None)
    agent = AssessmentAgent(cfg, Scope(include=["t.test"]), transport=httpx.MockTransport(site),
                            on_status=lambda m: None)

    async def run():
        orig = agent._retest_obstructed

        async def retest(*a, **kw):
            state["blocks"] = 10**6  # the burst window has passed by the time of the re-test pass
            return await orig(*a, **kw)

        agent._retest_obstructed = retest
        return await agent.run("https://t.test/")

    res = asyncio.run(run())
    assert any(f.check == "xss" and f.parameter == "q" for f in res.findings)
    assert any("re-test" in x for x in res.facts)


def test_hunt_ranking_does_not_penalise_waf_hosts():
    from webguard.models import Host
    from webguard.workflows.redteam import prioritise

    a = Host("https://a.t.test", 200, "App", technologies=["nginx"])
    b = Host("https://b.t.test", 200, "App", technologies=["nginx"], waf=["Cloudflare"])
    scores = {r["host"].url: r["score"] for r in prioritise([a, b], {}, [])}
    assert scores["https://a.t.test"] == scores["https://b.t.test"]


# ----------------------------------------------------------------------------- user configuration

def test_config_file_defaults_set_and_phases(tmp_path, monkeypatch):
    from webguard import cli

    conf = tmp_path / "wg.yml"
    conf.write_text("defaults:\n  rate: 7\n  header: ['X-Bug-Bounty: alice']\nscan:\n  checks: [sqli, xss]\n"
                    "  profile: standard\nset:\n  retries: 5\n  user_agent: acme-test\n")
    parser = cli.build_parser()
    argv = cli._load_user_config(["scan", "https://t.test", "--config", str(conf), "--rate", "9",
                                  "--set", "oob_wait=3", "--only-phases", "input,verify"], parser)
    args = parser.parse_args(argv)
    cfg = cli.make_config(args)
    assert cfg.rate_limit == 9  # command line beats the file
    assert cfg.headers == {"X-Bug-Bounty": "alice"} and cfg.checks == ("sqli", "xss")
    assert cfg.retries == 5 and cfg.user_agent == "acme-test" and cfg.oob_wait == 3.0
    assert set(cfg.skip_phases) == {"config", "identity", "authz_client"}


def test_config_init_and_keys(tmp_path, capsys):
    from webguard import cli

    path = tmp_path / "webguard.yml"
    assert cli.main(["config", "init", str(path)]) == 0 and "defaults:" in path.read_text()
    assert cli.main(["config", "keys"]) == 0 and "waf_cooldown" in capsys.readouterr().out
    json.dumps({})
