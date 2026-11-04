"""Terminal UX: verbosity, payload tracing, colours, findings, wizard, help, resumable sessions."""

from __future__ import annotations

import asyncio

import pytest
from vulnapp import VulnServer

from webguard import cli, ui
from webguard.models import Confidence, Finding, Severity
from webguard.session import Session


@pytest.fixture(autouse=True)
def _reset_ui():
    yield
    ui.set_level(1)
    ui.set_color(False)


def test_verbosity_argv_and_levels():
    assert cli._verbosity_argv(["scan", "x", "-vvv"]) == ["scan", "x", "-v", "3"]
    assert cli._verbosity_argv(["scan", "x", "-v", "4"]) == ["scan", "x", "-v", "4"]
    p = cli.build_parser()
    assert p.parse_args(["scan", "x"]).verbose == 1
    assert p.parse_args(["scan", "x", "-v"]).verbose == 2
    assert p.parse_args(["scan", "x", "-v", "5"]).verbose == 5


def test_severity_colours():
    assert {k: ui.SEV_TEXT[k] for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")} == {
        "CRITICAL": "red_bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
    ui.set_color(True)
    assert "\033[93m" in ui.c("x", ui.SEV_TEXT["MEDIUM"]) and "\033[94m" in ui.c("x", ui.SEV_TEXT["LOW"])
    assert "\033[92m" in ui.c("x", ui.SEV_TEXT["INFO"]) and "\033[91m" in ui.c("x", ui.SEV_TEXT["HIGH"])


def test_finding_block_is_raw_and_shows_payload(capsys):
    f = Finding(check="sqli", title="SQL injection", severity=Severity.HIGH, confidence=Confidence.FIRM,
                url="https://t.test/item", parameter="id", location="query", payload="1' OR '1'='1",
                evidence="leaked alice@shop.test", context={"value_encoding": "base64"})
    ui.print_finding(f)
    out = capsys.readouterr().out
    assert "[HIGH] SQL injection" in out and "Parameter : id (query)" in out and "Payload   : 1' OR '1'='1" in out
    assert "MScgT1IgJzEnPScx" in out  # base64 of the payload: what was actually sent
    assert "alice@shop.test" in out  # terminal output is never redacted


def test_payload_trace_levels(capsys):
    args = ("sqli", "GET", "https://t.test/item", "id", "query", "1' AND 1=1-- -", "1'/**/AND/**/1=1--/**/-")
    ui.set_level(2)
    ui.payload(*args)
    assert capsys.readouterr().out == ""
    ui.set_level(3)
    ui.payload(*args, variant="space2comment")
    out = capsys.readouterr().out
    assert "[PAYLOAD] sqli · GET https://t.test/item [id] (query)" in out
    assert "raw     : 1' AND 1=1-- -" in out and "encoded : 1%27%2F%2A%2A%2FAND" in out and "space2comment" in out


def test_http_trace_shows_requests_at_level_4(capsys):
    import httpx

    from webguard.config import ScanConfig
    from webguard.http import HttpClient
    from webguard.scope import Scope

    ui.set_level(5)

    async def run():
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="hello", headers={"X-Test": "1"}))
        async with HttpClient(ScanConfig(rate_limit=1000), Scope.for_target("https://t.test"), transport) as c:
            await c.get("https://t.test/a?q=1")

    asyncio.run(run())
    out = capsys.readouterr().out
    assert "[REQUEST] GET https://t.test/a?q=1" in out and "HTTP 200" in out and "x-test: 1" in out.lower()
    assert "hello" not in out  # bodies only at level 6


def test_wizard_builds_command():
    answers = iter(["https://shop.test", "y", "3", "y", "sid=abc", "", "30", "", "n", "ACME", "y"])
    argv = cli.wizard_argv(lambda q, d: next(answers))
    assert argv == ["assess", "https://shop.test", "--profile", "safe", "--cookie", "sid=abc",
                    "--budget-minutes", "30", "--no-timing", "--report-author", "ACME", "-v", "3"]
    # no permission -> nothing runs
    answers = iter(["https://shop.test", "n"])
    assert cli.wizard_argv(lambda q, d: next(answers)) is None
    # recon takes a domain
    answers = iter(["https://shop.test/x", "y", "5", ""])
    assert cli.wizard_argv(lambda q, d: next(answers)) == ["recon", "shop.test"]


def test_help_has_examples(capsys):
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "examples:" in out and "webguard wizard" in out and "-v N" in out
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    out = capsys.readouterr().out
    assert "examples:" in out and "--fresh" in out and "--no-color" in out


def test_session_roundtrip(tmp_path):
    s = Session.open(tmp_path, "https://t.test", "scan", "all")
    assert not s.resumed
    f = Finding(check="xss", title="XSS", severity=Severity.HIGH, confidence=Confidence.CERTAIN, url="https://t.test/s",
                parameter="q")
    s.save({"inject:a", "headers:b"}, [f], "input", 120)
    s2 = Session.open(tmp_path, "https://t.test/", "scan", "all")
    assert s2.resumed and s2.done == {"inject:a", "headers:b"} and s2.requests == 120
    assert s2.restored_findings()[0].fingerprint == f.fingerprint
    assert not Session.open(tmp_path, "https://t.test", "scan", "all", fresh=True).resumed
    assert not Session.open(tmp_path, "https://t.test", "scan", "sqli-only").resumed  # different test selection
    s2.finish()
    assert not s2.path.exists()


def test_resume_skips_completed_tests_and_restores_findings(tmp_path):
    from webguard.assessment.agent import AssessmentAgent
    from webguard.config import ScanConfig
    from webguard.scope import Scope

    cfg = ScanConfig(rate_limit=1000, timing_checks=False, browser=False, model_path=tmp_path / "m.json",
                     checks=("sqli", "xss", "headers", "exposure"))
    with VulnServer() as server:
        first = AssessmentAgent(cfg, Scope.for_target(server.url), on_status=lambda m: None)
        res1 = asyncio.run(first.run(server.url))
        done = set(first._done)
        # pretend the scan was interrupted after every test had completed, then resume it
        sess = Session.open(tmp_path, server.url, "scan")
        sess.save(done, res1.findings, "input", res1.stats["requests"])
        sess = Session.open(tmp_path, server.url, "scan")
        second = AssessmentAgent(cfg, Scope.for_target(server.url), on_status=lambda m: None, checkpoint=sess)
        res2 = asyncio.run(second.run(server.url))
    assert res2.stats["requests"] < res1.stats["requests"] / 3  # only mapping is repeated
    assert {f.fingerprint for f in res1.findings} <= {f.fingerprint for f in res2.findings}
    assert any("Resumed from saved session" in x for x in res2.facts)


def test_interrupted_run_saves_session(tmp_path):
    from webguard.assessment.agent import AssessmentAgent
    from webguard.config import ScanConfig
    from webguard.scope import Scope

    cfg = ScanConfig(rate_limit=1000, timing_checks=False, browser=False, model_path=tmp_path / "m.json")
    with VulnServer() as server:
        sess = Session.open(tmp_path, server.url, "scan")
        agent = AssessmentAgent(cfg, Scope.for_target(server.url), on_status=lambda m: None, checkpoint=sess)

        async def run():
            task = asyncio.create_task(agent.run(server.url))
            while not getattr(agent, "_done", None):  # cancel (Ctrl+C) once the first tests have completed
                await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(run())
    saved = Session.open(tmp_path, server.url, "scan")
    assert saved.resumed and saved.done and saved.stage
