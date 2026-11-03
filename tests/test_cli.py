from __future__ import annotations

import json

from vulnapp import VulnServer

import webguard  # noqa: F401  (package import must win over the legacy webguard.py shim)
from webguard import cli
from webguard.db import Database
from webguard.models import Severity


def _legacy():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("legacy_webguard", Path(__file__).parent.parent / "webguard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_legacy_argument_translation():
    t = _legacy().translate
    assert t(["-d", "x.com", "-m", "passive"]) == ["recon", "x.com", "--passive"]
    assert t(["-d", "x.com", "-m", "active"]) == ["surface", "x.com"]
    assert t(["-d", "x.com", "-m", "vulnerability", "--tor"]) == ["scan", "x.com", "--proxy", "socks5://127.0.0.1:9050"]
    assert t([]) == ["wizard"]


def test_cli_scan_end_to_end(tmp_path, capsys):
    db_path = tmp_path / "w.db"
    out = tmp_path / "reports"
    with VulnServer() as server:
        code = cli.main(["scan", server.url, "--no-timing", "--rate", "1000", "--db", str(db_path),
                         "--model", str(tmp_path / "m.json"), "-o", str(out), "-f", "json,html,sarif,md",
                         "--checks", "xss,sqli,exposure,headers"])
    assert code == 2  # HIGH findings -> non-zero exit for CI gating
    files = {p.suffix for p in out.iterdir()}
    assert files == {".json", ".html", ".sarif", ".md"}
    report = json.loads(next(out.glob("*.json")).read_text())
    assert report["summary"]["HIGH"] >= 3
    db = Database(db_path)
    rows = db.finding_rows()
    assert rows and all(Severity(r["severity"]) >= Severity.INFO for r in rows)
    # label + report regeneration from DB
    assert cli.main(["db", "--db", str(db_path), "label", str(rows[0]["id"]), "tp"]) == 0
    assert cli.main(["report", "1", "--db", str(db_path), "-o", str(tmp_path / "r2"), "-f", "md"]) == 0
    md = next((tmp_path / "r2").glob("*.md")).read_text()
    assert "Steps to reproduce" in md and "curl" in md


def test_cli_assess_grep_ask_analyze(tmp_path, capsys):
    db_path = tmp_path / "w.db"
    out = tmp_path / "reports"
    with VulnServer() as server:
        code = cli.main(["assess", server.url, "--no-timing", "--rate", "1000", "--db", str(db_path),
                         "--model", str(tmp_path / "m.json"), "-o", str(out), "-f", "json,html,md",
                         "--no-browser", "--show-trace", "--budget-requests", "5000"])
    assert code == 2
    printed = capsys.readouterr().out
    assert "Rules of engagement" in printed and "thought:" in printed and "Executive summary" in printed
    report = json.loads(next(out.glob("*.json")).read_text())
    meta = report["meta"]
    assert meta["trace"] and meta["wstg_coverage"] and meta["attack_chains"] and meta["narrative"]["executive_summary"]
    html = next(out.glob("*.html")).read_text()
    assert "Attack chains" in html and "reasoning trace" in html and "OWASP WSTG coverage" in html
    scan_id = Database(db_path).scans()[0]["id"]
    # grep stored responses
    assert cli.main(["grep", str(scan_id), "--db", str(db_path), "--pack", "dom-sinks"]) == 0
    assert "innerHTML" in capsys.readouterr().out
    assert cli.main(["grep", str(scan_id), "--db", str(db_path), "--regex", r"AKIA[0-9A-Z]{16}", "--in", "js"]) == 0
    assert "AKIAIOSFODNN7ABCDXYZ" in capsys.readouterr().out
    # natural-language question over findings
    assert cli.main(["ask", "critical sql injection or authentication bypass", "--db", str(db_path)]) == 0
    assert "Authentication bypass" in capsys.readouterr().out
    # analysis view
    assert cli.main(["analyze", str(scan_id), "--db", str(db_path)]) == 0
    text = capsys.readouterr().out
    assert "Root-cause issues" in text and "Reasoning trace" in text


def test_budget_limits_active_testing(tmp_path):
    import asyncio

    from webguard.assessment.agent import AssessmentAgent
    from webguard.config import ScanConfig
    from webguard.scope import Scope

    with VulnServer() as server:
        agent = AssessmentAgent(ScanConfig(rate_limit=1000, timing_checks=False, browser=False,
                                           model_path=tmp_path / "m.json"),
                                Scope.for_target(server.url), budget_requests=400, on_status=lambda m: None)
        res = asyncio.run(agent.run(server.url))
    assert res.stats["requests"] < 400 * 1.5  # in-flight checks finish, then testing stops (verification still runs)
    assert any(f.check in ("auth", "ssti", "cmdi") for f in res.findings)  # high-value hypotheses tested first
    assert any("budget" in t.thought.lower() for t in res.trace)
