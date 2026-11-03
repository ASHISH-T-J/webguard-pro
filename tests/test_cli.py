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
