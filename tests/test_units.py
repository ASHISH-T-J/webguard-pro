from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from webguard.config import ScanConfig
from webguard.db import Database
from webguard.detection import anomaly
from webguard.detection.baseline import similarity
from webguard.detection.checks.xss import contexts
from webguard.http import HttpClient, OutOfScopeError
from webguard.ml.triage import TriageModel
from webguard.models import Confidence, Finding, Severity
from webguard.reporting import build_report, write_all, write_html, write_sarif
from webguard.scope import Scope
from webguard.signatures import default_db

# ------------------------------------------------------------------ scope


def test_scope_rules(tmp_path):
    s = Scope(include=["example.com", ".corp.example", "*.api.example.net", "10.0.0.0/24", "re:^dev\\d+\\.x\\.io$"],
              exclude=["admin.corp.example"])
    assert s.in_scope("https://example.com/a")
    assert not s.in_scope("https://www.example.com/")
    assert s.in_scope("https://corp.example/") and s.in_scope("https://a.b.corp.example/")
    assert not s.in_scope("https://admin.corp.example/")
    assert s.in_scope("https://v1.api.example.net/") and not s.in_scope("https://api.example.net/")
    assert s.in_scope("http://10.0.0.7/") and not s.in_scope("http://10.0.1.7/")
    assert s.in_scope("http://dev12.x.io/")
    assert not s.in_scope("https://example.com/logout")
    f = tmp_path / "scope.txt"
    f.write_text("# program\n.target.com\n!blog.target.com\n")
    fs = Scope.from_file(f)
    assert fs.in_scope("https://app.target.com/") and not fs.in_scope("https://blog.target.com/")


def test_redirects_never_leave_scope():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "in.test":
            return httpx.Response(302, headers={"Location": "https://evil.test/steal"})
        raise AssertionError("out-of-scope request sent")

    async def run():
        async with HttpClient(ScanConfig(), Scope(include=["in.test"]), transport=httpx.MockTransport(handler)) as c:
            r = await c.get("https://in.test/", follow_redirects=True)
            assert r.status == 302
            assert c.stats["blocked_out_of_scope"] == 1
            with pytest.raises(OutOfScopeError):
                await c.get("https://evil.test/")

    asyncio.run(run())


# ------------------------------------------------------------------ detection primitives


def test_similarity_ignores_dynamic_tokens():
    a = "<p>Hello user</p><p>csrf=9f8e7d6c5b4a39281716 at 2024-05-01 12:00:01</p>" * 5
    b = "<p>Hello user</p><p>csrf=0a1b2c3d4e5f60718293 at 2025-06-02 13:11:59</p>" * 5
    assert similarity(a, b) > 0.95
    assert similarity(a, "<p>Totally different page content here now</p>") < 0.3


def test_xss_context_detection():
    html = '<div title="wgX1">wgX1</div><script>var a = "wgX1";</script><a href="wgX1">x</a><!-- wgX1 -->'
    ctxs = contexts(html, "wgX1")
    assert {"attr", "html", "script", "url-attr", "comment"} <= ctxs


def test_signature_db_loads_and_matches():
    db = default_db()
    stats = db.stats()
    assert stats["sql_errors"] > 100 and stats["technologies"] > 50 and stats["secrets"] > 30
    assert db.match_sql_error("ORA-00933: SQL command not properly ended").name == "Oracle"
    assert db.match_sql_error("Welcome to our store") is None
    secrets = db.match_secrets('key="AKIAIOSFODNN7ABCDXYZ" token="ghp_' + "a1B2" * 9 + '"')
    assert {m.name for m in secrets} >= {"AWS Access Key ID", "GitHub Token"}
    assert not db.match_secrets('api_key = "your_api_key_here_xxxxxxxx"')
    # minified-code fragments are not passwords (real FP seen in swagger-ui-bundle.js on Juice Shop)
    assert not db.match_secrets('{password:"),$?Re(t).ent(",x:1}')
    assert db.match_secrets('db_password = "Tr0ub4dor&3xyz"')[0].name == "Generic Password Assignment"
    tech = db.fingerprint_tech({"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.1"}, ["PHPSESSID"],
                               '<meta name="generator" content="WordPress 6.4.2">')
    assert tech["nginx"] == "1.25.3" and tech["PHP"] == "8.2.1" and tech["WordPress"] == "6.4.2"
    assert "Cloudflare" in db.detect_waf({"Server": "cloudflare", "CF-RAY": "x"}, [], "")


def test_anomaly_scoring_flags_outlier_only():
    benign = [[2, 0, 7.0, 1.0, 120, 30, 40, 0, 0.05, 1.0, 0, 0, 8, 4.5] for _ in range(6)]
    benign[1][2] = 7.02
    probes = [("quote", "'", [5, 1, 6.0, 0.4, 60, 10, 10, 5, 0.05, 0.3, 1, 0, 8, 4.4]),
              ("ok", "x", [2, 0, 7.01, 1.0, 120, 30, 40, 0, 0.05, 1.0, 0, 0, 8, 4.5])]
    res = {r.probe: r for r in anomaly.score(benign, probes)}
    assert res["quote"].is_anomalous
    assert not res["ok"].is_anomalous


# ------------------------------------------------------------------ DB + ML


def _finding(i: int, check="xss", conf=Confidence.FIRM, detection="signature", evidence="ev") -> Finding:
    return Finding(check=check, title=f"{check} finding", severity=Severity.HIGH, confidence=conf,
                   url=f"https://t.test/p{i}", parameter="q", location="query", detection=detection, evidence=evidence)


def test_db_tracks_new_assets_and_findings(tmp_path):
    db = Database(tmp_path / "w.db")
    s1 = db.start_scan("t.test", "scan")
    assert db.upsert_assets(s1, "t.test", "subdomain", ["a.t.test", "b.t.test"]) == ["a.t.test", "b.t.test"]
    assert len(db.save_findings(s1, "t.test", [_finding(1), _finding(2)])) == 2
    s2 = db.start_scan("t.test", "scan")
    assert db.upsert_assets(s2, "t.test", "subdomain", ["a.t.test", "c.t.test"]) == ["c.t.test"]
    new = db.save_findings(s2, "t.test", [_finding(1), _finding(3)])
    assert [f.url for f in new] == ["https://t.test/p3"]
    assert [r["value"] for r in db.new_assets("t.test", s2)] == ["c.t.test"]
    assert [r["url"] for r in db.fixed_findings("t.test", s2)] == ["https://t.test/p2"]


def test_triage_model_learns_from_labels(tmp_path):
    db = Database(tmp_path / "w.db")
    sid = db.start_scan("t.test", "scan")
    noisy = [_finding(i, check="anomaly", conf=Confidence.TENTATIVE, detection="anomaly", evidence="noise") for i in range(8)]
    real = [_finding(100 + i, check="sqli", detection="differential", evidence="boolean diff") for i in range(8)]
    db.save_findings(sid, "t.test", noisy + real)
    for row in db.finding_rows(sid):
        db.label(row["id"], "fp" if row["check_name"] == "anomaly" else "tp")
    samples = db.labeled()
    assert len(samples) == 16
    model = TriageModel()
    meta = model.fit(samples)
    assert meta["train_accuracy"] == 1.0
    model.save(tmp_path / "m.json")
    loaded = TriageModel.load(tmp_path / "m.json")
    assert loaded.predict(_finding(999, check="sqli", detection="differential")) > \
        loaded.predict(_finding(998, check="anomaly", conf=Confidence.TENTATIVE, detection="anomaly"))


# ------------------------------------------------------------------ reporting


def test_html_report_escapes_payloads(tmp_path):
    f = _finding(1)
    f.payload = "<script>alert(1)</script>"
    f.evidence = '"><img src=x onerror=alert(1)>'
    path = write_html(build_report("t.test", [f]), tmp_path / "r.html")
    text = path.read_text()
    assert "<script>alert(1)</script>" not in text and "<img src=x" not in text
    assert "&lt;script&gt;" in text


def test_sarif_is_valid_shape(tmp_path):
    path = write_sarif(build_report("t.test", [_finding(1)]), tmp_path / "r.sarif")
    sarif = json.loads(path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_report_filenames_keep_target_and_timestamp(tmp_path):
    paths = write_all("https://app.example.com:8443", [_finding(1)], tmp_path, ["json", "html", "md", "sarif"])
    names = sorted(p.name for p in paths)
    assert len(names) == 4 and all(n.startswith("app.example.com_8443_2") for n in names)
    assert {p.suffix for p in paths} == {".json", ".html", ".md", ".sarif"}
