"""Report hygiene: client vs technical style, PII/secret redaction."""

from __future__ import annotations

import json

from webguard.models import Confidence, Finding, Severity
from webguard.reporting import ReportOptions, write_all
from webguard.reporting.redact import redact, redact_obj


def test_redaction_rules():
    out = redact("alice@shop.test 555-0101 4242 4242 4242 4242 123-45-6789 "
                 "0192023a7bbd73250516f069df18b500 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig AKIAIOSFODNN7ABCDXYZ")
    for raw in ("alice@", "555-0101", "4242 4242 4242 4242", "123-45-6789", "0192023a7bbd73250516f069df18b500",
                "eyJzdWIiOiIxIn0", "AKIAIOSFODNN7ABCDXYZ"):
        assert raw not in out, raw
    assert "a***@shop.test" in out and "**** **** **** 4242" in out and "[MD5 hash]" in out
    # not PII: left untouched
    keep = "Server 192.168.100.200 · 2026-11-04 03:30:00 · v1.18.0 · order 1234567890123 · ts 1793736276.9"
    assert redact(keep) == keep
    assert redact("Cookie: sid=abc; theme=dark") == "Cookie: sid=[redacted]; theme=[redacted]"
    assert redact('{"password":"hunter2"}') == '{"password":"[redacted]"}'


def test_redact_obj_preserves_identifiers():
    obj = {"url": "https://t.test/u?email=a@b.co", "fingerprint": "0123456789abcdef0123456789abcdef",
           "evidence": "leaked bob@shop.test"}
    out = redact_obj(obj)
    assert out["url"] == obj["url"] and out["fingerprint"] == obj["fingerprint"]
    assert "b***@shop.test" in out["evidence"]


def _finding():
    f = Finding(check="data_exposure", title="Credentials exposed", severity=Severity.HIGH,
                confidence=Confidence.CERTAIN, url="https://t.test/api/users/1",
                evidence="email alice@shop.test password 0192023a7bbd73250516f069df18b500")
    f.ml_score = 0.91
    f.context = {"http_response": '{"email":"alice@shop.test","password":"0192023a7bbd73250516f069df18b500"}',
                 "review_notes": ["internal note"], "verification": "verified by independent re-test"}
    return f


def test_client_report_is_clean_and_redacted(tmp_path):
    meta = {"trace": [{"step": 1, "phase": "recon", "thought": "t", "actions": [], "observation": "o"}],
            "reasoner": "claude", "narrative": {"executive_summary": "Summary for alice@shop.test"}}
    paths = write_all("https://t.test", [_finding()], tmp_path, ["json", "html", "md", "sarif"], meta,
                      ReportOptions(author="ACME Security"))
    for p in paths:
        text = p.read_text()
        assert "WebGuard" not in text, p.suffix
        assert "alice@shop.test" not in text and "0192023a7bbd73250516f069df18b500" not in text, p.suffix
    html = next(p for p in paths if p.suffix == ".html").read_text()
    assert "Security Assessment Report" in html and "prepared by ACME Security" in html
    assert "ML true-positive" not in html and "reasoning trace" not in html and "internal note" not in html
    data = json.loads(next(p for p in paths if p.suffix == ".json").read_text())
    assert "trace" not in data["meta"] and "ml_score" not in data["findings"][0] and data["report"]["redacted"]


def test_technical_report_keeps_internals(tmp_path):
    meta = {"trace": [{"step": 1, "phase": "recon", "thought": "t", "actions": [], "observation": "o"}]}
    paths = write_all("https://t.test", [_finding()], tmp_path, ["html", "json"], meta,
                      ReportOptions(style="technical", redact=False))
    html = next(p for p in paths if p.suffix == ".html").read_text()
    assert "ML true-positive" in html and "reasoning trace" in html and "alice@shop.test" in html
    assert json.loads(next(p for p in paths if p.suffix == ".json").read_text())["tool"]["name"] == "WebGuard Pro"
