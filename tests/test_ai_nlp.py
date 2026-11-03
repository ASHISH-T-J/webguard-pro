"""NLP, grep/analysis, reasoning engines, OpenAPI import, JWT and JS-mining unit tests."""

from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

from webguard.ai.reasoner import Candidate, ClaudeReasoner, LocalReasoner, OllamaReasoner, make_reasoner
from webguard.analysis.correlate import attack_chains, cluster
from webguard.analysis.grep import grep
from webguard.crawler import js_strings
from webguard.detection.checks.analyzers import crack_hs
from webguard.models import Confidence, Finding, Severity
from webguard.nlp.models import classify_page, classify_param, hypotheses_for_param
from webguard.nlp.query import parse, search
from webguard.nlp.summarize import executive_summary
from webguard.recon.openapi import guess_body, points_from_spec

# ------------------------------------------------------------------ NLP


@pytest.mark.parametrize("name,label", [
    ("q", "search"), ("returnUrl", "redirect"), ("next", "redirect"), ("imgPath", "file"), ("userId", "id"),
    ("cmd", "command"), ("callbackUrl", "url"), ("sortBy", "sort"), ("email", "email"), ("lang", "lang"),
])
def test_param_classifier(name, label):
    assert classify_param(name)[0] == label


def test_hypotheses_use_value_shape():
    assert hypotheses_for_param("x", "https://a.example/")[:2] == ["ssrf", "redirect"]
    assert hypotheses_for_param("doc", "report.pdf")[0] == "lfi"
    assert hypotheses_for_param("file")[0] == "lfi"


@pytest.mark.parametrize("status,ctype,body,label", [
    (200, "text/html", "<title>Sign in</title><form><input name=u><input type=password name=p></form>", "login"),
    (500, "text/html", "Traceback (most recent call last): File app.py line 3 in module Error", "stack_trace"),
    (403, "text/html", "Request blocked by web application firewall. Incident ID 99", "waf_block"),
    (200, "text/html", "<h1>Index of /backup</h1> Parent Directory Name Last modified Size", "directory_listing"),
    (200, "application/json", '{"data": []}', "api_json"),
])
def test_page_classifier(status, ctype, body, label):
    assert classify_page(status, ctype, body).label == label


def _f(check, sev=Severity.HIGH, url="https://t.test/a", param="q", evidence="ev", conf=Confidence.FIRM, title=None):
    return Finding(check=check, title=title or f"{check} title", severity=sev, confidence=conf, url=url,
                   parameter=param, evidence=evidence)


def test_natural_language_query():
    fs = [_f("sqli", url="https://t.test/api/x"), _f("sqli", Severity.MEDIUM, url="https://t.test/page"),
          _f("xss", Severity.HIGH), _f("headers", Severity.LOW, param=None)]
    assert len(search(fs, "high sql injection on api")) == 1
    assert len(search(fs, "medium and above")) == 3
    assert {f.check for f in search(fs, "everything high except xss")} == {"sqli"}
    q = parse("critical or high cross-site scripting with certain confidence")
    assert q.checks == {"xss"} and q.confidence == {Confidence.CERTAIN}


def test_executive_summary_is_grounded():
    text = executive_summary("t.test", [_f("sqli", Severity.CRITICAL), _f("headers", Severity.LOW)])
    assert "Critical" in text and "database" in text and "2 issues" in text
    assert "No exploitable" in executive_summary("t.test", [])

# ------------------------------------------------------------------ JS mining, OpenAPI, JWT


def test_js_tokenizer_handles_minified_code():
    code = 'a="x"/2;b=`${h}/rest/s?q=${t}`;c=\'it\\\'s\';d="/api/Users";e=`\n<div>long template</div>\n`;f="/x?y=1"'
    out = list(js_strings(code))
    assert "${h}/rest/s?q=${t}" in out and "/api/Users" in out and "/x?y=1" in out


def test_openapi_points_and_body_guessing():
    spec = {"openapi": "3.0.0", "servers": [{"url": "/v1"}], "paths": {
        "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}},
                                                {"name": "fields", "in": "query", "schema": {"type": "string"}}]}},
        "/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/L"}}}}}},
    }, "components": {"schemas": {"L": {"type": "object", "properties": {"email": {"type": "string", "format": "email"},
                                                                           "password": {"type": "string"}}}}}}
    pts = points_from_spec(spec, "https://t.test/openapi.json")
    keys = {(p.method, p.url, p.location, p.name) for p in pts}
    assert ("GET", "https://t.test/v1/users/1", "query", "fields") in keys
    assert ("POST", "https://t.test/v1/login", "json", "email") in keys
    assert guess_body("https://t.test/rest/user/login") == {"email": "test@example.com", "password": "Passw0rd!"}


def test_jwt_weak_secret_cracked():
    sys.path.insert(0, "tests")
    from vulnapp import TOKEN

    assert crack_hs(TOKEN) == "secret"
    assert crack_hs(TOKEN, ["nope"]) is None

# ------------------------------------------------------------------ grep + correlation


def test_grep_packs_rank_and_dedupe():
    responses = [
        {"url": "https://t.test/app.js", "content_type": "application/javascript", "headers": {},
         "body": "el.innerHTML = location.hash; fetch('/api/v2/admin/users'); x='db01.internal'"},
        {"url": "https://t.test/other.js", "content_type": "application/javascript", "headers": {},
         "body": "x.innerHTML = location.hash;"},
    ]
    hits = grep(responses)
    sink = next(h for h in hits if h.rule == "innerHTML/outerHTML assignment")
    assert len(sink.locations) == 2  # same value from two files -> one hit, two locations
    assert any(h.rule == "internal hostname" and h.value == "db01.internal" for h in hits)
    assert any(h.value == "/api/v2/admin/users" for h in hits)
    assert grep(responses, regex=r"admin/\w+")[0].value == "admin/users"


def test_clustering_and_attack_chains():
    fs = [_f("xss", url="https://t.test/a", param="q"), _f("xss", url="https://t.test/b", param="q"),
          _f("headers", Severity.LOW, url="https://t.test/#cookie-sid", param=None,
             evidence="Set-Cookie: sid=1 (missing HttpOnly)", title="Session cookie 'sid' missing flags"),
          _f("auth", Severity.CRITICAL, url="https://t.test/login", param="email")]
    issues = cluster(fs)
    assert len(issues) == 3 and issues[0].check == "auth"
    xss_issue = next(i for i in issues if i.check == "xss")
    assert len(xss_issue.findings) == 2 and xss_issue.cvss == 6.1
    titles = [c["title"] for c in attack_chains(fs)]
    assert titles[0] in ("Account takeover: XSS + session cookie readable by JavaScript",
                         "Administrative access: authentication bypass")
    assert len(titles) == 2

# ------------------------------------------------------------------ reasoners


def _cands():
    return [Candidate("inject:a", "inject", "GET /a q", "input", "q looks like search", 6, 50),
            Candidate("exposure:r", "exposure", "root", "config", "probe files", 7, 70),
            Candidate("headers:r", "headers", "root", "config", "hardening", 3, 3)]


def test_local_reasoner_ranks_by_expected_value():
    d = asyncio.run(LocalReasoner().decide("phase", {}, _cands(), limit=2))
    assert d.selected == ["exposure:r", "inject:a"] and d.engine == "local"
    d_all = asyncio.run(LocalReasoner(exhaustive=True).decide("phase", {}, _cands(), limit=1))
    assert len(d_all.selected) == 3


def _fake_anthropic(monkeypatch, reply: dict, stop_reason="end_turn"):
    calls = []

    class Messages:
        async def create(self, **kw):
            calls.append(kw)
            return types.SimpleNamespace(stop_reason=stop_reason, stop_details=None,
                                         content=[types.SimpleNamespace(type="text", text=json.dumps(reply))])

    class AsyncAnthropic:
        def __init__(self):
            self.beta = types.SimpleNamespace(messages=Messages())

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropic=AsyncAnthropic))
    return calls


def test_claude_reasoner_request_and_validation(monkeypatch):
    calls = _fake_anthropic(monkeypatch, {"thought": "login first", "selected": ["inject:a", "rm -rf /"],
                                          "hypotheses": ["sqli"]})
    r = make_reasoner("claude")
    assert isinstance(r, ClaudeReasoner)
    d = asyncio.run(r.decide("Input validation", {"k": 1}, _cands(), limit=5))
    assert d.selected == ["inject:a"]  # ids not in the candidate list are discarded
    assert d.engine == "claude" and d.thought == "login first"
    kw = calls[0]
    assert kw["model"] == "claude-opus-5-5" and kw["fallbacks"] == "default"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert kw["output_config"]["format"]["type"] == "json_schema" and kw["output_config"]["effort"] == "high"


def test_claude_refusal_falls_back_to_local(monkeypatch):
    _fake_anthropic(monkeypatch, {}, stop_reason="refusal")
    d = asyncio.run(make_reasoner("claude").decide("p", {}, _cands(), limit=2))
    assert d.engine == "local" and d.selected == ["exposure:r", "inject:a"] and "unavailable" in d.thought


def test_ollama_unreachable_falls_back(monkeypatch):
    r = OllamaReasoner(base_url="http://127.0.0.1:9", timeout=1)
    d = asyncio.run(r.decide("p", {}, _cands(), limit=1))
    assert d.engine == "local" and r.failures == 1


def test_make_reasoner_rejects_unknown():
    with pytest.raises(ValueError):
        make_reasoner("gpt")
