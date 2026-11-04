"""Encoding contexts and per-bug-class bypass variants."""

from __future__ import annotations

import asyncio

import httpx

from webguard.config import ScanConfig
from webguard.detection.context import ACTIVE_VARIANT, Context
from webguard.detection.encoding import (
    DECODE,
    Raw,
    detect_encoding,
    fullwidth,
    html_entities,
    unicode_js,
    url_encode_all,
    variants_for,
)
from webguard.http import HttpClient
from webguard.models import InjectionPoint
from webguard.scope import Scope
from webguard.signatures import default_db


def test_detect_value_encodings():
    assert detect_encoding("MTAwMQ==") == "base64" and DECODE["base64"]("MTAwMQ==") == "1001"
    assert detect_encoding("7b226964223a317d") == "hex"
    assert detect_encoding("eyJpZCI6MX0") == "base64url"
    assert detect_encoding("%2Fhome%2Fuser") == "url"
    for plain in ("hello", "12345678", "alice", "about.txt", "abcdefgh"):
        assert detect_encoding(plain) is None


def test_primitive_encoders():
    assert url_encode_all("../") == "%2E%2E%2F"
    assert unicode_js("'<") == "\\u0027\\u003c"
    assert html_entities("<a>") == "&#60;a&#62;"
    assert fullwidth("<'/") == "＜＇／"


def test_lfi_variants_follow_portswigger_scenarios():
    v = {x.name: x for x in variants_for("lfi", "/var/www/images/a.png")}
    payload = "../../../etc/passwd"
    assert v["nested-traversal"].transform(payload) == "....//....//....//etc/passwd"
    assert v["double-url-encoding"].transform(payload).startswith("%2E%2E%2F")
    assert isinstance(v["overlong-utf8"].transform(payload), Raw) and "..%c0%af" in v["overlong-utf8"].transform(payload)
    assert v["path-prefix"].transform(payload) == "/var/www/images/" + payload
    assert v["null-byte-extension"].transform(payload) == payload + "\x00.png"


def test_ssrf_allowlist_variants():
    v = {x.name: x for x in variants_for("ssrf", "https://trusted.example/logo.png")}
    assert v["allowlist-userinfo"].transform("http://example.com/") == "http://trusted.example@example.com/"
    assert v["allowlist-fragment"].transform("http://example.com/") == "http://example.com/#trusted.example"


def test_every_injection_class_has_meaningful_variants():
    for check in ("lfi", "xss", "sqli", "cmdi", "ssti", "redirect", "ssrf", "crlf"):
        assert variants_for(check, "x"), check
    assert variants_for("nosqli") == []  # operator injection has no encoding analogue


def test_raw_values_reach_the_wire_unescaped_and_variants_are_task_local():
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, text="ok")

    async def run():
        async with HttpClient(ScanConfig(), Scope(include=["t.test"]), transport=httpx.MockTransport(handler)) as c:
            ctx = Context(c, ScanConfig(), default_db())
            p = InjectionPoint("https://t.test/f", "GET", "query", "file", {"file": "a.png", "x": "1"})
            v = {x.name: x for x in variants_for("lfi", "a.png")}["overlong-utf8"]
            tok = ACTIVE_VARIANT.set(v)
            await ctx.send(p, "../etc/passwd")
            ACTIVE_VARIANT.reset(tok)
            await ctx.send(p, "../etc/passwd")  # no variant after reset
            enc = InjectionPoint("https://t.test/f", "GET", "query", "d", {"d": "1001"}, encoding="base64")
            await ctx.send(enc, "1001'")

    asyncio.run(run())
    assert "file=..%c0%afetc/passwd" in seen[0] and "x=1" in seen[0]
    assert "file=..%2Fetc%2Fpasswd" in seen[1] or "file=../etc/passwd" in seen[1]
    assert "d=MTAwMSc%3D" in seen[2]  # injected inside the decoded value, re-encoded
