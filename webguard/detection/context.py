"""Shared state and helpers for detection checks."""

from __future__ import annotations

import asyncio
import contextvars
import html as _html
import logging
import random
import re
import string
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode

from webguard import ui
from webguard.config import ScanConfig
from webguard.detection.baseline import Baseline
from webguard.detection.encoding import Raw, Variant, encode_context
from webguard.http import HttpClient, OutOfScopeError, Resp
from webguard.models import Finding, InjectionPoint
from webguard.signatures import SignatureDB

log = logging.getLogger("webguard.detect")


# the input-filter bypass variant active for the current test (per asyncio task, so concurrent tests are isolated)
ACTIVE_VARIANT: contextvars.ContextVar[Variant | None] = contextvars.ContextVar("webguard_variant", default=None)
# value encoding of the point currently under test (base64/hex/url), recorded on findings for verification
ACTIVE_ENCODING: contextvars.ContextVar[str] = contextvars.ContextVar("webguard_encoding", default="")
# check (bug class) currently being tested in this task - shown in verbose payload output
ACTIVE_CHECK: contextvars.ContextVar[str] = contextvars.ContextVar("webguard_check", default="")
# set while re-verifying a finding: confirmed-class short-circuiting must not block the re-test
VERIFYING: contextvars.ContextVar[bool] = contextvars.ContextVar("webguard_verifying", default=False)

# bug classes whose confirmation holds for the whole host (one origin-wide misconfiguration)
HOST_SCOPED = {"cors", "host_header", "headers", "cache_deception", "tls", "server"}
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|"
                     r"[A-Za-z0-9_-]{22,})$", re.I)


def route_key(url: str) -> str:
    """'/users/42/orders/9f3a...' -> 'host/users/{id}/orders/{id}': URLs that are one route in the app."""
    from urllib.parse import urlsplit

    p = urlsplit(url)
    segs = ["{id}" if _ID_SEG.match(s) else s for s in p.path.split("/")]
    return f"{p.netloc.lower()}{'/'.join(segs)}"


def check_family(check: str) -> str:
    """Bug class of a finding/check ('cve:CVE-1' -> 'cve', 'xss' -> 'xss')."""
    return check.split(":", 1)[0]
FILTER_HINT = re.compile(r"(?i)invalid (?:characters?|input|value|parameter|request|file ?name|path)|not allowed|"
                         r"illegal (?:characters?|input)|forbidden characters?|bad input|disallowed|"
                         r"hack(?:ing)? attempt|possible (?:attack|injection)|detected (?:sql|injection)|"
                         r"path traversal|must (?:start|end) with")
STRIP_TOKENS = ("../", "..\\", "<", ">", "'", '"', "{{", "${", ";", "|", "`", "$(")


def token(n: int = 8) -> str:
    """Random lowercase canary that is extremely unlikely to occur naturally."""
    return "wg" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class Context:
    def __init__(
        self,
        client: HttpClient,
        config: ScanConfig,
        sigdb: SignatureDB,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> None:
        self.client = client
        self.config = config
        self.sigdb = sigdb
        self.on_finding = on_finding
        self.findings: dict[str, Finding] = {}
        self.oob_log: list[dict[str, str]] = []
        self.oob = None  # webguard.oob.Provider when out-of-band detection is enabled
        # inputs where a WAF / CDN challenge / rate limiter answered instead of the application
        self.obstructed: dict[str, set[str]] = {}
        self.obstructed_keys: set[tuple] = set()
        # evidence that the application filters input for a point (validation errors, stripped characters)
        self.filter_signals: dict[tuple, int] = {}
        self.escaped_points: set[tuple] = set()  # reflections came back HTML-escaped (decode-order bugs possible)
        self._baselines: dict[tuple, Baseline | None] = {}
        # confirmed bug class per input / route / host: later tests of that class there are redundant
        self.confirmed: set[tuple] = set()
        self.skipped_redundant = 0
        self._baseline_locks: dict[tuple, asyncio.Lock] = {}

    # ------------------------------------------------------------------ findings
    def report(self, finding: Finding) -> None:
        variant = ACTIVE_VARIANT.get()
        if variant is not None:
            finding.title += f" - input filter bypassed ({variant.name})"
            finding.tags = [*finding.tags, f"bypass:{variant.name}"]
            finding.context = {**finding.context, "bypass": {"variant": variant.name, "technique_source": variant.source}}
            if finding.payload:
                finding.payload = variant.transform(finding.payload)
        enc = ACTIVE_ENCODING.get()
        if enc and finding.parameter:
            finding.title += f" (inside {enc}-encoded value)"
            finding.context = {**finding.context, "value_encoding": enc}
        fp = finding.fingerprint
        existing = self.findings.get(fp)
        if existing and (existing.confidence, existing.severity) >= (finding.confidence, finding.severity):
            return
        self.findings[fp] = finding
        self._confirm(finding)
        if not existing and self.on_finding:
            self.on_finding(finding)

    # ------------------------------------------------------------------ confirmation ledger
    def _confirm(self, f: Finding) -> None:
        from webguard.models import Confidence

        if f.confidence < Confidence.FIRM or f.detection == "anomaly":
            return  # only proven bugs stop further testing; leads keep the class open
        fam = check_family(f.check)
        if fam in HOST_SCOPED:
            self.confirmed.add((fam, "host", route_key(f.url).split("/", 1)[0]))
        elif f.parameter:
            self.confirmed.add((fam, route_key(f.url), f.location or "", f.parameter))
        else:
            self.confirmed.add((fam, "url", route_key(f.url)))

    def is_confirmed(self, check: str, point: InjectionPoint | None = None, url: str | None = None) -> bool:
        """Has this bug class already been proven for this input (any URL of the same route) / URL / host?"""
        fam = check_family(check)
        target = point.url if point is not None else url or ""
        if (fam, "host", route_key(target).split("/", 1)[0]) in self.confirmed:
            return True
        if point is not None:
            return (fam, route_key(point.url), point.location, point.name) in self.confirmed
        return (fam, "url", route_key(target)) in self.confirmed

    def has(self, check: str, point: InjectionPoint | None = None, url: str | None = None) -> bool:
        """Was ``check`` already confirmed for this point / URL? (avoid redundant requests)"""
        for f in self.findings.values():
            if f.check != check:
                continue
            if point is not None and f.parameter == point.name and f.url == point.url and f.location == point.location:
                return True
            if url is not None and f.url == url:
                return True
        return False

    def oob_payload(self, check: str, point: InjectionPoint | None = None, **label):
        """A unique, single-use callback for this test (None when OOB detection is off)."""
        if self.oob is None:
            return None
        if point is not None:
            label = {"url": point.url, "method": point.method, "parameter": point.name,
                     "location": point.location, **label}
        p = self.oob.new_payload({"check": check, **label})
        self.oob_log.append({"id": p.id, "check": check, "url": label.get("url", ""),
                             "parameter": label.get("parameter") or "", "callback": p.url})
        return p

    # ------------------------------------------------------------------ response context
    def app_answered(self, resp, point: InjectionPoint | None = None, check: str = "") -> bool:
        """True if the application (not a WAF/CDN challenge/rate limiter) produced this response.

        Non-application responses are never used as evidence; the input is recorded as obstructed so the
        report can say "not tested" instead of implying "not vulnerable".
        """
        from webguard.analysis.context import classify

        rc = classify(resp)
        if rc.is_app_response:
            return True
        if point is not None:
            self.obstructed.setdefault(rc.kind, set()).add(f"{point.method} {point.url} [{point.name}] {check}".strip())
            self.obstructed_keys.add(point.key)
        return False

    def _observe_filter(self, point: InjectionPoint, value: str, resp: Resp) -> None:
        """Remember application-level filtering for this input (enables bypass variants)."""
        from webguard.analysis.context import classify

        if resp is None or not classify(resp).is_app_response:
            return
        hit = resp.status in (400, 406, 422) or (resp.status < 500 and FILTER_HINT.search(resp.text[:5000]))
        if any(c in value for c in "<>\"'") and value not in resp.text and _html.escape(value) in resp.text:
            self.escaped_points.add(point.key)
        if not hit and len(value) >= 6 and value not in resp.text and _html.escape(value) not in resp.text \
                and _html.escape(value, quote=False) not in resp.text:
            for tok in STRIP_TOKENS:  # our value came back with the dangerous characters removed
                parts = value.split(tok)
                # the token must sit BETWEEN surviving text, otherwise a truncated/escaped echo looks the same
                if len(parts) >= 2 and len(parts[0]) >= 2 and len(parts[-1]) >= 2 and "".join(parts) in resp.text:
                    hit = True
                    break
        if hit and value != point.original:
            self.filter_signals[point.key] = self.filter_signals.get(point.key, 0) + 1

    # ------------------------------------------------------------------ requests
    @staticmethod
    def _wire_value(point: InjectionPoint, value: str) -> str:
        """The value after the active tamper/variant and the parameter's own encoding (base64, hex, ...)."""
        variant = ACTIVE_VARIANT.get()
        if variant is not None and value != point.original:
            value = variant.transform(value)
        if point.encoding:  # encoded value context: the app decodes this parameter before using it
            value = encode_context(str(value), point.encoding)
        return value

    def _build(self, point: InjectionPoint, value: str) -> dict[str, Any]:
        value = self._wire_value(point, value)
        method = point.method.upper()
        kw: dict[str, Any] = {"method": method, "url": point.url}
        in_query = point.location in ("query", "path") or (point.location == "form" and method == "GET")
        if in_query and isinstance(value, Raw):
            # wire-exact value: place it in the query string ourselves so it isn't percent-encoded again
            others = urlencode({k: v for k, v in point.params.items() if k != point.name})
            raw_pair = f"{quote(point.name, safe='')}={value}"
            kw["url"] = point.url + "?" + "&".join(x for x in (others, raw_pair) if x)
        elif in_query:
            kw["params"] = point.with_value(value)
        elif point.location == "form":
            kw["data"] = point.with_value(value)
        elif point.location == "json":
            kw["json"] = _json_value(point.with_value(value), point.params)
        elif point.location == "header":
            kw["headers"] = {point.name: value}
        elif point.location == "cookie":
            kw["headers"] = {"Cookie": f"{point.name}={value}"}
        return kw

    async def send(self, point: InjectionPoint, value: str, *, timeout: float | None = None,
                   follow_redirects: bool = False) -> Resp | None:
        check = ACTIVE_CHECK.get()
        if check and not VERIFYING.get() and str(value) != str(point.original) and self.is_confirmed(check, point):
            self.skipped_redundant += 1  # class already proven on this input (possibly by a concurrent task)
            return None
        kw = self._build(point, value)
        if ui.LEVEL >= 3 and str(value) != str(point.original):
            variant = ACTIVE_VARIANT.get()
            wire = self._wire_value(point, value)
            ui.payload(ACTIVE_CHECK.get(), point.method.upper(), point.url, point.name, point.location, str(value),
                       str(wire), variant.name if variant is not None else None, point.encoding or None,
                       wire_exact=isinstance(wire, Raw))
        try:
            resp = await self.client.request(
                kw.pop("method"), kw.pop("url"), timeout=timeout, follow_redirects=follow_redirects, **kw
            )
        except OutOfScopeError:
            return None
        if resp is not None:
            self._observe_filter(point, str(value), resp)
        return resp

    def curl(self, point: InjectionPoint, value: str) -> str:
        kw = self._build(point, value)
        return self.client.curl(
            kw["method"], kw["url"], params=kw.get("params"), data=kw.get("data"),
            json_body=kw.get("json"), headers=kw.get("headers"),
        )

    async def baseline(self, point: InjectionPoint, samples: int = 3) -> Baseline | None:
        key = point.key
        lock = self._baseline_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._baselines:
                return self._baselines[key]
            resps = []
            for _ in range(samples):  # sequential so timings are not skewed by our own concurrency
                r = await self.send(point, point.original)
                if r is not None:
                    resps.append(r)
            self._baselines[key] = Baseline(resps) if resps else None
            return self._baselines[key]

    async def timing_confirm(self, point: InjectionPoint, make_payload: Callable[[int], str],
                             base: Baseline) -> tuple[bool, dict[str, float]]:
        """Confirm a time-based injection: slow(d) -> fast(0) -> slow(d), all relative to baseline.

        Returns (confirmed, evidence) where evidence has measured timings.
        """
        # jitter-aware: on noisy networks the injected delay must clearly exceed natural variation
        jitter = max(base.std_time, base.max_time - base.mean_time)
        d = max(self.config.time_delay, min(30, int(jitter * 6) + 1))
        threshold = base.max_time + d * 0.8
        fast_limit = base.max_time + d * 0.5
        req_timeout = self.config.timeout + d + 2
        evidence: dict[str, float] = {"baseline_max": round(base.max_time, 3), "delay": float(d),
                                      "baseline_jitter": round(jitter, 3)}
        r1 = await self.send(point, make_payload(d), timeout=req_timeout)
        if r1 is None or r1.elapsed < threshold:
            return False, evidence
        evidence["slow_1"] = round(r1.elapsed, 3)
        r0 = await self.send(point, make_payload(0), timeout=req_timeout)
        if r0 is None or r0.elapsed >= fast_limit:
            return False, evidence
        evidence["fast"] = round(r0.elapsed, 3)
        r2 = await self.send(point, make_payload(d), timeout=req_timeout)
        if r2 is None or r2.elapsed < threshold:
            return False, evidence
        evidence["slow_2"] = round(r2.elapsed, 3)
        return True, evidence


def _json_value(values: dict[str, str], originals: dict[str, Any]) -> dict[str, Any]:
    """Keep the original JSON types for parameters we are not injecting into."""
    out: dict[str, Any] = {}
    for k, v in values.items():
        orig = originals.get(k)
        out[k] = orig if (v == orig) else v
    return out
