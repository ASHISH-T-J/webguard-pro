"""Shared state and helpers for detection checks."""

from __future__ import annotations

import asyncio
import logging
import random
import string
from collections.abc import Callable
from typing import Any

from webguard.config import ScanConfig
from webguard.detection.baseline import Baseline
from webguard.http import HttpClient, OutOfScopeError, Resp
from webguard.models import Finding, InjectionPoint
from webguard.signatures import SignatureDB

log = logging.getLogger("webguard.detect")


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
        self._baselines: dict[tuple, Baseline | None] = {}
        self._baseline_locks: dict[tuple, asyncio.Lock] = {}

    # ------------------------------------------------------------------ findings
    def report(self, finding: Finding) -> None:
        fp = finding.fingerprint
        existing = self.findings.get(fp)
        if existing and (existing.confidence, existing.severity) >= (finding.confidence, finding.severity):
            return
        self.findings[fp] = finding
        if not existing and self.on_finding:
            self.on_finding(finding)

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

    # ------------------------------------------------------------------ requests
    def _build(self, point: InjectionPoint, value: str) -> dict[str, Any]:
        method = point.method.upper()
        kw: dict[str, Any] = {"method": method, "url": point.url}
        if point.location in ("query", "path"):
            kw["params"] = point.with_value(value)
        elif point.location == "form":
            if method == "GET":
                kw["params"] = point.with_value(value)
            else:
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
        kw = self._build(point, value)
        try:
            return await self.client.request(
                kw.pop("method"), kw.pop("url"), timeout=timeout, follow_redirects=follow_redirects, **kw
            )
        except OutOfScopeError:
            return None

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
        d = self.config.time_delay
        threshold = base.max_time + d * 0.8
        fast_limit = base.max_time + d * 0.5
        req_timeout = self.config.timeout + d + 2
        evidence: dict[str, float] = {"baseline_max": round(base.max_time, 3), "delay": float(d)}
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
