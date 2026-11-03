"""Signature database loader and matchers.

Signatures ship as JSON in ``webguard/data/signatures``. Extra signature directories can be
added with the ``WEBGUARD_SIGNATURES`` environment variable (``os.pathsep`` separated) or
``SignatureDB(extra_dirs=[...])``; files with the same name are merged (user entries win).
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any

from webguard.config import DATA_DIR

SIG_DIR = DATA_DIR / "signatures"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass
class Match:
    name: str
    value: str
    meta: dict[str, Any]


class SignatureDB:
    def __init__(self, extra_dirs: list[str | Path] | None = None) -> None:
        dirs = [SIG_DIR]
        env = os.environ.get("WEBGUARD_SIGNATURES")
        if env:
            dirs += [Path(p) for p in env.split(os.pathsep) if p]
        dirs += [Path(d) for d in (extra_dirs or [])]
        self.dirs = dirs

    def load(self, name: str) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for d in self.dirs:
            path = d / f"{name}.json"
            if path.exists():
                data = json.loads(path.read_text())
                merged.update({k: v for k, v in data.items() if not k.startswith("_")})
        return merged

    # --- compiled views -------------------------------------------------------------------

    @cached_property
    def sql_errors(self) -> list[tuple[str, re.Pattern[str]]]:
        return [
            (dbms, re.compile(p, re.I))
            for dbms, patterns in self.load("sql_errors").items()
            for p in patterns
        ]

    @cached_property
    def tech(self) -> dict[str, Any]:
        return self.load("tech")

    @cached_property
    def waf(self) -> dict[str, Any]:
        return self.load("waf")

    @cached_property
    def secrets(self) -> list[tuple[str, re.Pattern[str], dict[str, Any]]]:
        return [(name, re.compile(s["regex"]), s) for name, s in self.load("secrets").items()]

    @cached_property
    def exposures(self) -> dict[str, Any]:
        return self.load("exposures")

    @cached_property
    def takeover(self) -> dict[str, Any]:
        return self.load("takeover")

    @cached_property
    def disclosure(self) -> list[tuple[str, re.Pattern[str], dict[str, Any]]]:
        return [(name, re.compile(s["regex"]), s) for name, s in self.load("disclosure").items()]

    def stats(self) -> dict[str, int]:
        return {
            "sql_errors": len(self.sql_errors),
            "technologies": len(self.tech),
            "wafs": len(self.waf),
            "secrets": len(self.secrets),
            "exposures": len(self.exposures),
            "takeover": len(self.takeover),
            "disclosure": len(self.disclosure),
        }

    # --- matchers -------------------------------------------------------------------------

    def match_sql_error(self, text: str) -> Match | None:
        for dbms, rx in self.sql_errors:
            m = rx.search(text)
            if m:
                return Match(dbms, m.group(0)[:200], {})
        return None

    def match_secrets(self, text: str) -> list[Match]:
        found: list[Match] = []
        seen: set[str] = set()
        for name, rx, meta in self.secrets:
            for m in rx.finditer(text):
                secret = m.groupdict().get("secret") or m.group(0)
                if secret in seen:
                    continue
                if shannon_entropy(secret) < meta.get("entropy", 0):
                    continue
                if _looks_like_placeholder(secret):
                    continue
                seen.add(secret)
                found.append(Match(name, secret, meta))
        return found

    def match_disclosure(self, text: str) -> list[Match]:
        out = []
        for name, rx, meta in self.disclosure:
            m = rx.search(text)
            if m:
                out.append(Match(name, m.group(0)[:300], meta))
        return out

    def fingerprint_tech(self, headers: Any, cookies: list[str], html: str) -> dict[str, str]:
        """Return {technology: version-or-empty}."""
        result: dict[str, str] = {}
        lower_headers = {k.lower(): v for k, v in headers.items()}
        scripts = re.findall(r"<script[^>]+src=[\"']([^\"']+)", html, re.I)
        metas = {
            m.group(1).lower(): m.group(2)
            for m in re.finditer(r"<meta[^>]+name=[\"']([^\"']+)[\"'][^>]+content=[\"']([^\"']*)", html, re.I)
        }
        for name, sig in self.tech.items():
            version = None
            hit = False
            for h, pattern in sig.get("headers", {}).items():
                if h in lower_headers:
                    m = _rx(pattern).search(lower_headers[h])
                    if m:
                        hit = True
                        version = version or m.groupdict().get("version")
            for pattern in sig.get("cookies", []):
                if any(_rx(pattern).search(c) for c in cookies):
                    hit = True
            for pattern in sig.get("html", []):
                m = _rx(pattern).search(html)
                if m:
                    hit = True
                    version = version or m.groupdict().get("version")
            for meta_name, pattern in sig.get("meta", {}).items():
                if meta_name in metas:
                    m = _rx(pattern).search(metas[meta_name])
                    if m:
                        hit = True
                        version = version or m.groupdict().get("version")
            for pattern in sig.get("scripts", []):
                for src in scripts:
                    m = _rx(pattern).search(src)
                    if m:
                        hit = True
                        version = version or m.groupdict().get("version")
            if hit:
                result[name] = version or ""
        return result

    def detect_waf(self, headers: Any, cookies: list[str], body: str) -> list[str]:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        found = []
        for name, sig in self.waf.items():
            hit = any(
                h in lower_headers and _rx(p).search(lower_headers[h]) for h, p in sig.get("headers", {}).items()
            )
            hit = hit or any(_rx(p).search(c) for p in sig.get("cookies", []) for c in cookies)
            hit = hit or any(_rx(p).search(body) for p in sig.get("body", []))
            if hit:
                found.append(name)
        return found


_PLACEHOLDERS = re.compile(r"(?i)(?:x{6,}|your[_-]?|example|sample|dummy|placeholder|changeme|test(?:ing)?key|<|\{\{|\$\{|\*{4,}|0{8,}|1234567)")


def _looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDERS.search(value))


@lru_cache(maxsize=4096)
def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


_default: SignatureDB | None = None


def default_db() -> SignatureDB:
    global _default
    if _default is None:
        _default = SignatureDB()
    return _default
