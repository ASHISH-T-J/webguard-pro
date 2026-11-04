"""ffuf-style fuzzer: put ``FUZZ`` anywhere in the URL path/query, a header or the body.

    webguard fuzz "https://shop.example.com/FUZZ" -w dirs
    webguard fuzz "https://shop.example.com/api/items?FUZZ=1" -w params -mc 200
    webguard fuzz "https://shop.example.com/api/login" -X POST -d '{"user":"FUZZ"}' -H 'Content-Type: application/json' -w users.txt

Every request goes through the scanner's HTTP client: scope enforcement, adaptive rate limiting, retries.
Auto-calibration (default on) sends random values first and filters responses that look like them
(same status and size within 2%, or very similar body), like ffuf ``-ac``.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from webguard.config import DATA_DIR, ScanConfig
from webguard.detection.baseline import similarity
from webguard.detection.context import token
from webguard.http import HttpClient
from webguard.scope import Scope

KEYWORD = "FUZZ"
BUILTIN = {"dirs": DATA_DIR / "wordlists" / "quick.txt", "dirs-large": DATA_DIR / "wordlists" / "common.txt",
           "params": DATA_DIR / "wordlists" / "params.txt"}
DEFAULT_MATCH = {200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405, 500}


@dataclass
class Filters:
    match_codes: set[int] = field(default_factory=lambda: set(DEFAULT_MATCH))
    filter_codes: set[int] = field(default_factory=set)
    filter_sizes: set[int] = field(default_factory=set)
    filter_words: set[int] = field(default_factory=set)
    filter_lines: set[int] = field(default_factory=set)
    filter_regex: re.Pattern | None = None
    match_regex: re.Pattern | None = None


@dataclass
class Hit:
    value: str
    url: str
    status: int
    size: int
    words: int
    lines: int
    elapsed_ms: int
    redirect: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def load_words(spec: str) -> list[str]:
    path = BUILTIN.get(spec, spec)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(dict.fromkeys(w.strip() for w in fh if w.strip() and not w.startswith("#")))


def parse_codes(spec: str | None) -> set[int]:
    out: set[int] = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out |= set(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return out


class Fuzzer:
    def __init__(self, url: str, words: list[str], config: ScanConfig, scope: Scope, method: str = "GET",
                 headers: dict[str, str] | None = None, data: str | None = None, filters: Filters | None = None,
                 calibrate: bool = True, transport=None) -> None:
        if KEYWORD not in url + str(headers or {}) + (data or ""):
            raise ValueError(f"put the {KEYWORD} keyword in the URL, a header or the body (-d)")
        host_part = url.split("://", 1)[-1].split("/", 1)[0]
        if KEYWORD in host_part:
            raise ValueError("FUZZ in the host name is not supported: use 'webguard recon' for subdomains")
        self.url, self.words, self.config, self.scope = url, words, config, scope
        self.method, self.headers, self.data = method.upper(), headers or {}, data
        self.filters = filters or Filters()
        self.calibrate, self.transport = calibrate, transport
        self._calibration: list = []

    def _request(self, value: str) -> tuple[str, dict, str | None]:
        sub = lambda s: s.replace(KEYWORD, value)  # noqa: E731
        return sub(self.url), {k: sub(v) for k, v in self.headers.items()}, sub(self.data) if self.data else None

    async def _send(self, client: HttpClient, value: str):
        url, headers, data = self._request(value)
        return url, await client.request(self.method, url, headers=headers or None, content=data)

    def _filtered(self, value: str, r) -> bool:
        f = self.filters
        text = r.text or ""
        size, words, lines = len(r.text.encode()), len(text.split()), text.count("\n") + 1
        if r.status not in f.match_codes or r.status in f.filter_codes:
            return True
        if size in f.filter_sizes or words in f.filter_words or lines in f.filter_lines:
            return True
        if f.filter_regex is not None and f.filter_regex.search(text):
            return True
        if f.match_regex is not None and not f.match_regex.search(text):
            return True
        for c in self._calibration:  # looks like a random value -> not interesting
            if c.status == r.status and (abs(len(c.text) - len(text)) <= max(4, len(c.text) * 0.02)
                                         or similarity(c.text, text, [value]) > 0.92):
                return True
        return False

    async def run(self, on_hit=None) -> list[Hit]:
        hits: list[Hit] = []
        async with HttpClient(self.config, self.scope, self.transport) as client:
            self.client = client
            if self.calibrate:
                for v in (token(8), token(12) + ".html", "." + token(6)):
                    _, r = await self._send(client, v)
                    if r is not None:
                        self._calibration.append(r)

            async def one(value: str) -> None:
                url, r = await self._send(client, value)
                if r is None or self._filtered(value, r):
                    return
                text = r.text or ""
                hit = Hit(value, url, r.status, len(text.encode()), len(text.split()), text.count("\n") + 1,
                          int(r.elapsed * 1000), r.headers.get("location", ""))
                hits.append(hit)
                if on_hit:
                    on_hit(hit)

            await asyncio.gather(*(one(w) for w in self.words))
        return sorted(hits, key=lambda h: (h.status, h.value))
