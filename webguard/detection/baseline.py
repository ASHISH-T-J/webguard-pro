"""Response normalisation, similarity and feature extraction.

Differential detection (boolean SQLi, anomaly hunting, soft-404) depends on comparing
responses while ignoring content that changes on every request (timestamps, CSRF tokens,
nonces, session ids). We strip such dynamic tokens, then compare word-shingle sets.
"""

from __future__ import annotations

import html
import math
import re
import statistics
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

from webguard.http import Resp

_DYNAMIC = [
    re.compile(r"\b[0-9a-f]{16,}\b", re.I),  # hashes / ids / tokens
    re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}"),  # base64-ish tokens / csrf
    re.compile(r"\b\d{1,4}[-/:.]\d{1,2}[-/:.]\d{1,4}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?)?Z?\b"),  # dates
    re.compile(r"\b\d{9,}\b"),  # epoch timestamps
    re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds)\b", re.I),  # render timings
]
_TAG = re.compile(r"<[a-zA-Z][^>]*>")
_WORD = re.compile(r"\w+")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_ERROR_WORDS = re.compile(
    r"(?i)\b(?:error|exception|warning|fatal|syntax|unexpected|traceback|stack|undefined|invalid|denied|failed)\b"
)


def _variants(value: str) -> list[str]:
    """Forms in which a reflected value commonly appears (raw, HTML-escaped, URL-encoded)."""
    out = {value, html.escape(value), html.escape(value, quote=False), quote(value), quote_plus(value)}
    return sorted((v for v in out if v), key=len, reverse=True)


def normalize(text: str, reflect: list[str] | None = None) -> str:
    for value in reflect or []:
        if value and len(value) > 2:
            for variant in _variants(value):
                text = text.replace(variant, " ")
    for rx in _DYNAMIC:
        text = rx.sub(" ", text)
    return text


def shingles(text: str, k: int = 3) -> set[int]:
    words = _WORD.findall(text.lower())
    if len(words) < k:
        return {hash(tuple(words))} if words else set()
    return {hash(tuple(words[i : i + k])) for i in range(len(words) - k + 1)}


def similarity(a: str, b: str, reflect: list[str] | None = None) -> float:
    """Jaccard similarity of 3-word shingles after removing dynamic content (0..1)."""
    sa, sb = shingles(normalize(a, reflect)), shingles(normalize(b, reflect))
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def title(text: str) -> str:
    m = _TITLE.search(text)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


def entropy(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:20000]
    counts: dict[str, int] = {}
    for ch in sample:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(sample)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


FEATURE_NAMES = (
    "status_class",
    "status_changed",
    "log_length",
    "length_ratio",
    "words",
    "lines",
    "tags",
    "error_words",
    "elapsed",
    "similarity",
    "title_changed",
    "ctype_changed",
    "header_count",
    "entropy",
)


def features(resp: Resp, base: Resp, reflect: list[str] | None = None) -> list[float]:
    """Numeric feature vector describing ``resp`` relative to the baseline ``base``."""
    text, btext = resp.text, base.text
    clean = normalize(text, reflect)
    return [
        resp.status // 100,
        float(resp.status != base.status),
        math.log1p(len(clean)),
        (len(clean) + 1) / (len(normalize(btext)) + 1),
        float(len(_WORD.findall(clean))),
        float(clean.count("\n")),
        float(len(_TAG.findall(clean))),
        float(len(_ERROR_WORDS.findall(clean))),
        resp.elapsed,
        similarity(text, btext, reflect),
        float(title(text) != title(btext)),
        float(resp.content_type.split(";")[0] != base.content_type.split(";")[0]),
        float(len(resp.headers)),
        entropy(clean),
    ]


@dataclass
class Baseline:
    """Behaviour of an endpoint for benign input, built from several samples."""

    samples: list[Resp] = field(default_factory=list)

    @property
    def primary(self) -> Resp:
        return self.samples[0]

    @property
    def stable_similarity(self) -> float:
        """How similar the page is to itself across benign requests (1.0 == fully static)."""
        if len(self.samples) < 2:
            return 1.0
        sims = [similarity(self.samples[0].text, s.text) for s in self.samples[1:]]
        return min(sims)

    @property
    def timings(self) -> list[float]:
        return [s.elapsed for s in self.samples]

    @property
    def max_time(self) -> float:
        return max(self.timings) if self.samples else 0.0

    @property
    def mean_time(self) -> float:
        return statistics.fmean(self.timings) if self.samples else 0.0

    @property
    def std_time(self) -> float:
        return statistics.pstdev(self.timings) if len(self.samples) > 1 else 0.0

    def contains(self, needle: str) -> bool:
        return any(needle in s.text for s in self.samples)

    def matches(self, resp: Resp, margin: float = 0.05, reflect: list[str] | None = None) -> bool:
        """True if ``resp`` looks like a normal (benign) response for this endpoint."""
        if resp.status != self.primary.status:
            return False
        threshold = max(0.0, self.stable_similarity - margin)
        return similarity(resp.text, self.primary.text, reflect) >= threshold
