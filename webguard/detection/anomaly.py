"""Unsupervised anomaly detection for vulnerability hunting.

For every injection point we collect:

* *benign* samples - the parameter filled with random alphanumerics of varying length,
* *probe* samples - generic "breaker" inputs (quotes, template braces, traversal, null bytes,
  type confusion, oversized values ...).

Each response is turned into a feature vector relative to the baseline (status, length, word
and tag counts, error vocabulary, timing, similarity, title/content-type change, entropy).
We then score each probe against the benign distribution with

1. an IsolationForest model when scikit-learn is installed, and
2. a robust z-score (median / MAD) on every feature, which also explains *why* a probe is
   anomalous (top deviating features) and works with zero dependencies.

A probe is reported only when both agree (or the robust score is extreme), which keeps the
false-positive rate low while still surfacing behaviour no signature knows about - the kind
of lead a human hunter wants to dig into manually.
"""

from __future__ import annotations

import random
import statistics
import string
from dataclasses import dataclass

from webguard.detection.baseline import FEATURE_NAMES

try:  # optional ML backend
    import numpy as np
    from sklearn.ensemble import IsolationForest

    HAVE_SKLEARN = True
except Exception:  # pragma: no cover - depends on environment
    HAVE_SKLEARN = False

PROBES: list[tuple[str, str]] = [
    ("single-quote", "'"),
    ("double-quote", '"'),
    ("backslash", "\\"),
    ("quote-paren", "')"),
    ("sql-comment", "'-- -"),
    ("template", "{{"),
    ("template-dollar", "${"),
    ("traversal", "../../../../"),
    ("null-byte", "%00"),
    ("semicolon", ";"),
    ("pipe", "|"),
    ("backtick", "`"),
    ("angle", "<wg>"),
    ("negative", "-1"),
    ("zero", "0"),
    ("huge-number", "99999999999999999999"),
    ("float", "1.0e309"),
    ("array", "[]"),
    ("object", "{}"),
    ("unicode", "\u0000﻿‮"),
    ("format-string", "%s%n%x"),
    ("long", "A" * 2048),
    ("crlf", "\r\nX-WG: 1"),
    ("xml", "<?xml version='1.0'?><!DOCTYPE a>"),
]

# features excluded from the robust-z explanation because they are noisy or redundant
_SKIP_Z = {"header_count", "elapsed"}


def benign_values(original: str, n: int = 6) -> list[str]:
    rng = random.Random(hash(original) & 0xFFFF)
    out = []
    lengths = [3, 6, 8, 12, len(original) or 5, 16]
    for i in range(n):
        length = max(1, lengths[i % len(lengths)])
        alphabet = string.digits if original.isdigit() and i % 2 == 0 else string.ascii_lowercase + string.digits
        out.append("".join(rng.choice(alphabet) for _ in range(length)))
    return out


@dataclass
class AnomalyResult:
    probe: str
    payload: str
    score: float  # robust anomaly score (max |z|)
    forest_outlier: bool | None
    top_features: list[tuple[str, float]]

    @property
    def is_anomalous(self) -> bool:
        if self.forest_outlier is None:
            return self.score >= 8.0
        return (self.forest_outlier and self.score >= 4.0) or self.score >= 12.0


def _robust_z(values: list[float], x: float) -> float:
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    spread = max(1.4826 * mad, 0.05 * abs(med), 1e-3)
    return (x - med) / spread


def score(benign: list[list[float]], probes: list[tuple[str, str, list[float]]]) -> list[AnomalyResult]:
    if len(benign) < 3 or not probes:
        return []
    columns = list(zip(*benign))
    forest_flags: list[bool | None] = [None] * len(probes)
    if HAVE_SKLEARN:
        try:
            model = IsolationForest(n_estimators=100, contamination="auto", random_state=7)
            model.fit(np.array(benign))
            preds = model.predict(np.array([p[2] for p in probes]))
            forest_flags = [bool(p == -1) for p in preds]
        except Exception:  # pragma: no cover
            pass
    results = []
    for (name, payload, vec), flag in zip(probes, forest_flags):
        zs = []
        for idx, (fname, x) in enumerate(zip(FEATURE_NAMES, vec)):
            if fname in _SKIP_Z:
                continue
            zs.append((fname, _robust_z(list(columns[idx]), x)))
        zs.sort(key=lambda t: abs(t[1]), reverse=True)
        top = [(f, round(z, 2)) for f, z in zs[:3] if abs(z) >= 3]
        results.append(AnomalyResult(name, payload, abs(zs[0][1]) if zs else 0.0, flag, top))
    return results
