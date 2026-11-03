"""ML triage: predicts the probability that a finding is a true positive.

Trained on analyst labels stored in the database (``webguard db label <id> tp|fp``) with
L2-regularised logistic regression (pure Python, no heavy dependencies). Features combine
categorical facts (check, detection method, confidence, severity, location, response
evidence numbers) and hashed tokens from title/evidence (the "hashing trick"), so the model
learns which signatures / hosts / patterns generate noise in *your* targets.

Without a trained model a calibrated prior based on confidence and detection method is used.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
from pathlib import Path

from webguard.models import Confidence, Finding

HASH_DIM = 512
PRIOR = {Confidence.CERTAIN: 0.95, Confidence.FIRM: 0.8, Confidence.TENTATIVE: 0.35}
DETECTION_ADJ = {"signature": 0.0, "differential": -0.05, "timing": -0.1, "anomaly": -0.15, "passive": 0.0,
                 "external": -0.05}
_TOKEN = re.compile(r"[a-z][a-z0-9_-]{2,30}")


def _h(name: str) -> int:
    return int(hashlib.md5(name.encode()).hexdigest()[:8], 16) % HASH_DIM


def featurize(f: Finding) -> dict[int, float]:
    vec: dict[int, float] = {}

    def add(name: str, value: float = 1.0) -> None:
        idx = _h(name)
        vec[idx] = vec.get(idx, 0.0) + value

    add("bias")
    add(f"check={f.check}")
    add(f"detection={f.detection}")
    add(f"confidence={f.confidence.name}")
    add(f"severity={f.severity.name}")
    add(f"location={f.location}")
    add(f"check*detection={f.check}*{f.detection}")
    add(f"host={f.host}")
    for name, value in (f.features or {}).items():
        if isinstance(value, (int, float)) and math.isfinite(value):
            add(f"num:{f.check}:{name}", math.tanh(float(value) / 10.0))
    for tok in set(_TOKEN.findall(f"{f.title} {f.evidence[:300]}".lower())):
        add(f"tok:{tok}", 0.5)
    return vec


def _dot(w: list[float], x: dict[int, float]) -> float:
    return sum(w[i] * v for i, v in x.items())


def _sigmoid(z: float) -> float:
    if z < -30:
        return 0.0
    if z > 30:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class TriageModel:
    def __init__(self, weights: list[float] | None = None, meta: dict | None = None) -> None:
        self.weights = weights
        self.meta = meta or {}

    @property
    def trained(self) -> bool:
        return self.weights is not None

    def prior(self, f: Finding) -> float:
        return max(0.01, min(0.99, PRIOR[f.confidence] + DETECTION_ADJ.get(f.detection, 0.0)))

    def predict(self, f: Finding) -> float:
        if not self.trained:
            return round(self.prior(f), 3)
        p = _sigmoid(_dot(self.weights, featurize(f)))
        # blend with prior when few labels exist (shrinkage)
        n = self.meta.get("samples", 0)
        alpha = n / (n + 20)
        return round(alpha * p + (1 - alpha) * self.prior(f), 3)

    def fit(self, samples: list[tuple[Finding, int]], epochs: int = 200, lr: float = 0.1, l2: float = 1e-3) -> dict:
        if len(samples) < 4 or len({y for _, y in samples}) < 2:
            raise ValueError("need at least 4 labelled findings including both tp and fp")
        data = [(featurize(f), y) for f, y in samples]
        w = [0.0] * HASH_DIM
        rng = random.Random(42)
        pos = sum(y for _, y in data)
        cw = {1: len(data) / (2 * pos), 0: len(data) / (2 * (len(data) - pos))}  # class balancing
        for epoch in range(epochs):
            rng.shuffle(data)
            step = lr / (1 + epoch * 0.05)
            for x, y in data:
                err = (_sigmoid(_dot(w, x)) - y) * cw[y]
                for i, v in x.items():
                    w[i] -= step * (err * v + l2 * w[i])
        self.weights = w
        preds = [(_sigmoid(_dot(w, x)) >= 0.5) == bool(y) for x, y in data]
        self.meta = {"samples": len(data), "positives": pos, "train_accuracy": round(sum(preds) / len(preds), 3)}
        return self.meta

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"weights": self.weights, "meta": self.meta, "dim": HASH_DIM}))

    @classmethod
    def load(cls, path: str | Path) -> TriageModel:
        path = Path(path)
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        if data.get("dim") != HASH_DIM:
            return cls()
        return cls(data["weights"], data.get("meta"))


def cross_validate(samples: list[tuple[Finding, int]], folds: int = 5) -> float:
    """k-fold accuracy estimate for `webguard ml train`."""
    rng = random.Random(1)
    samples = samples[:]
    rng.shuffle(samples)
    folds = max(2, min(folds, len(samples)))
    correct = total = 0
    for k in range(folds):
        test = samples[k::folds]
        train = [s for i, s in enumerate(samples) if i % folds != k]
        if len({y for _, y in train}) < 2 or len(train) < 4:
            continue
        m = TriageModel()
        m.fit(train)
        m.meta["samples"] = 10**9  # evaluate the raw model, no prior shrinkage
        for f, y in test:
            correct += int((m.predict(f) >= 0.5) == bool(y))
            total += 1
    return correct / total if total else float("nan")
