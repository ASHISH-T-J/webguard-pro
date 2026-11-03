"""Multinomial naive Bayes text classifier (pure Python, Laplace smoothing, log-space)."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable


class NaiveBayes:
    def __init__(self, featurizer: Callable[[str], list[str]], alpha: float = 0.5) -> None:
        self.featurizer = featurizer
        self.alpha = alpha
        self.class_counts: Counter[str] = Counter()
        self.feature_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self.totals: Counter[str] = Counter()
        self.vocab: set[str] = set()

    def fit(self, samples: Iterable[tuple[str, str]]) -> NaiveBayes:
        for text, label in samples:
            feats = self.featurizer(text)
            self.class_counts[label] += 1
            self.feature_counts[label].update(feats)
            self.totals[label] += len(feats)
            self.vocab.update(feats)
        return self

    def scores(self, text: str) -> dict[str, float]:
        """Posterior probabilities per class."""
        feats = [f for f in self.featurizer(text) if f in self.vocab]
        n_docs = sum(self.class_counts.values())
        v = len(self.vocab) or 1
        logp = {}
        for label, count in self.class_counts.items():
            lp = math.log(count / n_docs)
            denom = self.totals[label] + self.alpha * v
            fc = self.feature_counts[label]
            for f in feats:
                lp += math.log((fc[f] + self.alpha) / denom)
            logp[label] = lp
        if not logp:
            return {}
        m = max(logp.values())
        exp = {k: math.exp(v - m) for k, v in logp.items()}
        z = sum(exp.values())
        return {k: v / z for k, v in sorted(exp.items(), key=lambda kv: -kv[1])}

    def predict(self, text: str) -> tuple[str, float]:
        s = self.scores(text)
        if not s:
            return "unknown", 0.0
        label = next(iter(s))
        return label, s[label]
