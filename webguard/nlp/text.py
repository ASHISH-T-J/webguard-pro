"""Text processing primitives: tokenisation, light stemming, n-grams, TF-IDF keywords."""

from __future__ import annotations

import math
import re
from collections import Counter

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]+")
_TAGS = re.compile(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", re.I)
STOPWORDS = frozenset(
    "a an and are as at be been but by can do for from has have if in into is it its may more no not of on or "
    "our so such than that the their then there these they this to was we were what when which while who will "
    "with you your all any each other some only own same too very just also about over after before here how "
    "html http https www com org net js css div span var function return true false null undefined".split()
)


def split_identifier(name: str) -> list[str]:
    """`userEmail` / `user_email` / `user-email[]` -> ['user', 'email']"""
    parts = re.split(r"[^A-Za-z0-9]+", _CAMEL.sub(" ", name))
    return [p.lower() for p in parts if p]


def stem(word: str) -> str:
    """Tiny suffix-stripping stemmer (good enough for short technical vocabularies)."""
    for suffix in ("ations", "ation", "ings", "ing", "ies", "ers", "er", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)] + ("y" if suffix == "ies" else "")
    return word


def html_to_text(html: str) -> str:
    return re.sub(r"\s+", " ", _TAGS.sub(" ", html)).strip()


def tokens(text: str, keep_stop: bool = False) -> list[str]:
    out = []
    for w in _WORD.findall(text):
        for part in split_identifier(w):
            if len(part) < 2 or (not keep_stop and part in STOPWORDS):
                continue
            out.append(stem(part))
    return out


def char_ngrams(text: str, n_min: int = 2, n_max: int = 4) -> list[str]:
    t = f"^{text.lower()}$"
    return [t[i : i + n] for n in range(n_min, n_max + 1) for i in range(len(t) - n + 1)]


def keywords(docs: list[str], top: int = 10) -> list[list[tuple[str, float]]]:
    """TF-IDF keywords per document."""
    toks = [Counter(tokens(d)) for d in docs]
    df = Counter(t for c in toks for t in c)
    n = len(docs)
    out = []
    for c in toks:
        total = sum(c.values()) or 1
        scored = {t: (cnt / total) * math.log((1 + n) / (1 + df[t]) + 1) for t, cnt in c.items()}
        out.append(sorted(scored.items(), key=lambda kv: -kv[1])[:top])
    return out
