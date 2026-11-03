"""Deterministic, sqlmap-style payload transformations.

Used two ways:

* explicitly with ``--tamper`` (applied to every SQL payload), and
* automatically by the SQLi check when the basic tests fail **and the application itself** shows an
  input-filter reaction (e.g. "invalid characters" from the app). A blacklist that a tamper defeats is
  a real vulnerability (insufficient input validation) and is reported as such.

Automatic tampering never runs against responses produced by a WAF, CDN challenge or rate limiter -
those inputs are reported as NOT TESTED instead (see README, "WAF policy").
Each tamper keeps the payload semantically valid SQL.
"""

from __future__ import annotations

import re

_KEYWORDS = re.compile(r"\b(AND|OR|SELECT|UNION|FROM|WHERE|SLEEP|WAITFOR|DELAY)\b", re.I)


def space2comment(p: str) -> str:
    return p.replace(" ", "/**/")


def randomcase(p: str) -> str:
    return _KEYWORDS.sub(lambda m: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group(0))), p)


def space2plus(p: str) -> str:
    return p.replace(" ", "+")


def versioned_keywords(p: str) -> str:
    """MySQL versioned comments: SELECT -> /*!SELECT*/"""
    return _KEYWORDS.sub(lambda m: f"/*!{m.group(0)}*/", p)


def charencode(p: str) -> str:
    """Percent-encode every character (server decodes once more than usual)."""
    return "".join(f"%{ord(c):02X}" for c in p)


def between(p: str) -> str:
    """'A > B' -> 'A NOT BETWEEN 0 AND B' (filters that block '>')."""
    return re.sub(r"\s*>\s*", " NOT BETWEEN 0 AND ", p)


def equaltolike(p: str) -> str:
    """'A = B' -> 'A LIKE B' (filters that block '=')."""
    return re.sub(r"\s*=\s*", " LIKE ", p)


def symboliclogical(p: str) -> str:
    """AND/OR -> &&/|| (MySQL; filters that block keywords)."""
    return re.sub(r"(?i)\bAND\b", "&&", re.sub(r"(?i)\bOR\b", "||", p))


def space2tab(p: str) -> str:
    return p.replace(" ", "\t")


def space2newline(p: str) -> str:
    return p.replace(" ", "\n")


TAMPERS = {
    "space2comment": space2comment,
    "randomcase": randomcase,
    "space2plus": space2plus,
    "versioned": versioned_keywords,
    "charencode": charencode,
    "between": between,
    "equaltolike": equaltolike,
    "symboliclogical": symboliclogical,
    "space2tab": space2tab,
    "space2newline": space2newline,
}

# chains tried automatically (cheapest / most common filter bypasses first)
AUTO_CHAINS: list[tuple[str, ...]] = [
    ("space2comment",),
    ("randomcase",),
    ("space2comment", "randomcase"),
    ("space2tab",),
    ("equaltolike", "space2comment"),
    ("symboliclogical", "space2comment"),
    ("versioned", "space2comment"),
    ("space2newline", "randomcase"),
]


def apply_tamper(payload: str, names: tuple[str, ...] | list[str]) -> str:
    for name in names:
        payload = TAMPERS[name](payload)
    return payload
