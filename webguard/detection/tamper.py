"""Deterministic payload transformations (opt-in via --tamper), sqlmap-style.

Unlike random multi-layer encoding, each tamper keeps the payload semantically valid for the
target parser, so detection still works when a filter/WAF normalises simple patterns.
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


TAMPERS = {
    "space2comment": space2comment,
    "randomcase": randomcase,
    "space2plus": space2plus,
    "versioned": versioned_keywords,
    "charencode": charencode,
}


def apply_tamper(payload: str, names: tuple[str, ...] | list[str]) -> str:
    for name in names:
        payload = TAMPERS[name](payload)
    return payload
