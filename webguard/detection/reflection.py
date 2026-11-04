"""Reflection analysis: where (and how) does a parameter's value come back?

One request per input with a unique marker followed by ``'"<``:

    contexts   html_text | html_attr | script | comment | json | header | location
    escaped    the special characters came back HTML/JS-escaped (not just the marker)

The agent uses this to pick tests the way a tester would: XSS-type tests go to inputs that reflect into
HTML/script, open-redirect and header-injection tests go first on inputs that reflect into ``Location`` or
other headers, and blind classes (SQLi, command injection, SSRF, ...) are unaffected.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from webguard.detection.context import Context, token
from webguard.models import InjectionPoint

SPECIALS = "'\"<"
BODY_CONTEXTS = {"html_text", "html_attr", "script", "comment"}


@dataclass
class Reflection:
    marker: str
    contexts: set[str] = field(default_factory=set)
    escaped: bool = False
    raw_specials: bool = False
    count: int = 0
    status: int = 0

    @property
    def in_body_markup(self) -> bool:
        return bool(self.contexts & BODY_CONTEXTS)

    @property
    def in_headers(self) -> bool:
        return bool(self.contexts & {"header", "location"})

    def to_dict(self) -> dict:
        return {"contexts": sorted(self.contexts), "escaped": self.escaped, "raw_specials": self.raw_specials,
                "count": self.count}


def body_contexts(text: str, marker: str) -> list[str]:
    """Markup context of every occurrence of ``marker`` in an HTML document."""
    out = []
    for m in re.finditer(re.escape(marker), text):
        before = text[: m.start()]
        low = before.lower()
        if low.rfind("<!--") > low.rfind("-->"):
            out.append("comment")
        elif low.rfind("<script") > low.rfind("</script"):
            out.append("script")
        elif before.rfind("<") > before.rfind(">"):
            out.append("html_attr")
        else:
            out.append("html_text")
    return out


def classify(resp, marker: str) -> Reflection:
    ref = Reflection(marker, status=resp.status)
    text = resp.text or ""
    ref.count = text.count(marker)
    if ref.count:
        if "json" in resp.content_type or text.lstrip()[:1] in "{[" and _is_json(text):
            ref.contexts.add("json")
        else:
            ref.contexts.update(body_contexts(text, marker))
        ref.raw_specials = (marker + SPECIALS) in text
        ref.escaped = not ref.raw_specials and any(
            marker + esc in text for esc in ("&#39;", "&#x27;", "&apos;", "\\'", "%27", "&quot;", "\\u0027"))
    for k, v in resp.headers.items():
        if marker in v:
            ref.contexts.add("location" if k.lower() == "location" else "header")
    return ref


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


async def analyse(ctx: Context, point: InjectionPoint) -> Reflection | None:
    marker = token(8)
    r = await ctx.send(point, marker + SPECIALS)
    if r is None or not ctx.app_answered(r, point, "reflection"):
        return None
    return classify(r, marker)


def plan(order: list[str], ref: Reflection | None, method: str, budgeted: bool) -> list[str]:
    """Reorder (and in tight budgets prune) checks for an input from its reflection profile."""
    if ref is None:
        return order
    front: list[str] = []
    if ref.in_headers:
        front += [c for c in ("redirect", "crlf") if c in order]
    if ref.in_body_markup:
        front += [c for c in ("xss", "ssti") if c in order]
    rest = [c for c in order if c not in front]
    if not ref.in_body_markup and not ref.contexts & {"json"}:
        # no reflection at all: XSS can still be stored/second-order (POST) but is unlikely here
        demote = [c for c in ("xss",) if c in rest]
        rest = [c for c in rest if c not in demote]
        if not (budgeted and method.upper() == "GET"):
            rest += demote
    return front + rest
