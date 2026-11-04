"""Dynamic parameter extraction: target-specific parameter names for hidden-parameter discovery.

Applications reuse names: a key returned in one JSON response, a form field on another page or a
``searchParams.get('debug')`` in a bundle is often accepted by other endpoints too. These names are
added in front of the generic wordlist when brute-forcing hidden parameters.
"""

from __future__ import annotations

import json
import re
from collections import Counter

JS_PARAM = re.compile(r"""(?:searchParams|URLSearchParams\([^)]*\)|params|query)\s*\.\s*(?:get|has|getAll)\(\s*["']([\w.-]{1,40})["']""")
JS_QUERY = re.compile(r"""[?&]([A-Za-z_][\w-]{0,39})=""")
FORM_NAME = re.compile(r"""<(?:input|select|textarea)[^>]+name=["']?([\w\[\].-]{1,40})""", re.I)
NAME_OK = re.compile(r"^[A-Za-z_][\w.-]{0,39}$")


def _json_keys(obj, out: Counter, depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and NAME_OK.match(k):
                out[k] += 1
            _json_keys(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:50]:
            _json_keys(v, out, depth + 1)


def site_param_names(pages: dict, limit: int = 300) -> list[str]:
    """Most frequent candidate parameter names seen across the crawled responses."""
    names: Counter[str] = Counter()
    for r in pages.values():
        text = (r.text or "")[:500000]
        ctype = r.content_type
        if "json" in ctype:
            try:
                _json_keys(json.loads(text), names)
            except ValueError:
                pass
        if "html" in ctype or "javascript" in ctype or not ctype:
            names.update(m.group(1).split("[")[0] for m in FORM_NAME.finditer(text))
            names.update(JS_PARAM.findall(text))
            names.update(JS_QUERY.findall(text))
    return [n for n, _ in names.most_common(limit) if NAME_OK.match(n)]
