"""Asset discovery from application content: host names referenced in HTML, JavaScript and API responses.

Front-ends reference their whole estate: API back-ends (``api.example.com``), admin portals, staging
environments, storage buckets and CDNs. Names under the target's registrable domain are new attack
surface; other domains are listed as third-party dependencies (never tested).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

# common two-label public suffixes (enough to find the registrable domain without a PSL download)
SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "edu.au",
                "gov.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.hk", "com.sg",
                "com.my", "co.in", "net.in", "org.in", "gov.in", "co.za", "com.mx", "com.ar", "com.tr", "co.kr",
                "or.kr", "com.tw", "co.id", "com.ph", "com.vn", "co.il", "com.sa", "com.eg", "com.pk", "com.ng"}
URL_HOST = re.compile(r"(?i)(?:https?:)?//([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)")


def registrable(host: str) -> str:
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def hosts_in(texts: Iterable[str], root: str, limit: int = 2_000_000) -> tuple[set[str], set[str]]:
    """(names under ``root``, other host names in absolute URLs) referenced in ``texts``."""
    root = root.lower()
    own_rx = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+" + re.escape(root) + r")(?![\w-])")
    own: set[str] = set()
    other: set[str] = set()
    budget = limit
    for text in texts:
        if budget <= 0:
            break
        chunk = (text or "")[:budget]
        budget -= len(chunk)
        own |= {m.lower().rstrip(".") for m in own_rx.findall(chunk)}
        for h in URL_HOST.findall(chunk):
            h = h.lower()
            if not (h == root or h.endswith("." + root)) and "." in h and not h.endswith((".js", ".css", ".png")):
                other.add(h)
    return own, other
