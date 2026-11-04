"""Fingerprint templates: nuclei-style, identification only.

YAML files in ``data/fingerprints/`` (and ``--fingerprints DIR``) describe how to recognise a product and
read its version. HTTP templates GET public pages; service templates match the greeting a TCP service
sends by itself. No template sends attack payloads: results feed the CVE / end-of-life matcher.

    - id: grafana
      product: grafana
      requires: []                      # workflow gating: only run when one of these was detected first
      http:
        - path: ["/login", "/api/health"]
          matchers-condition: or        # and | or
          matchers:
            - {type: word, part: body, words: ["grafana-app", "\"database\":"]}
            - {type: header, name: x-grafana-version}
          extractors:
            - {type: regex, part: body, regex: ['"version"\\s*:\\s*"([\\d.]+)'], group: 1}
      service:                          # TCP greeting templates use part: banner
        ports: [22]
        matchers: [{type: regex, part: banner, regex: ['^SSH-[\\d.]+-OpenSSH_([\\w.]+)']}]
        extractors: [{type: regex, part: banner, regex: ['OpenSSH_([\\w.]+)'], group: 1}]
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from webguard.config import DATA_DIR

FP_DIR = DATA_DIR / "fingerprints"


@dataclass
class Template:
    id: str
    product: str
    requires: list[str] = field(default_factory=list)
    http: list[dict] = field(default_factory=list)
    service: dict | None = None
    source: str = ""


@lru_cache(maxsize=8)
def load(extra: tuple[str, ...] = ()) -> list[Template]:
    out: list[Template] = []
    for d in (FP_DIR, *map(Path, extra)):
        for path in sorted(Path(d).glob("*.yml")):
            for item in yaml.safe_load(path.read_text()) or []:
                out.append(Template(item["id"], item.get("product", item["id"]), item.get("requires") or [],
                                    item.get("http") or [], item.get("service"), path.name))
    return out


def _part(part: str, body: str, headers: dict[str, str], status: int) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    if part in ("all", "response"):
        return "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n\n" + body
    return body  # body / banner


def _matcher(m: dict, body: str, headers: dict[str, str], status: int) -> bool:
    kind = m.get("type", "word")
    if kind == "status":
        ok = status in m.get("status", [])
    elif kind == "header":
        value = headers.get(m["name"].lower(), "")
        ok = bool(value) and (not m.get("regex") or re.search(m["regex"], value, re.I) is not None)
    else:
        text = _part(m.get("part", "body"), body, headers, status)
        items = m.get("words" if kind == "word" else "regex", [])
        hits = [(w.lower() in text.lower()) if kind == "word" else re.search(w, text, re.M) is not None
                for w in items]
        ok = all(hits) if m.get("condition") == "and" else any(hits)
    return not ok if m.get("negative") else ok


def matches(block: dict, body: str, headers: dict[str, str], status: int = 200) -> bool:
    results = [_matcher(m, body, headers, status) for m in block.get("matchers", [])]
    if not results:
        return False
    return all(results) if block.get("matchers-condition", "or") == "and" else any(results)


def extract(block: dict, body: str, headers: dict[str, str], status: int = 200) -> str | None:
    for e in block.get("extractors", []):
        if e.get("type", "regex") == "header":
            value = headers.get(e["name"].lower(), "")
            m = re.search(e.get("regex", r"(.+)"), value)
            if m:
                return m.group(e.get("group", 1))
            continue
        text = _part(e.get("part", "body"), body, headers, status)
        for rx in e.get("regex", []):
            m = re.search(rx, text, re.M)
            if m:
                return m.group(e.get("group", 1))
    return None


@dataclass
class Detection:
    product: str
    version: str | None
    template: str
    evidence: str  # URL or host:port


async def run_http(client, root: str, known: set[str], templates: list[Template] | None = None,
                   concurrency: int = 6) -> list[Detection]:
    """Run HTTP fingerprints against one origin. Pass 1: ungated; pass 2: templates whose ``requires``
    products were detected (nuclei workflow style). ``known`` holds products already identified."""
    templates = templates if templates is not None else load()
    detections: list[Detection] = []
    cache: dict[str, tuple] = {}
    sem = asyncio.Semaphore(concurrency)

    async def fetch(path: str):
        if path not in cache:
            async with sem:
                r = await client.safe_get(root + path)
            cache[path] = (r.text[:300000], {k.lower(): v for k, v in r.headers.items()}, r.status) if r else None
        return cache[path]

    async def one(t: Template) -> None:
        for block in t.http:
            for path in block.get("path", ["/"]):
                got = await fetch(path)
                if got is None:
                    continue
                body, headers, status = got
                if status >= 500 or not matches(block, body, headers, status):
                    continue
                detections.append(Detection(t.product, extract(block, body, headers, status), t.id, root + path))
                return

    found = set(known)
    for gated in (False, True):
        batch = [t for t in templates if t.http and bool(t.requires) == gated
                 and (not gated or found & set(t.requires))]
        await asyncio.gather(*(one(t) for t in batch))
        found |= {d.product for d in detections}
    return detections


def match_service(banner: str, port: int, templates: list[Template] | None = None) -> Detection | None:
    for t in templates if templates is not None else load():
        svc = t.service
        if not svc or not matches(svc, banner, {}, 0):
            continue
        return Detection(t.product, extract(svc, banner, {}, 0), t.id, f"port {port}")
    return None


def stats() -> dict[str, int]:
    ts = load()
    return {"templates": len(ts), "http": sum(bool(t.http) for t in ts), "service": sum(bool(t.service) for t in ts),
            "gated": sum(bool(t.requires) for t in ts)}
