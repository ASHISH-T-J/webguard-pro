"""Grep engine over everything a scan saw.

Professional testers spend a lot of time grepping proxy history: for DOM sinks in JS,
forgotten endpoints, internal hostnames, keys, debug switches, cloud buckets. This module
does that systematically with curated pattern *packs*, de-duplicates matches across
responses, ranks them (rarer + more sensitive = higher) and keeps context for each hit.

    webguard grep 12 --pack dom-sinks
    webguard grep 12 --regex "api/v[0-9]+/admin" --in js
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from webguard.signatures import default_db

PACKS: dict[str, dict[str, str]] = {
    "dom-sinks": {
        "innerHTML/outerHTML assignment": r"\.(?:inner|outer)HTML\s*\+?=(?!=)",
        "document.write": r"document\.write(?:ln)?\s*\(",
        "eval / Function / setTimeout(string)": r"\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?![\s)]*function|\(\)\s*=>)[^)]{0,40}(?:location|hash|search|param|query|input|data)",
        "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
        "jQuery html()/append() sink": r"\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\(\s*[A-Za-z_$]",
        "Angular sanitizer bypass": r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(",
        "React dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
        "Vue v-html": r"v-html\s*=",
        "location assignment": r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*(?![\"'](?:/|https?:)[^\"'+]*[\"'];)[^;]{0,60}",
        "postMessage listener": r"addEventListener\s*\(\s*[\"']message[\"']",
    },
    "dom-sources": {
        "location.hash/search": r"location\.(?:hash|search|href)\b",
        "document.referrer": r"document\.referrer",
        "window.name": r"window\.name\b",
        "URLSearchParams": r"new URLSearchParams\s*\(",
        "localStorage/sessionStorage read": r"(?:local|session)Storage\.getItem\s*\(",
    },
    "endpoints": {
        "API path": r"[\"'`](/(?:api|rest|v\d|graphql|internal|admin|private|debug)[A-Za-z0-9_\-/.{}$]*)[\"'`]",
        "absolute URL": r"https?://[A-Za-z0-9.\-]+(?::\d+)?/[^\s\"'`<>)]{3,120}",
        "websocket": r"wss?://[^\s\"'`<>]{4,120}",
    },
    "infrastructure": {
        "internal hostname": r"\b[a-z0-9\-]+\.(?:internal|intranet|corp|local|lan|svc\.cluster\.local|consul)\b",
        "private IP": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "S3 bucket": r"\b[a-z0-9.\-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3://[a-z0-9.\-]{3,63}",
        "GCS / Azure blob": r"storage\.googleapis\.com/[a-z0-9._\-]+|[a-z0-9]{3,24}\.blob\.core\.windows\.net",
        "Firebase": r"[a-z0-9\-]+\.firebaseio\.com|[a-z0-9\-]+\.firebaseapp\.com",
        "staging/dev host": r"\b(?:dev|stag(?:e|ing)|test|qa|uat|preprod|sandbox)[.\-][a-z0-9.\-]+\.[a-z]{2,}\b",
    },
    "debug": {
        "debug flag": r"(?i)[\"']?(?:debug|isDebug|devMode|enableDebug|showErrors)[\"']?\s*[:=]\s*(?:true|1|[\"']true[\"'])",
        "feature/admin flag": r"(?i)[\"']?(?:isAdmin|is_admin|admin|role)[\"']?\s*[:=]\s*[\"']?(?:true|admin|superuser)",
        "TODO/FIXME": r"(?i)(?://|#|<!--)\s*(?:todo|fixme|hack|xxx)\b[^\n]{0,100}",
        "source map": r"//[#@]\s*sourceMappingURL=\S+",
        "verbose error": r"(?i)(?:stack trace|traceback|exception in thread|at [\w.$]+\([\w.]+:\d+\))",
    },
    "identity": {
        "email address": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "JWT": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
        "hash-like value": r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}",
    },
    "versions": {
        "library version": r"(?i)\b(jquery|angular|react|vue|bootstrap|lodash|moment|express|django|rails|spring|laravel|struts|log4j)[\s/@:-]v?(\d+\.\d+(?:\.\d+)?)",
        "server banner": r"(?i)\b(apache|nginx|iis|tomcat|jetty|php|openssl)/(\d+\.\d+(?:\.\d+)?)",
    },
}
# relative sensitivity of packs for ranking
WEIGHT = {"secrets": 5, "dom-sinks": 4, "infrastructure": 3, "debug": 3, "identity": 2, "endpoints": 1,
          "dom-sources": 1, "versions": 1}


@dataclass
class Hit:
    pack: str
    rule: str
    value: str
    locations: list[str] = field(default_factory=list)
    context: str = ""

    @property
    def score(self) -> float:
        # sensitive packs first; values seen in few places are more interesting than boilerplate
        return WEIGHT.get(self.pack, 1) * 10 / (1 + len(self.locations) ** 0.5)


def _kind(resp: dict) -> str:
    ct = (resp.get("content_type") or "").lower()
    if "javascript" in ct or resp["url"].split("?")[0].endswith(".js"):
        return "js"
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    return "other"


def grep(responses: Iterable[dict], packs: list[str] | None = None, regex: str | None = None,
         kinds: set[str] | None = None, include_headers: bool = True, max_value: int = 160) -> list[Hit]:
    rules: list[tuple[str, str, re.Pattern[str]]] = []
    if regex:
        rules.append(("custom", regex, re.compile(regex)))
    for pack in packs or ([] if regex else list(PACKS) + ["secrets"]):
        if pack == "secrets":
            rules += [("secrets", name, rx) for name, rx, _meta in default_db().secrets]
        else:
            rules += [(pack, name, re.compile(rx)) for name, rx in PACKS[pack].items()]
    hits: dict[tuple[str, str, str], Hit] = {}
    for resp in responses:
        if kinds and _kind(resp) not in kinds:
            continue
        text = resp.get("body") or ""
        if include_headers:
            text = "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items()) + "\n" + text
        for pack, name, rx in rules:
            for m in rx.finditer(text[:3_000_000]):
                value = (m.group(1) if rx.groups and m.group(1) else m.group(0)).strip()[:max_value]
                key = (pack, name, value)
                hit = hits.get(key)
                if hit is None:
                    s, e = max(0, m.start() - 60), min(len(text), m.end() + 60)
                    hit = hits[key] = Hit(pack, name, value, context=text[s:e].replace("\n", " "))
                if resp["url"] not in hit.locations:
                    hit.locations.append(resp["url"])
    return sorted(hits.values(), key=lambda h: (-h.score, h.pack, h.rule, h.value))


def summarize(hits: list[Hit]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = defaultdict(dict)
    for h in hits:
        out[h.pack][h.rule] = out[h.pack].get(h.rule, 0) + 1
    return dict(out)
