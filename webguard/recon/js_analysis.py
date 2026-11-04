"""Advanced JavaScript analysis.

What experienced hunters do with a target's JavaScript, automated:

1. **Source maps** - find ``sourceMappingURL`` / ``*.js.map``; an exposed map gives back the original,
   commented source tree (internal routes, feature flags, sometimes credentials). Original sources are
   then mined like any other JS.
2. **Lazy chunks** - bundlers split code into chunks loaded on demand; chunk files referenced from the
   runtime are fetched so admin-only/feature-flagged code is analysed too.
3. **Static DOM-XSS flow analysis** - a light taint analysis: a variable assigned from an attacker
   controlled *source* (location.*, document.referrer, window.name, postMessage data, URL params)
   that later reaches a dangerous *sink* (innerHTML, document.write, eval, location assignment, ...).
4. **Client-read URL parameters** - ``URLSearchParams.get('x')``, ``$route.query.x`` ... tell us which
   query parameters the front end consumes; they become DOM-XSS browser test candidates.
5. **postMessage handlers without origin validation**.
6. **Vulnerable libraries** - retire.js-style version detection against ``js_libs.json``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from webguard.crawler import JS_NOISE, PATHLIKE, TEMPLATE_EXPR, js_strings, normalize_url
from webguard.detection.context import Context
from webguard.http import Resp
from webguard.models import PASSIVE, Confidence, Finding, Severity
from webguard.signatures import SIG_DIR

SOURCES = (r"location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer|baseURI)|window\.name|"
           r"(?:searchParams|urlParams|params|query)\.get\s*\(|\$route\.query|router\.query|"
           r"(?:event|e|evt|msg|message)\.data\b")
SINKS = (r"\.(?:inner|outer)HTML\s*\+?=|document\.write(?:ln)?\s*\(|insertAdjacentHTML\s*\(|\beval\s*\(|"
         r"new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*[A-Za-z_$]|(?:window\.|document\.)?location(?:\.href)?\s*=|"
         r"\.src\s*=|jQuery\s*\(|\$\s*\(\s*[A-Za-z_$]|\.html\s*\(|bypassSecurityTrust\w+\s*\(|dangerouslySetInnerHTML")
ASSIGN_FROM_SOURCE = re.compile(rf"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;\n]{{0,120}}?(?:{SOURCES})")
DIRECT_FLOW = re.compile(rf"(?:{SINKS})[^;\n]{{0,120}}?(?:{SOURCES})")
PARAM_READS = [
    re.compile(r"""(?:searchParams|URLSearchParams\([^)]*\)|urlParams|params|query)\.get\(\s*["'`]([\w\-\[\]]{1,40})["'`]"""),
    re.compile(r"""\$route\.query\.([A-Za-z_]\w{0,40})"""),
    re.compile(r"""(?:router|route)\.query(?:\.|\[["'])([A-Za-z_]\w{0,40})"""),
    re.compile(r"""getParameter(?:ByName)?\(\s*["']([\w\-]{1,40})["']"""),
    re.compile(r"""[?&]([A-Za-z_][\w\-]{0,30})=["'`]\s*\+"""),
]
MESSAGE_LISTENER = re.compile(r"""addEventListener\(\s*["']message["']\s*,\s*(?:function\s*\(?\s*(\w+)?|\(?\s*(\w+)\s*\)?\s*=>)""")
SOURCEMAP = re.compile(r"[#@]\s*sourceMappingURL=\s*(\S+)")
CHUNK_FILE = re.compile(r"^[\w./\-~@]{1,160}\.(?:js|mjs)(?:\?[\w=.\-]*)?$")


@dataclass
class JsReport:
    endpoints: set[str] = field(default_factory=set)
    client_params: dict[str, set[str]] = field(default_factory=dict)  # param -> pages reading it ("" = unknown)
    source_maps: dict[str, int] = field(default_factory=dict)  # map url -> number of sources
    flows: list[dict] = field(default_factory=list)
    libraries: dict[str, str] = field(default_factory=dict)
    extra_js: set[str] = field(default_factory=set)


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _load_libs() -> dict:
    data = json.loads((SIG_DIR / "js_libs.json").read_text())
    return {k: v for k, v in data.items() if not k.startswith("_")}


def detect_libraries(url: str, text: str) -> dict[str, str]:
    found = {}
    head = text[:3000]
    for lib, spec in _load_libs().items():
        for pattern in spec["version"]:
            m = re.search(pattern, url, re.I) or re.search(pattern, head, re.I)
            if m:
                found[lib] = m.group(1)
                break
    return found


def vulnerable(lib: str, version: str) -> list[dict]:
    spec = _load_libs().get(lib)
    if not spec:
        return []
    v = _version_tuple(version)
    out = []
    for vuln in spec["vulns"]:
        if v < _version_tuple(vuln["below"]) and ("from" not in vuln or v >= _version_tuple(vuln["from"])):
            out.append(vuln)
    return out


def static_flows(code: str, source_url: str, limit: int = 20) -> list[dict]:
    """Taint-lite: source -> variable -> sink (same script), plus direct source-in-sink expressions."""
    flows: list[dict] = []
    for m in DIRECT_FLOW.finditer(code[:3_000_000]):
        flows.append({"kind": "direct", "snippet": m.group(0)[:200], "url": source_url})
        if len(flows) >= limit:
            return flows
    sink_rx = re.compile(SINKS)
    for m in ASSIGN_FROM_SOURCE.finditer(code[:3_000_000]):
        var = m.group(1)
        if len(var) < 2 and not var.startswith("$"):
            continue  # single-letter minified names produce too much noise
        window = code[m.end(): m.end() + 1500]
        use = re.search(rf"(?:{SINKS})[^;\n]{{0,80}}?\b{re.escape(var)}\b", window)
        if use and sink_rx.search(use.group(0)):
            flows.append({"kind": "variable", "variable": var, "source": m.group(0)[:150],
                          "sink": use.group(0)[:150], "url": source_url})
            if len(flows) >= limit:
                break
    return flows


def unchecked_message_handlers(code: str) -> list[str]:
    out = []
    for m in MESSAGE_LISTENER.finditer(code[:3_000_000]):
        body = code[m.end(): m.end() + 800]
        if not re.search(r"\.origin\b|origin\s*[!=]==?|allowedOrigins|checkOrigin|isTrusted", body):
            out.append(code[m.start(): m.start() + 160])
    return out[:10]


async def analyze(ctx: Context, js: dict[str, Resp], inline: dict[str, str], max_extra: int = 60) -> JsReport:
    """Analyse fetched JS files (+ inline scripts); fetches source maps and lazy chunks within scope."""
    report = JsReport()
    files = dict(js)
    # 1) lazy chunks referenced from loaded code
    for url, r in list(files.items()):
        for s in js_strings(r.text[:3_000_000]):
            if CHUNK_FILE.match(s) and not s.startswith(("http", "//")):
                cand = normalize_url(urljoin(url, s))
                if ctx.client.scope.in_scope(cand) and cand not in files and len(report.extra_js) < max_extra:
                    report.extra_js.add(cand)
    for url in sorted(report.extra_js):
        r = await ctx.client.safe_get(url)
        if r is not None and r.status == 200 and ("javascript" in r.content_type or url.endswith((".js", ".mjs"))) \
                and not r.is_html:
            files[url] = r
    # 2) source maps
    for url, r in list(files.items()):
        m = SOURCEMAP.search(r.text[-500:]) or SOURCEMAP.search(r.headers.get("sourcemap", "") or r.headers.get("x-sourcemap", ""))
        map_url = normalize_url(urljoin(url, m.group(1))) if m and not m.group(1).startswith("data:") else url.split("?")[0] + ".map"
        if not ctx.client.scope.in_scope(map_url):
            continue
        mr = await ctx.client.safe_get(map_url)
        if mr is None or mr.status != 200 or not mr.text.lstrip().startswith("{"):
            continue
        try:
            sm = json.loads(mr.text)
        except ValueError:
            continue
        sources = sm.get("sources") or []
        contents = [c for c in (sm.get("sourcesContent") or []) if isinstance(c, str)]
        if not sources:
            continue
        report.source_maps[map_url] = len(sources)
        for i, code in enumerate(contents[:400]):
            name = sources[i] if i < len(sources) else f"source-{i}"
            inline[f"{map_url}#{name}"] = code
    # 3) mine everything
    corpus = {u: r.text for u, r in files.items()} | inline
    for url, code in corpus.items():
        base_url = url.split("#")[0]
        if url not in js:  # new code (chunks, original sources): extract endpoints like the crawler does
            for raw in js_strings(code[:3_000_000]):
                cand = TEMPLATE_EXPR.sub("1", TEMPLATE_EXPR.sub("", raw, count=1) if raw.startswith("${") else raw)
                if "/" in cand and PATHLIKE.match(cand) and not JS_NOISE.search(cand):
                    full = normalize_url(urljoin(base_url, cand))
                    if ctx.client.scope.in_scope(full):
                        report.endpoints.add(full)
        for lib, version in detect_libraries(base_url, code).items():
            report.libraries[f"{lib}@{version}"] = base_url
        report.flows += static_flows(code, url)
        page = base_url if "#inline-" in url else ""
        for rx in PARAM_READS:
            for name in rx.findall(code[:3_000_000]):
                report.client_params.setdefault(name, set()).add(page)
        for handler in unchecked_message_handlers(code):
            report.flows.append({"kind": "postmessage", "snippet": handler, "url": url})
    report.flows = report.flows[:40]
    return report


def report_findings(ctx: Context, rep: JsReport) -> None:
    for map_url, n in rep.source_maps.items():
        ctx.report(Finding(
            check="exposure", title="JavaScript source map exposed", severity=Severity.LOW, confidence=Confidence.CERTAIN,
            url=map_url, evidence=f"Source map with {n} original source file(s) is publicly readable.",
            description="Source maps reveal the original, un-minified source tree: internal routes, comments, feature "
                        "flags and occasionally hard-coded credentials. The original sources were also analysed for "
                        "endpoints and secrets (findings attributed to '.map#<file>').",
            remediation="Do not deploy .map files to production (or restrict them to internal networks).",
            cwe="CWE-540", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE, tags=["js", "source-map"],
            request=ctx.client.curl("GET", map_url),
        ))
    for lib_ver, where in rep.libraries.items():
        lib, version = lib_ver.split("@", 1)
        vulns = vulnerable(lib, version)
        if not vulns:
            continue
        worst = max(Severity.parse(v["severity"]) for v in vulns)
        ctx.report(Finding(
            check="vulnerable_component", title=f"Vulnerable JavaScript library: {lib} {version}",
            severity=min(worst, Severity.MEDIUM), confidence=Confidence.FIRM, url=where.split("?")[0] + f"#{lib}",
            evidence="; ".join(f"{v['id']}: {v['summary']} (fixed in {v['below']})" for v in vulns),
            description="The page loads a library version with published vulnerabilities. Exploitability depends on "
                        "how the application uses the affected API - confirm the vulnerable pattern before reporting.",
            remediation=f"Upgrade {lib} to a supported version (>= {max(vulns, key=lambda v: _version_tuple(v['below']))['below']}).",
            cwe="CWE-1395", owasp="A06:2021-Vulnerable and Outdated Components", detection=PASSIVE,
            references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"], tags=["js", "component"],
        ))
    seen = set()
    for flow in rep.flows:
        key = (flow["kind"], flow.get("snippet") or flow.get("sink"))
        if key in seen:
            continue
        seen.add(key)
        if flow["kind"] == "postmessage":
            title, desc = ("postMessage handler without origin check",
                           "A 'message' event listener processes data without verifying event.origin, so any "
                           "website that can frame or open this page can send it messages.")
            evidence = flow["snippet"]
        else:
            title, desc = ("Potential DOM XSS flow (static analysis)",
                           "Attacker-controllable data (URL, referrer, window.name, message data) flows into a "
                           "dangerous DOM sink. Static analysis cannot see sanitisation in between - verify in a browser.")
            evidence = flow.get("snippet") or f"{flow['source']}  ->  {flow['sink']}"
        ctx.report(Finding(
            check="dom_flow", title=title, severity=Severity.LOW, confidence=Confidence.TENTATIVE,
            url=flow["url"].split("#")[0] + "#flow-" + hashlib.sha1(evidence.encode()).hexdigest()[:10],
            evidence=evidence[:300],
            description=desc, remediation="Validate origins / sanitise data before it reaches HTML or code sinks.",
            cwe="CWE-79" if flow["kind"] != "postmessage" else "CWE-346", detection=PASSIVE,
            tags=["js", "dom", "hunting"],
        ))
