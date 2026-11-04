"""Autonomous, methodology-driven assessment agent.

The agent works the way a professional tester (or Claude acting as one) conducts an assessment:

    observe  -> build a model of the application (tech, pages, entry points, parameter meaning)
    hypothesise -> for each input/feature, what is the most likely weakness?
    plan     -> rank candidate tests by likelihood x impact / cost  (reasoner: local, Claude or Ollama)
    act      -> run the chosen tests (pre-built, scope-enforced, non-destructive)
    observe  -> record evidence, update facts, adapt (rate limits, WAF, new leads)
    verify   -> independently re-test every active finding before it is reported
    analyse  -> cluster by root cause, find attack chains, score risk, write the narrative

Every decision is logged as a reasoning-trace step (thought / actions / observation), which
is included in the report so the client can audit *why* each test was run.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import httpx

from webguard.ai.reasoner import Candidate, LocalReasoner
from webguard.analysis import correlate
from webguard.analysis.grep import grep
from webguard.assessment.methodology import CHECK_WSTG, PHASES, WSTG
from webguard.config import ScanConfig
from webguard.crawler import Crawler, CrawlResult, normalize_url
from webguard.detection.baseline import title as page_title
from webguard.detection.checks import POINT_CHECKS, advanced, analyzers, dom, hunting, passive
from webguard.detection.checks import host as host_checks
from webguard.detection.context import ACTIVE_ENCODING, ACTIVE_VARIANT, Context
from webguard.detection.encoding import DECODE, detect_encoding, variants_for
from webguard.http import HttpClient, Resp
from webguard.ml.triage import TriageModel
from webguard.models import Confidence, Finding, Host, InjectionPoint
from webguard.nlp.models import PageInfo, classify_page, classify_param, hypotheses_for_param
from webguard.recon import js_analysis, openapi
from webguard.recon.active import probe
from webguard.scope import Scope
from webguard.signatures import SignatureDB, default_db

log = logging.getLogger("webguard.agent")

SKIP_PARAMS = re.compile(
    r"(?i)^(?:csrf.*|_?token|authenticity_token|__requestverificationtoken|__viewstate.*|__eventvalidation|"
    r"__eventtarget|__eventargument|_wpnonce|nonce|captcha.*|g-recaptcha-response|submit|utm_\w+|fbclid|gclid)$"
)
PRIVILEGED = re.compile(r"(?i)/(?:admin|administrator|manage|management|internal|console|dashboard)(?:/|$)")
SKIP_STATIC = re.compile(r"(?i)\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|map|txt|xml)(?:$|\?)")
JWT_LIKE = re.compile(r"^eyJ[\w-]+\.")
API_HINT = re.compile(r"(?i)/(?:api|v\d+|graphql|rest|ajax|json)(?:/|$)|\.json(?:$|\?)")
# technology -> bug classes worth prioritising (tester intuition)
TECH_PRIORS = {
    "php": {"lfi": 1.3, "sqli": 1.2, "cmdi": 1.1, "deserialization": 1.2},
    "express": {"nosqli": 1.4, "ssti": 1.2, "xss": 1.1},
    "node": {"nosqli": 1.3, "ssti": 1.1},
    "next.js": {"ssrf": 1.2},
    "flask": {"ssti": 1.5}, "werkzeug": {"ssti": 1.5}, "django": {"ssti": 1.2},
    "java": {"ssti": 1.2, "xxe": 1.4, "deserialization": 1.4}, "spring": {"ssti": 1.3, "xxe": 1.3},
    "asp.net": {"xxe": 1.2, "deserialization": 1.3, "sqli": 1.2},
    "wordpress": {"sqli": 1.3, "xss": 1.2}, "angular": {"dom_xss": 1.3}, "react": {"dom_xss": 1.1},
}
# share of a request budget per phase (unused share carries over to later phases)
PHASE_SHARE = {"config": 0.2, "identity": 0.1, "input": 0.5, "authz_client": 0.1, "verify": 0.1}
CHECK_IMPACT = {"sqli": 9, "cmdi": 10, "ssti": 9.5, "lfi": 8, "nosqli": 8, "ssrf": 7.5, "xss": 6, "redirect": 4,
                "crlf": 4.5, "anomaly": 2, "auth": 10, "xxe": 8, "exposure": 7, "access": 6, "cors": 4,
                "headers": 2, "host_header": 5, "idor": 6.5, "dom_xss": 6, "graphql": 3, "verify": 10, "passive": 6}


@dataclass
class TraceStep:
    step: int
    phase: str
    engine: str
    thought: str
    actions: list[str]
    observation: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class AssessmentResult:
    target: str
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    points: list[InjectionPoint] = field(default_factory=list)
    oob: list[dict[str, str]] = field(default_factory=list)
    stats: dict[str, float] = field(default_factory=dict)
    started: float = field(default_factory=time.time)
    pages: dict[str, Resp] = field(default_factory=dict)
    page_types: dict[str, PageInfo] = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)
    trace: list[TraceStep] = field(default_factory=list)
    coverage: dict[str, str] = field(default_factory=dict)
    issues: list[correlate.Issue] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    narrative: dict = field(default_factory=dict)
    grep_highlights: list[dict] = field(default_factory=list)
    reasoner: str = "local"
    environment: str = "production"
    obstructed: dict[str, list[str]] = field(default_factory=dict)
    resilience: dict = field(default_factory=dict)

    def meta(self) -> dict:
        """Serializable assessment context for reports."""
        return {
            "hosts": [h.to_dict() for h in self.hosts], "stats": self.stats, "oob": self.oob,
            "methodology": [name for _, name in PHASES], "facts": self.facts,
            "trace": [t.to_dict() for t in self.trace], "wstg_coverage": self.coverage,
            "wstg_names": {k: WSTG[k] for k in self.coverage},
            "attack_chains": self.chains, "narrative": self.narrative, "grep_highlights": self.grep_highlights,
            "issues": [{"title": i.title, "check": i.check, "severity": i.severity.name, "risk": i.risk,
                        "cvss": i.cvss, "cvss_vector": i.cvss_vector, "locations": i.locations[:20]}
                       for i in self.issues],
            "page_types": dict(Counter(p.label for p in self.page_types.values())),
            "reasoner": self.reasoner, "environment": self.environment,
            "obstructed_inputs": self.obstructed, "resilience": self.resilience,
        }


def injection_points(crawl: CrawlResult, extra_urls: list[str] = ()) -> list[InjectionPoint]:
    points: dict[tuple, InjectionPoint] = {}

    def add(p: InjectionPoint) -> None:
        if not SKIP_PARAMS.match(p.name):
            points.setdefault(p.key, p)

    urls = set(crawl.pages) | crawl.urls_with_params | crawl.js_endpoints | set(extra_urls)
    for url in sorted(urls):
        parts = urlsplit(url)
        if not parts.query:
            continue
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        bare = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        for name in params:
            add(InjectionPoint(bare, "GET", "query", name, dict(params), source="crawl"))
    for form in crawl.forms:
        url, parts, params = form.url, urlsplit(form.url), dict(form.inputs)
        if form.method == "GET" and parts.query:
            params = {**dict(parse_qsl(parts.query, keep_blank_values=True)), **params}
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        location = "json" if "json" in (form.enctype or "") else "form"
        for name in form.inputs:
            add(InjectionPoint(url, form.method, location, name, params, source="form"))
    return list(points.values())


class AssessmentAgent:
    def __init__(self, config: ScanConfig, scope: Scope, reasoner: LocalReasoner | None = None,
                 sigdb: SignatureDB | None = None, transport: httpx.AsyncBaseTransport | None = None,
                 on_finding: Callable[[Finding], None] | None = None, on_status: Callable[[str], None] | None = None,
                 on_trace: Callable[[TraceStep], None] | None = None, budget_requests: int | None = None,
                 budget_minutes: float | None = None, per_step: int = 25) -> None:
        self.config = config
        self.scope = scope
        self.reasoner = reasoner or LocalReasoner()
        self.sigdb = sigdb or default_db()
        self.transport = transport
        self.on_finding = on_finding
        self.on_status = on_status or (lambda m: log.info(m))
        self.on_trace = on_trace
        self.budget_requests = budget_requests
        self.budget_minutes = budget_minutes
        self.per_step = per_step
        self.model = TriageModel.load(config.model_path)

    # ------------------------------------------------------------------ public API
    async def run(self, target: str, extra_urls: list[str] = (), hosts: list[Host] | None = None) -> AssessmentResult:
        self.res = AssessmentResult(target=target, reasoner=self.reasoner.name)
        self.res.coverage = {k: "not tested" for k in WSTG}
        self._step = 0
        self._done: set[str] = set()
        self._auth_required: set[str] = set()
        self._recon_used = 0
        self._variant_runs = 0
        self._client_params: dict[str, set[str]] = {}
        self._seen_status: dict[str, int] = {}
        self._t0 = time.time()
        async with HttpClient(self.config, self.scope, self.transport) as client:
            self.client = client
            self.ctx = Context(client, self.config, self.sigdb, self._report)
            try:
                await self._recon(target, list(extra_urls), hosts)
                self._recon_used = client.stats["requests"]
                if self.res.hosts:
                    for phase, name in PHASES[1:]:
                        await self._phase(phase, name)
            finally:
                self.res.oob = self.ctx.oob_log
                self.res.stats.update(client.stats)
                self.res.resilience = client.resilience_report()
                self.res.obstructed = {k: sorted(v)[:50] for k, v in self.ctx.obstructed.items()}
        self._analyse()
        self.res.narrative = await self.reasoner.narrate(target, self.res.findings, self.res.chains, self.res.coverage)
        self.res.stats["duration_s"] = round(time.time() - self.res.started, 1)
        self.res.stats["findings"] = len(self.res.findings)
        return self.res

    # ------------------------------------------------------------------ helpers
    def _report(self, f: Finding) -> None:
        for wid in CHECK_WSTG.get(f.check.split(":")[0], []):
            self.res.coverage[wid] = "vulnerable"
        if self.on_finding:
            self.on_finding(f)

    def _cover(self, check: str) -> None:
        for wid in CHECK_WSTG.get(check, []):
            if self.res.coverage.get(wid) == "not tested":
                self.res.coverage[wid] = "tested"

    def _trace(self, phase: str, thought: str, actions: list[str], observation: str, engine: str = "local") -> None:
        self._step += 1
        step = TraceStep(self._step, phase, engine, thought, actions, observation)
        self.res.trace.append(step)
        if self.on_trace:
            self.on_trace(step)

    def _budget_left(self) -> float:
        """Fraction of the budget remaining (1.0 when unlimited)."""
        left = 1.0
        if self.budget_requests:
            left = min(left, 1 - self.client.stats["requests"] / self.budget_requests)
        if self.budget_minutes:
            left = min(left, 1 - (time.time() - self._t0) / (self.budget_minutes * 60))
        return left

    def _adapt(self) -> str | None:
        """React to defensive behaviour like a human tester would."""
        s = self.client.stats
        if s["rate_limited"] > getattr(self, "_seen_429", 0):
            self._seen_429 = s["rate_limited"]
            return f"HTTP 429 observed; reduced rate to {self.client.slow_down():.1f} req/s"
        if s["waf_blocks"] > getattr(self, "_seen_waf", 0) + 10:
            self._seen_waf = s["waf_blocks"]
            if not self.config.tamper:
                self.config.tamper = ("space2comment",)
            return f"Repeated WAF blocks; reduced rate to {self.client.slow_down(0.7):.1f} req/s and enabled tamper"
        return None

    def _state(self, phase: str) -> dict:
        tech = sorted({t for h in self.res.hosts for t in h.technologies})
        return {
            "target": self.res.target, "phase": phase, "technologies": tech,
            "waf": sorted({w for h in self.res.hosts for w in h.waf}),
            "page_types": dict(Counter(p.label for p in self.res.page_types.values())),
            "entry_points": len(self.res.points),
            "facts": self.res.facts[-25:],
            "findings_so_far": [f"{f.severity.name} {f.title} @ {urlsplit(f.url).path} {f.parameter or ''}"
                                for f in list(self.ctx.findings.values())[-25:]],
            "budget_remaining": round(self._budget_left(), 2),
            "budgeted": bool(self.budget_requests or self.budget_minutes),
            "requests_sent": self.client.stats["requests"],
        }

    # ------------------------------------------------------------------ phase 1: recon & mapping
    async def _recon(self, target: str, extra_urls: list[str], hosts: list[Host] | None) -> None:
        cfg = self.config
        seeds: list[str] = []
        explicit = target if target.startswith(("http://", "https://")) else None
        if hosts is None:
            host = urlsplit(explicit).netloc if explicit else target
            self.on_status(f"[recon] fingerprinting {host}")
            hosts = await probe(self.client, self.sigdb, host)
            if explicit:
                seeds.append(normalize_url(explicit))
        self.res.hosts = hosts
        self._cover("fingerprint")
        if not hosts:
            self._trace("recon", "Start by confirming the target is reachable and fingerprinting it.",
                        ["fingerprint"], "No live HTTP service found - nothing further to test.")
            return
        from webguard.analysis.context import environment

        self.res.environment = environment(urlsplit(hosts[0].url).hostname or "", "")
        self.res.facts.append(f"Environment: {self.res.environment} (from hostname); "
                              f"profile rate {cfg.rate_limit:g} req/s, timing checks {'on' if cfg.timing_checks else 'off'}")
        for h in hosts:
            self.res.facts.append(f"Live: {h.url} [{h.status}] title='{h.title}' tech={', '.join(h.technologies) or '?'}"
                                  + (f" WAF={', '.join(h.waf)}" if h.waf else ""))
        self._trace("recon", "Fingerprint every live service first: technology and WAF determine which bug classes "
                    "are likely and how aggressively we can test.", ["fingerprint"], "; ".join(self.res.facts))

        seeds += [h.url + "/" for h in hosts] + [u for u in extra_urls if self.scope.in_scope(u)][: cfg.max_urls]
        self.on_status(f"[recon] mapping the application (crawl depth {cfg.max_depth}, JS & API mining)")
        crawl = await Crawler(self.client, cfg.max_depth, cfg.max_urls).crawl(seeds)
        self._crawl = crawl
        self.res.pages = crawl.pages
        self.res.urls = sorted(crawl.pages)
        self.res.js_files = sorted(crawl.js_files)
        self._cover("crawl")
        points = injection_points(crawl, [u for u in extra_urls if self.scope.in_scope(u)])

        specs = []
        for h in hosts:
            specs += await openapi.discover_specs(self.client, h.url, [u for u in crawl.pages if "swagger" in u or "api-docs" in u])
        for spec_url, spec in specs:
            sp = [p for p in openapi.points_from_spec(spec, spec_url) if self.scope.in_scope(p.url)]
            points += sp
            self.res.facts.append(f"OpenAPI spec at {spec_url}: {len(spec.get('paths', {}))} paths -> {len(sp)} inputs")
        points += [p for p in openapi.points_from_writes(crawl.api_writes) if self.scope.in_scope(p.url)]
        uniq: dict[tuple, InjectionPoint] = {}
        for p in points:
            if not SKIP_PARAMS.match(p.name):
                uniq.setdefault(p.key, p)
        self.res.points = list(uniq.values())
        self.res.points += self._header_points(crawl, hosts)
        self.res.points += self._encoded_points(self.res.points)
        # status observed for each bare URL during mapping (used to prefer reachable inputs)
        self._seen_status: dict[str, int] = {}
        for u, r in crawl.pages.items():
            self._seen_status.setdefault(u.split("?")[0], r.status)

        # NLP: page types and parameter semantics
        for url, r in crawl.pages.items():
            self.res.page_types[url] = classify_page(r.status, r.content_type, r.text[:20000], page_title(r.text))
        kinds = Counter(p.label for p in self.res.page_types.values())
        logins = [u for u, p in self.res.page_types.items() if p.label == "login"]
        param_kinds = Counter(classify_param(p.name)[0] for p in self.res.points)
        self.res.facts.append(f"Mapped {len(crawl.pages)} URLs, {len(crawl.forms)} forms, {len(crawl.js_files)} JS files, "
                              f"{len(crawl.js_endpoints)} JS endpoints, {len(crawl.api_writes)} API write calls, "
                              f"{len(crawl.spa_routes)} SPA routes, {len(self.res.points)} injectable inputs")
        self.res.facts.append("Page types: " + ", ".join(f"{k}={v}" for k, v in kinds.most_common()))
        self.res.facts.append("Parameter semantics: " + ", ".join(f"{k}={v}" for k, v in param_kinds.most_common()))
        if logins:
            self.res.facts.append(f"Login pages: {', '.join(logins[:5])}")

        # advanced JS analysis: source maps, lazy chunks, DOM flows, client-read params, vulnerable libraries
        self._client_params: dict[str, set[str]] = {}
        if cfg.enabled("js_analysis"):
            await self._js_analysis(crawl)

        # grep the corpus for leads (DOM sinks, infra, debug flags)
        corpus = [{"url": u, "body": r.text, "content_type": r.content_type, "headers": dict(r.headers)}
                  for u, r in crawl.pages.items()]
        hits = grep(corpus, packs=["dom-sinks", "infrastructure", "debug"])
        self.res.grep_highlights = [{"pack": h.pack, "rule": h.rule, "value": h.value, "locations": h.locations[:5]}
                                    for h in hits[:60]]
        self._dom_sinks = [h for h in hits if h.pack == "dom-sinks"]
        for h in hits[:8]:
            self.res.facts.append(f"grep[{h.pack}] {h.rule}: {h.value[:80]} ({len(h.locations)} location(s))")
        self._trace(
            "recon",
            "Map the attack surface before testing: crawl, mine JavaScript bundles and API specs for endpoints the UI "
            "hides, classify every page and parameter by meaning (NLP), and grep responses for leads such as DOM "
            "sinks and internal hosts.",
            ["crawl", "js-mining", "openapi-import", "nlp-classify", "grep"],
            "; ".join(self.res.facts[len(hosts):]),
        )
        note = self._adapt()
        if note:
            self.res.facts.append(note)

    async def _js_analysis(self, crawl: CrawlResult) -> None:
        js = {u: crawl.pages[u] for u in crawl.js_files if u in crawl.pages and crawl.pages[u].status == 200}
        inline: dict[str, str] = {}
        for u, r in crawl.pages.items():
            if r.is_html:
                for i, m in enumerate(re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>", r.text[:500000], re.I)):
                    if len(m.group(1)) > 30:
                        inline[f"{u}#inline-{i}"] = m.group(1)
        rep = await js_analysis.analyze(self.ctx, js, inline)
        js_analysis.report_findings(self.ctx, rep)
        for name, code in inline.items():  # original sources from source maps: secrets too
            if ".map#" in name and self.config.enabled("secrets"):
                passive.secrets(self.ctx, Resp(name, 200, httpx.Headers({"content-type": "application/javascript"}),
                                               code, 0.0, "GET"))
        known = {p.key for p in self.res.points}
        for url in sorted(rep.endpoints):
            crawl.js_endpoints.add(url)
            parts = urlsplit(url)
            if parts.query:
                params = dict(parse_qsl(parts.query, keep_blank_values=True))
                bare = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                for name in params:
                    p = InjectionPoint(bare, "GET", "query", name, dict(params), source="js-analysis")
                    if p.key not in known and not SKIP_PARAMS.match(name):
                        known.add(p.key)
                        self.res.points.append(p)
        self._client_params = {n: pages for n, pages in rep.client_params.items() if not SKIP_PARAMS.match(n)}
        self.res.facts.append(
            f"JS analysis: {len(js) + len(rep.extra_js)} files ({len(rep.extra_js)} lazy chunks), "
            f"{len(rep.source_maps)} source map(s), {len(rep.endpoints)} new endpoint(s), "
            f"{len(rep.flows)} DOM flow/postMessage lead(s), libraries: {', '.join(sorted(rep.libraries)) or 'none'}, "
            f"client-read params: {', '.join(sorted(self._client_params)[:15]) or 'none'}")

    def _header_points(self, crawl: CrawlResult, hosts: list[Host]) -> list[InjectionPoint]:
        """Request headers and cookies as injection points (logged/rendered header values are a classic
        source of SQLi/XSS in writeups). Tested on a focused sample of endpoints, not on every URL."""
        cfg = self.config
        ua_marker = cfg.user_agent.split("(")[0].strip()[-20:]
        scored: list[tuple[int, str]] = []
        for u, r in crawl.pages.items():
            if r.status != 200 or not (r.is_html or "json" in r.content_type) or SKIP_STATIC.search(u):
                continue
            score = 0
            if ua_marker and ua_marker in r.text:
                score += 5  # the page reflects our User-Agent
            if r.headers.get_list("set-cookie"):
                score += 2
            if re.search(r"(?i)track|log|stat|visit|analytic|audit|history|welcome|referr?er", urlsplit(u).path):
                score += 3
            scored.append((score, u))
        roots = [h.url + "/" for h in hosts]
        picked = list(dict.fromkeys(roots + [u.split("?")[0] for s, u in sorted(scored, key=lambda t: (-t[0], t[1]))]))[:8]
        cookies: dict[str, str] = {}
        for r in crawl.pages.values():
            for raw in r.headers.get_list("set-cookie"):
                name, _, rest = raw.partition("=")
                value = rest.split(";", 1)[0]
                if name and not JWT_LIKE.match(value) and len(cookies) < 6:
                    cookies.setdefault(name.strip(), value)
        out = []
        for u in picked:
            root = "{0.scheme}://{0.netloc}/".format(urlsplit(u))
            for name, orig in (("User-Agent", cfg.user_agent), ("Referer", root), ("X-Forwarded-For", "203.0.113.10")):
                out.append(InjectionPoint(u, "GET", "header", name, {name: orig}, source="header"))
            for name, value in cookies.items():
                out.append(InjectionPoint(u, "GET", "cookie", name, {name: value}, source="cookie"))
        return out

    # ------------------------------------------------------------------ candidate generation
    def _tech_mult(self, check: str) -> float:
        tech = " ".join(t.lower() for h in self.res.hosts for t in h.technologies)
        mult = 1.0
        for name, priors in TECH_PRIORS.items():
            if name in tech and check in priors:
                mult = max(mult, priors[check])
        return mult

    def _candidates(self, phase: str) -> list[Candidate]:
        cfg, out = self.config, []
        roots = sorted({h.url for h in self.res.hosts})
        pages = self.res.pages

        def add(action: str, target: str, why: str, prior: float, cost: int, check: str | None = None) -> None:
            cid = f"{action}:{target}"
            if cid in self._done or (check and not cfg.enabled(check)):
                return
            out.append(Candidate(cid, action, target, phase, why, prior, cost))

        if phase == "config":
            for root in roots:
                add("headers", root, "baseline hardening: security headers, CSP, HTTP methods", 3, 3, "headers")
                add("exposure", root, "probe known sensitive files/admin interfaces (soft-404 aware) - historically "
                    "the highest-yield configuration test", 9, 70, "exposure")
                # CORS matters where data is returned: JSON API responses first, one URL per path
                api_paths: dict[str, str] = {}
                for u in sorted(pages, key=lambda u: ("json" not in pages[u].content_type, u)):
                    if u.startswith(root) and (API_HINT.search(u) or "json" in pages[u].content_type):
                        api_paths.setdefault(urlsplit(u).path, u)
                apis = list(api_paths.values())[:4]  # CORS is usually global middleware: sample, don't sweep
                for u in [root + "/", *apis]:
                    add("cors", u, "check origin trust on " + ("API endpoint" if u in apis else "root"), 4 + (1 if u in apis else 0), 6, "cors")
            if cfg.discovery_wordlist and cfg.enabled("exposure"):
                n = sum(1 for line in open(cfg.discovery_wordlist) if line.strip())
                for root in roots:
                    add("content_discovery", root, f"brute-force {n} unlinked paths (soft-404 calibrated) to find "
                        "hidden admin/backup/debug content", 6.5, n)
            for u, r in pages.items():
                if r.status in (401, 403) and len([c for c in out if c.action == "forbidden_bypass"]) < 10:
                    # 403 = "forbidden" (often a proxy rule: bypassable); 401 = "log in first" (usually app-enforced)
                    prior = 5 if r.status == 403 or PRIVILEGED.search(u) else 2
                    add("forbidden_bypass", u, f"access-controlled resource (HTTP {r.status}) - try path/header bypasses",
                        prior, 14, "access")
            for u in list(pages) + sorted(self._crawl.js_endpoints):
                if "graphql" in u.lower():
                    add("graphql", u.split("?")[0], "GraphQL endpoint: introspection & batching", 4, 2, "graphql")
        elif phase == "identity":
            add("passive_analysis", "all-responses", "analyse cookies, JWTs, CSRF tokens, serialized objects, data leaks in every response", 8, 0)
            for p in self.res.points:
                if advanced.LOGIN_PATH.search(urlsplit(p.url).path) or any(k.lower() in advanced.PASS_FIELDS for k in p.params):
                    user_f, pass_f = advanced.login_fields(p.params)
                    if user_f and pass_f:
                        add("auth_bypass", f"{p.method} {p.url} [{p.location}]",
                            "login endpoint: SQL/NoSQL authentication bypass is high impact and cheap to test", 9.5, 10, "auth")
        elif phase == "input":
            remaining = self._budget_left()
            for p in self.res.points:
                hyps = [h for h in hypotheses_for_param(p.name, p.original) if h in POINT_CHECKS and cfg.enabled(h)]
                if not hyps:
                    continue
                kind, conf = classify_param(p.name)
                prior = max(CHECK_IMPACT.get(h, 3) * self._tech_mult(h) for h in hyps[:3]) * (0.7 + 0.3 * conf)
                ptype = self.res.page_types.get(p.url)
                if p.source in ("openapi", "param-discovery"):
                    prior *= 1.15  # documented/confirmed inputs the UI doesn't expose: less tested by others
                elif p.source == "js-write":
                    prior *= 0.6  # body field names are guessed from the endpoint name - lower likelihood
                if p.location in ("header", "cookie"):
                    prior *= 0.6  # less common than parameter injection; tested after the main inputs
                status = self._seen_status.get(p.url)
                if status is not None:  # evidence beats guesses: reachable inputs first, auth-gated last
                    prior *= 1.25 if status < 300 else 0.3 if status in (401, 403) else 1.0
                if ptype and ptype.label in ("login", "admin", "api_json"):
                    prior *= 1.1
                cost = 25 * min(len(hyps), 4) if remaining > 0.3 else 25 * min(len(hyps), 2)
                add("inject", f"{p.method} {p.url} [{p.location}{'+' + p.encoding if p.encoding else ''}] {p.name}",
                    f"'{p.name}' looks like {kind} (p={conf:.2f}) -> try {', '.join(hyps[:3])} first", prior, cost)
            posts = sorted({u for m, u in self._crawl.api_writes if m in ("POST", "PUT")} |
                           {f.url for f in self._crawl.forms if f.method == "POST"})
            for u in posts[:10]:
                add("xxe", u, "endpoint accepts a request body - check whether it parses XML with external entities",
                    5 * self._tech_mult("xxe"), 2, "xxe")
            for root in roots:
                add("host_header", root + "/", "absolute URLs/cache keyed on Host? (cache-busted probe)", 4, 4, "host_header")
            # pages that build absolute links to their own host (reset/confirm flows) are the classic targets
            for u, r in list(pages.items())[:300]:
                host = urlsplit(u).netloc
                if r.is_html and urlsplit(u).path not in ("", "/") and (
                        re.search(rf"https?://{re.escape(host)}/", r.text[:100000]) or
                        re.search(r"(?i)reset|forgot|confirm|verify|invite", urlsplit(u).path)):
                    add("host_header", u.split("?")[0], "page builds absolute URLs from the request host - test "
                        "password-reset/cache poisoning via X-Forwarded-Host", 5.5, 4, "host_header")
            if cfg.param_discovery:
                for u, r in list(pages.items())[:15]:
                    if r.is_html and r.status == 200 and not urlsplit(u).query:
                        add("param_discovery", u, "bisect hidden parameters (Arjun-style)", 3, 40)
        elif phase == "authz_client":
            for u, r in pages.items():
                if "json" in r.content_type and advanced.ID_SEGMENT.search(urlsplit(u).path):
                    add("idor", u, "JSON object addressed by sequential id - neighbour ids may leak other users' data", 6, 2, "idor")
            authenticated = bool(cfg.headers or cfg.cookies)
            if cfg.enabled("cache_deception"):
                personal = [u for u, r in pages.items() if r.status == 200 and r.is_html and not SKIP_STATIC.search(u)
                            and (authenticated or r.headers.get_list("set-cookie")
                                 or re.search(r"(?i)account|profile|settings|dashboard|my|user|order", urlsplit(u).path))]
                for u in sorted(personal, key=lambda u: (urlsplit(u).query != "", len(u)))[:6]:
                    add("cache_deception", u.split("#")[0], "dynamic page - does a static-looking suffix get it "
                        "cached (web cache deception)?", 6 if authenticated else 3, 12, "cache_deception")
            if cfg.enabled("prototype_pollution") and cfg.browser and dom.HAVE_PLAYWRIGHT:
                add("prototype_pollution", "browser", "URL/hash parsers merging __proto__ keys (client-side prototype "
                    "pollution, verified in headless Chromium)", 4.5 * self._tech_mult("dom_xss"), 20)
            if cfg.enabled("dom_xss") and cfg.browser and dom.HAVE_PLAYWRIGHT:
                sink_boost = 1.5 if self._dom_sinks else 1.0
                add("dom_xss", "browser", f"verify DOM XSS in headless Chromium ({len(self._crawl.spa_routes)} SPA routes, "
                    f"{len(self._dom_sinks)} DOM sink patterns found by grep)", 6 * sink_boost * self._tech_mult("dom_xss"), 40)
        elif phase == "verify":
            for f in self.ctx.findings.values():
                if f.check.split(":")[0] in POINT_CHECKS and f.check != "anomaly" and f.parameter:
                    add("verify", f.fingerprint, f"independently re-test '{f.title}' on {urlsplit(f.url).path} [{f.parameter}]", 10, 30)
        return out

    # ------------------------------------------------------------------ phase loop
    async def _phase(self, phase: str, name: str) -> None:
        if self._budget_left() <= 0 and phase != "verify":
            self._trace(phase, f"Skipping {name}: budget exhausted.", [], "coverage partial")
            return
        self.on_status(f"[{phase}] {name}")
        phase_start = self.client.stats["requests"]
        cap = None
        if self.budget_requests:
            # shares apply to what is left after mapping; unused share of earlier phases carries over
            testing_budget = max(0, self.budget_requests - self._recon_used)
            used = self.client.stats["requests"] - self._recon_used
            share_so_far = sum(PHASE_SHARE[p] for p, _ in PHASES[1:][: [x for x, _ in PHASES[1:]].index(phase) + 1])
            cap = max(0, int(testing_budget * share_so_far) - used)
        skipped: list[str] = []
        rounds = 0
        while rounds < 50:
            rounds += 1
            cands = self._candidates(phase)
            if not cands:
                break
            limit = len(cands) if getattr(self.reasoner, "exhaustive", False) else self.per_step
            decision = await self.reasoner.decide(name, self._state(phase), cands, limit)
            by_id = {c.id: c for c in cands}
            chosen = [by_id[i] for i in dict.fromkeys(decision.selected) if i in by_id]  # keep the reasoner's order
            if not chosen:
                break
            before = set(self.ctx.findings)
            req_before = self.client.stats["requests"]
            # with a budget, fewer tests in flight so the highest-ranked ones complete before it runs out
            width = 4 if (self.budget_requests or self.budget_minutes) else max(2, self.config.concurrency // 2)
            sem = asyncio.Semaphore(width)

            async def run(c: Candidate, sem: asyncio.Semaphore = sem) -> None:
                async with sem:
                    if self._budget_left() <= 0 and phase != "verify":
                        return
                    spent = self.client.stats["requests"] - phase_start
                    if cap is not None and phase != "verify" and spent + c.cost > cap and spent > 0:
                        skipped.append(c.id)  # does not fit this phase's share of the budget
                        self._done.add(c.id)
                        return
                    self._done.add(c.id)
                    try:
                        await self._execute(c)
                    except Exception as exc:  # one broken test must not stop the assessment
                        log.debug("action %s failed: %s", c.id, exc, exc_info=True)

            await asyncio.gather(*(run(c) for c in chosen))
            for c in chosen:
                self._done.add(c.id)
            new = [self.ctx.findings[k] for k in set(self.ctx.findings) - before]
            obs = (f"{len(chosen)} test(s), {self.client.stats['requests'] - req_before} requests; "
                   + (f"{len(new)} new finding(s): " + "; ".join(f"{f.severity.name} {f.title} @ {urlsplit(f.url).path}"
                                                                  f"{' [' + f.parameter + ']' if f.parameter else ''}" for f in new[:6])
                      if new else "no new findings"))
            note = self._adapt()
            if note:
                obs += f"; ADAPT: {note}"
                self.res.facts.append(note)
            self._trace(phase, decision.thought, [c.id for c in chosen][:40], obs, decision.engine)
            if self._budget_left() <= 0 and phase != "verify":
                self._trace(phase, "Request/time budget exhausted - stopping active testing.", [], "coverage partial")
                break
        if skipped:
            self._trace(phase, f"Budget allocation: {len(skipped)} lower-priority test(s) did not fit this phase's share "
                        f"of the request budget and were skipped.", skipped[:20], "coverage partial for these items")

    # ------------------------------------------------------------------ action execution
    async def _execute(self, c: Candidate) -> None:
        ctx, cfg = self.ctx, self.config
        a, t = c.action, c.target
        if a == "headers":
            r = self.res.pages.get(t + "/") or await self.client.safe_get(t + "/")
            if r is not None:
                await host_checks.security_headers(ctx, r)
            await host_checks.http_methods(ctx, t)
            self._cover("headers")
        elif a == "exposure":
            await host_checks.exposures(ctx, t)
            self._cover("exposure")
        elif a == "cors":
            await host_checks.cors(ctx, t)
            self._cover("cors")
        elif a == "content_discovery":
            words = [w.strip() for w in open(cfg.discovery_wordlist) if w.strip() and not w.startswith("#")]
            found = await hunting.content_discovery(ctx, t, words)
            new_urls = [u for u, _ in found if u not in self.res.pages]
            if new_urls:  # crawl one level into what we found and merge it into the attack surface
                sub = await Crawler(self.client, 1, 200).crawl(new_urls)
                self.res.pages.update({u: r for u, r in sub.pages.items() if u not in self.res.pages})
                self._crawl.forms += sub.forms
                self._crawl.js_endpoints |= sub.js_endpoints
                self._crawl.api_writes |= sub.api_writes
                known = {p.key for p in self.res.points}
                self.res.points += [p for p in injection_points(sub) if p.key not in known and not SKIP_PARAMS.match(p.name)]
                for u in sub.pages:
                    r = sub.pages[u]
                    self.res.page_types[u] = classify_page(r.status, r.content_type, r.text[:20000], page_title(r.text))
                self.res.urls = sorted(self.res.pages)
                self.res.facts.append(f"Content discovery on {t}: {len(found)} unlinked path(s), "
                                      f"{len(sub.pages)} new URL(s) mapped")
            self._cover("exposure")
        elif a == "forbidden_bypass":
            await advanced.forbidden_bypass(ctx, t, self.res.pages[t])
            self._cover("access")
        elif a == "graphql":
            await advanced.graphql(ctx, t)
            self._cover("graphql")
        elif a == "passive_analysis":
            self._passive_all()
        elif a == "auth_bypass":
            method, url, loc = re.match(r"(\S+) (\S+) \[(\w+)\]", t).groups()
            p = next(p for p in self.res.points if p.url == url and p.method == method and p.location == loc)
            await advanced.auth_bypass(ctx, url, method, p.params, loc)
            self._cover("auth")
        elif a == "inject":
            p = self._point_for(t)
            base = await ctx.baseline(p)
            if base is not None and base.primary.status in (401, 403) and not (cfg.headers or cfg.cookies) \
                    and not advanced.LOGIN_PATH.search(urlsplit(p.url).path):
                # an unauthenticated tester only reaches the access check; fuzzing it wastes budget
                self._auth_required.add(f"{p.method} {urlsplit(p.url).path}")
                return
            hyps = self._ordered_hypotheses(p)
            if p.location in ("header", "cookie"):  # header values: logged (SQLi/cmd) or rendered (XSS/SSTI)
                hyps = [c for c in ("sqli", "xss", "ssti", "cmdi") if cfg.enabled(c)]
            thorough = self._budget_left() > 0.3 and p.location not in ("header", "cookie")
            order = hyps + ([x for x in POINT_CHECKS if x not in hyps and cfg.enabled(x)] if thorough else [])
            ACTIVE_ENCODING.set(p.encoding)  # task-local: labels findings made inside an encoded value
            for check in order:
                if self._budget_left() <= 0:
                    break  # stop between checks, not only between actions
                if check == "anomaly" and any(f.parameter == p.name and f.url == p.url for f in ctx.findings.values()):
                    continue
                try:
                    await POINT_CHECKS[check](ctx, p)
                    if cfg.bypass_variants and not self._found(check, p):
                        await self._bypass_variants(p, check, hyps)
                except Exception as exc:  # isolate checks: one failure must not skip the others
                    log.debug("check %s failed on %s [%s]: %s", check, p.url, p.name, exc, exc_info=True)
                self._cover(check)
        elif a == "xxe":
            await advanced.xxe(ctx, t)
            self._cover("xxe")
        elif a == "host_header":
            await advanced.host_header(ctx, t)
            self._cover("host_header")
        elif a == "param_discovery":
            new_points = await hunting.discover_params(ctx, t)
            self.res.points += new_points
        elif a == "idor":
            await advanced.idor(ctx, t, self.res.pages[t])
            self._cover("idor")
        elif a == "dom_xss":
            root = sorted({h.url for h in self.res.hosts})[0]
            confirmed = {(f.url, f.parameter) for f in ctx.findings.values() if f.check == "xss"}
            targets = dom.candidates(self.res.pages, sorted(self._crawl.spa_routes), root, confirmed,
                                     extra_params=sorted((n, pg) for n, pages in self._client_params.items()
                                                         for pg in pages))
            await dom.dom_xss(ctx, targets)
            self._cover("dom_xss")
        elif a == "cache_deception":
            await advanced.cache_deception(ctx, t, self.res.pages.get(t) or await self.client.safe_get(t),
                                           authenticated=bool(cfg.headers or cfg.cookies))
            self._cover("cache_deception")
        elif a == "prototype_pollution":
            script_pages = [u for u, r in self.res.pages.items() if r.is_html and "<script" in r.text.lower()]
            roots = [h.url + "/" for h in self.res.hosts]
            await dom.prototype_pollution(ctx, list(dict.fromkeys(roots + sorted(script_pages)))[:8])
            self._cover("prototype_pollution")
        elif a == "verify":
            await self._verify(t)

    def _found(self, check: str, p: InjectionPoint) -> bool:
        return any(f.check == check and f.parameter == p.name and f.url == p.url for f in self.ctx.findings.values())

    async def _bypass_variants(self, p: InjectionPoint, check: str, hyps: list[str]) -> None:
        """Re-run a check through bug-class-specific encoding/normalisation variants.

        Only when the application (not a WAF/CDN/rate limiter) answered, and either the app showed input
        filtering for this parameter or the class is one of the parameter's two leading hypotheses.
        """
        ctx = self.ctx
        if p.key in ctx.obstructed_keys or check == "anomaly" or p.location in ("header", "cookie"):
            return
        filtered = ctx.filter_signals.get(p.key, 0) > 0
        kind = classify_param(p.name)[0]
        # without an observed filter, only where parameter semantics make an encoding-sensitive bug likely
        strong = {"lfi": "file", "ssrf": "url", "redirect": "redirect", "cmdi": "command"}.get(check) == kind \
            and check in hyps[:2]
        escaped = check == "xss" and p.key in ctx.escaped_points
        if not (strong or escaped or (filtered and check in hyps[:4])):
            return  # a filter only justifies variants for bug classes plausible for this parameter
        variants = variants_for(check, p.original)
        if escaped and not filtered:
            variants = [v for v in variants if v.name in ("double-url-encoding", "html-entities")]  # decode-after-escape
        elif not filtered:
            variants = variants[:2]
        for variant in variants:
            if self._budget_left() <= 0:
                return
            tok = ACTIVE_VARIANT.set(variant)
            try:
                await POINT_CHECKS[check](ctx, p)
            finally:
                ACTIVE_VARIANT.reset(tok)
            self._variant_runs += 1
            if self._found(check, p):
                self.res.facts.append(f"Input filter on {urlsplit(p.url).path} [{p.name}] bypassed for {check} "
                                      f"with '{variant.name}' ({variant.source})")
                return

    def _encoded_points(self, points: list[InjectionPoint]) -> list[InjectionPoint]:
        """Parameters whose value is base64/hex/URL-encoded: inject inside the decoded value."""
        out = []
        for p in points:
            if p.location not in ("query", "form", "json") or p.encoding:
                continue
            enc = detect_encoding(p.original)
            if not enc:
                continue
            try:
                decoded = DECODE[enc](p.original)
            except Exception:
                continue
            params = dict(p.params)
            params[p.name] = decoded
            out.append(InjectionPoint(p.url, p.method, p.location, p.name, params, source=f"{p.source}+{enc}",
                                      encoding=enc))
        if out:
            self.res.facts.append("Encoded parameter values (testing inside the decoded value): " + ", ".join(
                f"{urlsplit(x.url).path}[{x.name}]={x.encoding}" for x in out[:10]))
        return out

    def _ordered_hypotheses(self, p: InjectionPoint) -> list[str]:
        """NLP rank x impact x technology prior: e.g. on a search field SQLi (9) outranks XSS (6)."""
        hyps = [h for h in hypotheses_for_param(p.name, p.original) if h in POINT_CHECKS and self.config.enabled(h)]
        return sorted(hyps, key=lambda h: -(0.85 ** hyps.index(h)) * CHECK_IMPACT.get(h, 3) * self._tech_mult(h))

    def _point_for(self, target: str) -> InjectionPoint:
        m = re.match(r"(\S+) (\S+) \[([\w+]+)\] (.+)$", target)
        method, url, loc, name = m.groups()
        loc, _, enc = loc.partition("+")
        return next(p for p in self.res.points
                    if (p.method, p.url, p.location, p.name, p.encoding) == (method, url, loc, name, enc))

    def _passive_all(self) -> None:
        cfg, ctx = self.config, self.ctx
        root_text = " ".join(r.text[:200000] for u, r in self.res.pages.items() if urlsplit(u).path in ("", "/"))
        samesite = any("samesite" in c.lower() for r in self.res.pages.values() for c in r.headers.get_list("set-cookie"))
        for url, resp in self.res.pages.items():
            if cfg.enabled("disclosure"):
                passive.disclosure(ctx, resp, root_text if urlsplit(url).path not in ("", "/") else "")
            if cfg.enabled("secrets") and (resp.is_html or "javascript" in resp.content_type or "json" in resp.content_type):
                passive.secrets(ctx, resp)
            if cfg.enabled("exposure"):
                passive.directory_listing(ctx, resp)
                analyzers.sensitive_url_params(ctx, url)
            if cfg.enabled("headers"):
                host_checks.cookie_flags(ctx, resp)
                analyzers.subresource_integrity(ctx, resp)
            if cfg.enabled("jwt"):
                analyzers.jwt(ctx, resp)
            if cfg.enabled("data_exposure"):
                analyzers.data_exposure(ctx, resp)
            if cfg.enabled("csrf"):
                analyzers.csrf(ctx, resp, samesite)
            if cfg.enabled("deserialization"):
                analyzers.deserialization(ctx, resp, url)
            if cfg.enabled("access"):
                analyzers.privileged_api(ctx, resp, authenticated=bool(cfg.headers or cfg.cookies))
        self._cover("passive")
        for c in ("disclosure", "secrets", "jwt", "csrf", "data_exposure"):
            self._cover(c)

    async def _verify(self, fingerprint: str) -> None:
        """Re-test a finding in a fresh context; unreproducible findings are downgraded, not silently kept."""
        f = self.ctx.findings.get(fingerprint)
        if f is None:
            return
        enc = (f.context or {}).get("value_encoding", "")
        p = next((p for p in self.res.points if p.name == f.parameter and p.url == f.url and p.location == f.location
                  and p.encoding == enc), None)
        if p is None:
            return
        fresh = Context(self.client, self.config, self.sigdb)
        bypass = (f.context or {}).get("bypass", {}).get("variant")
        variant = next((v for v in variants_for(f.check, p.original) if v.name == bypass), None)
        tok = ACTIVE_VARIANT.set(variant)
        etok = ACTIVE_ENCODING.set(enc)
        try:
            await POINT_CHECKS[f.check](fresh, p)
        finally:
            ACTIVE_VARIANT.reset(tok)
            ACTIVE_ENCODING.reset(etok)
        if any(g.check == f.check for g in fresh.findings.values()):
            if "verified" not in f.tags:
                f.tags.append("verified")
            if f.payload:  # attach the exact HTTP exchange as report evidence (payload is already transformed)
                tok = ACTIVE_VARIANT.set(None)
                try:
                    r = await self.ctx.send(p, f.payload)
                finally:
                    ACTIVE_VARIANT.reset(tok)
                if r is not None:
                    marker = f.payload if f.payload in r.text else None
                    f.context["http_request"] = r.raw_request()
                    f.context["http_response"] = r.raw_response(around=marker)
        else:
            f.tags.append("not-reproduced")
            f.confidence = Confidence.TENTATIVE
            f.evidence += " [Re-test did not reproduce this result; treat as unconfirmed.]"

    # ------------------------------------------------------------------ analysis
    def _analyse(self) -> None:
        for kind, items in self.ctx.obstructed.items():
            self.res.facts.append(f"{len(items)} test(s) were answered by a {kind.replace('_', ' ')} instead of the "
                                  "application - those inputs are NOT TESTED (not 'not vulnerable').")
        if self._auth_required:
            self.res.facts.append(
                f"{len(self._auth_required)} endpoint(s) answered 401/403 and were not fuzzed without a session - "
                f"re-run with credentials (-H 'Authorization: ...' / --cookie) for full coverage: "
                + ", ".join(sorted(self._auth_required)[:15]))
        findings = sorted(self.ctx.findings.values(), key=lambda f: (-f.severity, -f.confidence, f.url))
        for f in findings:
            f.ml_score = self.model.predict(f)
            if "not-reproduced" in f.tags:
                f.ml_score = round(f.ml_score * 0.5, 3)
        self.res.findings = findings
        waf = sorted({w for h in self.res.hosts for w in h.waf})
        for f in findings:
            pt = self.res.page_types.get(f.url)
            f.context.update({
                "environment": self.res.environment,
                "page_type": pt.label if pt else None,
                "waf": waf or None,
                "verification": ("verified by independent re-test" if "verified" in f.tags else
                                 "NOT reproduced on re-test" if "not-reproduced" in f.tags else
                                 "deterministic evidence (not re-tested)"),
                "review_notes": correlate.false_positive_signals(f) or None,
            })
            if self.res.environment != "production":
                f.context["environment_note"] = (f"Target looks like a {self.res.environment} environment - confirm the "
                                                 "issue also exists in production before rating business impact.")
        self.res.issues = correlate.cluster(findings)
        self.res.chains = correlate.attack_chains(findings)
        vuln = sum(1 for v in self.res.coverage.values() if v == "vulnerable")
        tested = sum(1 for v in self.res.coverage.values() if v != "not tested")
        self._trace(
            "analysis",
            "Consolidate: group findings by root cause, look for combinations that form attack chains, and score "
            "risk by severity x confidence x ML true-positive probability x breadth.",
            ["cluster", "attack-chains", "risk-scoring", "ml-triage"],
            f"{len(findings)} findings -> {len(self.res.issues)} root-cause issues, {len(self.res.chains)} attack "
            f"chain(s); WSTG coverage {tested}/{len(self.res.coverage)} areas tested, {vuln} vulnerable."
            + (f" Coverage gap: {len(self._auth_required)} authenticated endpoint(s) need credentials."
               if self._auth_required else ""),
        )
