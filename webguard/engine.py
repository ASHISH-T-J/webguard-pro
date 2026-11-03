"""Scan orchestration: probe -> crawl -> map injection points -> checks -> ML triage."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import httpx

from webguard.config import ScanConfig
from webguard.crawler import Crawler, CrawlResult, normalize_url
from webguard.detection.checks import POINT_CHECKS, hunting, passive
from webguard.detection.checks import host as host_checks
from webguard.detection.context import Context
from webguard.http import HttpClient
from webguard.ml.triage import TriageModel
from webguard.models import Finding, Host, InjectionPoint
from webguard.recon.active import probe
from webguard.scope import Scope
from webguard.signatures import SignatureDB, default_db

log = logging.getLogger("webguard.engine")

SKIP_PARAMS = re.compile(
    r"(?i)^(?:csrf.*|_?token|authenticity_token|__requestverificationtoken|__viewstate.*|__eventvalidation|"
    r"__eventtarget|__eventargument|_wpnonce|nonce|captcha.*|g-recaptcha-response|submit|utm_\w+|fbclid|gclid)$"
)
API_HINT = re.compile(r"(?i)/(?:api|v\d+|graphql|rest|ajax|json)(?:/|$)|\.json(?:$|\?)")


@dataclass
class ScanResult:
    target: str
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    points: list[InjectionPoint] = field(default_factory=list)
    oob: list[dict[str, str]] = field(default_factory=list)
    stats: dict[str, float] = field(default_factory=dict)
    started: float = field(default_factory=time.time)


def target_url(target: str) -> str | None:
    return target if target.startswith(("http://", "https://")) else None


def injection_points(crawl: CrawlResult, extra_urls: list[str] = ()) -> list[InjectionPoint]:
    points: dict[tuple, InjectionPoint] = {}

    def add(p: InjectionPoint) -> None:
        if SKIP_PARAMS.match(p.name):
            return
        points.setdefault(p.key, p)

    urls = set(crawl.pages) | crawl.urls_with_params | crawl.js_endpoints | set(extra_urls)
    for url in urls:
        parts = urlsplit(url)
        if not parts.query:
            continue
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        bare = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        for name in params:
            add(InjectionPoint(bare, "GET", "query", name, dict(params), source="crawl"))
    for form in crawl.forms:
        url = form.url
        parts = urlsplit(url)
        params = dict(form.inputs)
        if form.method == "GET" and parts.query:
            params = {**dict(parse_qsl(parts.query, keep_blank_values=True)), **params}
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        location = "json" if "json" in (form.enctype or "") else "form"
        for name in form.inputs:
            add(InjectionPoint(url, form.method, location, name, params, source="form"))
    return list(points.values())


class ScanEngine:
    def __init__(self, config: ScanConfig, scope: Scope, sigdb: SignatureDB | None = None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 on_finding: Callable[[Finding], None] | None = None,
                 on_status: Callable[[str], None] | None = None) -> None:
        self.config = config
        self.scope = scope
        self.sigdb = sigdb or default_db()
        self.transport = transport
        self.on_finding = on_finding
        self.on_status = on_status or (lambda msg: log.info(msg))
        self.model = TriageModel.load(config.model_path)

    async def scan(self, target: str, extra_urls: list[str] = (), hosts: list[Host] | None = None) -> ScanResult:
        result = ScanResult(target=target)
        async with HttpClient(self.config, self.scope, self.transport) as client:
            ctx = Context(client, self.config, self.sigdb, self.on_finding)
            await self._run(ctx, client, target, list(extra_urls), hosts, result)
            result.findings = sorted(ctx.findings.values(), key=lambda f: (-f.severity, -f.confidence, f.url))
            for f in result.findings:
                f.ml_score = self.model.predict(f)
            result.oob = ctx.oob_log
            result.stats.update(client.stats)
        result.stats["duration_s"] = round(time.time() - result.started, 1)
        result.stats["findings"] = len(result.findings)
        return result

    async def _run(self, ctx: Context, client: HttpClient, target: str, extra_urls: list[str],
                   hosts: list[Host] | None, result: ScanResult) -> None:
        cfg = self.config
        # 1) live hosts -------------------------------------------------------------------
        seeds: list[str] = []
        if hosts is None:
            explicit = target_url(target)
            host = urlsplit(explicit).netloc if explicit else target
            self.on_status(f"Probing {host}")
            hosts = await probe(client, self.sigdb, host)
            if explicit:
                seeds.append(normalize_url(explicit))
        result.hosts = hosts
        if not hosts:
            self.on_status("No live HTTP service found")
            return
        seeds += [h.url + "/" for h in hosts]
        seeds += [u for u in extra_urls if self.scope.in_scope(u)][:cfg.max_urls]

        # 2) crawl --------------------------------------------------------------------------
        self.on_status(f"Crawling {len(seeds)} seed URL(s) (depth {cfg.max_depth}, max {cfg.max_urls} URLs)")
        crawl = await Crawler(client, cfg.max_depth, cfg.max_urls).crawl(seeds)
        result.urls = sorted(crawl.pages)
        result.js_files = sorted(crawl.js_files)
        points = injection_points(crawl, [u for u in extra_urls if self.scope.in_scope(u)])
        self.on_status(f"Mapped {len(crawl.pages)} URLs, {len(crawl.forms)} forms, {len(crawl.js_files)} JS files, "
                       f"{len(points)} injection points")

        # 3) host-level + passive checks ----------------------------------------------------
        roots = sorted({h.url for h in hosts})
        tasks = []
        for root in roots:
            root_resp = crawl.pages.get(root + "/") or await client.safe_get(root + "/")
            if root_resp is not None and cfg.enabled("headers"):
                tasks.append(host_checks.security_headers(ctx, root_resp))
            if cfg.enabled("cors"):
                api_urls = [u for u in crawl.pages if u.startswith(root) and API_HINT.search(u)][:5]
                tasks += [host_checks.cors(ctx, u) for u in [root + "/", *api_urls]]
            if cfg.enabled("exposure"):
                tasks.append(host_checks.exposures(ctx, root))
            if cfg.enabled("headers"):
                tasks.append(host_checks.http_methods(ctx, root))
        await asyncio.gather(*tasks)
        root_text = " ".join(r.text[:200000] for u, r in crawl.pages.items() if urlsplit(u).path in ("", "/"))
        for url, resp in crawl.pages.items():
            if cfg.enabled("disclosure"):
                passive.disclosure(ctx, resp, root_text if urlsplit(url).path not in ("", "/") else "")
            if cfg.enabled("secrets") and (resp.is_html or "javascript" in resp.content_type or "json" in resp.content_type):
                passive.secrets(ctx, resp)
            if cfg.enabled("exposure"):
                passive.directory_listing(ctx, resp)
            if cfg.enabled("headers"):
                host_checks.cookie_flags(ctx, resp)

        # 4) hidden parameter discovery -----------------------------------------------------
        if cfg.param_discovery:
            endpoints = [u for u, r in crawl.pages.items() if r.is_html and r.status == 200 and not urlsplit(u).query][:15]
            self.on_status(f"Hidden parameter discovery on {len(endpoints)} endpoints")
            found = await asyncio.gather(*(hunting.discover_params(ctx, u) for u in endpoints))
            points += [p for group in found for p in group]

        # 5) active checks per injection point ----------------------------------------------
        active = [name for name in POINT_CHECKS if cfg.enabled(name)]
        result.points = points
        if points and active:
            self.on_status(f"Testing {len(points)} injection points with: {', '.join(active)}")
            sem = asyncio.Semaphore(max(2, cfg.concurrency // 2))
            done = 0

            async def test(point: InjectionPoint) -> None:
                nonlocal done
                async with sem:
                    for name in active:
                        try:
                            await POINT_CHECKS[name](ctx, point)
                        except Exception as exc:  # a broken check must not abort the scan
                            log.debug("check %s failed on %s:%s: %s", name, point.url, point.name, exc, exc_info=True)
                    done += 1
                    if cfg.verbose and done % 10 == 0:
                        self.on_status(f"  {done}/{len(points)} injection points tested")

            await asyncio.gather(*(test(p) for p in points))
