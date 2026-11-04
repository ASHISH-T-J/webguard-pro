"""Bug bounty hunting pipeline.

    scope ─► recon (subdomains, DNS, live hosts, takeover, wayback) ─► prioritise assets
          ─► per-host scan (crawl, JS mining, hidden params, signature + differential + ML anomaly checks)
          ─► nuclei templates (optional) ─► ML triage ─► DB (new vs known) ─► reports + submission drafts

Designed for continuous monitoring: run it on a schedule and only *new* assets/findings are
highlighted, which is where fresh bugs usually are.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from webguard.config import ScanConfig
from webguard.db import Database
from webguard.engine import ScanEngine
from webguard.ml.triage import TriageModel
from webguard.models import Finding, Host
from webguard.recon import tools
from webguard.reporting import ReportOptions, write_all
from webguard.scope import Scope
from webguard.session import Session
from webguard.workflows.recon import ReconResult, run_recon, urls_for_host
from webguard.workflows.redteam import prioritise


@dataclass
class HuntResult:
    target: str
    scan_id: int
    recon: ReconResult
    findings: list[Finding] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    reports: list[Path] = field(default_factory=list)
    ranking: list[dict] = field(default_factory=list)
    host_results: dict = field(default_factory=dict)  # host url -> AssessmentResult


async def hunt(domain: str, config: ScanConfig, scope: Scope, db: Database, out_dir: Path,
               formats: list[str], max_hosts: int = 25, use_nuclei: bool = True, use_tools: bool = True,
               content_discovery: bool = False, parallel_hosts: int = 4, screenshots: bool = True,
               report_options: ReportOptions | None = None, session_dir: Path | None = None,
               transport: httpx.AsyncBaseTransport | None = None, on_finding: Callable[[Finding], None] | None = None,
               status: Callable[[str], None] = print) -> HuntResult:
    scan_id = db.start_scan(domain, "hunt")
    recon = await run_recon(domain, config, scope, db, scan_id, use_tools=use_tools, transport=transport, status=status)
    result = HuntResult(domain, scan_id, recon)
    result.findings += recon.findings

    ranking = prioritise(recon.hosts, {}, recon.interesting_urls)
    result.ranking = ranking
    targets: list[Host] = [r["host"] for r in ranking][:max_hosts]
    status(f"Scanning top {len(targets)} of {len(recon.hosts)} web services (ranked by attack-surface score)")

    discovered: list[str] = []
    if use_tools and targets and tools.available().get("katana"):
        status("katana: JS-aware crawl of top targets")
        discovered += sorted(u for u in await tools.katana([h.url for h in targets]) if scope.in_scope(u))
    if content_discovery and tools.available().get("ffuf"):
        for host in targets:
            status(f"ffuf content discovery on {host.url}")
            hits = await tools.ffuf(host.url, config.wordlist, rate=int(config.rate_limit))
            discovered += [h["url"] for h in hits if h.get("url") and scope.in_scope(h["url"])]
    if discovered:
        db.upsert_assets(scan_id, domain, "endpoint", discovered)

    # scan hosts concurrently; the user's global rate/concurrency budget is split between them
    width = max(1, min(parallel_hosts, len(targets)))
    per_host = dataclasses.replace(config, rate_limit=max(1.0, config.rate_limit / width),
                                   concurrency=max(4, config.concurrency // width))
    sem = asyncio.Semaphore(width)
    if width > 1:
        status(f"Scanning {len(targets)} hosts, {width} in parallel ({per_host.rate_limit:g} req/s each)")

    async def scan_host(host: Host) -> None:
        async with sem:
            status(f"── {host.url}")
            # one resumable session per host: an interrupted hunt skips hosts/tests already completed
            sess = Session.open(session_dir, host.url, "hunt", ",".join(per_host.checks)) if session_dir else None
            if sess is not None and sess.resumed:
                status(f"[{host.url}] resuming: {sess.describe()}")
            engine = ScanEngine(per_host, scope, transport=transport, on_finding=on_finding,
                                on_status=lambda m, h=host.url: status(f"[{h}] {m}"), checkpoint=sess,
                                on_stage=lambda i, n, name, h=host.url: status(f"[{h}] stage {i}/{n}: {name}"))
            extra = (urls_for_host(discovered, host.url) + urls_for_host(recon.historical_urls, host.url))[:500]
            try:
                res = await engine.scan(host.url, extra_urls=extra, hosts=[host])
            except Exception as exc:  # one broken host must not abort the hunt
                status(f"   {host.url} failed: {type(exc).__name__}: {exc}")
                return
            if sess is not None:
                sess.finish()
            result.findings.extend(res.findings)
            result.host_results[host.url] = res
            db.upsert_assets(scan_id, domain, "endpoint", res.urls)
            db.upsert_assets(scan_id, domain, "js", res.js_files)
            db.upsert_assets(scan_id, domain, "param", sorted({f"{p.method} {p.url} [{p.location}] {p.name}"
                                                              for p in res.points}))

    await asyncio.gather(*(scan_host(h) for h in targets))

    if use_nuclei and tools.available().get("nuclei"):
        status("Running nuclei templates against live services")
        nuclei_findings = await tools.nuclei([h.url for h in targets], rate=int(config.rate_limit))
        model = TriageModel.load(config.model_path)
        for f in nuclei_findings:
            f.ml_score = model.predict(f)
        result.findings += nuclei_findings

    if screenshots:
        from webguard.reporting import poc

        n = await poc.capture(result.findings, config, scope, out_dir,
                              redact=report_options.redact if report_options else True)
        if n:
            status(f"Captured {n} PoC screenshot(s)")
    result.new_findings = db.save_findings(scan_id, domain, result.findings)
    db.finish_scan(scan_id, {"hosts": len(recon.hosts), "findings": len(result.findings),
                             "new_findings": len(result.new_findings)})
    meta = {"scan_id": scan_id, "hosts": [h.to_dict() for h in recon.hosts], "ranking": [
        {k: v for k, v in r.items() if k != "host"} for r in ranking],
        "new_assets": recon.new_assets, "interesting_urls": recon.interesting_urls[:500],
        "subdomain_status": recon.liveness}
    result.reports = write_all(domain, result.findings, out_dir, formats, meta, report_options)
    return result
