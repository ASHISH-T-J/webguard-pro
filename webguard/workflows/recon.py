"""Recon workflow: subdomains -> DNS -> live HTTP services -> takeover -> historical URLs.

Results are stored in the asset inventory so repeated runs surface *new* attack surface.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from webguard.config import ScanConfig
from webguard.db import Database
from webguard.http import HttpClient
from webguard.models import Finding, Host
from webguard.recon import active, passive
from webguard.scope import Scope
from webguard.signatures import SignatureDB, default_db


@dataclass
class ReconResult:
    domain: str
    subdomains: dict[str, list[str]] = field(default_factory=dict)  # sub -> IPs ('' list if unresolved)
    sources: dict[str, int] = field(default_factory=dict)
    hosts: list[Host] = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)
    interesting_urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    new_assets: dict[str, list[str]] = field(default_factory=dict)


async def run_recon(domain: str, config: ScanConfig, scope: Scope, db: Database | None = None, scan_id: int | None = None,
                    passive_only: bool = False, use_tools: bool = True, history: bool = True,
                    sigdb: SignatureDB | None = None, transport: httpx.AsyncBaseTransport | None = None,
                    status: Callable[[str], None] = print) -> ReconResult:
    sigdb = sigdb or default_db()
    res = ReconResult(domain)

    status(f"Passive subdomain enumeration for {domain}")
    by_source = await passive.enumerate_subdomains(domain, config.proxy, use_tools)
    subs = {domain}
    for source, hosts in by_source.items():
        res.sources[source] = len(hosts)
        subs |= hosts
    subs = {s for s in subs if scope.host_in_scope(s)}
    status(f"  {len(subs)} in-scope names from {', '.join(f'{k}={v}' for k, v in res.sources.items())}")

    resolved = await active.resolve_many(sorted(subs))
    res.subdomains = resolved
    live_names = [h for h, ips in resolved.items() if ips]
    status(f"  {len(live_names)} resolve in DNS")

    if history:
        status("Collecting historical URLs (Wayback/gau)")
        urls = await passive.historical_urls(domain, config.proxy, use_tools)
        res.historical_urls = sorted(u for u in urls if scope.in_scope(u))
        res.interesting_urls = passive.interesting_urls(set(res.historical_urls))
        status(f"  {len(res.historical_urls)} URLs, {len(res.interesting_urls)} look interesting")

    if not passive_only:
        status(f"Probing {len(live_names)} hosts for HTTP services")
        async with HttpClient(config, scope, transport) as client:
            groups = await asyncio.gather(*(active.probe(client, sigdb, h) for h in live_names))
            res.hosts = [h for g in groups for h in g]
            status(f"  {len(res.hosts)} live web services; checking subdomain takeover")
            res.findings += await active.takeover(client, sigdb, sorted(subs))

    for f in res.findings:  # recon results are asset inventory: reported as collected (never masked)
        f.context.setdefault("phase", "recon")
    if db is not None and scan_id is not None:
        res.new_assets["subdomain"] = db.upsert_assets(scan_id, domain, "subdomain",
                                                       [(s, {"ips": ips}) for s, ips in resolved.items()])
        res.new_assets["host"] = db.upsert_assets(scan_id, domain, "host", [(h.url, h.to_dict()) for h in res.hosts])
        res.new_assets["url"] = db.upsert_assets(scan_id, domain, "url", res.interesting_urls)
    return res


def urls_for_host(urls: list[str], host_url: str) -> list[str]:
    netloc = urlsplit(host_url).netloc
    return [u for u in urls if urlsplit(u).netloc == netloc]
