"""Passive reconnaissance from public data sources (no traffic to the target).

Sources: certificate transparency (crt.sh), Wayback Machine CDX, AlienVault OTX passive DNS,
plus any installed external tools (subfinder, assetfinder, amass, gau, waybackurls).
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlsplit

import httpx

from webguard.recon import tools

log = logging.getLogger("webguard.recon")

HOST_RX = re.compile(r"^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$")


def _clean(host: str, domain: str) -> str | None:
    host = host.strip().lower().rstrip(".")
    m = HOST_RX.match(host)
    if not m:
        return None
    host = m.group(1)
    return host if host == domain or host.endswith("." + domain) else None


async def crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=60)
        if r.status_code != 200:
            return set()
        out = set()
        for row in r.json():
            for name in str(row.get("name_value", "")).split("\n"):
                h = _clean(name, domain)
                if h:
                    out.add(h)
        return out
    except Exception as exc:
        log.debug("crt.sh failed: %s", exc)
        return set()


async def otx(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=30)
        if r.status_code != 200:
            return set()
        return {h for rec in r.json().get("passive_dns", []) if (h := _clean(rec.get("hostname", ""), domain))}
    except Exception as exc:
        log.debug("otx failed: %s", exc)
        return set()


async def wayback_urls(client: httpx.AsyncClient, domain: str, limit: int = 20000) -> set[str]:
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "text", "fl": "original", "collapse": "urlkey",
                    "limit": str(limit)},
            timeout=90,
        )
        if r.status_code != 200:
            return set()
        return {line.strip() for line in r.text.splitlines() if line.strip().startswith("http")}
    except Exception as exc:
        log.debug("wayback failed: %s", exc)
        return set()


async def enumerate_subdomains(domain: str, proxy: str | None = None, use_tools: bool = True) -> dict[str, set[str]]:
    """Returns {source: subdomains}."""
    results: dict[str, set[str]] = {}
    async with httpx.AsyncClient(proxy=proxy, headers={"User-Agent": "webguard-recon"}, follow_redirects=True) as c:
        crt, alien = await asyncio.gather(crtsh(c, domain), otx(c, domain))
    results["crt.sh"] = crt
    results["otx"] = alien
    if use_tools:
        for name, hosts in (await tools.subdomain_tools(domain)).items():
            results[name] = {h for x in hosts if (h := _clean(x, domain))}
    return results


async def historical_urls(domain: str, proxy: str | None = None, use_tools: bool = True) -> set[str]:
    async with httpx.AsyncClient(proxy=proxy, headers={"User-Agent": "webguard-recon"}, follow_redirects=True) as c:
        urls = await wayback_urls(c, domain)
    if use_tools:
        urls |= await tools.url_tools(domain)
    return {u for u in urls if (urlsplit(u).hostname or "").endswith(domain)}


INTERESTING_URL = re.compile(
    r"(?i)(?:\.(?:bak|old|orig|swp|sql|db|backup|zip|tar|gz|7z|config|conf|cfg|ini|env|log|pem|key|xml|json|yml|yaml)"
    r"(?:$|\?))|(?:[?&](?:url|redirect|next|file|path|cmd|exec|query|token|key|api_key|secret|password|debug)=)|"
    r"(?:/(?:admin|internal|debug|actuator|graphql|swagger|api-docs|\.git|wp-admin|phpmyadmin|server-status|console)\b)"
)


def interesting_urls(urls: set[str]) -> list[str]:
    """Bug-bounty triage of historical URLs: backups, configs, juicy params, admin/debug paths."""
    return sorted(u for u in urls if INTERESTING_URL.search(u))
