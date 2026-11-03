"""Red-team / external attack-surface workflow.

Maps the external perimeter (subdomains, web services, open ports, exposed services,
takeover candidates), ranks assets by likely exploitability and maps every finding to MITRE
ATT&CK techniques so results drop straight into an engagement report. This module performs
reconnaissance and vulnerability *identification* only - no exploitation or persistence.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from webguard.config import ScanConfig
from webguard.db import Database
from webguard.models import Finding, Host
from webguard.recon import active, tools
from webguard.scope import Scope
from webguard.workflows.recon import ReconResult, run_recon

ATTACK = {
    "sqli": [("T1190", "Exploit Public-Facing Application")],
    "cmdi": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "ssti": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "lfi": [("T1190", "Exploit Public-Facing Application"), ("T1005", "Data from Local System")],
    "ssrf": [("T1190", "Exploit Public-Facing Application"), ("T1552.005", "Cloud Instance Metadata API")],
    "xss": [("T1189", "Drive-by Compromise"), ("T1539", "Steal Web Session Cookie")],
    "redirect": [("T1566.002", "Phishing: Spearphishing Link")],
    "crlf": [("T1190", "Exploit Public-Facing Application")],
    "cors": [("T1539", "Steal Web Session Cookie")],
    "secrets": [("T1552.001", "Unsecured Credentials: Credentials In Files"), ("T1078", "Valid Accounts")],
    "exposure": [("T1213", "Data from Information Repositories"), ("T1133", "External Remote Services")],
    "takeover": [("T1584.001", "Compromise Infrastructure: Domains")],
    "disclosure": [("T1592", "Gather Victim Host Information")],
    "headers": [("T1592", "Gather Victim Host Information")],
    "anomaly": [("T1190", "Exploit Public-Facing Application")],
}
RECON_TECHNIQUES = [("T1595.002", "Active Scanning: Vulnerability Scanning"),
                    ("T1596.003", "Search Open Technical Databases: Digital Certificates"),
                    ("T1593", "Search Open Websites/Domains"), ("T1590.002", "Gather Victim Network Information: DNS")]

HOT_NAMES = re.compile(r"(?i)\b(?:dev|stag(?:e|ing)|test|qa|uat|beta|old|legacy|internal|intranet|admin|panel|vpn|"
                       r"jenkins|gitlab|git|jira|confluence|grafana|kibana|sonar|nexus|artifactory|ci|cd|build|"
                       r"backup|bak|sandbox|demo|preprod|debug|api|graphql|sso|auth|login|portal|mail|owa|remote)\b")
HOT_TECH = re.compile(r"(?i)jenkins|phpmyadmin|grafana|kibana|elasticsearch|solr|tomcat|weblogic|jboss|"
                      r"confluence|jira|gitlab|swagger|graphql|actuator|wordpress|drupal|joomla|magento|struts")


def attack_mapping(f: Finding) -> list[tuple[str, str]]:
    return ATTACK.get(f.check.split(":")[0], [("T1190", "Exploit Public-Facing Application")])


def prioritise(hosts: list[Host], ports: dict[str, list[int]], interesting_urls: list[str]) -> list[dict]:
    """Score web services by how promising they are to attack/hunt (higher = look first)."""
    ranked = []
    for h in hosts:
        name = urlsplit(h.url).hostname or ""
        score, reasons = 1.0, []
        if HOT_NAMES.search(name.replace(".", " ").replace("-", " ")):
            score += 3
            reasons.append("interesting hostname")
        tech = " ".join(h.technologies)
        if HOT_TECH.search(tech + " " + h.title):
            score += 3
            reasons.append("high-value technology")
        if not h.waf:
            score += 1.5
            reasons.append("no WAF detected")
        if h.status in (401, 403):
            score += 1
            reasons.append(f"access-controlled ({h.status}) - try bypasses")
        if re.search(r"(?i)login|sign in|admin|dashboard|console", h.title):
            score += 2
            reasons.append("login/admin page")
        if any(re.search(r"\d+\.\d+", t) for t in h.technologies):
            score += 1
            reasons.append("version disclosed (CVE matching)")
        juicy = [u for u in interesting_urls if urlsplit(u).netloc == urlsplit(h.url).netloc]
        if juicy:
            score += min(3, len(juicy) / 5)
            reasons.append(f"{len(juicy)} interesting historical URLs")
        risky_ports = [p for p in ports.get(name, []) if p in active.RISKY_SERVICES]
        if risky_ports:
            score += 2
            reasons.append(f"risky ports {risky_ports}")
        ranked.append({"host": h, "url": h.url, "score": round(score, 1), "reasons": reasons})
    return sorted(ranked, key=lambda r: -r["score"])


@dataclass
class SurfaceResult:
    domain: str
    scan_id: int | None
    recon: ReconResult
    ports: dict[str, list[int]] = field(default_factory=dict)
    services: dict[str, list[dict]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    ranking: list[dict] = field(default_factory=list)


async def attack_surface(domain: str, config: ScanConfig, scope: Scope, db: Database | None = None,
                         scan_ports: bool = True, use_nmap: bool = True, use_tools: bool = True,
                         transport: httpx.AsyncBaseTransport | None = None,
                         status: Callable[[str], None] = print) -> SurfaceResult:
    scan_id = db.start_scan(domain, "redteam") if db else None
    recon = await run_recon(domain, config, scope, db, scan_id, use_tools=use_tools, transport=transport,
                            status=status)
    res = SurfaceResult(domain, scan_id, recon, findings=list(recon.findings))
    resolved = [h for h, ips in recon.subdomains.items() if ips]
    if scan_ports and resolved:
        if use_nmap and tools.available().get("nmap"):
            status(f"nmap service scan of {len(resolved)} hosts")
            for h in resolved:
                res.services[h] = await tools.nmap(h, top_ports=200)
                res.ports[h] = [s["port"] for s in res.services[h]]
        else:
            status(f"TCP connect scan of {len(active.TOP_PORTS)} common ports on {len(resolved)} hosts")
            sem = asyncio.Semaphore(10)

            async def scan(h: str) -> None:
                async with sem:
                    res.ports[h] = await active.port_scan(h)

            await asyncio.gather(*(scan(h) for h in resolved))
        for h, ports in res.ports.items():
            res.findings += active.exposed_service_findings(h, ports)
    res.ranking = prioritise(recon.hosts, res.ports, recon.interesting_urls)
    if db and scan_id:
        db.upsert_assets(scan_id, domain, "port", [f"{h}:{p}" for h, ps in res.ports.items() for p in ps])
        db.save_findings(scan_id, domain, res.findings)
        db.finish_scan(scan_id, {"hosts": len(recon.hosts), "open_ports": sum(map(len, res.ports.values()))})
    return res
