"""Integration with external security tools (used when installed, skipped gracefully otherwise).

Supported: subfinder, assetfinder, amass, gau, waybackurls, katana, nuclei, nmap, ffuf,
sqlmap (hand-off command generation), dalfox (hand-off command generation).
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from webguard.models import EXTERNAL, Confidence, Finding, Severity

log = logging.getLogger("webguard.tools")

KNOWN_TOOLS = {
    "subfinder": "Passive subdomain enumeration (go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)",
    "assetfinder": "Subdomain discovery (go install github.com/tomnomnom/assetfinder@latest)",
    "amass": "In-depth attack surface mapping (https://github.com/owasp-amass/amass)",
    "gau": "Historical URLs from multiple archives (go install github.com/lc/gau/v2/cmd/gau@latest)",
    "waybackurls": "Wayback Machine URLs (go install github.com/tomnomnom/waybackurls@latest)",
    "katana": "Headless/JS-aware crawler (go install github.com/projectdiscovery/katana/cmd/katana@latest)",
    "nuclei": "Template-based vulnerability scanner with 9000+ community templates",
    "nmap": "Port and service scanning",
    "ffuf": "Fast content discovery fuzzer",
    "sqlmap": "SQL injection exploitation/confirmation",
    "dalfox": "XSS verification",
}


def available() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in KNOWN_TOOLS}


async def run(cmd: list[str], timeout: float = 600, stdin: str | None = None) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(stdin.encode() if stdin else None), timeout)
        return out.decode(errors="replace")
    except asyncio.TimeoutError:
        log.warning("%s timed out after %ss", cmd[0], timeout)
        proc.kill()
        return ""
    except Exception as exc:
        log.warning("%s failed: %s", cmd[0], exc)
        return ""


async def subdomain_tools(domain: str) -> dict[str, set[str]]:
    jobs = {
        "subfinder": ["subfinder", "-d", domain, "-silent", "-all"],
        "assetfinder": ["assetfinder", "--subs-only", domain],
        "amass": ["amass", "enum", "-passive", "-d", domain, "-silent"],
    }
    jobs = {k: v for k, v in jobs.items() if shutil.which(v[0])}
    outs = await asyncio.gather(*(run(cmd) for cmd in jobs.values()))
    return {name: set(out.split()) for name, out in zip(jobs, outs)}


async def url_tools(domain: str) -> set[str]:
    outs = await asyncio.gather(
        run(["gau", "--subs", domain], timeout=900),
        run(["waybackurls", domain], timeout=900),
    )
    return {u for out in outs for u in out.split() if u.startswith("http")}


async def katana(urls: list[str], depth: int = 3) -> set[str]:
    out = await run(["katana", "-silent", "-jc", "-d", str(depth), "-list", "/dev/stdin"], stdin="\n".join(urls),
                    timeout=1800)
    return {u for u in out.split() if u.startswith("http")}


NUCLEI_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
              "critical": Severity.CRITICAL, "unknown": Severity.INFO}


async def nuclei(urls: list[str], severity: str = "low,medium,high,critical", rate: int = 50,
                 extra: list[str] | None = None) -> list[Finding]:
    """Run nuclei and convert its JSONL output into WebGuard findings."""
    if not shutil.which("nuclei") or not urls:
        return []
    cmd = ["nuclei", "-silent", "-jsonl", "-severity", severity, "-rate-limit", str(rate), "-list", "/dev/stdin",
           *(extra or [])]
    out = await run(cmd, timeout=7200, stdin="\n".join(urls))
    findings = []
    for line in out.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info", {})
        classification = info.get("classification") or {}
        cwe = (classification.get("cwe-id") or [None])[0]
        findings.append(Finding(
            check=f"nuclei:{item.get('template-id', 'unknown')}",
            title=info.get("name", item.get("template-id", "nuclei finding")),
            severity=NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO),
            confidence=Confidence.FIRM,
            url=item.get("matched-at") or item.get("host", ""),
            evidence=json.dumps(item.get("extracted-results") or item.get("matcher-name") or "")[:500],
            description=info.get("description", "").strip(),
            remediation=info.get("remediation", "").strip(),
            cwe=cwe.upper() if isinstance(cwe, str) else None,
            detection=EXTERNAL,
            references=info.get("reference") or [],
            tags=["nuclei", *(info.get("tags") or [])] if isinstance(info.get("tags"), list)
            else ["nuclei", *str(info.get("tags", "")).split(",")],
            request=item.get("curl-command"),
        ))
    return findings


async def nmap(host: str, top_ports: int = 1000) -> list[dict]:
    """Service scan with nmap; returns [{port, proto, service, product, version}]."""
    if not shutil.which("nmap"):
        return []
    out = await run(["nmap", "-Pn", "-sV", "--top-ports", str(top_ports), "-oX", "-", host], timeout=3600)
    services = []
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        services.append({
            "port": int(port.get("portid", 0)),
            "proto": port.get("protocol"),
            "service": svc.get("name") if svc is not None else "",
            "product": svc.get("product", "") if svc is not None else "",
            "version": svc.get("version", "") if svc is not None else "",
        })
    return services


async def ffuf(url: str, wordlist: Path, rate: int = 50, extensions: str = "") -> list[dict]:
    """Content discovery with ffuf (auto-calibrated to filter soft-404s)."""
    if not shutil.which("ffuf"):
        return []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    cmd = ["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", str(wordlist), "-ac", "-rate", str(rate), "-s",
           "-o", out_path, "-of", "json"]
    if extensions:
        cmd += ["-e", extensions]
    await run(cmd, timeout=3600)
    try:
        data = json.loads(Path(out_path).read_text() or "{}")
    except (OSError, ValueError):
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)
    return [{"url": r.get("url"), "status": r.get("status"), "length": r.get("length")} for r in data.get("results", [])]


def handoff_commands(finding: Finding) -> list[str]:
    """Commands for deeper manual verification with specialised tools (never run automatically)."""
    cmds = []
    if finding.check == "sqli" and finding.request:
        cmds.append(f"sqlmap --batch --level 3 --risk 1 -p {finding.parameter} " + _curl_to_sqlmap(finding.request))
    if finding.check == "xss" and finding.request:
        cmds.append(f"dalfox url '{finding.url}' -p {finding.parameter}")
    return cmds


def _curl_to_sqlmap(curl: str) -> str:
    import shlex

    parts = shlex.split(curl)
    url = next((p for p in parts if p.startswith("http")), "")
    data = parts[parts.index("--data-raw") + 1] if "--data-raw" in parts else None
    out = f"-u {shlex.quote(url)}"
    if data:
        out += f" --data {shlex.quote(data)}"
    return out
