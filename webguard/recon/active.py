"""Active recon: DNS resolution, HTTP probing + fingerprinting, WAF detection, port scan, takeover."""

from __future__ import annotations

import asyncio
import re
import socket
from urllib.parse import urlsplit

from webguard.detection.baseline import title as page_title
from webguard.http import HttpClient
from webguard.models import SIGNATURE, Confidence, Finding, Host, Severity
from webguard.signatures import SignatureDB

try:
    import dns.asyncresolver  # dnspython (optional): enables CNAME-based takeover detection

    HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    HAVE_DNSPYTHON = False

TOP_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995, 1433,
             1521, 2049, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900, 5985, 6379, 6443, 7001,
             8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 9443, 10250, 11211, 15672, 27017]
RISKY_SERVICES = {
    2375: ("Docker API (unauthenticated)", Severity.CRITICAL), 6379: ("Redis", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH), 27017: ("MongoDB", Severity.HIGH), 11211: ("Memcached", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM), 3306: ("MySQL", Severity.MEDIUM), 1433: ("MSSQL", Severity.MEDIUM),
    1521: ("Oracle DB", Severity.MEDIUM), 3389: ("RDP", Severity.MEDIUM), 5900: ("VNC", Severity.MEDIUM),
    10250: ("Kubelet API", Severity.HIGH), 6443: ("Kubernetes API", Severity.LOW), 23: ("Telnet", Severity.MEDIUM),
    445: ("SMB", Severity.MEDIUM), 5985: ("WinRM", Severity.MEDIUM), 2049: ("NFS", Severity.MEDIUM),
    15672: ("RabbitMQ management", Severity.LOW), 5601: ("Kibana", Severity.LOW), 21: ("FTP", Severity.LOW),
}
WAF_PROBE = "/?id=1%27%20OR%201=1--%20&q=%3Cscript%3Ealert(1)%3C/script%3E&f=../../../../etc/passwd"


async def resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 10)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


async def resolve_many(hosts: list[str], concurrency: int = 50) -> dict[str, list[str]]:
    sem = asyncio.Semaphore(concurrency)

    async def one(h: str) -> tuple[str, list[str]]:
        async with sem:
            return h, await resolve(h)

    return dict(await asyncio.gather(*(one(h) for h in hosts)))


async def cname(host: str) -> str | None:
    if not HAVE_DNSPYTHON:
        return None
    try:
        ans = await dns.asyncresolver.resolve(host, "CNAME", lifetime=8)
        return str(ans[0].target).rstrip(".").lower()
    except Exception:
        return None


async def describe(client: HttpClient, sigdb: SignatureDB, base: str) -> Host | None:
    """Fingerprint one live base URL (technologies, WAF, title)."""
    r = await client.safe_get(base + "/", follow_redirects=True)
    if r is None or not r.status:
        r = await client.safe_get(base + "/", follow_redirects=True, timeout=30.0)  # slow app: one long try
    if r is None or not r.status:
        return None
    cookies = [c.split("=", 1)[0].strip() for c in r.headers.get_list("set-cookie")]
    tech = sigdb.fingerprint_tech(r.headers, cookies, r.text[:300000])
    waf = set(sigdb.detect_waf(r.headers, cookies, r.text[:50000]))
    w = await client.safe_get(base + WAF_PROBE)
    if w is not None:
        wc = [c.split("=", 1)[0].strip() for c in w.headers.get_list("set-cookie")]
        waf |= set(sigdb.detect_waf(w.headers, wc, w.text[:50000]))
        if not waf and w.status in (403, 406, 419, 429, 501, 503) and r.status < 400:
            waf.add("Generic (malicious probe blocked)")
    final = urlsplit(r.url)
    if not client.scope.in_scope(r.url):
        final = urlsplit(base)  # redirected off-scope: keep the original origin
    return Host(url=f"{final.scheme}://{final.netloc}", status=r.status, title=page_title(r.text),
                server=r.headers.get("server", ""), technologies=[f"{k} {v}".strip() for k, v in sorted(tech.items())],
                waf=sorted(waf), content_length=len(r.text))


async def probe(client: HttpClient, sigdb: SignatureDB, host: str, liveness: dict | None = None) -> list[Host]:
    """Live HTTP services for a host (robust: DNS -> TCP -> HTTP with escalating timeouts and a second chance).

    ``liveness`` (optional dict) receives the :class:`~webguard.recon.liveness.Liveness` verdict.
    """
    from webguard.recon import liveness as lv

    verdict = (await lv.check_many(client, [host]))[host]
    if liveness is not None:
        liveness[host] = verdict
    out: list[Host] = []
    for base in verdict.urls:
        h = await describe(client, sigdb, base)
        if h is not None:
            out.append(h)
    uniq = {h.url: h for h in out}
    hosts = list(uniq.values())
    # the same app over https and http: keep https only
    https_hosts = {urlsplit(h.url).hostname for h in hosts if h.url.startswith("https://")}
    return [h for h in hosts if h.url.startswith("https://") or urlsplit(h.url).hostname not in https_hosts]


async def port_scan(host: str, ports: list[int] | None = None, timeout: float = 2.0,
                    concurrency: int = 200) -> list[int]:
    """Fast asyncio TCP connect scan (fallback when nmap is not installed)."""
    sem = asyncio.Semaphore(concurrency)

    async def check(port: int) -> int | None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None

    res = await asyncio.gather(*(check(p) for p in (ports or TOP_PORTS)))
    return sorted(p for p in res if p)


def exposed_service_findings(host: str, ports: list[int]) -> list[Finding]:
    out = []
    for p in ports:
        if p in RISKY_SERVICES:
            name, sev = RISKY_SERVICES[p]
            out.append(Finding(
                check="exposure", title=f"{name} port exposed to the internet", severity=sev,
                confidence=Confidence.FIRM, url=f"tcp://{host}:{p}",
                evidence=f"TCP port {p} accepts connections.",
                description=f"{name} is reachable from the internet. Such services are frequent initial-access "
                            "vectors (default/weak credentials, unauthenticated APIs, known CVEs).",
                remediation="Restrict the service to internal networks / VPN via firewall rules and require auth.",
                cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
                tags=["network", "exposure", f"port-{p}"],
            ))
    return out


async def takeover(client: HttpClient, sigdb: SignatureDB, hosts: list[str]) -> list[Finding]:
    findings = []

    async def check(host: str) -> None:
        target = await cname(host)
        r = None
        for scheme in ("https", "http"):
            r = await client.safe_get(f"{scheme}://{host}/")
            if r is not None:
                break
        body = r.text if r is not None else ""
        for service, sig in sigdb.takeover.items():
            cname_hit = bool(target) and any(s in target for s in sig["cname"])
            body_hit = bool(body) and re.search(sig["body"], body[:100000]) is not None
            dangling = sig.get("nxdomain") and cname_hit and not await resolve(target)
            # without DNS data only trust long, service-specific body fingerprints
            body_only = body_hit and not HAVE_DNSPYTHON and len(sig["body"]) > 25
            if (cname_hit and body_hit) or dangling or body_only:
                conf = Confidence.FIRM if cname_hit else Confidence.TENTATIVE
                findings.append(Finding(
                    check="takeover", title=f"Potential subdomain takeover ({service})",
                    severity=Severity.HIGH, confidence=conf, url=f"https://{host}/",
                    evidence=f"CNAME: {target or 'unknown (install dnspython)'}; unclaimed-resource fingerprint "
                             f"{'matched' if body_hit else 'n/a'}{'; CNAME target does not resolve' if dangling else ''}",
                    description=f"{host} points to a {service} resource that appears unclaimed. An attacker who "
                                "registers it can serve content on your domain (phishing, cookie theft, CSP/OAuth bypass).",
                    remediation="Remove the dangling DNS record or re-claim the resource at the provider.",
                    cwe="CWE-350", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"], tags=["takeover", service.lower()],
                ))
                return

    await asyncio.gather(*(check(h) for h in hosts))
    return findings
