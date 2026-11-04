"""Network service audit: open ports -> service / product / version -> CVE, end-of-life and exposure findings.

For every open TCP port the banner is read passively (SSH, FTP, SMTP, POP3/IMAP, MySQL, VNC and
ActiveMQ greet first). HTTP(S) ports receive one ``HEAD /`` request. Nothing else is sent: no logins, no
protocol commands. Banners are matched against the service fingerprint templates and the CVE knowledge
base; version-only matches are potential findings (distribution back-ports lower the confidence).
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass

from webguard import cve, fingerprints
from webguard.models import PASSIVE, Confidence, Finding, Severity
from webguard.recon.active import TOP_PORTS, exposed_service_findings, port_scan

HTTP_PORTS = {80, 81, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 9200, 10000, 15672}
TLS_PORTS = {443, 4443, 6443, 8443, 9443, 10250, 465, 993, 995, 636}
PORT_SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 110: "pop3", 143: "imap", 389: "ldap",
                445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
                1521: "oracle", 2375: "docker", 2376: "docker-tls", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
                5672: "amqp", 5900: "vnc", 5985: "winrm", 6379: "redis", 6443: "kubernetes-api", 9200: "elasticsearch",
                9300: "elasticsearch-transport", 10250: "kubelet", 11211: "memcached", 27017: "mongodb",
                61616: "activemq"}
CLEARTEXT = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}


@dataclass
class Service:
    host: str
    port: int
    service: str
    banner: str = ""
    product: str | None = None
    version: str | None = None
    tls: bool = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def grab(host: str, port: int, timeout: float = 4.0) -> tuple[str, bool]:
    """(banner text, tls?) - passive read first, a single HEAD for HTTP(S) ports."""
    use_tls = port in TLS_PORTS
    ctx = None
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if ctx else None), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return "", use_tls
    data = b""
    try:
        if port not in HTTP_PORTS and port not in (443, 4443, 8443, 9443):
            try:
                data = await asyncio.wait_for(reader.read(2048), 2.5)  # services that greet first
            except asyncio.TimeoutError:
                data = b""
        if not data and (port in HTTP_PORTS or port in TLS_PORTS or port not in PORT_SERVICE):
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return data.decode("latin-1", "replace"), use_tls


def identify(host: str, port: int, banner: str, tls: bool) -> Service:
    svc = Service(host, port, PORT_SERVICE.get(port, "unknown"), banner[:600], tls=tls)
    det = fingerprints.match_service(banner, port)
    if det is not None:
        svc.product, svc.version = det.product, det.version
        if det.product == "http":
            svc.service = "https" if tls else "http"
            from webguard.detection.checks.server import SERVER_TOKENS, TOKEN_RX

            server = next((line.split(":", 1)[1].strip() for line in banner.splitlines()
                           if line.lower().startswith("server:")), "")
            for prod, ver in TOKEN_RX.findall(server):
                key = SERVER_TOKENS.get(prod.strip().lower())
                if key:
                    svc.product, svc.version = key, ver
                    break
            else:
                svc.product = None
    return svc


def findings_for(svc: Service) -> list[Finding]:
    url = f"tcp://{svc.host}:{svc.port}"
    out: list[Finding] = []
    if svc.product and svc.version:
        out += cve.findings_for(svc.product, svc.version, url, f"{svc.service} banner", svc.banner)
        eol = cve.eol_finding(svc.product, svc.version, url, f"{svc.service} banner")
        if eol:
            out.append(eol)
        out.append(Finding(
            check="server", title=f"Service banner discloses version: {svc.product.replace('_', ' ')} {svc.version}",
            severity=Severity.INFO, confidence=Confidence.CERTAIN, url=url,
            evidence=svc.banner.strip().splitlines()[0][:160] if svc.banner.strip() else "",
            description="The exact version lets attackers match known vulnerabilities without probing.",
            remediation="Suppress version details in service banners where the software allows it.",
            cwe="CWE-200", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE,
            tags=["network", "banner", svc.service]))
    if svc.port in CLEARTEXT and svc.banner:
        out.append(Finding(
            check="server", title=f"Cleartext {CLEARTEXT[svc.port]} service exposed", severity=Severity.MEDIUM,
            confidence=Confidence.CERTAIN, url=url, evidence=svc.banner.strip().splitlines()[0][:160],
            description=f"{CLEARTEXT[svc.port]} sends credentials and data unencrypted.",
            remediation="Disable the cleartext protocol or require TLS (FTPS/SFTP, POP3S/IMAPS, SSH).",
            cwe="CWE-319", owasp="A02:2021-Cryptographic Failures", detection=PASSIVE,
            tags=["network", "cleartext", svc.service]))
    return out


async def audit(host: str, ports: list[int] | None = None, concurrency: int = 50) -> tuple[list[Service], list[Finding]]:
    open_ports = await port_scan(host, ports or TOP_PORTS)
    sem = asyncio.Semaphore(concurrency)

    async def one(port: int) -> Service:
        async with sem:
            banner, tls = await grab(host, port)
        return identify(host, port, banner, tls)

    services = await asyncio.gather(*(one(p) for p in open_ports))
    findings = exposed_service_findings(host, open_ports)
    for svc in services:
        findings += findings_for(svc)
    return list(services), findings


def parse_ports(spec: str | None) -> list[int] | None:
    """'top' / None -> default list; '22,80,8000-8100' -> explicit ports."""
    if not spec or spec == "top":
        return None
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            out += range(int(a), int(b) + 1)
        elif part.strip():
            out.append(int(part))
    return sorted({p for p in out if 0 < p < 65536})
