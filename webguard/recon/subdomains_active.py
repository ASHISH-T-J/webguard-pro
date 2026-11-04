"""Active subdomain enumeration: DNS brute force, permutations and zone-transfer check.

* **Brute force** of a label wordlist (``data/wordlists/subdomains.txt`` or ``--sub-wordlist``).
* **Permutations** of labels already found (dev-api, api-staging, api2, staging.api, ...), the way new
  environments are usually named.
* **Wildcard DNS** is detected first (random labels that resolve); names that only resolve to the wildcard
  addresses are discarded, so a ``*.example.com`` record cannot flood the results.
* **Zone transfer (AXFR)** is attempted against each authoritative name server (needs dnspython). A
  successful transfer is itself a finding and lists every name in the zone.

Only DNS queries are sent; no HTTP traffic.
"""

from __future__ import annotations

import asyncio
import random
import string

from webguard.config import DATA_DIR
from webguard.models import SIGNATURE, Confidence, Finding, Severity
from webguard.recon.active import resolve_many

WORDLIST = DATA_DIR / "wordlists" / "subdomains.txt"
ENV_WORDS = ("dev", "staging", "stage", "stg", "test", "qa", "uat", "preprod", "prod", "beta", "internal", "old",
             "new", "admin", "api", "v2", "backup", "demo", "sandbox")


def _rand_label() -> str:
    return "wg" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


async def wildcard_ips(domain: str) -> set[str]:
    res = await resolve_many([f"{_rand_label()}.{domain}" for _ in range(3)])
    return {ip for ips in res.values() for ip in ips}


def permutations(found: set[str], domain: str, limit: int = 1500) -> list[str]:
    out: list[str] = []
    for name in sorted(found):
        if not name.endswith("." + domain):
            continue
        label = name[: -len(domain) - 1]
        first = label.split(".")[0]
        rest = label[len(first):]
        for e in ENV_WORDS:
            if e == first:
                continue
            out += [f"{first}-{e}{rest}", f"{e}-{first}{rest}", f"{e}.{label}"]
        out += [f"{first}{n}{rest}" for n in (1, 2, 3)]
    cands = [f"{x}.{domain}" for x in dict.fromkeys(out)]
    return [c for c in cands if c not in found][:limit]


async def zone_transfer(domain: str) -> tuple[list[str], Finding | None]:
    try:
        import dns.query
        import dns.resolver
        import dns.zone
    except ImportError:
        return [], None
    loop = asyncio.get_running_loop()

    def attempt() -> tuple[list[str], str | None]:
        try:
            ns = [str(r.target).rstrip(".") for r in dns.resolver.resolve(domain, "NS")]
        except Exception:
            return [], None
        for server in ns:
            try:
                addr = str(dns.resolver.resolve(server, "A")[0])
                zone = dns.zone.from_xfr(dns.query.xfr(addr, domain, timeout=8, lifetime=15))
                names = sorted({f"{n}.{domain}" for n in zone.nodes if str(n) not in ("@", "*")})
                return names, server
            except Exception:
                continue
        return [], None

    names, server = await loop.run_in_executor(None, attempt)
    if not server:
        return [], None
    return names, Finding(
        check="exposure", title="DNS zone transfer (AXFR) allowed", severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN, url=f"dns://{server}/{domain}",
        evidence=f"{server} returned the full zone for {domain}: {len(names)} name(s)",
        description="Anyone can download the complete DNS zone, revealing internal host names and the whole "
                    "attack surface.", remediation="Restrict AXFR to secondary name servers (allow-transfer / "
                    "TSIG).", cwe="CWE-200", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
        tags=["dns", "axfr", "recon"], context={"phase": "recon"})


async def enumerate_active(domain: str, known: set[str], words: list[str] | None = None, status=print,
                           concurrency: int = 100) -> tuple[dict[str, list[str]], list[Finding]]:
    """Returns ({name: ips} for newly found names, findings)."""
    findings: list[Finding] = []
    wild = await wildcard_ips(domain)
    if wild:
        status(f"  wildcard DNS detected for *.{domain} ({', '.join(sorted(wild)[:3])}) - filtering those answers")
    axfr, f = await zone_transfer(domain)
    if f:
        findings.append(f)
        status(f"  zone transfer allowed: {len(axfr)} name(s)")
    if words is None:
        words = [w.strip() for w in WORDLIST.read_text().splitlines() if w.strip() and not w.startswith("#")]
    cands = [n for n in dict.fromkeys([*axfr, *(f"{w}.{domain}" for w in words)]) if n not in known]
    status(f"  DNS brute force: {len(cands)} candidate name(s)")
    found = {h: ips for h, ips in (await resolve_many(cands, concurrency)).items()
             if ips and not set(ips) <= wild}
    perms = permutations(set(known) | set(found), domain)
    if perms:
        status(f"  permutations of {len(set(known) | set(found))} known name(s): {len(perms)} candidate(s)")
        found.update({h: ips for h, ips in (await resolve_many(perms, concurrency)).items()
                      if ips and not set(ips) <= wild and h not in known})
    return found, findings
