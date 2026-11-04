"""Natural-language generation of assessment narratives (template + content selection).

Produces an executive summary a client can read without security background, and a
technical summary for engineers. Used when no LLM backend is configured; when one is, the
LLM output is preferred but these facts are still passed to it as grounding.
"""

from __future__ import annotations

from collections import Counter

from webguard.models import Finding, Severity

PLAIN = {
    "sqli": "attackers could read or change data in the database",
    "nosqli": "attackers could manipulate database queries",
    "xss": "attackers could run malicious scripts in users' browsers and hijack their sessions",
    "dom_xss": "attackers could run malicious scripts in users' browsers via crafted links",
    "ssti": "attackers could likely execute code on the server",
    "cmdi": "attackers could execute operating-system commands on the server",
    "lfi": "attackers could read files from the server, such as configuration and source code",
    "xxe": "attackers could read server files through XML processing",
    "ssrf": "the server could be abused to reach internal systems",
    "redirect": "the site could be used to redirect victims to phishing pages",
    "crlf": "attackers could inject HTTP headers into responses",
    "cors": "other websites could read data from this application on behalf of logged-in users",
    "auth": "the login could be bypassed without valid credentials",
    "jwt": "authentication tokens are weak or leak sensitive data",
    "secrets": "credentials or API keys are exposed publicly",
    "data_exposure": "sensitive personal data or password hashes are exposed",
    "exposure": "sensitive files or internal endpoints are publicly reachable",
    "takeover": "a subdomain could be taken over by an attacker",
    "idor": "users may be able to access other users' records",
    "host_header": "responses can be poisoned via manipulated Host headers",
    "access": "access controls on restricted pages can be bypassed",
    "csrf": "actions could be triggered on behalf of users from other websites",
    "headers": "browser security hardening is incomplete",
    "disclosure": "error messages reveal internal implementation details",
    "deserialization": "serialized objects are exposed, a common remote-code-execution vector",
    "graphql": "the GraphQL API exposes more of its schema than necessary",
}


def _risk_rating(findings: list[Finding]) -> str:
    if not findings:
        return "Low"
    worst = max(f.severity for f in findings)
    return {Severity.CRITICAL: "Critical", Severity.HIGH: "High", Severity.MEDIUM: "Moderate"}.get(worst, "Low")


def executive_summary(target: str, findings: list[Finding], chains: list[dict] | None = None,
                      coverage: dict[str, str] | None = None) -> str:
    real = [f for f in findings if f.severity >= Severity.LOW and f.check != "anomaly"]
    counts = Counter(f.severity.name for f in real)
    rating = _risk_rating(real)
    parts = [f"The assessment of {target} resulted in an overall risk rating of **{rating}**."]
    if not real:
        parts.append("No exploitable vulnerabilities were confirmed within the tested scope.")
    else:
        sev_txt = ", ".join(f"{counts[s]} {s.lower()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s))
        parts.append(f"{len(real)} issues were identified ({sev_txt}).")
        top = sorted(real, key=lambda f: (-f.severity, -f.confidence))
        seen, impacts = set(), []
        for f in top:
            base = f.check.split(":")[0]
            if base in seen or f.severity < Severity.MEDIUM:
                continue
            seen.add(base)
            impacts.append(PLAIN.get(base, f.title.lower()))
            if len(impacts) == 4:
                break
        if impacts:
            parts.append("The most significant risks are that " + "; ".join(impacts) + ".")
    if chains:
        parts.append(f"{len(chains)} attack chain(s) combine individual weaknesses into higher-impact scenarios, "
                     f"most notably: {chains[0]['title']}.")
    if coverage:
        tested = sum(1 for v in coverage.values() if v != "not tested")
        parts.append(f"{tested} of {len(coverage)} OWASP WSTG test areas were covered.")
    if real:
        parts.append("We recommend fixing critical and high findings immediately, re-testing, and then "
                     "addressing the remaining items as part of regular hardening.")
    return " ".join(parts)


def technical_summary(findings: list[Finding]) -> list[str]:
    lines = []
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f"{f.check.split(':')[0]}|{f.title}", []).append(f)  # group by root cause
    for _check, group in sorted(by_check.items(), key=lambda kv: -max(f.severity for f in kv[1])):
        worst = max(group, key=lambda f: (f.severity, f.confidence))
        where = ", ".join(sorted({(f.url.split('?')[0] + (f' [{f.parameter}]' if f.parameter else '')) for f in group})[:3])
        more = f" (+{len(group) - 3} more)" if len(group) > 3 else ""
        lines.append(f"{worst.severity.name}: {worst.title} - {len(group)} instance(s) at {where}{more}")
    return lines
