"""Result analysis: de-duplication by root cause, attack-chain detection and contextual risk scoring.

A scanner reports symptoms; a professional reports *issues*. Ten reflected-XSS hits caused by
one shared template are one issue with ten affected locations. Several individually medium
issues can combine into a critical attack path (e.g. XSS + session cookie without HttpOnly =
account takeover). This module does that reasoning over the finding list.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from webguard.models import Confidence, Finding, Severity

# CVSS 3.1 base vectors per check (typical worst case; adjusted by context below)
CVSS = {
    "sqli": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), "auth": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "cmdi": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), "ssti": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "xxe": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5), "lfi": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "nosqli": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2), "ssrf": ("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
    "xss": ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1), "dom_xss": ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "redirect": ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1), "crlf": ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "cors": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3), "data_exposure": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "jwt": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1), "secrets": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "idor": ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5), "access": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5),
    "host_header": ("AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 5.4), "takeover": ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "csrf": ("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3), "exposure": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "deserialization": ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1), "graphql": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "headers": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1), "disclosure": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
}


@dataclass
class Issue:
    """A root-cause issue grouping one or more findings."""

    key: str
    title: str
    check: str
    severity: Severity
    confidence: Confidence
    findings: list[Finding] = field(default_factory=list)
    cvss_vector: str = ""
    cvss: float = 0.0
    risk: float = 0.0

    @property
    def locations(self) -> list[str]:
        return sorted({f.url + (f" [{f.parameter}]" if f.parameter else "") for f in self.findings})


def _root_cause_key(f: Finding) -> str:
    base = f.check.split(":")[0]
    host = urlsplit(f.url).netloc
    if base in ("headers", "cors", "csrf", "jwt", "disclosure"):
        return f"{base}|{host}|{f.title}"
    if base in ("xss", "sqli", "ssti", "cmdi", "lfi", "nosqli", "redirect", "crlf", "ssrf"):
        # same parameter name across endpoints of one host -> usually one shared handler/template
        return f"{base}|{host}|{f.parameter or ''}"
    return f"{base}|{f.fingerprint}"


def cluster(findings: list[Finding]) -> list[Issue]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[_root_cause_key(f)].append(f)
    issues = []
    for key, group in groups.items():
        worst = max(group, key=lambda f: (f.severity, f.confidence))
        base = worst.check.split(":")[0]
        vector, score = CVSS.get(base, ("", 0.0))
        issue = Issue(key, worst.title, base, worst.severity, worst.confidence, group, vector, score)
        # risk = severity x confidence x ML true-positive probability x breadth
        ml = worst.ml_score if worst.ml_score is not None else 0.7
        breadth = min(1.5, 1 + 0.1 * (len(group) - 1))
        issue.risk = round((int(worst.severity) + 1) * (int(worst.confidence) + 1) * ml * breadth, 2)
        issues.append(issue)
    return sorted(issues, key=lambda i: -i.risk)


CHAINS = [
    ({"xss"}, lambda fs: any(f.check == "headers" and "missing flags" in f.title and "HttpOnly" in f.evidence for f in fs),
     "Account takeover: XSS + session cookie readable by JavaScript", Severity.CRITICAL,
     "Steal the session cookie with the XSS payload (document.cookie) and replay it."),
    ({"xss", "dom_xss"}, lambda fs: any(f.check == "cors" for f in fs),
     "Cross-origin data theft: XSS combined with permissive CORS", Severity.HIGH,
     "Use the XSS foothold to issue credentialed cross-origin API calls and exfiltrate responses."),
    ({"redirect"}, lambda fs: any("oauth" in f.url.lower() or "callback" in f.url.lower() or "authorize" in f.url.lower() for f in fs),
     "OAuth token theft via open redirect", Severity.HIGH,
     "Abuse the open redirect as redirect_uri to leak authorization codes/tokens to an attacker host."),
    ({"redirect"}, lambda fs: any(f.check == "ssrf" for f in fs),
     "SSRF filter bypass via open redirect", Severity.HIGH,
     "Point the SSRF parameter at the trusted open-redirect URL to reach internal hosts."),
    ({"data_exposure"}, lambda fs: any("MD5" in f.evidence or "SHA-1" in f.evidence for f in fs),
     "Credential compromise: weak password hashes exposed", Severity.CRITICAL,
     "Crack exposed unsalted hashes offline and log in as the affected users (including admins)."),
    ({"jwt"}, lambda fs: any("cracked" in f.evidence for f in fs),
     "Privilege escalation: forge JWTs with cracked signing secret", Severity.CRITICAL,
     "Sign a token with role=admin / another user id using the recovered secret."),
    ({"lfi", "xxe"}, lambda fs: any(f.check in ("exposure", "disclosure") for f in fs),
     "Source/credential disclosure: file read + known file locations", Severity.HIGH,
     "Use paths leaked by error pages/exposed files to read configuration and credentials via the file-read bug."),
    ({"auth"}, lambda fs: True,
     "Administrative access: authentication bypass", Severity.CRITICAL,
     "Log in as the first account in the user table (typically admin) and use admin functionality."),
    ({"host_header"}, lambda fs: any("reset" in f.url.lower() or "forgot" in f.url.lower() for f in fs),
     "Password reset poisoning", Severity.HIGH,
     "Trigger a reset for the victim with a poisoned host; the reset token is sent to the attacker host."),
    ({"secrets"}, lambda fs: any(f.check == "secrets" and f.severity >= Severity.HIGH for f in fs),
     "Cloud/third-party account access via leaked credentials", Severity.CRITICAL,
     "Validate the leaked key (within program rules) and enumerate the permissions it grants."),
]


def attack_chains(findings: list[Finding]) -> list[dict]:
    present = {f.check.split(":")[0] for f in findings}
    chains = []
    for needed, extra, title, sev, path in CHAINS:
        if needed & present and extra(findings):
            parts = [f for f in findings if f.check.split(":")[0] in needed][:3]
            chains.append({"title": title, "severity": sev.name, "steps": path,
                           "findings": [f"{f.title} @ {f.url}" for f in parts]})
    return sorted(chains, key=lambda c: -Severity[c["severity"]])


def false_positive_signals(f: Finding) -> list[str]:
    """Heuristic red flags a reviewer would double-check."""
    flags = []
    if f.detection == "timing":
        flags.append("timing-based: re-run under low load")
    if f.confidence == Confidence.TENTATIVE:
        flags.append("tentative: needs manual verification")
    if f.ml_score is not None and f.ml_score < 0.4:
        flags.append(f"low ML true-positive probability ({f.ml_score})")
    if f.check == "secrets" and any(w in f.evidence.lower() for w in ("example", "test", "demo", "sample")):
        flags.append("secret looks like sample data")
    return flags
