"""Natural-language queries over findings.

    "critical and high sql injection on api hosts"
    "xss with certain confidence"
    "new findings in example.com excluding headers"
    "secrets in javascript"

Parsed into a structured filter with keyword/synonym matching (no external model needed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from webguard.models import Confidence, Finding, Severity

CHECK_SYNONYMS = {
    "sqli": ["sql", "sqli", "sql injection", "database injection"],
    "nosqli": ["nosql", "mongo", "nosqli"],
    "xss": ["xss", "cross site scripting", "cross-site scripting", "script injection"],
    "dom_xss": ["dom xss", "dom-based", "client side xss"],
    "ssti": ["ssti", "template injection", "template"],
    "lfi": ["lfi", "path traversal", "file inclusion", "traversal", "directory traversal"],
    "cmdi": ["command injection", "rce", "os command", "cmdi", "remote code"],
    "ssrf": ["ssrf", "server side request", "request forgery"],
    "xxe": ["xxe", "xml external", "xml"],
    "redirect": ["redirect", "open redirect"],
    "crlf": ["crlf", "header injection", "response splitting"],
    "cors": ["cors", "cross origin"],
    "headers": ["header", "headers", "hardening", "cookie", "csp"],
    "exposure": ["exposure", "exposed", "leak", "backup", "git", "listing", "sensitive file"],
    "secrets": ["secret", "secrets", "key", "token", "credential", "credentials", "api key"],
    "disclosure": ["disclosure", "stack trace", "debug", "error message"],
    "auth": ["auth", "authentication", "login", "bypass"],
    "jwt": ["jwt", "json web token"],
    "idor": ["idor", "authorization", "access control", "object level"],
    "takeover": ["takeover", "subdomain takeover", "dangling"],
    "anomaly": ["anomaly", "anomalies", "lead", "leads", "hunting"],
    "data_exposure": ["pii", "personal data", "password hash", "hashes", "data exposure"],
    "csrf": ["csrf", "cross site request"],
    "host_header": ["host header", "cache poisoning", "poisoning"],
    "access": ["403", "forbidden", "bypass"],
    "graphql": ["graphql"],
    "deserialization": ["deserialization", "serialized", "serialization"],
}
LOCATION_WORDS = {"api": r"/(?:api|rest|v\d+|graphql)/", "javascript": r"\.js(?:$|#|\?)", "js": r"\.js(?:$|#|\?)",
                  "admin": r"admin", "login": r"log[-_]?in|sign[-_]?in|auth"}


@dataclass
class Query:
    checks: set[str] = field(default_factory=set)
    exclude_checks: set[str] = field(default_factory=set)
    severities: set[Severity] = field(default_factory=set)
    min_severity: Severity | None = None
    confidence: set[Confidence] = field(default_factory=set)
    url_patterns: list[str] = field(default_factory=list)
    host: str | None = None
    text: list[str] = field(default_factory=list)

    def matches(self, f: Finding) -> bool:
        base = f.check.split(":")[0]
        if self.checks and base not in self.checks:
            return False
        if base in self.exclude_checks:
            return False
        if self.severities and f.severity not in self.severities:
            return False
        if self.min_severity is not None and f.severity < self.min_severity:
            return False
        if self.confidence and f.confidence not in self.confidence:
            return False
        if self.host and self.host not in f.url:
            return False
        if any(not re.search(p, f.url, re.I) for p in self.url_patterns):
            return False
        blob = f"{f.title} {f.evidence} {f.url} {f.parameter or ''}".lower()
        return all(t in blob for t in self.text)


def parse(q: str) -> Query:
    q = q.lower().strip()
    out = Query()
    excl = re.split(r"\b(?:excluding|except|without|but not|not)\b", q, maxsplit=1)
    main, rest = excl[0], (excl[1] if len(excl) > 1 else "")
    for check, words in CHECK_SYNONYMS.items():
        for w in sorted(words, key=len, reverse=True):
            if re.search(rf"\b{re.escape(w)}\b", main):
                out.checks.add(check)
                break
            if rest and re.search(rf"\b{re.escape(w)}\b", rest):
                out.exclude_checks.add(check)
                break
    for sev in Severity:
        if re.search(rf"\b{sev.name.lower()}\b", main):
            out.severities.add(sev)
    m = re.search(r"\b(critical|high|medium|low)\s*(?:and|or)?\s*(?:above|\+|or higher|and up)", main)
    if m:
        out.severities.clear()
        out.min_severity = Severity.parse(m.group(1))
    if re.search(r"\b(serious|important|severe)\b", main) and not out.severities:
        out.min_severity = Severity.HIGH
    for conf in Confidence:
        if re.search(rf"\b{conf.name.lower()}\b", main) or (conf == Confidence.CERTAIN and "confirmed" in main):
            out.confidence.add(conf)
    for word, pattern in LOCATION_WORDS.items():
        if re.search(rf"\b(?:on|in|at)\s+(?:the\s+)?{word}\b", main):
            out.url_patterns.append(pattern)
    m = re.search(r"\b(?:on|in|for)\s+([a-z0-9.-]+\.[a-z]{2,})\b", main)
    if m:
        out.host = m.group(1)
    for quoted in re.findall(r"\"([^\"]+)\"|'([^']+)'", q):
        out.text.append((quoted[0] or quoted[1]).lower())
    return out


def search(findings: list[Finding], q: str) -> list[Finding]:
    query = parse(q)
    return [f for f in findings if query.matches(f)]
