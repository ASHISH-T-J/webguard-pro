"""Passive checks applied to every crawled response (no extra requests)."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from webguard.detection.context import Context
from webguard.http import Resp
from webguard.models import PASSIVE, Confidence, Finding, Severity

SECRET_REMEDIATION = (
    "Revoke and rotate the credential immediately, remove it from client-side code / responses, and "
    "move secrets to server-side configuration or a secret manager."
)


def disclosure(ctx: Context, resp: Resp, baseline_text: str = "") -> None:
    for m in ctx.sigdb.match_disclosure(resp.text):
        if m.value in baseline_text:
            continue
        ctx.report(Finding(
            check="disclosure", title=m.name, severity=Severity.parse(m.meta.get("severity", "INFO")),
            confidence=Confidence.FIRM, url=resp.url.split("#")[0], evidence=m.value,
            description="The response discloses internal implementation details (stack traces, debug output, "
                        "paths) that help attackers fingerprint and exploit the application.",
            remediation="Disable debug mode in production and return generic error pages; log details server-side.",
            cwe=m.meta.get("cwe"), owasp="A05:2021-Security Misconfiguration", detection=PASSIVE,
            tags=["disclosure"],
        ))


def secrets(ctx: Context, resp: Resp) -> None:
    for m in ctx.sigdb.match_secrets(resp.text):
        sev = Severity.parse(m.meta.get("severity", "MEDIUM"))
        if sev == Severity.INFO and m.name == "Internal IP Address" and urlsplit(resp.url).hostname == m.value:
            continue
        masked = m.value if len(m.value) <= 12 else m.value[:6] + "…" + m.value[-4:]
        ctx.report(Finding(
            check="secrets", title=f"Exposed secret: {m.name}", severity=sev,
            confidence=Confidence.FIRM if sev >= Severity.MEDIUM else Confidence.TENTATIVE,
            url=resp.url.split("#")[0] + f"#secret-{hashlib.sha1(m.value.encode()).hexdigest()[:10]}", evidence=f"{m.name}: {masked}",
            description=f"A {m.name} is exposed in a publicly reachable response. Validate whether it is live "
                        "and what it grants access to (only within program rules).",
            remediation=SECRET_REMEDIATION, cwe="CWE-798", owasp="A07:2021-Identification and Authentication Failures",
            detection=PASSIVE, tags=["secrets", m.name.lower().replace(" ", "-")],
        ))


def directory_listing(ctx: Context, resp: Resp) -> None:
    head = resp.text[:3000]
    if resp.status == 200 and ("<title>Index of /" in head or "<h1>Directory listing for" in head):
        ctx.report(Finding(
            check="exposure", title="Directory listing enabled", severity=Severity.LOW, confidence=Confidence.CERTAIN,
            url=resp.url, evidence="Auto-generated directory index page.",
            description="The web server lists directory contents, exposing files that are not linked anywhere.",
            remediation="Disable auto-indexing (Options -Indexes / autoindex off).",
            cwe="CWE-548", owasp="A05:2021-Security Misconfiguration", detection=PASSIVE, tags=["exposure"],
        ))
