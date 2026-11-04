"""Additional injection classes from OWASP WSTG / PortSwigger:

* LDAP injection (WSTG-INPV-06) - filter-breaking characters trigger LDAP errors.
* XPath injection (WSTG-INPV-09) - quote/predicate breaking triggers XPath errors.
* XInclude (PortSwigger "Exploiting XInclude to retrieve files") - a plain parameter that the server embeds
  into an XML document; we cannot add a DOCTYPE, but an xi:include element still reads local files.

All are confirmed by evidence absent from the baseline (error signatures or file contents).
"""

from __future__ import annotations

import re

from webguard.analysis.context import ERROR_TYPES
from webguard.detection.context import Context
from webguard.models import SIGNATURE, Confidence, Finding, InjectionPoint, Severity

ERR = dict(ERROR_TYPES)
LDAP_PROBES = ["*)(", ")(cn=*", "*()|&'", "\\", "*)(|(objectClass=*"]
XPATH_PROBES = ["'", '"]', "' or '", "')]", "1' and count(/*)=1 and '1'='1"]
XINCLUDE = ('<wg xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/>'
            "</wg>")
PASSWD = re.compile(r"root:[^:\n]*:0:0:")


async def _error_based(ctx: Context, point: InjectionPoint, check: str, probes: list[str], rx: re.Pattern[str],
                       title: str, cwe: str, wstg_desc: str, remediation: str) -> None:
    if ctx.has(check, point):
        return
    base = await ctx.baseline(point)
    if base is None or any(rx.search(s.text) for s in base.samples):
        return
    for probe in probes:
        payload = point.original + probe
        r = await ctx.send(point, payload)
        if r is None or not ctx.app_answered(r, point, check):
            continue
        m = rx.search(r.text)
        if m:
            ctx.report(Finding(
                check=check, title=title, severity=Severity.HIGH, confidence=Confidence.FIRM,
                url=point.url, method=point.method, parameter=point.name, location=point.location, payload=payload,
                evidence=f"Error triggered by payload: {m.group(0)[:160]}", description=wstg_desc,
                remediation=remediation, cwe=cwe, owasp="A03:2021-Injection", detection=SIGNATURE,
                tags=["injection", check], request=ctx.curl(point, payload),
            ))
            return


async def ldapi(ctx: Context, point: InjectionPoint) -> None:
    await _error_based(
        ctx, point, "ldapi", LDAP_PROBES, ERR["ldap"], "LDAP injection (error-based)", "CWE-90",
        "User input is placed into an LDAP search filter without escaping. Attackers can change the filter "
        "logic to bypass authentication or enumerate directory entries.",
        "Escape LDAP filter special characters (RFC 4515: * ( ) \\ NUL) or use a framework filter builder.")


async def xpathi(ctx: Context, point: InjectionPoint) -> None:
    await _error_based(
        ctx, point, "xpathi", XPATH_PROBES, ERR["xpath"], "XPath injection (error-based)", "CWE-643",
        "User input is concatenated into an XPath query, letting attackers alter the query to bypass "
        "authentication or read arbitrary nodes of the XML document.",
        "Use parameterised XPath (variable resolvers) or strictly validate input against an allow-list.")


async def xinclude(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("xxe", point) or point.location not in ("query", "form", "json"):
        return
    base = await ctx.baseline(point)
    if base is None or any(PASSWD.search(s.text) for s in base.samples):
        return
    r = await ctx.send(point, XINCLUDE)
    if r is not None and PASSWD.search(r.text):
        ctx.report(Finding(
            check="xxe", title="XInclude injection (file disclosure)", severity=Severity.HIGH,
            confidence=Confidence.CERTAIN, url=point.url, method=point.method, parameter=point.name,
            location=point.location, payload=XINCLUDE, evidence="xi:include of file:///etc/passwd returned its contents.",
            description="The parameter is embedded into a server-side XML document that is processed with XInclude "
                        "enabled, allowing local files to be read even without control of the DOCTYPE.",
            remediation="Disable XInclude (and DTD processing) in the XML parser; never build XML by string concatenation.",
            cwe="CWE-611", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
            references=["https://portswigger.net/web-security/xxe#xinclude-attacks"],
            tags=["xxe", "xinclude"], request=ctx.curl(point, XINCLUDE),
        ))
