"""Blind (out-of-band) detection: tests that only show up as an interaction on the OOB server.

Each probe embeds a unique, single-use callback (see :mod:`webguard.oob`); the agent polls the provider
and :func:`interaction_finding` turns a correlated interaction into a finding for the exact test, URL and
parameter that caused it.
"""

from __future__ import annotations

from webguard.detection.context import Context
from webguard.models import Confidence, Finding, InjectionPoint, Severity
from webguard.oob import Interaction, Payload

OOB = "oob"
XXE_OOB = '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY wgoob SYSTEM "{url}">]>\n<root><name>&wgoob;</name></root>'


async def blind_ssrf(ctx: Context, point: InjectionPoint) -> None:
    """URL-like input whose fetch result is not shown: does the server reach our callback?"""
    p = ctx.oob_payload("ssrf", point=point)
    if p is None:
        return
    p.label["payload"] = p.url
    p.label["request"] = ctx.curl(point, p.url)
    await ctx.send(point, p.url)


async def blind_xxe(ctx: Context, url: str, method: str = "POST") -> None:
    """XML endpoint: does the parser resolve an external entity pointing at our callback?"""
    if ctx.has("xxe", url=url):
        return
    for ctype in ("application/xml", "text/xml"):
        p = ctx.oob_payload("xxe", url=url, method=method, location="body")
        if p is None:
            return
        body = XXE_OOB.format(url=p.url)
        p.label.update(payload=body, request=ctx.client.curl(method, url, headers={"Content-Type": ctype},
                                                             content=body))
        try:
            r = await ctx.client.request(method, url, content=body, headers={"Content-Type": ctype})
        except Exception:
            return
        if r is None or r.status in (404, 405, 415):
            continue  # endpoint does not take this content type: try the next one
        return


TEMPLATES = {
    "ssrf": dict(title="Blind server-side request forgery (out-of-band interaction)", severity=Severity.HIGH,
                 cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery",
                 description="The server made a network request to a unique callback address supplied in this "
                             "input, without showing the result. It can be pointed at internal services and cloud "
                             "metadata endpoints.",
                 remediation="Allow-list destination hosts and schemes, resolve and block private / link-local "
                             "ranges after DNS resolution, disable redirects and isolate the fetcher."),
    "xxe": dict(title="Blind XML external entity injection (out-of-band interaction)", severity=Severity.HIGH,
                cwe="CWE-611", owasp="A05:2021-Security Misconfiguration",
                description="The XML parser resolved an external entity pointing at a unique callback address, "
                            "so it fetches attacker-chosen resources (file exfiltration and SSRF are possible).",
                remediation="Disable DTD processing and external entity resolution in the XML parser."),
}


def interaction_finding(payload: Payload, interactions: list[Interaction]) -> Finding:
    label = payload.label
    tpl = TEMPLATES.get(label.get("check", ""), TEMPLATES["ssrf"])
    protocols = sorted({i.protocol.lower() for i in interactions})
    remotes = sorted({i.remote for i in interactions if i.remote})
    # an HTTP request proves the target fetched the URL; a DNS lookup alone may come from a resolver,
    # proxy or link scanner on the way, so it is FIRM rather than CERTAIN
    conf = Confidence.CERTAIN if "http" in protocols or "https" in protocols else Confidence.FIRM
    first = interactions[0]
    delay = _ts(first) - payload.created if _ts(first) else None
    when = f", {max(0, int(delay))}s after the probe" if delay is not None else ""
    return Finding(
        check=label.get("check", "ssrf"), title=tpl["title"], severity=tpl["severity"], confidence=conf,
        url=label.get("url", ""), method=label.get("method", "GET"), parameter=label.get("parameter"),
        location=label.get("location"), payload=label.get("payload"),
        evidence=f"{len(interactions)} {'/'.join(protocols).upper()} interaction(s) for unique id {payload.id}"
                 + (f" from {', '.join(remotes[:3])}" if remotes else "") + when,
        description=tpl["description"], remediation=tpl["remediation"], cwe=tpl["cwe"], owasp=tpl["owasp"],
        detection=OOB, tags=[label.get("check", "ssrf"), "oob", "blind"], request=label.get("request"),
        context={"oob": {"id": payload.id, "protocols": protocols, "remote": remotes[:5],
                         "raw": first.raw[:600]}})


def _ts(it: Interaction) -> float:
    import datetime as dt

    try:
        return dt.datetime.fromisoformat(it.timestamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0
