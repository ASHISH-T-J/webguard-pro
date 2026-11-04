"""Hunting helpers: ML anomaly fuzzing and hidden-parameter discovery."""

from __future__ import annotations

import asyncio
import re

from webguard.config import DATA_DIR
from webguard.detection import anomaly
from webguard.detection.baseline import features, similarity
from webguard.detection.context import Context, token
from webguard.models import ANOMALY, Confidence, Finding, InjectionPoint, Severity

VALIDATION = re.compile(r"(?i)invalid|not allowed|illegal|must (?:be|start with|end with|contain)|is required|"
                        r"validation|malformed|bad request|"
                        r"unexpected (?:value|character)|out of range|not a valid|unsupported")


async def anomaly_fuzz(ctx: Context, point: InjectionPoint) -> None:
    confirmed = any(f.parameter == point.name and f.url == point.url and f.location == point.location
                    for f in ctx.findings.values())
    if confirmed:  # a concrete vulnerability already explains this parameter's behaviour
        return
    base = await ctx.baseline(point)
    if base is None:
        return
    benign_vecs = []
    for value in anomaly.benign_values(point.original):
        r = await ctx.send(point, value)
        if r is not None:
            benign_vecs.append(features(r, base.primary, [value]))
    benign_vecs += [features(s, base.primary) for s in base.samples]
    probe_vecs = []
    statuses = {}
    for name, payload in anomaly.PROBES:
        value = point.original + payload
        r = await ctx.send(point, value)
        if r is not None and 400 <= r.status < 500 and VALIDATION.search(r.text[:5000]):
            continue  # the app cleanly rejected the input: correct validation, not an anomaly
        if r is not None and ctx.app_answered(r, point, "anomaly"):  # blocked probes are not app behaviour
            probe_vecs.append((name, value, features(r, base.primary, [value])))
            statuses[name] = r.status
    results = anomaly.score(benign_vecs, probe_vecs)
    hits = [res for res in results if res.is_anomalous]
    if not hits or len(hits) > 0.6 * len(results):
        # nothing unusual, or the parameter rejects *any* non-trivial input (strict validation) - not a lead
        return
    server_errors = [h for h in hits if statuses.get(h.probe, 0) >= 500]
    if len(hits) < 2 and not server_errors:
        return  # one slightly different echo is noise; leads need repeated deviation or a server error
    sev = Severity.LOW if server_errors else Severity.INFO
    detail = "; ".join(
        f"{h.probe} (score {h.score:.1f}{', HTTP ' + str(statuses.get(h.probe)) if statuses.get(h.probe) else ''}: "
        + ", ".join(f"{f}={z:+.1f}σ" for f, z in h.top_features) + ")"
        for h in sorted(hits, key=lambda h: -h.score)[:6]
    )
    ctx.report(Finding(
        check="anomaly",
        title="Anomalous input handling" + (" (server errors)" if server_errors else ""),
        severity=sev, confidence=Confidence.TENTATIVE,
        url=point.url, method=point.method, parameter=point.name, location=point.location,
        payload=hits[0].payload,
        evidence=f"{len(hits)}/{len(results)} probes deviate from benign behaviour: {detail}",
        description="Machine-learning anomaly detection (IsolationForest + robust z-scores over response "
                    "features) found inputs that change the application's behaviour in ways benign values do "
                    "not. This is a hunting lead: probe these characters manually for injection bugs.",
        remediation="Review how this parameter is parsed and used; ensure invalid input is handled uniformly.",
        cwe="CWE-20", detection=ANOMALY, tags=["anomaly", "hunting"] + [h.probe for h in hits[:5]],
        request=ctx.curl(point, hits[0].payload),
        features={"hits": float(len(hits)), "max_score": max(h.score for h in hits),
                  "server_errors": float(len(server_errors))},
    ))


def _param_words() -> list[str]:
    path = DATA_DIR / "wordlists" / "params.txt"
    return [w.strip() for w in path.read_text().splitlines() if w.strip()]


async def discover_params(ctx: Context, url: str, method: str = "GET", known: dict[str, str] | None = None,
                          chunk: int = 30) -> list[InjectionPoint]:
    """Arjun-style hidden parameter discovery: batch candidate params, bisect chunks that change the page."""
    known = dict(known or {})
    probe_point = InjectionPoint(url=url, method=method, location="query", name="__wg__", params=dict(known))
    base = await ctx.baseline(probe_point)
    if base is None or base.stable_similarity < 0.85:
        return []
    words = [w for w in _param_words() if w not in known]

    async def changed(names: list[str]) -> bool:
        params = dict(known)
        values = {n: token(5) for n in names}
        params.update(values)
        try:
            r = await ctx.client.request(method, url, params=params)
        except Exception:
            return False
        if r is None:
            return False
        if any(v in r.text for v in values.values()):
            return True
        if r.status != base.primary.status:
            return True
        return similarity(r.text, base.primary.text, list(values.values())) < base.stable_similarity - 0.05

    found: list[str] = []

    async def bisect(names: list[str]) -> None:
        if not await changed(names):
            return
        if len(names) == 1:
            found.append(names[0])
            return
        mid = len(names) // 2
        await bisect(names[:mid])
        await bisect(names[mid:])

    for i in range(0, len(words), chunk):
        await bisect(words[i : i + chunk])
        if len(found) > 15:  # page reacts to everything - stop
            return []
    points = []
    for name in found:
        params = dict(known)
        params[name] = "1"
        points.append(InjectionPoint(url=url, method=method, location="query", name=name, params=params,
                                     source="param-discovery"))
        ctx.report(Finding(
            check="anomaly", title="Hidden parameter discovered", severity=Severity.INFO,
            confidence=Confidence.FIRM, url=url, method=method, parameter=name, location="query",
            evidence=f"Adding '{name}' changes the response (reflection or content difference).",
            description="An unlinked parameter influences the response. Hidden parameters frequently expose "
                        "debug features, mass assignment or unvalidated input paths.",
            remediation="Remove unused parameters and validate all accepted input.",
            detection=ANOMALY, tags=["hunting", "param-discovery"],
        ))
    return points


async def content_discovery(ctx: Context, root: str, words: list[str]) -> list[tuple[str, int]]:  # noqa: C901
    """Soft-404-aware path brute force (ffuf-style auto-calibration, built in).

    Returns [(url, status)] for paths that are not the site's generic not-found / SPA fallback page.
    """
    from webguard.detection.checks.host import soft404

    fps = await soft404(ctx, root)
    fp_locations = {fp.headers.get("location") for fp in fps if fp.headers.get("location")}
    found: list[tuple[str, int]] = []

    async def probe(word: str) -> None:
        url = f"{root}/{word.lstrip('/')}"
        r = await ctx.client.safe_get(url)
        if r is None or r.status in (404, 400, 405, 410, 429, 500, 502, 503):
            return
        if r.status in (301, 302, 303, 307, 308) and r.headers.get("location", "") in fp_locations:
            return  # redirects exactly where random paths redirect (e.g. to the login page)
        for fp in fps:
            if fp.status == r.status and similarity(fp.text, r.text, [word]) > 0.9:
                return  # same as a random path -> soft 404 / SPA catch-all
        found.append((url, r.status))

    await asyncio.gather(*(probe(w) for w in words))
    if found:
        listing = ", ".join(f"/{u.split('/', 3)[-1]} ({s})" for u, s in sorted(found)[:40])
        ctx.report(Finding(
            check="exposure", title="Unlinked content discovered", severity=Severity.INFO, confidence=Confidence.FIRM,
            url=root + "/#content-discovery", evidence=f"{len(found)} path(s): {listing}",
            description="Paths not linked from the application respond with real content. Review them for "
                        "sensitive files, admin functionality and forgotten endpoints.",
            remediation="Remove unused content from production and protect administrative paths.",
            cwe="CWE-538", detection=ANOMALY, tags=["hunting", "content-discovery"],
        ))
    return found
