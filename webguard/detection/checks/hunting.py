"""Hunting helpers: ML anomaly fuzzing and hidden-parameter discovery."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from webguard.config import DATA_DIR
from webguard.detection import anomaly
from webguard.detection.baseline import features, similarity
from webguard.detection.context import Context, token
from webguard.http import Resp
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
                          chunk: int = 30, extra_words: list[str] = ()) -> list[InjectionPoint]:
    """Arjun-style hidden parameter discovery: batch candidate params, bisect chunks that change the page."""
    known = dict(known or {})
    probe_point = InjectionPoint(url=url, method=method, location="query", name="__wg__", params=dict(known))
    base = await ctx.baseline(probe_point)
    if base is None or base.stable_similarity < 0.85:
        return []
    # site-specific names first (seen in JSON / forms / JS of this application), then the generic list
    words = [w for w in dict.fromkeys([*extra_words, *_param_words()]) if w not in known]

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


REDIRECT = (301, 302, 303, 307, 308)
NOT_FOUND = (404, 400, 405, 410, 429, 500, 502, 503)


async def _calibrate(ctx: Context, base: str) -> list[Resp]:
    """Soft-404 fingerprints for one directory (catch-alls often differ per directory)."""
    out = []
    for name in (token(), token() + ".php", "." + token()):
        r = await ctx.client.safe_get(f"{base}/{name}")
        if r is not None:
            out.append(r)
    return out


def _is_dir(url: str, r: Resp) -> bool:
    """Directory evidence: redirect to the trailing-slash form, an index listing, or a forbidden directory."""
    last = url.rstrip("/").rsplit("/", 1)[-1]
    if "." in last:
        return False  # file-like name
    if r.status in REDIRECT:
        loc = r.headers.get("location", "")
        return loc.rstrip("?").endswith(f"/{last}/") or loc.split("?")[0].endswith(f"{urlsplit(url).path}/")
    return r.status in (200, 401, 403)


async def content_discovery(ctx: Context, root: str, words: list[str], depth: int = 1, max_dirs: int = 12,
                            deep_words: int = 400, bypass_limit: int = 10) -> list[tuple[str, int]]:  # noqa: C901
    """Recursive, soft-404-aware path brute force (ffuf/dirsearch-style recursion, auto-calibrated per directory).

    Level 0 brute-forces ``words`` under the root. Directories found (redirect to ``dir/``, listing, 401/403)
    are queued and brute-forced again up to ``depth`` levels, most interesting first (NLP path classifier:
    admin / api / backup / config directories before static assets), using the first ``deep_words``
    words at deeper levels. Every 401/403 directory or file is handed to the 403-bypass check.
    Returns [(url, status)] for paths that are not the site's generic not-found / SPA fallback page.
    """
    from webguard.detection.checks.advanced import forbidden_bypass
    from webguard.nlp.paths import classify_path, recursion_priority

    found: list[tuple[str, int]] = []
    blocked: dict[str, Resp] = {}
    queue: list[tuple[str, int]] = [(root, 0)]
    visited: set[str] = set()
    dirs_scanned = 0
    while queue and dirs_scanned < max_dirs + 1:
        base, level = queue.pop(0)
        if base in visited:
            continue
        visited.add(base)
        dirs_scanned += 1
        fps = await _calibrate(ctx, base)
        fp_locations = {fp.headers.get("location") for fp in fps if fp.headers.get("location")}
        batch = words if level == 0 else words[:deep_words]
        new_dirs: list[str] = []

        async def probe(word: str, base: str = base, fps: list[Resp] = fps, fp_locations: set = fp_locations,
                        new_dirs: list[str] = new_dirs, level: int = level) -> None:
            url = f"{base}/{word.strip('/')}"
            r = await ctx.client.safe_get(url)
            if r is None or r.status in NOT_FOUND:
                return
            if r.status in REDIRECT and r.headers.get("location", "") in fp_locations:
                return  # redirects exactly where random paths redirect (e.g. to the login page)
            for fp in fps:
                if fp.status == r.status and similarity(fp.text, r.text, [word]) > 0.9:
                    return  # same as a random path -> soft 404 / SPA catch-all
            found.append((url, r.status))
            if r.status in (401, 403):
                blocked[url] = r
            if level < depth and _is_dir(url, r):
                new_dirs.append(url)

        await asyncio.gather(*(probe(w) for w in batch))
        for d in sorted(new_dirs, key=recursion_priority):
            queue.append((d.rstrip("/"), level + 1))
    if found:
        cats: dict[str, list[str]] = {}
        for u, st in sorted(found):
            cats.setdefault(classify_path(u)[0], []).append(f"/{u.split('/', 3)[-1]} ({st})")
        listing = "; ".join(f"{c}: {', '.join(v[:12])}" for c, v in sorted(cats.items()))
        ctx.report(Finding(
            check="exposure", title="Unlinked content discovered", severity=Severity.INFO, confidence=Confidence.FIRM,
            url=root + "/#content-discovery", evidence=f"{len(found)} path(s), {dirs_scanned} director(ies) "
                                                      f"brute-forced (depth {depth}): {listing}"[:2000],
            description="Paths not linked from the application respond with real content. Review them for "
                        "sensitive files, admin functionality and forgotten endpoints.",
            remediation="Remove unused content from production and protect administrative paths.",
            cwe="CWE-538", detection=ANOMALY, tags=["hunting", "content-discovery"],
            context={"discovered": [{"url": u, "status": st, "category": classify_path(u)[0]} for u, st in found[:200]]},
        ))
    # forbidden paths found by brute force: try the access-control bypass variants (most interesting first)
    for url in sorted(blocked, key=recursion_priority)[:bypass_limit]:
        await forbidden_bypass(ctx, url, blocked[url])
    return found
