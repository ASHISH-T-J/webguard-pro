"""API-specific tests (OWASP API Security Top 10 2023 / WSTG-APIT).

* **Unauthenticated access** (API2 / API5): when the scan has credentials, every API GET endpoint that
  returned personal or account data is requested again *without* them. The same data coming back means
  the endpoint does not enforce authentication.
* **Undocumented API versions** (API9 improper inventory): ``/api/v2/users`` -> ``v1``, ``v3``, ``v0``,
  ``beta``, ``internal``. Older versions often lack fixes that were made to the current one.
* **Content-type confusion**: a JSON write endpoint that also accepts ``application/x-www-form-urlencoded``
  is reachable by cross-site HTML forms (CSRF against cookie-authenticated APIs).

All requests repeat what the application already does (GET of a crawled endpoint, the same write request
with a different encoding); nothing new is created.
"""

from __future__ import annotations

import dataclasses
import json
import re
from urllib.parse import urlencode, urlsplit, urlunsplit

from webguard.detection.baseline import similarity
from webguard.detection.context import Context
from webguard.http import HttpClient, Resp
from webguard.models import DIFFERENTIAL, Confidence, Finding, Severity

API_OWASP = "API2:2023-Broken Authentication"
PRIVATE_KEYS = re.compile(r"(?i)^(?:e?mail|phone|mobile|address|ssn|dob|birth\w*|first_?name|last_?name|full_?name|"
                          r"balance|iban|card\w*|account\w*|role|roles|is_?admin|permissions?|token|api_?key|"
                          r"salary|orders?|password\w*|username|user_?id)$")
VERSION_SEG = re.compile(r"/(v)(\d{1,2})(?=/)", re.I)


def _keys(obj, depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 5:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            out |= _keys(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:20]:
            out |= _keys(v, depth + 1)
    return out


def _json(resp: Resp):
    try:
        return json.loads(resp.text)
    except (ValueError, TypeError):
        return None


def private_fields(resp: Resp) -> set[str]:
    data = _json(resp) if resp is not None and "json" in resp.content_type else None
    return {k for k in _keys(data) if PRIVATE_KEYS.match(k)} if data is not None else set()


async def unauthenticated_access(ctx: Context, urls: list[str], pages: dict[str, Resp], transport=None) -> None:
    """Re-request private-looking API GET responses without the scan's credentials."""
    cfg = ctx.config
    if not (cfg.headers or cfg.cookies):
        return
    candidates = [(u, pages[u]) for u in urls if u in pages and pages[u].status == 200 and private_fields(pages[u])]
    if not candidates:
        return
    anon_cfg = dataclasses.replace(cfg, headers={k: v for k, v in cfg.headers.items()
                                                 if k.lower() not in ("authorization", "cookie", "x-api-key")},
                                   cookies={})
    async with HttpClient(anon_cfg, ctx.client.scope, transport) as anon:
        for url, authed in candidates[:15]:
            r = await anon.safe_get(url)
            if r is None or r.status != 200 or not ctx.app_answered(r):
                continue
            leaked = private_fields(r) & private_fields(authed)
            if not leaked or similarity(r.text, authed.text) < 0.85:
                continue
            ctx.report(Finding(
                check="auth", title="API endpoint returns private data without authentication",
                severity=Severity.HIGH if leaked & {"password", "token", "api_key", "iban", "ssn"} else Severity.MEDIUM,
                confidence=Confidence.FIRM, url=url,
                evidence=f"Same response with and without credentials (similarity >= 0.85); fields: "
                         f"{', '.join(sorted(leaked)[:10])}",
                description="The endpoint returned the same account data to an anonymous request as to the "
                            "authenticated scan session, so authentication is not enforced on it.",
                remediation="Require authentication on every API route (deny by default in the API gateway / "
                            "framework) and add an authorization check for the requested object.",
                cwe="CWE-306", owasp=API_OWASP, detection=DIFFERENTIAL, tags=["api", "authentication"],
                request=anon.curl("GET", url)))


async def api_versions(ctx: Context, url: str, original: Resp) -> None:
    """Try sibling API versions of a working JSON endpoint."""
    p = urlsplit(url)
    m = VERSION_SEG.search(p.path)
    if not m or original is None or original.status != 200 or "json" not in original.content_type:
        return
    n = int(m.group(2))
    siblings = [f"v{k}" for k in (n - 1, n + 1, 0) if k >= 0 and k != n] + ["beta", "internal", "dev"]
    found = []
    for seg in dict.fromkeys(siblings):
        path = p.path[: m.start()] + f"/{seg}" + p.path[m.end():]
        sib = urlunsplit(p._replace(path=path))
        r = await ctx.client.safe_get(sib)
        if r is not None and r.status == 200 and "json" in r.content_type and ctx.app_answered(r) \
                and _json(r) is not None:
            found.append((seg, sib, r))
    if not found:
        return
    names = ", ".join(seg for seg, _, _ in found)
    extra = {k for _, _, r in found for k in _keys(_json(r))} - _keys(_json(original))
    ctx.report(Finding(
        check="exposure", title=f"Additional API version(s) reachable: {names}",
        severity=Severity.LOW if not extra else Severity.MEDIUM, confidence=Confidence.FIRM, url=found[0][1],
        evidence=f"{url} also answers as {names}" + (f"; extra fields: {', '.join(sorted(extra)[:10])}" if extra else ""),
        description="Older, beta or internal API versions are deployed next to the current one. They are often "
                    "missing later security fixes and are easy to forget in inventories and gateways.",
        remediation="Retire unused API versions, or apply the same authentication, authorization and rate limits "
                    "to every version; keep an API inventory.",
        cwe="CWE-1059", owasp="API9:2023-Improper Inventory Management", detection=DIFFERENTIAL,
        tags=["api", "inventory"], request=ctx.client.curl("GET", found[0][1])))


async def content_type_confusion(ctx: Context, url: str, method: str, params: dict) -> None:
    """Does a JSON write endpoint accept the same request form-encoded (reachable by cross-site forms)?"""
    if not params or method.upper() not in ("POST", "PUT", "PATCH"):
        return
    flat = {k: v if isinstance(v, str) else json.dumps(v) for k, v in params.items()}
    try:
        as_json = await ctx.client.request(method, url, json=params)
        as_form = await ctx.client.request(method, url, content=urlencode(flat),
                                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    except Exception:
        return
    if as_json is None or as_form is None or not ctx.app_answered(as_form):
        return
    if "json" not in as_json.content_type:
        return  # not a JSON API
    if as_json.status >= 400 or as_form.status != as_json.status or similarity(as_json.text, as_form.text) < 0.8:
        return
    # the body must actually be parsed: a malformed body has to change the answer, otherwise the endpoint
    # simply ignores its input and "same response" proves nothing
    try:
        broken = await ctx.client.request(method, url, content="{wg-malformed",
                                          headers={"Content-Type": "application/json"})
    except Exception:
        return
    if broken is None or (broken.status == as_json.status and similarity(broken.text, as_json.text) > 0.9):
        return
    cookie_auth = bool(ctx.config.cookies) or any(k.lower() == "cookie" for k in ctx.config.headers)
    ctx.report(Finding(
        check="csrf", title="JSON API also accepts form-encoded requests", confidence=Confidence.FIRM,
        severity=Severity.MEDIUM if cookie_auth else Severity.LOW, url=url, method=method.upper(), location="body",
        evidence=f"Same HTTP {as_form.status} response for application/json and application/x-www-form-urlencoded",
        description="Browsers send form-encoded cross-site requests without a CORS preflight. With cookie-based "
                    "authentication, any website can submit this API call on behalf of a logged-in user.",
        remediation="Accept only application/json on JSON endpoints (reject other content types with 415) and use "
                    "anti-CSRF tokens or SameSite=Lax/Strict cookies.",
        cwe="CWE-352", owasp="API8:2023-Security Misconfiguration", detection=DIFFERENTIAL, tags=["api", "csrf"],
        request=ctx.client.curl(method, url, content=urlencode(flat),
                                headers={"Content-Type": "application/x-www-form-urlencoded"})))
