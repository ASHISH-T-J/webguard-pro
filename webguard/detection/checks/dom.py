"""DOM-based XSS verification in a real headless browser (Playwright/Chromium, optional).

Server-side reflection checks cannot see XSS that happens entirely in client-side JavaScript
(SPA routers, ``innerHTML`` from ``location``). Here each candidate URL is loaded with a payload
that sets a random global variable when executed; the finding is reported only if the
variable is set - i.e. the script really ran. All browser traffic is scope-enforced.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from webguard.detection.context import Context, token
from webguard.models import SIGNATURE, Confidence, Finding, Severity

log = logging.getLogger("webguard.dom")

try:
    from playwright.async_api import async_playwright

    HAVE_PLAYWRIGHT = True
except Exception:  # pragma: no cover
    HAVE_PLAYWRIGHT = False

CHROMIUM_PATHS = ["/opt/pw-browsers/chromium", "/usr/bin/chromium", "/usr/bin/chromium-browser",
                  "/usr/bin/google-chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]


async def launch_browser(pw):
    """Playwright's bundled Chromium, else WEBGUARD_CHROMIUM / a system Chrome/Chromium."""
    try:
        return await pw.chromium.launch(args=["--no-sandbox"])
    except Exception as first:
        for path in [os.environ.get("WEBGUARD_CHROMIUM"), shutil.which("chromium"), shutil.which("google-chrome"),
                     *CHROMIUM_PATHS]:
            if path and os.path.exists(path):
                try:
                    return await pw.chromium.launch(executable_path=path, args=["--no-sandbox"])
                except Exception:
                    continue
        log.warning("cannot launch headless browser (set WEBGUARD_CHROMIUM): %s", str(first).splitlines()[0])
        return None


ROUTE_PARAMS = ("q", "id", "search", "query", "name")
PAYLOADS = [
    '<img src=x onerror="window.{v}=1">',
    '"><svg onload="window.{v}=1">',
    "<iframe src=\"javascript:parent.{v}=1\"></iframe>",
    "javascript:window.{v}=1//",
]


def candidates(pages: dict, spa_routes: list[str], root: str, skip: set[tuple[str, str]] = frozenset(),
               limit: int = 60, extra_params: list[tuple[str, str]] = ()) -> list[tuple[str, str]]:
    """(url-template-with-{p}, description) pairs worth testing in a browser.

    DOM XSS needs client-side code, so only pages that run script are tested; parameters with an
    already-confirmed (server-side) reflected XSS are skipped.
    """
    out: list[tuple[str, str]] = []
    # routes whose name suggests they render user input go first (search, results, track, ...)
    spa_routes = sorted(spa_routes, key=lambda r: (not re.search(r"(?i)search|result|track|query|find|filter", r), r))
    for route in spa_routes:
        if route in ("", "/", "**"):
            continue
        for p in ROUTE_PARAMS[:2]:
            out.append((f"{root}/#/{route.strip('/')}?{p}={{p}}", f"SPA route #/{route} param {p}"))
    # parameters the front-end code reads (found by static JS analysis) - test them on the app shell
    for name, page in list(extra_params)[:15]:
        base = (page or root + "/").split("?")[0]
        out.insert(0, (f"{base}?{name}={{p}}", f"client-read param {name}"))
        if spa_routes and not page:
            out.insert(1, (f"{root}/#/?{name}={{p}}", f"client-read param {name} (hash)"))
    for url, resp in pages.items():
        if not getattr(resp, "is_html", False) or "<script" not in resp.text.lower():
            continue
        parts = urlsplit(url)
        bare = urlunsplit(parts._replace(query="", fragment=""))
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        for name in params:
            if (bare, name) in skip:
                continue
            q = dict(params)
            q[name] = "__WG__"
            out.append((urlunsplit(parts._replace(query=urlencode(q))).replace("__WG__", "{p}"), f"query parameter {name}"))
        if "location.hash" in resp.text or "location.href" in resp.text:
            out.append((bare + "#{p}", "location.hash"))
    seen, uniq = set(), []
    for templ, desc in out:
        if templ not in seen:
            seen.add(templ)
            uniq.append((templ, desc))
    return uniq[:limit]


async def dom_xss(ctx: Context, targets: list[tuple[str, str]], concurrency: int = 3, timeout_ms: int = 8000) -> None:
    if not HAVE_PLAYWRIGHT or not targets:
        return
    async with async_playwright() as pw:
        browser = await launch_browser(pw)
        if browser is None:
            return
        context = await browser.new_context(ignore_https_errors=True,
                                            extra_http_headers=ctx.config.headers or None,
                                            user_agent=ctx.config.user_agent)

        async def guard(route):
            url = route.request.url
            if url.startswith(("data:", "blob:", "about:")) or ctx.client.scope.in_scope(url):
                await route.continue_()
            else:
                ctx.client.stats["blocked_out_of_scope"] += 1
                await route.abort()

        await context.route("**/*", guard)
        sem = asyncio.Semaphore(concurrency)
        found_routes: set[str] = set()

        async def test(templ: str, desc: str) -> None:
            # one root cause per (page, source): a global search box reading ?q= on every SPA route is one bug
            key = templ.split("#")[0] + "|" + (desc.rsplit(" ", 1)[-1] if desc.startswith("SPA route") else desc)
            async with sem:
                for raw in PAYLOADS:
                    if key in found_routes:
                        return
                    var = "__" + token(6)
                    payload = raw.format(v=var)
                    url = templ.replace("{p}", payload)
                    page = await context.new_page()
                    try:
                        ctx.client.stats["requests"] += 1
                        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                        await page.wait_for_timeout(1000)
                        executed = await page.evaluate(f"() => window.{var} === 1 || "
                                                       f"Array.from(document.querySelectorAll('iframe')).some(f => {{try {{return f.contentWindow.parent.{var} === 1}} catch(e) {{return false}}}})")
                    except Exception as exc:
                        log.debug("dom test failed %s: %s", url, exc)
                        executed = False
                    finally:
                        await page.close()
                    if executed:
                        found_routes.add(key)
                        ctx.report(Finding(
                            check="dom_xss", title=f"DOM-based cross-site scripting ({desc})", severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN, url=urlunsplit(urlsplit(templ)._replace(query="", fragment="")),
                            parameter=desc.split(" ")[-1] if "param" in desc else desc, location="dom", payload=payload,
                            evidence="Payload executed in headless Chromium (marker variable set by injected script).",
                            description="Client-side JavaScript writes attacker-controlled URL data into the DOM "
                                        "unsafely (e.g. innerHTML / bypassSecurityTrustHtml), executing script when a "
                                        "victim opens a crafted link.",
                            remediation="Use textContent / framework auto-escaping, never bypass the sanitizer for "
                                        "user input, and deploy a strict CSP (Trusted Types).",
                            cwe="CWE-79", owasp="A03:2021-Injection", detection=SIGNATURE,
                            references=["https://portswigger.net/web-security/cross-site-scripting/dom-based"],
                            tags=["xss", "dom", "browser-verified"],
                            request="open in browser: " + templ.replace("{p}", quote(payload, safe="")),
                        ))
                        return

        for i in range(0, len(targets), concurrency):  # ordered batches so the most likely routes report first
            await asyncio.gather(*(test(t, d) for t, d in targets[i:i + concurrency]))
        await context.close()
        await browser.close()


PP_VECTORS = ["?__proto__[{k}]=wgpp", "?__proto__.{k}=wgpp", "?constructor[prototype][{k}]=wgpp",
              "#__proto__[{k}]=wgpp", "#constructor[prototype][{k}]=wgpp"]


async def prototype_pollution(ctx: Context, pages: list[str], timeout_ms: int = 8000) -> None:
    """Client-side prototype pollution via URL: does a crafted query/hash set Object.prototype.<key>?"""
    if not HAVE_PLAYWRIGHT or not pages:
        return
    async with async_playwright() as pw:
        browser = await launch_browser(pw)
        if browser is None:
            return
        context = await browser.new_context(ignore_https_errors=True, user_agent=ctx.config.user_agent)

        async def guard(route):
            if route.request.url.startswith(("data:", "blob:", "about:")) or ctx.client.scope.in_scope(route.request.url):
                await route.continue_()
            else:
                await route.abort()

        await context.route("**/*", guard)
        for base in pages[:8]:
            for vec in PP_VECTORS:
                key = "wg" + token(6)
                url = base.split("#")[0].split("?")[0] + vec.format(k=key)
                page = await context.new_page()
                try:
                    ctx.client.stats["requests"] += 1
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    await page.wait_for_timeout(800)
                    polluted = await page.evaluate(f"() => ({{}})['{key}'] === 'wgpp'")
                except Exception:
                    polluted = False
                finally:
                    await page.close()
                if polluted:
                    ctx.report(Finding(
                        check="prototype_pollution", title="Client-side prototype pollution via URL",
                        severity=Severity.MEDIUM, confidence=Confidence.CERTAIN, url=base.split("?")[0],
                        location="dom", payload=vec.format(k=key),
                        evidence=f"After loading {url}, Object.prototype.{key} === 'wgpp' in the page.",
                        description="A URL/hash parser merges keys like __proto__ into objects, polluting every object "
                                    "in the page. Combined with a script gadget this usually becomes DOM XSS.",
                        remediation="Use a parser that ignores __proto__/constructor keys (or Object.create(null) "
                                    "targets); freeze Object.prototype where possible; update vulnerable libraries.",
                        cwe="CWE-1321", owasp="A03:2021-Injection", detection=SIGNATURE,
                        references=["https://portswigger.net/web-security/prototype-pollution/client-side"],
                        tags=["prototype-pollution", "dom", "browser-verified"],
                        request="open in browser: " + url,
                    ))
                    break
        await context.close()
        await browser.close()
