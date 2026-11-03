"""Proof-of-concept screenshots (headless Chromium via Playwright).

Three kinds of evidence, chosen per finding and always labelled honestly on the image:

* ``browser-execution`` - XSS / DOM XSS / prototype pollution: the PoC URL is opened and the screenshot is
  only labelled as proof if script execution was actually observed (dialog or marker variable).
* ``live-response`` - GET-reproducible server-side findings (SQL errors, file reads, SSTI, exposures, data
  leaks): the real response is rendered with the evidence string highlighted.
* ``http-evidence`` - anything else (POST/JSON/header injection): the recorded HTTP request/response pair is
  rendered as an evidence panel.

All browser traffic is scope-enforced (out-of-scope loads are aborted), so a PoC for an open redirect is
captured as the redirect response, never by visiting the attacker host.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from webguard.config import ScanConfig
from webguard.detection.checks.dom import HAVE_PLAYWRIGHT, launch_browser, scoped_router
from webguard.http import HttpClient
from webguard.models import Finding, Severity
from webguard.scope import Scope

log = logging.getLogger("webguard.poc")

BROWSER_CHECKS = {"xss", "dom_xss", "prototype_pollution"}
BANNER_JS = """([text, ok]) => {
  const b = document.createElement('div');
  b.textContent = text;
  b.setAttribute('style', 'display:block;margin:0 0 8px 0;padding:10px 14px;' +
    'font:600 14px system-ui,sans-serif;color:#fff;background:' + (ok ? '#c62828' : '#455a64'));
  const root = document.body || document.documentElement;
  root.insertBefore(b, root.firstChild);  // in the flow, never covering the evidence
  window.scrollTo(0, 0);
}"""
HIGHLIGHT_JS = """(needles) => {
  let hits = 0;
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const n of nodes) {
    for (const needle of needles) {
      const i = n.nodeValue.indexOf(needle);
      if (needle && i >= 0) {
        const r = document.createRange(); r.setStart(n, i); r.setEnd(n, i + needle.length);
        const m = document.createElement('mark');
        m.setAttribute('style', 'background:#ffeb3b;outline:3px solid #f44336;color:#000');
        r.surroundContents(m); hits++;
        if (hits === 1 && m.getBoundingClientRect().top > window.innerHeight - 80) m.scrollIntoView({block: 'center'});
        break;
      }
    }
  }
  return hits;
}"""


def _get_url(f: Finding) -> str | None:
    """URL of a GET-reproducible PoC (from the recorded curl command)."""
    if (f.context or {}).get("poc_url"):
        return f.context["poc_url"]  # executing PoC recorded by the check
    if not f.request:
        return None
    if f.request.startswith("open in browser: "):
        return f.request[len("open in browser: "):]
    try:
        parts = shlex.split(f.request)
    except ValueError:
        return None
    if "--data-raw" in parts:
        return None
    method = parts[parts.index("-X") + 1] if "-X" in parts else "GET"
    headers = [parts[i + 1] for i, p in enumerate(parts) if p == "-H"]
    if method != "GET" or any(not h.lower().startswith(("x-bug-bounty", "authorization")) for h in headers):
        return None  # header-based PoCs can't be reproduced by simply opening a URL
    return next((p for p in parts if p.startswith(("http://", "https://"))), None)


def _needles(f: Finding) -> list[str]:
    out = []
    for q in re.findall(r"'([^']{4,80})'|\"([^\"]{4,80})\"", f.evidence or ""):
        out.append(q[0] or q[1])
    m = re.search(r":\s*(.{6,80}?)(?:\s*\(|$)", f.evidence or "")
    if m:
        out.append(m.group(1).strip())
    out += re.findall(r"root:[^:\n]*:0:0:", f.evidence or "") + re.findall(r"\b\d{6,}\b", f.evidence or "")
    if f.payload and len(f.payload) < 120:
        out.append(f.payload)
    return [n for n in dict.fromkeys(out) if n][:6]


def parse_curl(cmd: str) -> dict | None:
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return None
    if not parts or parts[0] != "curl":
        return None
    url = next((p for p in parts if p.startswith(("http://", "https://"))), None)
    if not url:
        return None
    headers = {}
    for i, p in enumerate(parts):
        if p == "-H" and i + 1 < len(parts) and ":" in parts[i + 1]:
            k, v = parts[i + 1].split(":", 1)
            headers[k.strip()] = v.strip()
    data = parts[parts.index("--data-raw") + 1] if "--data-raw" in parts else None
    method = parts[parts.index("-X") + 1] if "-X" in parts else ("POST" if data else "GET")
    return {"method": method, "url": url, "headers": headers, "content": data}


async def collect_evidence(findings: list[Finding], config: ScanConfig, scope: Scope) -> int:
    """Replay the recorded (non-destructive) PoC request for findings without HTTP evidence."""
    todo = [f for f in findings if f.request and f.request.startswith("curl ")
            and not (f.context or {}).get("http_response")]
    if not todo:
        return 0
    n = 0
    async with HttpClient(config, scope) as client:
        for f in todo:
            req = parse_curl(f.request)
            if req is None:
                continue
            try:
                r = await client.request(req["method"], req["url"], headers=req["headers"] or None,
                                         content=req["content"])
            except Exception:
                continue
            if r is None:
                continue
            marker = next((x for x in _needles(f) if x in r.text), None)
            f.context["http_request"] = r.raw_request()
            f.context["http_response"] = r.raw_response(around=marker)
            n += 1
    return n


def _panel_html(f: Finding) -> str:
    ctx = f.context or {}
    req = ctx.get("http_request") or f.request or ""
    resp = ctx.get("http_response") or ""
    marker = next((n for n in _needles(f) if n in resp), None)
    esc_resp = html.escape(resp)
    if marker:
        esc_resp = esc_resp.replace(html.escape(marker), f"<mark>{html.escape(marker)}</mark>", 1)
    return f"""<!doctype html><meta charset=utf-8><body style="margin:0;font:13px/1.45 ui-monospace,Menlo,monospace;
background:#1e1e1e;color:#ddd"><div style="padding:12px 16px;background:#c62828;color:#fff;font:600 15px system-ui">
{html.escape(f.severity.name)} · {html.escape(f.title)}</div><div style="padding:8px 16px;color:#aaa;font:12px system-ui">
{html.escape(f.url)}{' · parameter ' + html.escape(f.parameter) if f.parameter else ''} · evidence recorded by WebGuard ·
{html.escape(f.evidence[:300])}</div><div style="display:flex;gap:12px;padding:12px 16px">
<pre style="flex:1;white-space:pre-wrap;word-break:break-all;background:#252526;padding:10px;margin:0">{html.escape(req)}</pre>
<pre style="flex:1;white-space:pre-wrap;word-break:break-all;background:#252526;padding:10px;margin:0">{esc_resp}</pre>
</div><style>mark{{background:#ffeb3b;color:#000}}</style></body>"""


async def capture(findings: list[Finding], config: ScanConfig, scope: Scope, out_dir: Path,
                  min_severity: Severity = Severity.MEDIUM, limit: int = 40) -> int:
    """Capture PoC screenshots; stores the relative path in ``finding.context['poc_screenshot']``."""
    selected = [f for f in sorted(findings, key=lambda f: (-f.severity, -f.confidence))
                if f.severity >= min_severity and f.check != "anomaly"][:limit]
    if not selected:
        return 0
    await collect_evidence(selected, config, scope)
    if not HAVE_PLAYWRIGHT:
        return 0
    from playwright.async_api import async_playwright

    user_agent, headers = config.user_agent, config.headers
    shots = out_dir / "poc"
    shots.mkdir(parents=True, exist_ok=True)
    done = 0
    async with async_playwright() as pw:
        browser = await launch_browser(pw)
        if browser is None:
            return 0
        context = await browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800},
                                            user_agent=user_agent, extra_http_headers=headers or None)

        await context.route("**/*", scoped_router(scope))
        sem = asyncio.Semaphore(3)

        async def one(f: Finding) -> None:
            nonlocal done
            async with sem:
                page = await context.new_page()
                dialogs: list[str] = []

                async def on_dialog(d) -> None:
                    dialogs.append(f"{d.type}({d.message!r})")
                    await d.dismiss()

                page.on("dialog", on_dialog)
                stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                kind, url = "http-evidence", _get_url(f)
                try:
                    if url and urlsplit(url).scheme in ("http", "https") and scope.in_scope(url):
                        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                        await page.wait_for_timeout(1500)
                        if f.check in BROWSER_CHECKS:
                            observed = ", ".join(dialogs)
                            if f.check == "prototype_pollution":
                                key = re.search(r"\[(wg\w+)\]|\.(wg\w+)=", url)
                                k = (key.group(1) or key.group(2)) if key else ""
                                if k and await page.evaluate(f"() => ({{}})['{k}'] === 'wgpp'"):
                                    observed = f"Object.prototype.{k} === 'wgpp'"
                            if not observed:
                                # nothing executed on this load: fall back to the recorded HTTP evidence panel
                                raise RuntimeError("no execution observed")
                            kind = "browser-execution"
                            await page.evaluate(BANNER_JS, [f"WebGuard PoC - script executed: {observed} - {stamp}", True])
                        else:
                            kind = "live-response"
                            hits = await page.evaluate(HIGHLIGHT_JS, _needles(f))
                            note = "evidence highlighted" if hits else "live response (evidence not visible as text)"
                            await page.evaluate(BANNER_JS, [f"WebGuard PoC - {f.title} - {note} - {stamp}", False])
                    else:
                        raise RuntimeError("not GET-reproducible")
                except Exception:
                    await page.close()
                    if not ((f.context or {}).get("http_request") or f.request):
                        return
                    kind = "http-evidence"
                    page = await context.new_page()  # fresh page: the old one may still be navigating
                    try:
                        await page.set_content(_panel_html(f), wait_until="domcontentloaded")
                    except Exception as exc:
                        log.debug("evidence panel failed for %s: %s", f.title, exc)
                        await page.close()
                        return
                path = shots / f"{f.fingerprint}.png"
                try:
                    await page.screenshot(path=str(path), full_page=False)
                    f.context["poc_screenshot"] = f"poc/{path.name}"
                    f.context["poc_kind"] = kind
                    if dialogs:
                        f.context["poc_observed"] = dialogs[:3]
                    done += 1
                except Exception as exc:
                    log.debug("screenshot failed for %s: %s", f.title, exc)
                finally:
                    await page.close()

        async def safe(f: Finding) -> None:
            try:
                await one(f)
            except Exception as exc:  # a PoC capture problem must never break reporting
                log.debug("PoC capture failed for %s: %s", f.title, exc)

        await asyncio.gather(*(safe(f) for f in selected))
        await context.close()
        await browser.close()
    return done
