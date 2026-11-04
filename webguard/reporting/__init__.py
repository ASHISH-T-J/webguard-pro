"""Report writers: JSON, HTML, SARIF 2.1.0, Markdown (bug bounty submissions)."""

from __future__ import annotations

import base64
import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webguard import __version__
from webguard.models import Finding, Severity
from webguard.recon.tools import handoff_commands
from webguard.reporting.redact import redact_finding, redact_meta


@dataclass
class ReportOptions:
    """How a report is presented.

    ``client`` style is the deliverable: neutral title, no tool branding, no internal scoring/telemetry.
    ``technical`` style adds ML scores, detection methods, the reasoning trace and network diagnostics.
    ``redact`` masks personal data (not technical evidence, not recon results) in every format; the raw data
    stays in the local database and in terminal output.
    """

    style: str = "client"
    redact: bool = True
    author: str | None = None
    title: str = "Security Assessment Report"

    @property
    def technical(self) -> bool:
        return self.style == "technical"


CLIENT_META_DROP = {"trace", "reasoner", "resilience", "grep_highlights", "facts", "page_types", "stats", "oob"}
CLIENT_FINDING_DROP = {"ml_score", "features", "detection"}
CLIENT_CONTEXT_DROP = {"review_notes", "poc_observed"}

SEV_COLORS = {"CRITICAL": "#7b1fa2", "HIGH": "#d32f2f", "MEDIUM": "#f57c00", "LOW": "#1976d2", "INFO": "#607d8b"}
CVSS_HINT = {"CRITICAL": "9.0-10.0", "HIGH": "7.0-8.9", "MEDIUM": "4.0-6.9", "LOW": "0.1-3.9", "INFO": "0.0"}


def build_report(target: str, findings: list[Finding], meta: dict[str, Any] | None = None,
                 options: ReportOptions | None = None) -> dict[str, Any]:
    opts = options or ReportOptions()
    counts = Counter(f.severity.name for f in findings)
    items = [f.to_dict() for f in findings]
    meta = dict(meta or {})
    if not opts.technical:
        meta = {k: v for k, v in meta.items() if k not in CLIENT_META_DROP}
        for item in items:
            for k in CLIENT_FINDING_DROP:
                item.pop(k, None)
            item["context"] = {k: v for k, v in (item.get("context") or {}).items() if k not in CLIENT_CONTEXT_DROP}
    report = {
        "report": {"title": opts.title, "prepared_by": opts.author, "style": opts.style, "redacted": opts.redact},
        "target": target,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {s.name: counts.get(s.name, 0) for s in sorted(Severity, reverse=True)},
        "meta": meta,
        "findings": items,
    }
    if opts.technical:
        report["tool"] = {"name": "WebGuard Pro", "version": __version__}
    if opts.redact:
        report["meta"] = redact_meta(report["meta"])
        report["findings"] = [redact_finding(f) for f in report["findings"]]
    return report


def write_json(report: dict[str, Any], path: Path) -> Path:
    path.write_text(json.dumps(report, indent=2, default=str))
    return path


def write_sarif(report: dict[str, Any], path: Path) -> Path:
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules: dict[str, dict] = {}
    results = []
    for f in report["findings"]:
        rid = f["check"]
        rules.setdefault(rid, {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f.get("description") or f["title"]},
            "help": {"text": f.get("remediation") or ""},
            "properties": {"tags": [t for t in [f.get("cwe"), f.get("owasp")] if t]},
        })
        results.append({
            "ruleId": rid,
            "level": level[f["severity"]],
            "message": {"text": f"{f['title']}: {f.get('evidence', '')}"[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["url"]}}}],
            "partialFingerprints": {"webguard/v1": f["fingerprint"]},
            "properties": {k: v for k, v in {"severity": f["severity"], "confidence": f["confidence"],
                                             "parameter": f.get("parameter"), "payload": f.get("payload"),
                                             "ml_score": f.get("ml_score")}.items() if v is not None},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {**({"name": "WebGuard Pro", "version": __version__,
                                         "informationUri": "https://github.com/ashish-t-j/webguard-pro"}
                                        if "tool" in report else {"name": report["report"]["prepared_by"]
                                                                  or report["report"]["title"]}),
                                      "rules": list(rules.values())}},
                  "results": results}],
    }
    path.write_text(json.dumps(sarif, indent=2))
    return path


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def write_html(report: dict[str, Any], path: Path) -> Path:
    """Self-contained HTML report. Every value is escaped - payloads are attacker strings."""
    technical = report["report"].get("style") == "technical"
    rows = []
    for f in report["findings"]:
        color = SEV_COLORS[f["severity"]]
        details = "".join(
            f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in [
                ("URL", f"<code>{_e(f['url'])}</code>"),
                ("Method / location", _e(f"{f.get('method')} {f.get('location') or ''}")),
                ("Parameter", f"<code>{_e(f.get('parameter'))}</code>"),
                ("Payload", f"<code>{_e(f.get('payload'))}</code>"),
                ("Evidence", _e(f.get("evidence"))),
                ("Description", _e(f.get("description"))),
                ("Remediation", _e(f.get("remediation"))),
                ("Classification", _e(" · ".join(x for x in [f.get("cwe"), f.get("owasp")] if x))),
                ("Detection", _e(f"{f.get('detection')} · ML true-positive score {f.get('ml_score')}")
                 if technical else ""),
                ("Reproduce", f"<pre>{_e(f.get('request'))}</pre>" if f.get("request") else ""),
                ("Context", _context_html(f.get("context") or {}, technical)),
                ("HTTP evidence", _http_html(f.get("context") or {})),
                ("PoC screenshot", _poc_html(f.get("context") or {}, path.parent)),
            ] if v and v not in ("<code></code>", "<code>None</code>")
        )
        rows.append(
            f"<details class='f' data-sev='{_e(f['severity'])}'><summary><span class='sev' style='background:{color}'>"
            f"{_e(f['severity'])}</span> <span class='conf'>{_e(f['confidence'])}</span> {_e(f['title'])} "
            f"<span class='url'>{_e(f['url'])}{' · ' + _e(f['parameter']) if f.get('parameter') else ''}</span>"
            f"</summary><dl>{details}</dl></details>"
        )
    summary = "".join(
        f"<div class='card' style='border-color:{SEV_COLORS[k]}'><b style='color:{SEV_COLORS[k]}'>{v}</b>{k}</div>"
        for k, v in report["summary"].items()
    )
    meta = report.get("meta", {})
    hosts = meta.get("hosts", [])
    host_rows = "".join(
        f"<tr><td>{_e(h.get('url'))}</td><td>{_e(h.get('status'))}</td><td>{_e(h.get('title'))}</td>"
        f"<td>{_e(', '.join(h.get('technologies', [])))}</td><td>{_e(', '.join(h.get('waf', [])))}</td></tr>"
        for h in hosts
    )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(report['report']['title'])} - {_e(report['target'])}</title>
<style>
:root{{--bg:#fafafa;--fg:#212121;--card:#fff;--muted:#757575;--line:#e0e0e0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#121212;--fg:#eee;--card:#1e1e1e;--muted:#9e9e9e;--line:#333}}}}
body{{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;max-width:1100px;padding:16px}}
h1{{margin:.2em 0}} .muted{{color:var(--muted)}}
.cards{{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}}
.card{{background:var(--card);border-left:4px solid;padding:8px 14px;min-width:90px}} .card b{{display:block;font-size:22px}}
.f{{background:var(--card);border:1px solid var(--line);border-radius:6px;margin:6px 0;padding:8px 12px}}
.f summary{{cursor:pointer}} .sev{{color:#fff;border-radius:3px;padding:1px 6px;font-size:12px;font-weight:600}}
.conf{{font-size:11px;color:var(--muted)}} .url{{color:var(--muted);font-size:12px;word-break:break-all}}
dl{{display:grid;grid-template-columns:160px 1fr;gap:4px 12px}} dt{{color:var(--muted)}} dd{{margin:0;word-break:break-word}}
pre,code{{white-space:pre-wrap;word-break:break-all;font-size:12px}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid var(--line);padding:4px;text-align:left;font-size:13px}}
input#q{{padding:6px;width:100%;max-width:320px;margin:8px 0}} .bar{{display:flex;flex-wrap:wrap;gap:10px;align-items:center}}
@media (max-width:600px){{dl{{grid-template-columns:1fr}}}}
</style></head><body>
<h1>{_e(report['report']['title'])}</h1>
<div class="muted">Target <b>{_e(report['target'])}</b> · {_e(report['generated'][:10])}{(' · prepared by ' + _e(report['report']['prepared_by'])) if report['report'].get('prepared_by') else ''}{' · sensitive values masked' if report['report'].get('redacted') else ''}</div>
<div class="cards">{summary}</div>
{"<h2>Hosts</h2><table><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th><th>WAF</th></tr>" + host_rows + "</table>" if host_rows else ""}
{_assessment_sections(meta, technical)}
{_conditions_html(meta, technical)}
<h2>Findings ({len(report['findings'])})</h2>
<div class="bar"><input id="q" placeholder="Filter findings…" oninput="filt()">
{''.join(f'<label><input type="checkbox" class="sv" value="{k}" checked onchange="filt()"> {k}</label>' for k in report['summary'])}
<label><input type="checkbox" id="vo" onchange="filt()"> verified only</label></div>
<script>function filt(){{const q=document.getElementById('q').value.toLowerCase();const on=new Set([...document.querySelectorAll('.sv:checked')].map(c=>c.value));const vo=document.getElementById('vo').checked;for(const d of document.querySelectorAll('.f')){{const t=d.textContent.toLowerCase();d.style.display=(t.includes(q)&&on.has(d.dataset.sev)&&(!vo||t.includes('verified by independent')||t.includes('deterministic')))?'':'none'}}}}</script>
{''.join(rows) or '<p>No findings.</p>'}
</body></html>"""
    path.write_text(doc)
    return path


POC_LABEL = {"browser-execution": "script execution observed in the browser",
             "live-response": "live response, evidence highlighted",
             "http-evidence": "recorded HTTP request/response"}


def _poc_html(ctx: dict[str, Any], base: Path) -> str:
    rel = ctx.get("poc_screenshot")
    if not rel or not (base / rel).exists():
        return ""
    data = base64.b64encode((base / rel).read_bytes()).decode()
    label = POC_LABEL.get(ctx.get("poc_kind", ""), "")
    return (f"<figure style='margin:0'><img alt='PoC screenshot' src='data:image/png;base64,{data}' "
            f"style='max-width:100%;border:1px solid var(--line);border-radius:4px'>"
            f"<figcaption class='muted'>{_e(label)}</figcaption></figure>")


def _context_html(ctx: dict[str, Any], technical: bool = True) -> str:
    keys = [("environment", "Environment"), ("waf", "WAF in front"), ("verification", "Verification"),
            ("environment_note", "Note")]
    if technical:
        keys = [("page_type", "Page type"), *keys, ("review_notes", "Review before reporting")]
    if ctx.get("bypass"):
        keys.append(("bypass", "Filter bypass"))
    items = []
    for k, label in keys:
        v = ctx.get(k)
        if isinstance(v, dict):
            v = f"{v.get('variant')} ({v.get('technique_source')})"
        if v:
            items.append(f"<b>{_e(label)}:</b> {_e(', '.join(v) if isinstance(v, list) else v)}")
    return "<br>".join(items)


def _http_html(ctx: dict[str, Any]) -> str:
    if not ctx.get("http_request"):
        return ""
    return (f"<details><summary>request / response</summary><pre>{_e(ctx['http_request'])}</pre>"
            f"<pre>{_e(ctx.get('http_response', ''))}</pre></details>")


def _conditions_html(meta: dict[str, Any], technical: bool = True) -> str:
    """Test conditions: environment, defences encountered, untested inputs (+ network diagnostics if technical)."""
    if not meta.get("environment") and not meta.get("resilience") and not meta.get("obstructed_inputs"):
        return ""
    parts = [f"<p><b>Environment:</b> {_e(meta.get('environment', 'unknown'))}"
             + (f" · <b>Reasoner:</b> {_e(meta.get('reasoner', 'local'))}" if technical else "") + "</p>"]
    wafs = sorted({w for h in meta.get("hosts", []) for w in h.get("waf", [])})
    if wafs:
        parts.append(f"<p><b>Defences detected:</b> {_e(', '.join(wafs))}. Responses produced by these defences were "
                     "never used as evidence.</p>")
    obstructed = meta.get("obstructed_inputs") or {}
    if obstructed:
        rows = "".join(f"<tr><td>{_e(k.replace('_', ' '))}</td><td>{len(v)}</td><td>{_e('; '.join(v[:8]))}</td></tr>"
                       for k, v in obstructed.items())
        parts.append("<p><b>Not tested</b> (answered by a WAF/challenge/rate limiter instead of the application):</p>"
                     f"<table><tr><th>Obstruction</th><th>Tests</th><th>Examples</th></tr>{rows}</table>")
    res = meta.get("resilience") or {}
    if res.get("errors_by_kind") or any(h.get("rate_adjustments") for h in res.get("hosts", {}).values()):
        errs = ", ".join(f"{k}: {v}" for k, v in (res.get("errors_by_kind") or {}).items()) or "none"
        adj = "".join(f"<li>{_e(h)}: {_e('; '.join(d['rate_adjustments']))} (final {d['final_rate']} req/s, "
                      f"{d['latency_ms']} ms avg, circuit trips {d['circuit_trips']})</li>"
                      for h, d in res.get("hosts", {}).items() if d.get("rate_adjustments"))
        parts.append(f"<p><b>Network errors:</b> {_e(errs)}</p>" + (f"<p><b>Adaptive rate control:</b></p><ul>{adj}</ul>" if adj else ""))
    facts = [x for x in meta.get("facts", []) if x.startswith(("JS analysis", "Environment", "Content discovery"))]
    if facts:
        parts.append("<ul>" + "".join(f"<li>{_e(x)}</li>" for x in facts) + "</ul>")
    return "<h2>Test conditions</h2>" + "".join(parts)


def _assessment_sections(meta: dict[str, Any], technical: bool = True) -> str:
    """Narrative, attack chains, issues, WSTG coverage and reasoning trace (assessment mode)."""
    out = []
    narrative = meta.get("narrative") or {}
    if narrative.get("executive_summary"):
        risks = "".join(f"<li>{_e(r)}</li>" for r in narrative.get("key_risks", []))
        steps = "".join(f"<li>{_e(r)}</li>" for r in narrative.get("next_steps", []))
        out.append(f"<h2>Executive summary</h2><p>{_e(narrative['executive_summary']).replace('**', '')}</p>"
                   + (f"<h3>Key risks</h3><ul>{risks}</ul>" if risks else "")
                   + (f"<h3>Recommended next steps</h3><ol>{steps}</ol>" if steps else "")
                   + (f"<p class='muted'>Reasoning engine: {_e(meta.get('reasoner', 'local'))}</p>" if technical else ""))
    chains = meta.get("attack_chains") or []
    if chains:
        rows = "".join(f"<tr><td><span class='sev' style='background:{SEV_COLORS[c['severity']]}'>{_e(c['severity'])}</span></td>"
                       f"<td><b>{_e(c['title'])}</b><br><span class='muted'>{_e(c['steps'])}</span></td>"
                       f"<td>{'<br>'.join(_e(x) for x in c['findings'])}</td></tr>" for c in chains)
        out.append(f"<h2>Attack chains</h2><table><tr><th>Severity</th><th>Chain</th><th>Built from</th></tr>{rows}</table>")
    issues = meta.get("issues") or []
    if issues:
        rows = "".join(f"<tr><td>{i['risk']}</td><td><span class='sev' style='background:{SEV_COLORS[i['severity']]}'>"
                       f"{_e(i['severity'])}</span></td><td>{_e(i['title'])}</td><td>{_e(i['cvss'])}<br>"
                       f"<span class='muted'>{_e(i['cvss_vector'])}</span></td><td>{len(i['locations'])}</td></tr>"
                       for i in issues)
        out.append("<h2>Root-cause issues</h2><table><tr><th>Risk</th><th>Severity</th><th>Issue</th><th>CVSS 3.1</th>"
                   f"<th>Locations</th></tr>{rows}</table>")
    coverage = meta.get("wstg_coverage") or {}
    if coverage:
        names = meta.get("wstg_names", {})
        color = {"vulnerable": "#d32f2f", "tested": "#388e3c", "not tested": "#9e9e9e"}
        rows = "".join(f"<tr><td>{_e(k)}</td><td>{_e(names.get(k, ''))}</td>"
                       f"<td style='color:{color.get(v, '#000')}'><b>{_e(v)}</b></td></tr>" for k, v in coverage.items())
        out.append(f"<details><summary><h2 style='display:inline'>OWASP WSTG coverage</h2></summary><table>{rows}</table></details>")
    trace = meta.get("trace") or []
    if trace and technical:
        rows = "".join(f"<tr><td>{t['step']}</td><td>{_e(t['phase'])}</td><td>{_e(t['thought'])}</td>"
                       f"<td>{_e(', '.join(t['actions'][:8]))}{' …' if len(t['actions']) > 8 else ''}</td>"
                       f"<td>{_e(t['observation'])}</td></tr>" for t in trace)
        out.append("<details><summary><h2 style='display:inline'>Methodology &amp; reasoning trace</h2></summary>"
                   "<table><tr><th>#</th><th>Phase</th><th>Thought</th><th>Actions</th><th>Observation</th></tr>"
                   f"{rows}</table></details>")
    return "\n".join(out)


def finding_markdown(f: Finding, technical: bool = False) -> str:
    """One bug-bounty-ready submission (HackerOne / Bugcrowd / Intigriti style)."""
    steps = []
    if f.request:
        lang = "text" if f.request.startswith("open in browser") else "bash"
        steps.append(f"1. Send the following request:\n\n```{lang}\n{f.request}\n```")
    steps.append(f"{len(steps) + 1}. Observe: {f.evidence}")
    handoff = handoff_commands(f) if technical else []
    extra = ("\n\n### Further verification\n\n" + "\n".join(f"```bash\n{c}\n```" for c in handoff)) if handoff else ""
    refs = "\n".join(f"- {r}" for r in f.references)
    return f"""## {f.title}

**Severity:** {f.severity.name} (CVSS v3.1 range {CVSS_HINT[f.severity.name]}) · **Confidence:** {f.confidence.name}
**Weakness:** {f.cwe or 'n/a'} · {f.owasp or ''}
**Asset:** `{f.url}`{f"  **Parameter:** `{f.parameter}` ({f.location})" if f.parameter else ''}

### Summary

{f.description}

### Steps to reproduce

{chr(10).join(steps)}

**Payload:** `{f.payload or 'n/a'}`
{_md_evidence(f, technical)}

### Impact

{_impact(f)}

### Remediation

{f.remediation}{extra}

{('### References' + chr(10) + chr(10) + refs) if refs else ''}
"""


def _md_evidence(f: Finding, technical: bool = False) -> str:
    ctx = f.context or {}
    out = ""
    if ctx.get("poc_screenshot"):
        out += f"\n**PoC screenshot** ({POC_LABEL.get(ctx.get('poc_kind', ''), '')}):\n\n![PoC]({ctx['poc_screenshot']})\n"
    if ctx.get("http_request"):
        out += f"\n**HTTP request**\n\n```http\n{ctx['http_request']}\n```\n"
        out += f"\n**HTTP response (excerpt)**\n\n```http\n{ctx.get('http_response', '')[:2500]}\n```\n"
    notes = [ctx.get("verification"), ctx.get("environment_note")] + (list(ctx.get("review_notes") or [])
                                                                      if technical else [])
    notes = [n for n in notes if n]
    if notes:
        out += "\n> " + "  \n> ".join(notes) + "\n"
    return out


def _impact(f: Finding) -> str:
    impacts = {
        "sqli": "An attacker can read or modify database contents (user records, credentials, PII) and may "
                "escalate to code execution depending on DBMS privileges.",
        "xss": "An attacker can execute JavaScript in victims' browsers in the context of this origin: steal "
               "session tokens/CSRF tokens, perform actions as the victim and phish credentials.",
        "ssti": "Template evaluation typically allows arbitrary code execution on the server.",
        "cmdi": "Arbitrary operating-system commands can be executed on the server (full compromise).",
        "lfi": "Arbitrary files on the server can be read (source code, configuration, secrets).",
        "ssrf": "The server can be used to reach internal services and cloud metadata endpoints.",
        "redirect": "Users can be redirected from a trusted domain to attacker-controlled sites (phishing, OAuth token theft).",
        "crlf": "Arbitrary response headers can be injected (session fixation, cache poisoning, XSS via response splitting).",
        "cors": "A malicious website can read responses from this API on behalf of a logged-in victim.",
        "takeover": "An attacker can serve arbitrary content from a subdomain of the organisation.",
        "secrets": "Leaked credentials may grant direct access to third-party services or internal systems.",
    }
    return impacts.get(f.check, f.description)


def write_markdown(target: str, findings: list[Finding], path: Path, min_severity: Severity = Severity.LOW,
                   meta: dict[str, Any] | None = None, options: ReportOptions | None = None) -> Path:
    opts = options or ReportOptions()
    selected = [f for f in findings if f.severity >= min_severity]
    if opts.redact:  # work on masked copies; the raw findings stay in the database
        selected = [Finding.from_dict(redact_finding(f.to_dict())) for f in selected]
    byline = f" · Prepared by {opts.author}" if opts.author else ""
    head = f"# {opts.title}: {target}\n\n_Date: {datetime.now(timezone.utc):%Y-%m-%d}{byline}_\n\n"
    if opts.technical:
        head += f"_Generated by WebGuard {__version__}. Verify every finding manually before submitting._\n\n"
    toc = "\n".join(f"- [{f.severity.name}] {f.title} - `{f.url}`" for f in selected)
    meta = redact_meta(meta or {}) if opts.redact else (meta or {})
    extra = ""
    if (meta.get("narrative") or {}).get("executive_summary"):
        extra += "## Executive summary\n\n" + meta["narrative"]["executive_summary"] + "\n\n"
    if meta.get("attack_chains"):
        extra += "## Attack chains\n\n" + "\n".join(
            f"- **{c['severity']} - {c['title']}**: {c['steps']}" for c in meta["attack_chains"]) + "\n\n"
    path.write_text(head + extra + "## Findings\n\n" + toc + "\n\n---\n\n"
                    + "\n---\n\n".join(finding_markdown(f, opts.technical) for f in selected))
    return path


def write_all(target: str, findings: list[Finding], out_dir: Path, formats: list[str],
              meta: dict[str, Any] | None = None, options: ReportOptions | None = None) -> list[Path]:
    opts = options or ReportOptions()
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(target, findings, meta, opts)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in target.split("://")[-1]).strip("._")
    base = f"{safe}_{stamp}"  # note: not Path.with_suffix - targets contain dots
    written = []
    if "json" in formats:
        written.append(write_json(report, out_dir / f"{base}.json"))
    if "html" in formats:
        written.append(write_html(report, out_dir / f"{base}.html"))
    if "sarif" in formats:
        written.append(write_sarif(report, out_dir / f"{base}.sarif"))
    if "md" in formats:
        written.append(write_markdown(target, findings, out_dir / f"{base}.md", meta=meta, options=opts))
    return written
