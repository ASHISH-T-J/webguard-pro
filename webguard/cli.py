"""Command-line interface.

    webguard scan    <url|host>       crawl + active/passive vulnerability checks
    webguard recon   <domain>         subdomains, DNS, live hosts, takeover, historical URLs
    webguard hunt    <domain>         full bug bounty pipeline (recon -> rank -> scan -> nuclei -> triage -> reports)
    webguard surface <domain>         red-team external attack surface (ports, exposed services, ATT&CK mapping)
    webguard assess  <url>            autonomous methodology-driven assessment (local / Claude / Ollama reasoning)
    webguard grep    <scan-id>        grep stored responses with pattern packs (DOM sinks, secrets, infra, ...)
    webguard ask     "<question>"     natural-language query over findings
    webguard analyze <scan-id>        root-cause issues, attack chains, reasoning trace
    webguard report  <scan-id>        re-generate reports from the database
    webguard db ...                   scans, findings, assets, new attack surface, labels
    webguard ml ...                   train / inspect the ML triage model
    webguard tools                    external tool + signature database status
    webguard wizard                   interactive mode
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from webguard import __version__, ui
from webguard.config import ALL_CHECKS, DEFAULT_DB, DEFAULT_MODEL, ScanConfig
from webguard.db import Database
from webguard.models import Severity
from webguard.scope import Scope

FORMATS = ("json", "html", "sarif", "md")
FMT = argparse.RawDescriptionHelpFormatter

MAIN_EXAMPLES = """\
examples:
  new to security testing? start the guided wizard:
    webguard wizard

  quick, production-safe scan of one site:
    webguard scan https://shop.example.com --profile safe

  full assessment with live progress, showing every payload (raw + encoded):
    webguard assess https://shop.example.com -v 3

  authenticated scan through Burp, time-boxed to 20 minutes:
    webguard assess https://app.example.com --cookie session=abc123 \\
        --proxy http://127.0.0.1:8080 --budget-minutes 20

  bug bounty: recon -> rank subdomains -> scan the best 10 in parallel:
    webguard hunt example.com --max-hosts 10 -H 'X-Bug-Bounty: yourname'

  interrupted (Ctrl+C)? run the same command again to resume; --fresh starts over.

verbosity (-v N, like sqlmap):
  0 findings only · 1 stages & progress (default) · 2 debug · 3 payloads (raw + encoded, URL, parameter)
  4 + HTTP requests · 5 + response headers · 6 + response bodies.  -vv / -vvv also work.

severity colours: CRITICAL/HIGH red · MEDIUM yellow · LOW blue · INFO green

Only test systems you own or are explicitly authorised to assess.
"""

EXAMPLES = {
    "scan": """examples:
  webguard scan https://shop.example.com
  webguard scan https://shop.example.com --profile safe --no-timing
  webguard scan -l targets.txt --checks sqli,xss,ssrf -o out -f html,sarif
  webguard scan https://shop.example.com -v 3            # show every payload (raw + encoded)
  webguard scan https://shop.example.com --fresh         # ignore the saved session, start over
""",
    "assess": """examples:
  webguard assess https://shop.example.com
  webguard assess https://shop.example.com --budget-minutes 30 --show-trace
  webguard assess https://shop.example.com --llm claude          # Claude plans the tests (ANTHROPIC_API_KEY)
  webguard assess https://app.example.com --cookie sid=abc -H 'Authorization: Bearer eyJ...'
  webguard assess https://shop.example.com -v 4 --no-color > run.log
""",
    "recon": """examples:
  webguard recon example.com
  webguard recon example.com --passive        # public sources only, no traffic to the target
""",
    "hunt": """examples:
  webguard hunt example.com
  webguard hunt example.com --max-hosts 10 --parallel-hosts 4 --rate 20 -H 'X-Bug-Bounty: yourname'
""",
    "surface": """examples:
  webguard surface example.com
  webguard surface example.com --no-ports
""",
    "report": """examples:
  webguard report 12 -f html,md --report-author "ACME Security"
  webguard report 12 --report-style technical --min-severity MEDIUM
""",
    "grep": """examples:
  webguard grep 12 --pack secrets
  webguard grep 12 --regex 'AKIA[0-9A-Z]{16}' --in js
""",
    "ask": """examples:
  webguard ask "high sql injection on the api"
  webguard ask "what should I fix first?" --llm claude
""",
    "analyze": "examples:\n  webguard analyze 12\n",
    "db": "examples:\n  webguard db scans\n  webguard db findings --scan 12\n  webguard db label 42 fp\n  webguard db new example.com\n",
    "ml": "examples:\n  webguard ml status\n  webguard ml train\n",
    "tools": "examples:\n  webguard tools\n",
    "wizard": "examples:\n  webguard wizard\n  webguard --wizard\n",
}


def _verbosity_argv(argv: list[str]) -> list[str]:
    """Accept -vv / -vvv (count) as well as sqlmap's -v N."""
    out: list[str] = []
    for a in argv:
        if len(a) > 2 and a.startswith("-v") and set(a[1:]) == {"v"}:
            out += ["-v", str(len(a) - 1)]  # -vv -> 2, -vvv -> 3
        else:
            out.append(a)
    return out


# ----------------------------------------------------------------------------- argument parsing

def _common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("scope & engagement")
    g.add_argument("--scope", help="scope file (.txt rules or .yml with include/exclude/exclude_paths)")
    g.add_argument("--subdomains", action="store_true", help="treat *.target as in scope")
    g.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                   help="extra header on every request (e.g. bug bounty ID header, Authorization)")
    g.add_argument("--cookie", action="append", default=[], metavar="name=value", help="cookie for authenticated scans")
    g.add_argument("--proxy", help="HTTP/SOCKS proxy, e.g. http://127.0.0.1:8080 (Burp) or socks5://127.0.0.1:9050 (Tor)")
    g.add_argument("--profile", default="standard", choices=["safe", "standard", "thorough"],
                   help="safe = production-friendly (slow, no timing/fuzzing); thorough = lab/staging (more discovery)")
    g = p.add_argument_group("performance")
    g.add_argument("--rate", type=float, default=20.0, help="max requests/second (default 20)")
    g.add_argument("-c", "--concurrency", type=int, default=20, help="concurrent requests (default 20)")
    g.add_argument("--timeout", type=float, default=10.0, help="request timeout seconds")
    g.add_argument("--depth", type=int, default=3, help="crawl depth")
    g.add_argument("--max-urls", type=int, default=500, help="max URLs to crawl per host")
    g = p.add_argument_group("detection")
    g.add_argument("--checks", help=f"comma list of checks to run (default all): {','.join(ALL_CHECKS)}")
    g.add_argument("--skip", help="comma list of checks to skip")
    g.add_argument("--no-timing", action="store_true", help="disable time-based checks (faster, less noisy)")
    g.add_argument("--time-delay", type=int, default=5, help="sleep seconds for time-based payloads")
    g.add_argument("--param-discovery", action="store_true", help="brute-force hidden parameters (Arjun-style)")
    g.add_argument("--oob", metavar="DOMAIN", help="out-of-band interaction domain (interactsh/Collaborator) for blind SSRF")
    g.add_argument("--tamper", help="comma list: space2comment,randomcase,space2plus,versioned,charencode")
    g.add_argument("--signatures", action="append", default=[], help="extra signature directory (JSON files)")
    g.add_argument("--wordlist", help="content-discovery wordlist (default: built-in quick list of ~200 paths)")
    g.add_argument("--no-discovery", action="store_true", help="skip content discovery (path brute force)")
    g = p.add_argument_group("output")
    g.add_argument("-o", "--output", default="reports", help="report directory (default ./reports)")
    g.add_argument("-f", "--format", default="json,html,md", help=f"report formats: {','.join(FORMATS)}")
    g.add_argument("--no-screenshots", action="store_true", help="skip PoC screenshots (headless Chromium)")
    _report_args(g)
    g.add_argument("--db", default=str(DEFAULT_DB), help=f"SQLite database (default {DEFAULT_DB})")
    g.add_argument("--model", default=str(DEFAULT_MODEL), help="ML triage model path")
    g = p.add_argument_group("console & session")
    g.add_argument("-v", "--verbose", type=int, nargs="?", const=2, default=1, metavar="N",
                   help="verbosity 0-6 (default 1): 2 debug, 3 payloads raw+encoded, 4 HTTP requests, "
                        "5 response headers, 6 response bodies")
    g.add_argument("--no-color", action="store_true", help="disable coloured output")
    g.add_argument("--no-progress", action="store_true", help="disable the live progress line")
    g.add_argument("--fresh", "--flush-session", dest="fresh", action="store_true",
                   help="ignore a saved session and start the scan over")
    g.add_argument("--session-dir", help="where scan sessions are saved (default: next to the database)")


def _report_args(g) -> None:
    g.add_argument("--report-style", choices=["client", "technical"], default="client",
                   help="client = clean deliverable (default); technical = adds ML scores, trace, diagnostics")
    g.add_argument("--report-author", help="'Prepared by' line, e.g. your name or company")
    g.add_argument("--report-title", default="Security Assessment Report")
    g.add_argument("--no-redact", action="store_true",
                   help="do not mask personal data (names, addresses, e-mail, phone, financial) in reports "
                        "and screenshots")


def _report_options(args):
    from webguard.reporting import ReportOptions

    return ReportOptions(style=getattr(args, "report_style", "client"), redact=not getattr(args, "no_redact", False),
                         author=getattr(args, "report_author", None),
                         title=getattr(args, "report_title", "Security Assessment Report"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webguard", formatter_class=FMT, epilog=MAIN_EXAMPLES,
                                description="WebGuard Pro - web application security assessment: recon, "
                                            "methodology-driven testing, verification and reporting")
    p.add_argument("--version", action="version", version=f"webguard {__version__}")
    p.add_argument("--wizard", action="store_true", help="guided mode for non-technical users (same as 'wizard')")
    sub = p.add_subparsers(dest="cmd", metavar="<command>", title="commands")
    _add = sub.add_parser

    def add_parser(name: str, **kw):
        return _add(name, formatter_class=FMT, epilog=EXAMPLES.get(name), description=kw.get("help"), **kw)

    sub.add_parser = add_parser  # every sub-command gets a description and usage examples

    s = sub.add_parser("scan", help="scan a web application")
    s.add_argument("targets", nargs="*", help="URL(s) or host(s)")
    s.add_argument("-l", "--list", help="file with one target per line")
    _common(s)

    r = sub.add_parser("recon", help="reconnaissance for a domain")
    r.add_argument("domain")
    r.add_argument("--passive", action="store_true", help="no traffic to the target (public sources only)")
    r.add_argument("--no-tools", action="store_true", help="don't use installed external tools")
    r.add_argument("--no-history", action="store_true", help="skip Wayback/gau URL collection")
    _common(r)

    h = sub.add_parser("hunt", help="bug bounty pipeline: recon -> rank -> scan -> nuclei -> triage -> reports")
    h.add_argument("domain")
    h.add_argument("--max-hosts", type=int, default=25)
    h.add_argument("--parallel-hosts", type=int, default=4,
                   help="hosts scanned concurrently (the --rate budget is split between them)")
    h.add_argument("--no-nuclei", action="store_true")
    h.add_argument("--no-tools", action="store_true")
    h.add_argument("--content-discovery", action="store_true", help="brute-force paths with ffuf (if installed)")
    _common(h)

    a = sub.add_parser("surface", help="red-team external attack surface mapping")
    a.add_argument("domain")
    a.add_argument("--no-ports", action="store_true")
    a.add_argument("--no-nmap", action="store_true", help="use built-in TCP connect scan instead of nmap")
    a.add_argument("--no-tools", action="store_true")
    _common(a)

    rep = sub.add_parser("report", help="generate reports for a stored scan")
    rep.add_argument("scan_id", type=int)
    rep.add_argument("-o", "--output", default="reports")
    rep.add_argument("-f", "--format", default="json,html,md")
    rep.add_argument("--min-severity", default="INFO")
    rep.add_argument("--db", default=str(DEFAULT_DB))
    _report_args(rep)

    d = sub.add_parser("db", help="query the findings/asset database")
    d.add_argument("--db", default=str(DEFAULT_DB))
    dsub = d.add_subparsers(dest="dbcmd", required=True)
    ds = dsub.add_parser("scans")
    ds.add_argument("--target")
    df = dsub.add_parser("findings")
    df.add_argument("--scan", type=int)
    df.add_argument("--target")
    df.add_argument("--json", action="store_true")
    dl = dsub.add_parser("label", help="mark a finding as true/false positive (ML training data)")
    dl.add_argument("finding_id", type=int)
    dl.add_argument("label", choices=["tp", "fp"])
    dl.add_argument("--note", default="")
    da = dsub.add_parser("assets")
    da.add_argument("target")
    da.add_argument("--kind", help="subdomain|host|url|endpoint|js|param|port")
    dn = dsub.add_parser("new", help="assets and findings first seen in the latest scan of a target")
    dn.add_argument("target")

    m = sub.add_parser("ml", help="machine-learning triage model")
    m.add_argument("--db", default=str(DEFAULT_DB))
    m.add_argument("--model", default=str(DEFAULT_MODEL))
    msub = m.add_subparsers(dest="mlcmd", required=True)
    msub.add_parser("train", help="train from labelled findings")
    msub.add_parser("status")

    asr = sub.add_parser("assess", help="autonomous methodology-driven assessment (plan -> test -> verify -> analyse)")
    asr.add_argument("target", help="URL or host")
    asr.add_argument("--llm", default="local", help="reasoning engine: local (default), claude, ollama[:model]")
    asr.add_argument("--llm-model", help="model id (default claude-opus-5-5 for claude, qwen2.5:7b for ollama)")
    asr.add_argument("--llm-effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
                     help="Claude effort level for planning decisions")
    asr.add_argument("--budget-requests", type=int, help="stop active testing after N requests")
    asr.add_argument("--budget-minutes", type=float, help="stop active testing after N minutes")
    asr.add_argument("--no-browser", action="store_true", help="skip headless-browser DOM XSS verification")
    asr.add_argument("--show-trace", action="store_true", help="print every reasoning step (thought/action/observation)")
    _common(asr)

    g = sub.add_parser("grep", help="grep stored responses of a scan with pattern packs or a regex")
    g.add_argument("scan_id", type=int)
    g.add_argument("--pack", action="append", help="dom-sinks, dom-sources, endpoints, infrastructure, debug, "
                                                   "identity, versions, secrets (default: all)")
    g.add_argument("--regex", help="custom regular expression")
    g.add_argument("--in", dest="kinds", help="limit to response kinds: js,json,html,other")
    g.add_argument("--limit", type=int, default=100)
    g.add_argument("--db", default=str(DEFAULT_DB))

    q = sub.add_parser("ask", help="natural-language query over findings, e.g. \"high sql injection on api\"")
    q.add_argument("question")
    q.add_argument("--scan", type=int)
    q.add_argument("--target")
    q.add_argument("--llm", default="local", help="local (keyword NLP) or claude / ollama[:model] for free-form answers")
    q.add_argument("--db", default=str(DEFAULT_DB))

    an = sub.add_parser("analyze", help="root-cause issues, attack chains and narrative for a stored scan")
    an.add_argument("scan_id", type=int)
    an.add_argument("--db", default=str(DEFAULT_DB))

    sub.add_parser("tools", help="show external tools and signature database status")
    w = sub.add_parser("wizard", help="guided mode: answers a few questions, explains and runs the right command")
    w.add_argument("--batch", action="store_true", help="accept the default answer for every question")
    return p


def make_config(args: argparse.Namespace) -> ScanConfig:
    checks = tuple(x.strip() for x in args.checks.split(",")) if args.checks else ALL_CHECKS
    if args.skip:
        skip = {x.strip() for x in args.skip.split(",")}
        checks = tuple(c for c in checks if c not in skip)
    unknown = set(checks) - set(ALL_CHECKS)
    if unknown:
        raise SystemExit(f"unknown checks: {', '.join(sorted(unknown))}")
    headers = {}
    for h in args.header:
        if ":" not in h:
            raise SystemExit(f"bad header {h!r}, expected 'Name: value'")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    cookies = dict(c.split("=", 1) for c in args.cookie if "=" in c)
    tamper = tuple(t.strip() for t in args.tamper.split(",")) if args.tamper else ()
    from webguard.detection.tamper import TAMPERS

    if set(tamper) - set(TAMPERS):
        raise SystemExit(f"unknown tamper: {set(tamper) - set(TAMPERS)}")
    from webguard.config import apply_profile

    return apply_profile(ScanConfig(
        concurrency=args.concurrency, rate_limit=args.rate, timeout=args.timeout, max_depth=args.depth,
        max_urls=args.max_urls, proxy=args.proxy, headers=headers, cookies=cookies, checks=checks,
        time_delay=args.time_delay, timing_checks=not args.no_timing, param_discovery=args.param_discovery,
        oob_domain=args.oob, tamper=tamper, db_path=Path(args.db), model_path=Path(args.model), verbose=args.verbose or 0,
        **({"discovery_wordlist": None} if args.no_discovery else
           {"discovery_wordlist": Path(args.wordlist), "wordlist": Path(args.wordlist)} if args.wordlist else {}),
    ), args.profile, explicit_wordlist=bool(args.wordlist) or args.no_discovery)


def make_scope(args: argparse.Namespace, target: str) -> Scope:
    if args.scope:
        scope = Scope.from_file(args.scope)
        if not scope.in_scope(target if "://" in target else f"http://{target}/"):
            raise SystemExit(f"target {target} is not covered by scope file {args.scope}")
        return scope
    return Scope.for_target(target, include_subdomains=args.subdomains)


def _formats(spec: str) -> list[str]:
    fmts = [f.strip() for f in spec.split(",") if f.strip()]
    bad = set(fmts) - set(FORMATS)
    if bad:
        raise SystemExit(f"unknown formats: {bad}")
    return fmts


# ----------------------------------------------------------------------------- sessions & progress

def _session(args, cfg: ScanConfig, target: str, mode: str, extra: str = ""):
    """Open (or resume) the saved session for this exact scan."""
    from webguard.session import Session

    directory = Path(args.session_dir) if getattr(args, "session_dir", None) else Path(args.db).parent / "sessions"
    selection = f"{','.join(cfg.checks)}|{getattr(args, 'profile', '')}|{extra}"
    sess = Session.open(directory, target, mode, selection, fresh=getattr(args, "fresh", False))
    if sess.resumed:
        ui.status(ui.c(f"Resuming the previous {mode} of {target}: {sess.describe()}", "cyan"))
        ui.status("  (use --fresh to discard the saved session and start over)")
        for f in sess.restored_findings():
            ui.print_finding(f, resumed=True)
    return sess


def _progress(args, source) -> ui.Progress:
    progress = ui.Progress(source)
    if getattr(args, "no_progress", False):
        progress.enabled = False
    return progress


# ----------------------------------------------------------------------------- commands

async def cmd_scan(args: argparse.Namespace) -> int:
    from webguard.engine import ScanEngine
    from webguard.reporting import write_all
    from webguard.signatures import SignatureDB

    targets = list(args.targets)
    if args.list:
        targets += [line.strip() for line in Path(args.list).read_text().splitlines() if line.strip()]
    if not targets:
        raise SystemExit("no targets given")
    cfg = make_config(args)
    db = Database(cfg.db_path)
    sigdb = SignatureDB(args.signatures)
    worst = Severity.INFO
    for target in targets:
        scope = make_scope(args, target)
        ui.status(f"Scanning {ui.c(target, 'bold')}")
        sess = _session(args, cfg, target, "scan")
        engine = ScanEngine(cfg, scope, sigdb, on_finding=ui.print_finding, on_status=ui.status, checkpoint=sess,
                            on_stage=ui.stage)
        scan_id = db.start_scan(target, "scan")
        with _progress(args, engine.progress):
            res = await engine.scan(target)
        sess.finish()
        await _screenshots(args, cfg, scope, res.findings)
        new = _persist(db, scan_id, target, res)
        paths = write_all(target, res.findings, Path(args.output), _formats(args.format), {"scan_id": scan_id, **res.meta()},
                      _report_options(args))
        _summary(res.findings, new, res.stats, paths, scan_id)
        if res.oob:
            ui.warn(f"{len(res.oob)} OOB payloads sent - check {cfg.oob_domain} for interactions (tokens in JSON report)")
        if res.findings:
            worst = max(worst, max(f.severity for f in res.findings))
    return 2 if worst >= Severity.HIGH else 0


async def _screenshots(args, cfg: ScanConfig, scope: Scope, findings: list) -> None:
    if getattr(args, "no_screenshots", False):
        return
    from webguard.reporting import poc

    if not poc.HAVE_PLAYWRIGHT:  # HTTP evidence is still collected; only the images need a browser
        ui.warn("PoC screenshots skipped: pip install playwright (and a Chromium) to enable them")
    ui.status("Collecting PoC evidence and screenshots")
    n = await poc.capture(findings, cfg, scope, Path(args.output), redact=not args.no_redact)
    ui.status(f"  {n} screenshot(s) saved under {Path(args.output) / 'poc'}")


def _persist(db: Database, scan_id: int, target: str, res) -> list:
    """Store findings, assets, responses (for grep) and the reasoning trace; returns new findings."""
    new = db.save_findings(scan_id, target, res.findings)
    db.upsert_assets(scan_id, target, "endpoint", res.urls)
    db.upsert_assets(scan_id, target, "js", res.js_files)
    db.upsert_assets(scan_id, target, "param", sorted({f"{p.method} {p.url} [{p.location}] {p.name}" for p in res.points}))
    db.store_responses(scan_id, (
        (u, r.method, r.status, r.content_type, dict(r.headers), r.text,
         res.page_types[u].label if u in res.page_types else None) for u, r in res.pages.items()))
    for t in res.trace:
        db.add_trace(scan_id, t.step, t.phase, t.thought, ", ".join(t.actions), t.observation)
    db.finish_scan(scan_id, res.stats)
    return new


def _print_trace(step) -> None:
    ui.out(ui.c(f"\n  ▸ step {step.step} [{step.phase}] ({step.engine})", "bold"))
    ui.out("    " + ui.c("thought: ", "cyan") + step.thought[:600])
    if step.actions:
        acts = ", ".join(step.actions[:6]) + (f" (+{len(step.actions) - 6})" if len(step.actions) > 6 else "")
        ui.out("    " + ui.c("actions: ", "cyan") + acts[:400])
    ui.out("    " + ui.c("observed: ", "cyan") + step.observation[:600])


async def cmd_assess(args: argparse.Namespace) -> int:
    from webguard.ai.reasoner import make_reasoner
    from webguard.assessment.agent import AssessmentAgent
    from webguard.assessment.methodology import RULES_OF_ENGAGEMENT
    from webguard.reporting import write_all
    from webguard.signatures import SignatureDB

    cfg = make_config(args)
    cfg.browser = not args.no_browser
    scope = make_scope(args, args.target)
    try:
        reasoner = make_reasoner(args.llm, args.llm_model, args.llm_effort)
    except ImportError:
        raise SystemExit("the claude engine needs the Anthropic SDK: pip install 'webguard-pro[llm]'") from None
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    ui.out(ui.c("Rules of engagement", "bold"))
    for rule in RULES_OF_ENGAGEMENT:
        ui.out("  - " + rule)
    ui.status(f"Assessing {ui.c(args.target, 'bold')} with the {reasoner.name} reasoning engine")
    db = Database(cfg.db_path)
    sess = _session(args, cfg, args.target, "assess", reasoner.name)
    scan_id = db.start_scan(args.target, "assess")
    agent = AssessmentAgent(cfg, scope, reasoner, SignatureDB(args.signatures), on_finding=ui.print_finding,
                            on_status=ui.status, on_trace=_print_trace if args.show_trace else None,
                            budget_requests=args.budget_requests, budget_minutes=args.budget_minutes,
                            checkpoint=sess, on_stage=ui.stage)
    with _progress(args, agent.progress):
        res = await agent.run(args.target)
    sess.finish()
    await _screenshots(args, cfg, scope, res.findings)
    new = _persist(db, scan_id, args.target, res)
    paths = write_all(args.target, res.findings, Path(args.output), _formats(args.format), {"scan_id": scan_id, **res.meta()},
                      _report_options(args))
    print(ui.c("\nExecutive summary", "bold"))
    print("  " + res.narrative.get("executive_summary", ""))
    if res.chains:
        print(ui.c("\nAttack chains", "bold"))
        for ch in res.chains:
            print(f"  {ui.sev_tag(ch['severity'])} {ui.c(ch['title'], ui.SEV_TEXT[ch['severity']])}\n"
                  f"      {ui.c(ch['steps'], 'dim')}")
    tested = sum(1 for v in res.coverage.values() if v != "not tested")
    print(ui.c(f"\nOWASP WSTG coverage: {tested}/{len(res.coverage)} areas", "bold"))
    _summary(res.findings, new, res.stats, paths, scan_id)
    ui.status(f"Reasoning trace: {len(res.trace)} steps (webguard analyze {scan_id} / HTML report)")
    return 2 if any(f.severity >= Severity.HIGH for f in res.findings) else 0


def cmd_grep(args: argparse.Namespace) -> int:
    from webguard.analysis.grep import PACKS, grep, summarize

    packs = args.pack
    if packs:
        bad = set(packs) - set(PACKS) - {"secrets"}
        if bad:
            raise SystemExit(f"unknown packs: {bad}; available: {', '.join([*PACKS, 'secrets'])}")
    db = Database(args.db)
    kinds = set(args.kinds.split(",")) if args.kinds else None
    hits = grep(db.iter_responses(args.scan_id), packs=packs, regex=args.regex, kinds=kinds)
    if not hits:
        ui.warn("no matches (did the scan store responses? run scan/assess with this version)")
        return 1
    for pack, rules in summarize(hits).items():
        print(ui.c(f"{pack}: ", "bold") + ", ".join(f"{r} ({n})" for r, n in rules.items()))
    print()
    for h in hits[: args.limit]:
        where = h.locations[0] + (f" (+{len(h.locations) - 1})" if len(h.locations) > 1 else "")
        print(f"{ui.c(f'{h.score:5.1f}', 'dim')} {ui.c(h.pack, 'cyan')}/{h.rule}: {ui.c(h.value[:120], 'bold')}  {ui.c(where, 'dim')}")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from webguard.nlp.query import parse, search

    db = Database(args.db)
    findings = db.findings(scan_id=args.scan, target=args.target)
    if args.llm and args.llm != "local":
        from webguard.ai.reasoner import make_reasoner

        reasoner = make_reasoner(args.llm)
        system = ("Answer the analyst's question about findings from an authorised security assessment. Use only "
                  "the findings provided; cite URLs; say so if the data does not answer the question.")
        payload = json.dumps({"question": args.question, "findings": [f.to_dict() for f in findings[:200]]}, default=str)
        schema = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"],
                  "additionalProperties": False}
        try:
            data = asyncio.run(reasoner._complete(system, payload, schema))
            print(data["answer"])
            return 0
        except Exception as exc:
            ui.warn(f"{reasoner.name} unavailable ({exc}); falling back to local keyword query")
    q = parse(args.question)
    hits = search(findings, args.question)
    ui.status(f"interpreted as: checks={sorted(q.checks) or 'any'} severities={sorted(s.name for s in q.severities) or 'any'}"
              f"{' min=' + q.min_severity.name if q.min_severity is not None else ''} url~{q.url_patterns or 'any'}"
              f"{' excluding ' + str(sorted(q.exclude_checks)) if q.exclude_checks else ''}")
    for f in hits:
        print(ui.finding_line(f))
    print(ui.c(f"{len(hits)} of {len(findings)} findings match", "dim"))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from webguard.analysis.correlate import attack_chains, cluster, false_positive_signals
    from webguard.nlp.summarize import executive_summary

    db = Database(args.db)
    row = next((r for r in db.scans(limit=100000) if r["id"] == args.scan_id), None)
    if row is None:
        raise SystemExit(f"scan {args.scan_id} not found")
    findings = db.findings(scan_id=args.scan_id)
    chains = attack_chains(findings)
    print(ui.c("Executive summary", "bold"))
    print("  " + executive_summary(row["target"], findings, chains))
    print(ui.c("\nRoot-cause issues (by risk)", "bold"))
    for i in cluster(findings):
        flags = false_positive_signals(i.findings[0])
        print(f"  {i.risk:6.2f}  {ui.c(f'{i.severity.name:<8}', ui.SEV[i.severity.name])} {i.title}  "
              f"{ui.c(f'CVSS {i.cvss} x{len(i.findings)}', 'dim')}" + (ui.c(f"  ⚠ {'; '.join(flags)}", 'yellow') if flags else ""))
    if chains:
        print(ui.c("\nAttack chains", "bold"))
        for ch in chains:
            print(f"  {ch['severity']:<8} {ch['title']}\n           {ch['steps']}")
    trace = db.trace(args.scan_id)
    if trace:
        print(ui.c(f"\nReasoning trace ({len(trace)} steps)", "bold"))
        for t in trace:
            print(f"  {t['step']:>3} [{t['phase']}] {t['thought'][:200]}\n        -> {t['observation'][:200]}")
    return 0


async def cmd_recon(args: argparse.Namespace) -> int:
    from webguard.workflows.recon import run_recon

    cfg = make_config(args)
    scope = make_scope(args, args.domain) if args.scope else Scope.for_target(args.domain, include_subdomains=True)
    db = Database(cfg.db_path)
    scan_id = db.start_scan(args.domain, "recon")
    res = await run_recon(args.domain, cfg, scope, db, scan_id, passive_only=args.passive,
                          use_tools=not args.no_tools, history=not args.no_history, status=ui.status)
    db.save_findings(scan_id, args.domain, res.findings)
    db.finish_scan(scan_id, {"subdomains": len(res.subdomains), "hosts": len(res.hosts)})
    print()
    for h in sorted(res.hosts, key=lambda h: h.url):
        waf = ui.c(f" WAF:{','.join(h.waf)}", "yellow") if h.waf else ""
        print(f"  {h.status} {ui.c(h.url, 'bold')} {ui.c(h.title[:60], 'dim')} {', '.join(h.technologies)[:120]}{waf}")
    for f in res.findings:
        ui.print_finding(f)
    if res.interesting_urls:
        print(ui.c(f"\n  Interesting historical URLs ({len(res.interesting_urls)}):", "bold"))
        for u in res.interesting_urls[:40]:
            print("   ", u)
    new_subs = res.new_assets.get("subdomain", [])
    if new_subs and db.new_assets(args.domain, scan_id):
        print(ui.c(f"\n  NEW since last run: {len(new_subs)} subdomains", "green"))
        for s in new_subs[:50]:
            print("   ", s)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"recon_{args.domain}_{scan_id}.json"
    path.write_text(json.dumps({"domain": args.domain, "sources": res.sources, "subdomains": res.subdomains,
                                "hosts": [h.to_dict() for h in res.hosts], "interesting_urls": res.interesting_urls,
                                "historical_urls": res.historical_urls,
                                "findings": [f.to_dict() for f in res.findings]}, indent=2))
    ui.status(f"Recon saved to {path} (scan id {scan_id})")
    return 0


async def cmd_hunt(args: argparse.Namespace) -> int:
    from webguard.workflows.hunt import hunt

    cfg = make_config(args)
    scope = make_scope(args, args.domain) if args.scope else Scope.for_target(args.domain, include_subdomains=True)
    db = Database(cfg.db_path)
    res = await hunt(args.domain, cfg, scope, db, Path(args.output), _formats(args.format), max_hosts=args.max_hosts,
                     use_nuclei=not args.no_nuclei, use_tools=not args.no_tools,
                     content_discovery=args.content_discovery, parallel_hosts=args.parallel_hosts,
                     screenshots=not args.no_screenshots, report_options=_report_options(args), on_finding=ui.print_finding,
                     status=ui.status, session_dir=None if args.fresh else (
                         Path(args.session_dir) if args.session_dir else Path(args.db).parent / "sessions"))
    print(ui.c("\nTop targets by attack-surface score:", "bold"))
    for r in res.ranking[:10]:
        print(f"  {r['score']:>5}  {r['url']}  {ui.c('; '.join(r['reasons']), 'dim')}")
    _summary(res.findings, res.new_findings, {}, res.reports, res.scan_id)
    return 2 if any(f.severity >= Severity.HIGH for f in res.findings) else 0


async def cmd_surface(args: argparse.Namespace) -> int:
    from webguard.reporting import write_all
    from webguard.workflows.redteam import RECON_TECHNIQUES, attack_mapping, attack_surface

    cfg = make_config(args)
    scope = make_scope(args, args.domain) if args.scope else Scope.for_target(args.domain, include_subdomains=True)
    db = Database(cfg.db_path)
    res = await attack_surface(args.domain, cfg, scope, db, scan_ports=not args.no_ports, use_nmap=not args.no_nmap,
                               use_tools=not args.no_tools, status=ui.status)
    print(ui.c("\nExternal attack surface (ranked):", "bold"))
    for r in res.ranking[:25]:
        h = r["host"]
        print(f"  {r['score']:>5}  {h.url} [{h.status}] {', '.join(h.technologies)[:80]}  {ui.c('; '.join(r['reasons']), 'dim')}")
    if res.ports:
        print(ui.c("\nOpen ports:", "bold"))
        for host, ports in sorted(res.ports.items()):
            if ports:
                svc = {s["port"]: f"{s['service']} {s['product']} {s['version']}".strip() for s in res.services.get(host, [])}
                print(f"  {host}: " + ", ".join(f"{p}{'/' + svc[p] if p in svc else ''}" for p in ports))
    techniques: dict[str, str] = dict(RECON_TECHNIQUES)
    for f in res.findings:
        ui.print_finding(f)
        techniques.update(dict(attack_mapping(f)))
    print(ui.c("\nMITRE ATT&CK techniques covered:", "bold"))
    for tid, name in sorted(techniques.items()):
        print(f"  {tid:<10} {name}")
    meta = {"scan_id": res.scan_id, "hosts": [h.to_dict() for h in res.recon.hosts], "ports": res.ports,
            "services": res.services, "ranking": [{k: v for k, v in r.items() if k != "host"} for r in res.ranking],
            "attack_techniques": techniques}
    paths = write_all(args.domain, res.findings, Path(args.output), _formats(args.format), meta, _report_options(args))
    for p in paths:
        ui.status(f"Report: {p}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from webguard.reporting import write_all

    db = Database(args.db)
    row = next((r for r in db.scans(limit=100000) if r["id"] == args.scan_id), None)
    if row is None:
        raise SystemExit(f"scan {args.scan_id} not found")
    findings = db.findings(scan_id=args.scan_id, min_severity=int(Severity.parse(args.min_severity)))
    for p in write_all(row["target"], findings, Path(args.output), _formats(args.format), {"scan_id": args.scan_id},
                       _report_options(args)):
        ui.status(f"Report: {p}")
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    db = Database(args.db)
    if args.dbcmd == "scans":
        for r in db.scans(args.target):
            print(f"{r['id']:>5}  {r['started']}  {r['mode']:<8} {r['target']:<40} findings={r['n_findings']}")
    elif args.dbcmd == "findings":
        rows = db.finding_rows(args.scan, args.target)
        if args.json:
            print(json.dumps([dict(r) for r in rows], indent=2))
        for r in rows if not args.json else []:
            sev = Severity(r["severity"]).name
            label = f" [{r['label']}]" if r["label"] else ""
            ml = f" ml={r['ml_score']:.2f}" if r["ml_score"] is not None else ""
            print(f"{r['id']:>6}  {ui.sev_tag(sev)} {ui.c(r['title'], ui.SEV_TEXT[sev])}  {ui.c(r['url'], 'dim')} "
                  f"{r['parameter'] or ''}{ml}{label}")
    elif args.dbcmd == "label":
        if not db.label(args.finding_id, args.label, args.note):
            raise SystemExit("finding not found")
        ui.status(f"finding {args.finding_id} labelled {args.label}")
    elif args.dbcmd == "assets":
        for r in db.assets(args.target, args.kind):
            print(f"{r['kind']:<10} {r['value']}  (first scan {r['first_scan']}, last {r['last_scan']})")
    elif args.dbcmd == "new":
        last = db.last_scan_id(args.target)
        if last is None:
            raise SystemExit("no scans for target")
        assets = db.new_assets(args.target, last)
        print(ui.c(f"New assets in scan {last}: {len(assets)}", "bold"))
        for r in assets:
            print(f"  {r['kind']:<10} {r['value']}")
        fixed = db.fixed_findings(args.target, last)
        if fixed:
            print(ui.c(f"Findings no longer present (fixed?): {len(fixed)}", "bold"))
            for r in fixed:
                print(f"  {r['title']} {r['url']}")
    return 0


def cmd_ml(args: argparse.Namespace) -> int:
    from webguard.ml.triage import TriageModel, cross_validate

    model_path = Path(args.model)
    if args.mlcmd == "status":
        m = TriageModel.load(model_path)
        print(json.dumps({"trained": m.trained, "path": str(model_path), **m.meta}, indent=2))
        return 0
    samples = Database(args.db).labeled()
    ui.status(f"{len(samples)} labelled findings ({sum(y for _, y in samples)} tp)")
    m = TriageModel()
    try:
        meta = m.fit(samples)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if len(samples) >= 10:
        meta["cv_accuracy"] = round(cross_validate(samples), 3)
    m.meta = meta
    m.save(model_path)
    ui.status(f"model saved to {model_path}: {meta}")
    return 0


def cmd_tools() -> int:
    from webguard.detection.anomaly import HAVE_SKLEARN
    from webguard.recon import tools
    from webguard.recon.active import HAVE_DNSPYTHON
    from webguard.signatures import default_db

    print(ui.c("External tools", "bold"))
    for name, path in tools.available().items():
        mark = ui.c("✔", "green") if path else ui.c("✘", "red")
        print(f"  {mark} {name:<12} {path or tools.KNOWN_TOOLS[name]}")
    print(ui.c("\nOptional Python components", "bold"))
    print(f"  {'✔' if HAVE_SKLEARN else '✘'} scikit-learn (IsolationForest anomaly model; robust z-score fallback otherwise)")
    print(f"  {'✔' if HAVE_DNSPYTHON else '✘'} dnspython (CNAME-based subdomain takeover detection)")
    print(ui.c("\nSignature database", "bold"))
    for k, v in default_db().stats().items():
        print(f"  {k:<14} {v}")
    return 0


WIZARD_MODES = {
    "1": ("Quick safe check", "light, production-friendly tests (recommended for live sites)", ["scan", "--profile", "safe"]),
    "2": ("Full vulnerability scan", "every applicable test, the most thorough result", ["scan"]),
    "3": ("Smart assessment", "the most important tests first; can be time-boxed", ["assess"]),
    "4": ("Bug bounty hunt", "find subdomains, rank them and scan the most promising", ["hunt"]),
    "5": ("Recon only", "map subdomains, hosts and technologies - no attacks", ["recon"]),
}


def wizard_argv(ask) -> list[str] | None:
    """Ask plain-language questions and build the equivalent command line (``ask(question, default)``)."""
    def yes(q: str, default: bool) -> bool:
        a = ask(f"{q} [{'Y/n' if default else 'y/N'}] ", "y" if default else "n").strip().lower()
        return (a or ("y" if default else "n")).startswith("y")

    target = ask("Website or domain to test (e.g. https://shop.example.com): ", "").strip()
    if not target:
        ui.warn("No target given.")
        return None
    if not yes("Do you own this website or have written permission to test it?", False):
        ui.warn("Stopping: you need the owner's permission before testing a website.")
        return None
    ui.out(ui.c("\nWhat would you like to do?", "bold"))
    for k, (name, desc, _) in WIZARD_MODES.items():
        ui.out(f"  [{k}] {ui.c(name, 'bold')} - {desc}")
    choice = ask("Choose 1-5 [1]: ", "1").strip() or "1"
    if choice not in WIZARD_MODES:
        choice = "1"
    argv = [*WIZARD_MODES[choice][2], target]
    if argv[0] in ("hunt", "recon") and "://" in target:
        argv[-1] = target.split("://", 1)[1].split("/")[0]
    if argv[0] in ("scan", "assess") and choice != "1":
        if yes("Is this a live production website (real customers)?", True):
            argv += ["--profile", "safe"]
    if argv[0] != "recon":
        cookie = ask("If the test needs a login, paste a session cookie as name=value (Enter to skip): ", "").strip()
        if cookie and "=" in cookie:
            argv += ["--cookie", cookie]
        token = ask("Authorization header value, e.g. 'Bearer eyJ...' (Enter to skip): ", "").strip()
        if token:
            argv += ["-H", f"Authorization: {token}"]
    if argv[0] == "assess":
        minutes = ask("Maximum test duration in minutes (Enter for no limit): ", "").strip()
        if minutes.replace(".", "", 1).isdigit():
            argv += ["--budget-minutes", minutes]
    if argv[0] == "hunt":
        bb = ask("Bug bounty programme header, e.g. 'X-Bug-Bounty: yourname' (Enter to skip): ", "").strip()
        if ":" in bb:
            argv += ["-H", bb]
    proxy = ask("Send traffic through a proxy such as Burp, e.g. http://127.0.0.1:8080 (Enter to skip): ", "").strip()
    if proxy:
        argv += ["--proxy", proxy]
    if argv[0] != "recon":
        if not yes("Include slower time-based tests (more thorough)?", False):
            argv.append("--no-timing")
        author = ask("Your name or company for the report (Enter to skip): ", "").strip()
        if author:
            argv += ["--report-author", author]
        if yes("Show each payload as it is tested (raw and encoded)?", False):
            argv += ["-v", "3"]
    return argv


def cmd_wizard(batch: bool = False) -> int:
    import shlex

    ui.banner()
    ui.out(ui.c("Guided mode", "bold") + " - answer a few questions; press Enter to accept the [default].\n")

    def ask(question: str, default: str) -> str:
        if batch:
            ui.out(f"{question}{default}")
            return default
        return input(ui.c("[?] ", "cyan") + question)

    try:
        argv = wizard_argv(ask)
    except EOFError:
        return 1
    if not argv:
        return 1
    ui.out(ui.c("\nEquivalent command (use it directly next time):", "bold"))
    ui.out("  webguard " + " ".join(shlex.quote(a) for a in argv) + "\n")
    if not batch and input(ui.c("[?] ", "cyan") + "Start now? [Y/n] ").strip().lower().startswith("n"):
        return 0
    return main(argv)


def _summary(findings, new, stats, paths, scan_id) -> None:
    ui.findings_table(findings)
    ui.out("\n" + ui.c("Summary ", "bold") + ui.severity_counts(findings) + f"  (new: {len(new)}, scan id {scan_id})")
    if stats:
        ui.out(ui.c(f"  {stats.get('requests', 0)} requests in {stats.get('duration_s', '?')}s", "dim"))
    for p in paths:
        ui.status(f"Report: {p}")


def main(argv: list[str] | None = None) -> int:
    argv = _verbosity_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if args.wizard and not args.cmd:
        return cmd_wizard()
    if not args.cmd:
        parser.print_help()
        return 0
    verbose = getattr(args, "verbose", 1)
    ui.set_level(1 if verbose is None else verbose)
    if getattr(args, "no_color", False):
        ui.set_color(False)
    root = logging.getLogger()
    if not any(isinstance(h, ui.LogHandler) for h in root.handlers):
        root.addHandler(ui.LogHandler())
    root.setLevel(logging.WARNING)  # third-party libraries: warnings only
    logging.getLogger("webguard").setLevel(logging.DEBUG if ui.LEVEL >= 2 else logging.WARNING)
    try:
        if args.cmd in ("scan", "recon", "hunt", "surface", "assess"):
            ui.banner()
            fn = {"scan": cmd_scan, "recon": cmd_recon, "hunt": cmd_hunt, "surface": cmd_surface,
                  "assess": cmd_assess}[args.cmd]
            return asyncio.run(fn(args))
        if args.cmd == "grep":
            return cmd_grep(args)
        if args.cmd == "ask":
            return cmd_ask(args)
        if args.cmd == "analyze":
            return cmd_analyze(args)
        if args.cmd == "report":
            return cmd_report(args)
        if args.cmd == "db":
            return cmd_db(args)
        if args.cmd == "ml":
            return cmd_ml(args)
        if args.cmd == "tools":
            return cmd_tools()
        if args.cmd == "wizard":
            return cmd_wizard(args.batch)
    except KeyboardInterrupt:
        ui.warn("interrupted by user")
        if args.cmd in ("scan", "assess", "hunt"):
            ui.status("progress saved - run the same command again to resume where it stopped (--fresh to start over)")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
