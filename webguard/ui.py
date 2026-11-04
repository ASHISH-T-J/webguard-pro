"""Terminal output: colours, verbosity levels, findings, payload/HTTP tracing and a live progress line.

Verbosity (``-v N``, like sqlmap):

    0  findings, warnings and the final summary only
    1  + stages of testing and progress information (default)
    2  + debug: every test as it starts, rate adjustments, decisions
    3  + payloads: check, URL, parameter, raw and encoded (wire) payload
    4  + HTTP requests
    5  + HTTP response status and headers
    6  + HTTP response bodies

Terminal output is never redacted: it is the tester's own console. Colours are disabled when stdout is
not a terminal, with ``--no-color`` or when ``NO_COLOR`` is set.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import sys
import time
from collections import Counter
from collections.abc import Callable
from urllib.parse import quote

from webguard.config import DATA_DIR
from webguard.models import Finding, Severity

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
LEVEL = 1
CODES = {"red": "91", "green": "92", "yellow": "93", "blue": "94", "magenta": "95", "cyan": "96", "bold": "1",
         "dim": "2", "white": "97", "red_bold": "1;91", "bg_red": "1;97;41"}
# findings: critical & high red, medium yellow, low blue, informational green
SEV = {"CRITICAL": "bg_red", "HIGH": "red_bold", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
SEV_TEXT = {"CRITICAL": "red_bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
LIVE: Progress | None = None
_ANSI = re.compile(r"\033\[[0-9;]*m")


def set_level(level: int) -> None:
    global LEVEL
    LEVEL = max(0, min(6, int(level)))


def set_color(enabled: bool) -> None:
    global _COLOR
    _COLOR = enabled and not os.environ.get("NO_COLOR")


def c(text: str, color: str) -> str:
    return f"\033[{CODES[color]}m{text}\033[0m" if _COLOR else text


def _stamp() -> str:
    return c(time.strftime("[%H:%M:%S]"), "dim")


def out(text: str = "", *, err: bool = False) -> None:
    """Print without tearing the live progress line."""
    if LIVE is not None:
        LIVE.clear()
    print(text, file=sys.stderr if err else sys.stdout, flush=True)


def banner() -> None:
    if LEVEL == 0:
        return
    try:
        out(c((DATA_DIR / "banner.txt").read_text().rstrip("\n"), "cyan"))
    except OSError:
        pass
    out(c("  WebGuard Pro 3 · assess · recon · detection · hunting", "bold"))
    out(c("  Only test systems you own or are explicitly authorised to assess.\n", "yellow"))


def status(msg: str) -> None:
    if LEVEL >= 1:
        out(f"{_stamp()} {c('[INFO]', 'green')} {msg}")


def debug(msg: str) -> None:
    if LEVEL >= 2:
        out(f"{_stamp()} {c('[DEBUG]', 'dim')} {msg}")


def warn(msg: str) -> None:
    out(f"{_stamp()} {c('[WARNING]', 'yellow')} {msg}", err=True)


def error(msg: str) -> None:
    out(f"{_stamp()} {c('[ERROR]', 'red_bold')} {msg}", err=True)


class LogHandler(logging.Handler):
    """Route library log records through the console (same format, never tears the progress line)."""

    def emit(self, record: logging.LogRecord) -> None:
        tag = {"DEBUG": c("[DEBUG]", "dim"), "INFO": c("[INFO]", "green"), "WARNING": c("[WARNING]", "yellow")}.get(
            record.levelname, c(f"[{record.levelname}]", "red_bold"))
        out(f"{_stamp()} {tag} {c(record.name, 'dim')}: {record.getMessage()}",
            err=record.levelno >= logging.WARNING)


def stage(index: int, total: int, name: str, detail: str = "") -> None:
    """Stage-of-testing header, e.g. ``[stage 4/6] Input validation``."""
    if LIVE is not None:
        LIVE.set_stage(index, total, name)
    if LEVEL >= 1:
        bar = c("━" * 3, "cyan")
        out(f"\n{bar} {c(f'[stage {index}/{total}]', 'cyan')} {c(name, 'bold')}"
            + (f" {c('· ' + detail, 'dim')}" if detail else "") + f" {bar}")


# ----------------------------------------------------------------------------- findings

def sev_tag(name: str) -> str:
    return c(f" {name} " if _COLOR else f"[{name}]", SEV[name])


def finding_line(f: Finding) -> str:
    param = f" [{f.parameter}]" if f.parameter else ""
    return f"{sev_tag(f.severity.name)} {c(f.title, SEV_TEXT[f.severity.name])} {c(f.url + param, 'dim')}"


def finding_block(f: Finding, resumed: bool = False) -> str:
    """sqlmap-style finding block: what, where, how (payload) and the proof."""
    sev = f.severity.name
    note = f"({f.confidence.name.lower()} confidence{', restored from session' if resumed else ''})"
    lines = [f"{sev_tag(sev)} {c(f.title, SEV_TEXT[sev])}  {c(note, 'dim')}"]

    def row(label: str, value) -> None:
        if value:
            text = str(value).replace("\n", " ")
            lines.append(f"    {c(f'{label:<10}', 'bold')}: {text[:400]}{'…' if len(text) > 400 else ''}")

    row("URL", f.url)
    if f.parameter:
        row("Parameter", f"{f.parameter} ({f.location or 'query'})")
    row("Payload", f.payload)
    if f.payload:
        value = f.payload
        enc = (f.context or {}).get("value_encoding")
        if enc:  # the parameter carries base64/hex/...: the payload is encoded before it is sent
            from webguard.detection.encoding import encode_context

            value = str(encode_context(f.payload, enc))
        wire = encoded(value, f.location)
        if wire != f.payload:
            row("Encoded", wire + (f"  ({enc} value, then URL-encoded)" if enc and wire != value else
                                   f"  ({enc} value)" if enc else ""))
    row("Evidence", f.evidence)
    if f.cwe or f.owasp:
        row("Class", " · ".join(x for x in (f.cwe, f.owasp) if x))
    return "\n".join(lines)


def print_finding(f: Finding, resumed: bool = False) -> None:
    if LIVE is not None:
        LIVE.add_finding(f)
    # MEDIUM and above as a full block (payload + proof); LOW / INFO as one line
    out(finding_block(f, resumed) if f.severity >= Severity.MEDIUM else f"{_stamp()} {finding_line(f)}")


def findings_table(findings: list[Finding], limit: int = 60) -> None:
    """End-of-scan list, worst first."""
    if not findings:
        out(c("\nNo findings.", "green"))
        return
    out(c(f"\nFindings ({len(findings)})", "bold"))
    ordered = sorted(findings, key=lambda f: (-f.severity, -f.confidence, f.title))
    width = shutil.get_terminal_size((120, 20)).columns
    for f in ordered[:limit]:
        param = f" [{f.parameter}]" if f.parameter else ""
        text = f"{f.title} - {f.url}{param}"
        out(f"  {sev_tag(f.severity.name):<10} {c(text[: max(40, width - 14)], SEV_TEXT[f.severity.name])}")
    if len(ordered) > limit:
        out(c(f"  … {len(ordered) - limit} more in the report", "dim"))


def severity_counts(findings: list[Finding]) -> str:
    counts = Counter(f.severity.name for f in findings)
    return "  ".join(c(f"{s.name}:{counts.get(s.name, 0)}", SEV_TEXT[s.name]) for s in sorted(Severity, reverse=True))


# ----------------------------------------------------------------------------- payload / HTTP tracing

def encoded(value: str, location: str | None) -> str:
    """How a value travels on the wire for its location (query/form are percent-encoded)."""
    if location in (None, "", "query", "path", "form"):
        return quote(str(value), safe="")
    return str(value)


def payload(check: str, method: str, url: str, parameter: str, location: str, raw: str, wire: str,
            variant: str | None = None, encoding: str | None = None, wire_exact: bool = False) -> None:
    if LEVEL < 3:
        return
    head = (f"{_stamp()} {c('[PAYLOAD]', 'magenta')} {c(check or 'test', 'bold')} · {method} {url} "
            f"{c('[' + parameter + ']', 'cyan')} ({location})")
    lines = [head, f"           raw     : {raw}"]
    on_wire = wire if wire_exact else encoded(wire, location)  # Raw values are already wire-exact
    if on_wire != raw:
        lines.append(f"           encoded : {on_wire}")
    extra = " · ".join(x for x in (f"tamper/variant: {variant}" if variant else "",
                                   f"value encoding: {encoding}" if encoding else "") if x)
    if extra:
        lines.append(c(f"           {extra}", "dim"))
    out("\n".join(lines))


def http_exchange(request, status: int, headers, text: str, elapsed: float) -> None:
    """Called by the HTTP client for every response (levels 4-6)."""
    if LEVEL < 4:
        return
    lines = [f"{_stamp()} {c('[REQUEST]', 'blue')} {request.method} {request.url}"]
    lines += [c(f"    {k}: {v}", "dim") for k, v in request.headers.items()
              if k.lower() not in ("accept-encoding", "connection")]
    body = request.content.decode("utf-8", "replace") if getattr(request, "content", b"") else ""
    if body:
        lines.append(c(f"    {body[:2000]}", "dim"))
    if LEVEL >= 5:
        lines.append(f"{_stamp()} {c('[RESPONSE]', 'blue')} HTTP {status} ({len(text)} bytes, {elapsed * 1000:.0f} ms)")
        lines += [c(f"    {k}: {v}", "dim") for k, v in headers.items()]
    if LEVEL >= 6 and text:
        lines.append(text[:20000] + (c(f"\n    … {len(text) - 20000} more bytes", "dim") if len(text) > 20000 else ""))
    out("\n".join(lines))


# ----------------------------------------------------------------------------- live progress

class Progress:
    """Single redrawn status line on stderr (TTY only): stage, tests done, requests, findings, elapsed.

    ``source`` is a callable returning a dict with optional keys: done, total, requests, current.
    """

    def __init__(self, source: Callable[[], dict] | None = None, interval: float = 0.25) -> None:
        self.source = source or (lambda: {})
        self.interval = interval
        self.enabled = sys.stderr.isatty() and LEVEL >= 1 and not os.environ.get("WEBGUARD_NO_PROGRESS")
        self.stage = ""
        self.counts: Counter[str] = Counter()
        self.t0 = time.time()
        self._task: asyncio.Task | None = None
        self._drawn = False

    def set_stage(self, index: int, total: int, name: str) -> None:
        self.stage = f"{index}/{total} {name}"

    def add_finding(self, f: Finding) -> None:
        self.counts[f.severity.name] += 1

    def clear(self) -> None:
        if self._drawn:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
            self._drawn = False

    def line(self) -> str:
        s = self.source() or {}
        el = int(time.time() - self.t0)
        parts = [c(f"[{self.stage or 'starting'}]", "cyan")]
        done, total = s.get("done", 0), s.get("total", 0)
        if total:
            filled = int(20 * min(done, total) / total)
            parts.append(f"{'█' * filled}{'░' * (20 - filled)} {done}/{total} tests")
        req = s.get("requests", 0)
        parts.append(f"{req} req ({req / max(el, 1):.1f}/s)")
        found = " ".join(c(f"{n}{k[0]}", SEV_TEXT[k]) for k, n in sorted(
            self.counts.items(), key=lambda kv: -Severity[kv[0]]))
        if found:
            parts.append(found)
        parts.append(f"{el // 60:02d}:{el % 60:02d}")
        if s.get("current"):
            parts.append(c(str(s["current"]), "dim"))
        return " · ".join(parts)

    def draw(self) -> None:
        width = shutil.get_terminal_size((120, 20)).columns - 1
        text = self.line()
        if len(_ANSI.sub("", text)) > width:  # too wide: plain text, cut at the terminal edge
            text = _ANSI.sub("", text)[:width]
        sys.stderr.write("\r\033[K" + text)
        sys.stderr.flush()
        self._drawn = True

    async def _run(self) -> None:
        while True:
            self.draw()
            await asyncio.sleep(self.interval)

    def __enter__(self) -> Progress:
        global LIVE
        LIVE = self
        if self.enabled:
            self._task = asyncio.get_running_loop().create_task(self._run())
        return self

    def __exit__(self, *exc) -> None:
        global LIVE
        if self._task:
            self._task.cancel()
        self.clear()
        LIVE = None
