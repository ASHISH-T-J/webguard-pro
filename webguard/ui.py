"""Terminal output helpers (ANSI colours, disabled for non-TTY or NO_COLOR)."""

from __future__ import annotations

import os
import sys

from webguard.config import DATA_DIR
from webguard.models import Finding

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
CODES = {"red": "91", "green": "92", "yellow": "93", "blue": "94", "magenta": "95", "cyan": "96", "bold": "1",
         "dim": "2"}
SEV = {"CRITICAL": "magenta", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}


def c(text: str, color: str) -> str:
    return f"\033[{CODES[color]}m{text}\033[0m" if _COLOR else text


def banner() -> None:
    try:
        print(c((DATA_DIR / "banner.txt").read_text().rstrip("\n"), "cyan"))
    except OSError:
        pass
    print(c("  WebGuard Pro 3 · assess · recon · detection · hunting", "bold"))
    print(c("  Only test systems you own or are explicitly authorised to assess.\n", "yellow"))


def status(msg: str) -> None:
    print(c("[*] ", "cyan") + msg, flush=True)


def warn(msg: str) -> None:
    print(c("[!] ", "yellow") + msg, file=sys.stderr, flush=True)


def finding_line(f: Finding) -> str:
    sev = c(f"{f.severity.name:<8}", SEV[f.severity.name])
    param = f" [{f.parameter}]" if f.parameter else ""
    ml = f" ml={f.ml_score:.2f}" if f.ml_score is not None else ""
    return f"{sev} {c(f.confidence.name[:4], 'dim')} {f.title} {c(f.url + param, 'dim')}{c(ml, 'dim')}"


def print_finding(f: Finding) -> None:
    print(c("[+] ", "green") + finding_line(f), flush=True)
