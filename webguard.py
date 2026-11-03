#!/usr/bin/env python3
"""Backward-compatible entry point.

Legacy flags are translated to the new sub-command CLI:

    -d DOMAIN -m passive        ->  webguard recon DOMAIN --passive
    -d DOMAIN -m active         ->  webguard surface DOMAIN
    -d DOMAIN -m vulnerability  ->  webguard scan DOMAIN
    -f FILE                     ->  webguard scan -l FILE
    --tor                       ->  --proxy socks5://127.0.0.1:9050  (requires a running Tor client)
    --wizard / no arguments     ->  webguard wizard

Prefer the new CLI directly:  python -m webguard --help
"""

import sys

from webguard.cli import main

SUBCOMMANDS = {"scan", "recon", "hunt", "surface", "report", "db", "ml", "tools", "wizard"}


def translate(argv: list[str]) -> list[str]:
    if not argv or argv[0] == "--wizard":
        return ["wizard"]
    if argv[0] in SUBCOMMANDS or argv[0] in ("-h", "--help", "--version"):
        return argv
    mode, domain, file_, rest = "vulnerability", None, None, []
    it = iter(argv)
    for arg in it:
        if arg in ("-m", "--mode"):
            mode = next(it, mode)
        elif arg in ("-d", "--domain"):
            domain = next(it, None)
        elif arg in ("-f", "--file"):
            file_ = next(it, None)
        elif arg == "--tor":
            rest += ["--proxy", "socks5://127.0.0.1:9050"]
        elif arg.startswith("-v"):
            rest.append(arg)
        elif arg == "--subdomains":
            rest.append(arg)
    if mode == "passive":
        return ["recon", domain or "", "--passive", *[r for r in rest if r != "--subdomains"]]
    if mode == "active":
        return ["surface", domain or "", *[r for r in rest if r != "--subdomains"]]
    out = ["scan"] + ([domain] if domain else []) + (["-l", file_] if file_ else [])
    return out + rest


if __name__ == "__main__":
    sys.exit(main(translate(sys.argv[1:])))
