#!/usr/bin/env python3
"""Backward-compatible wrapper: `python3 scanner.py -d example.com` == `webguard scan example.com`."""

import sys

from webguard.cli import main

if __name__ == "__main__":
    argv = sys.argv[1:]
    out, targets = ["scan"], []
    it = iter(argv)
    for arg in it:
        if arg in ("-d", "--domains"):
            continue
        if arg in ("-f", "--file"):
            out += ["-l", next(it, "")]
        elif arg in ("-t", "--threads"):
            out += ["-c", next(it, "10")]
        elif arg == "--subdomains" or arg.startswith("-v") or arg in ("-h", "--help"):
            out.append(arg)
        elif arg in ("--depth", "--timeout"):
            out += [arg, next(it, "")]
        else:
            targets.append(arg)
    sys.exit(main(out[:1] + targets + out[1:]))
