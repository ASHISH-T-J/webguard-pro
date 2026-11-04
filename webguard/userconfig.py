"""User configuration: config files, per-command defaults and ``--set`` overrides.

Precedence (later wins): built-in defaults < config file ``defaults:`` < config file ``<command>:`` section
< command-line flags < ``--set key=value``.

Config file locations: ``--config FILE``, ``$WEBGUARD_CONFIG``, ``./webguard.yml``, ``~/.webguard/config.yml``
(first found). Keys are the long option names without dashes (``rate``, ``header``, ``checks``, ``profile``,
``report_author`` ...). The ``set:`` section takes any :class:`~webguard.config.ScanConfig` field, including
ones without a command-line flag (``retries``, ``user_agent``, ``oob_wait``, ``max_new_hosts`` ...).

    defaults:
      rate: 10
      header: ["X-Bug-Bounty: alice"]
      report_author: ACME Security
    scan:
      profile: safe
      checks: [sqli, xss, exposure, headers, tls, server, cms]
    assess:
      budget_minutes: 30
      skip_phases: [authz_client]
    set:
      retries: 4
      user_agent: "Mozilla/5.0 (compatible; acme-security-test)"
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any

import yaml

from webguard.config import ScanConfig

SEARCH = ("webguard.yml", "webguard.yaml", "~/.webguard/config.yml")


def find(explicit: str | None) -> Path | None:
    for cand in (explicit, os.environ.get("WEBGUARD_CONFIG"), *SEARCH):
        if cand and Path(cand).expanduser().is_file():
            return Path(cand).expanduser()
    if explicit:
        raise SystemExit(f"config file not found: {explicit}")
    return None


def load(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected a mapping at the top level")
    return data


def _as_list(v: Any) -> Any:
    return ",".join(map(str, v)) if isinstance(v, list) else v


def apply_defaults(parser, subparsers: dict, data: dict[str, Any]) -> list[str]:
    """Push config values into argparse defaults. Returns warnings for unknown keys."""
    warnings: list[str] = []
    common = data.get("defaults") or {}
    for name, sub in subparsers.items():
        known = {a.dest: a for a in sub._actions}
        values = {**common, **(data.get(name) or {})}
        for key, value in values.items():
            dest = key.replace("-", "_")
            if dest not in known:
                if name in data and key in (data.get(name) or {}):
                    warnings.append(f"config: '{key}' is not an option of '{name}'")
                continue
            action = known[dest]
            if action.default is not None and isinstance(action.default, list):  # append-style options
                value = value if isinstance(value, list) else [value]
            elif dest in ("checks", "skip", "format", "skip_phases", "only_phases"):
                value = _as_list(value)
            sub.set_defaults(**{dest: value})
    for section in data:
        if section not in subparsers and section not in ("defaults", "set"):
            warnings.append(f"config: unknown section '{section}'")
    return warnings


def coerce(field: dataclasses.Field, raw: Any) -> Any:
    t = str(field.type)
    if not isinstance(raw, str):
        return tuple(raw) if "tuple" in t and isinstance(raw, list) else raw
    if "bool" in t:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if "tuple" in t:
        return tuple(x.strip() for x in raw.split(",") if x.strip())
    if "Path" in t:
        return Path(raw)
    if "float" in t:
        return float(raw)
    if "int" in t:
        return int(raw)
    if "dict" in t:
        return dict(kv.split("=", 1) for kv in raw.split(",") if "=" in kv)
    return None if raw.lower() == "none" and "None" in t else raw


def apply_set(cfg: ScanConfig, items: dict[str, Any]) -> ScanConfig:
    fields = {f.name: f for f in dataclasses.fields(ScanConfig)}
    for key, raw in items.items():
        key = key.replace("-", "_")
        if key not in fields:
            raise SystemExit(f"--set: unknown setting '{key}' (see 'webguard config keys')")
        try:
            setattr(cfg, key, coerce(fields[key], raw))
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"--set {key}: {exc}") from None
    return cfg


def parse_set(pairs: list[str]) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"--set expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def keys() -> list[tuple[str, str, Any]]:
    return [(f.name, str(f.type), getattr(ScanConfig(), f.name)) for f in dataclasses.fields(ScanConfig)]


TEMPLATE = '''# WebGuard configuration. Keys are long option names without dashes. Command-line flags override this file.
# Find it at: --config FILE, $WEBGUARD_CONFIG, ./webguard.yml or ~/.webguard/config.yml

defaults:                      # every command
  # rate: 10                   # requests/second
  # concurrency: 10
  # header: ["X-Bug-Bounty: yourname"]
  # cookie: ["session=..."]
  # proxy: http://127.0.0.1:8080
  # report_author: Your Name / Company
  # report_style: client       # client | technical
  # format: [json, html, md]
  # output: reports

scan:
  # profile: standard          # safe | standard | thorough
  # checks: [sqli, xss, lfi, ssrf, exposure, headers, tls, server, cms]
  # skip: [anomaly]
  # ports: top                 # network service audit
  # discovery_depth: 1

assess:
  # budget_minutes: 30
  # skip_phases: [authz_client]
  # oob: auto

hunt:
  # max_hosts: 25
  # parallel_hosts: 4

set:                           # any engine setting (see 'webguard config keys'), also via --set key=value
  # retries: 3
  # user_agent: "Mozilla/5.0 (compatible; security-assessment)"
  # oob_wait: 20
  # waf_cooldown: 30
  # max_new_hosts: 10
'''
