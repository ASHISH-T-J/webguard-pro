"""Scope enforcement.

Every outbound request goes through :class:`Scope` so that the scanner never touches
assets that are not part of the authorized engagement / bug bounty program.

Rule syntax (one per line in a scope file, or YAML ``include``/``exclude`` lists):

    example.com            exact host
    *.example.com          any subdomain (not the apex)
    .example.com           apex + any subdomain
    10.0.0.0/24            IP network
    re:^api\\d+\\.example\\.com$   regular expression on the host
    https://example.com/app/   URL prefix (scheme + host + path)
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class _Rule:
    raw: str

    def matches(self, url: str) -> bool:
        parts = urlsplit(url if "://" in url else f"http://{url}")
        host = (parts.hostname or "").lower().rstrip(".")
        rule = self.raw
        if rule.startswith("re:"):
            return re.search(rule[3:], host) is not None
        if "://" in rule:
            return url.startswith(rule)
        if "/" in rule:
            try:
                net = ipaddress.ip_network(rule, strict=False)
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        rule_host = rule.lower().split(":")[0]
        rule_port = rule.split(":")[1] if ":" in rule else None
        if rule_port and str(parts.port or (443 if parts.scheme == "https" else 80)) != rule_port:
            return False
        if rule_host.startswith("."):
            return host == rule_host[1:] or host.endswith(rule_host)
        if "*" in rule_host or "?" in rule_host:
            return fnmatch.fnmatchcase(host, rule_host)
        return host == rule_host


@dataclass
class Scope:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    # Path regexes that must never be requested (e.g. logout, delete endpoints)
    exclude_paths: list[str] = field(
        default_factory=lambda: [r"(?i)/log(?:out|off)\b", r"(?i)/sign[-_]?out\b"]
    )

    def __post_init__(self) -> None:
        self._inc = [_Rule(r.strip()) for r in self.include if r.strip()]
        self._exc = [_Rule(r.strip()) for r in self.exclude if r.strip()]
        self._paths = [re.compile(p) for p in self.exclude_paths]

    @classmethod
    def for_target(cls, target: str, include_subdomains: bool = False) -> Scope:
        host = urlsplit(target if "://" in target else f"http://{target}").netloc
        rules = [host]
        if include_subdomains:
            rules.append("." + host.split(":")[0])
        return cls(include=rules)

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        path = Path(path)
        text = path.read_text()
        if path.suffix in {".yml", ".yaml"}:
            import yaml

            data = yaml.safe_load(text) or {}
            kwargs = {"include": data.get("include", []), "exclude": data.get("exclude", [])}
            if "exclude_paths" in data:
                kwargs["exclude_paths"] = data["exclude_paths"]
            return cls(**kwargs)
        include, exclude = [], []
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("!") or line.startswith("-"):
                exclude.append(line[1:].strip())
            else:
                include.append(line.lstrip("+").strip())
        return cls(include=include, exclude=exclude)

    def add(self, rule: str) -> None:
        self.include.append(rule)
        self._inc.append(_Rule(rule))

    def host_in_scope(self, host: str) -> bool:
        return self.in_scope(f"http://{host}/")

    def in_scope(self, url: str) -> bool:
        if not self._inc:
            return False
        if any(r.matches(url) for r in self._exc):
            return False
        if not any(r.matches(url) for r in self._inc):
            return False
        path = urlsplit(url).path or "/"
        return not any(p.search(path) for p in self._paths)
