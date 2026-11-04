"""Target parsing: URLs, domains, IPv4/IPv6 addresses, host:port, CIDR ranges and target files.

    https://shop.example.com/app     -> https://shop.example.com/app
    shop.example.com                 -> shop.example.com            (probed on https and http)
    10.0.0.5 / 10.0.0.5:8443         -> 10.0.0.5 / 10.0.0.5:8443
    [2001:db8::1]:8080               -> [2001:db8::1]:8080
    10.0.0.0/30                      -> 10.0.0.1, 10.0.0.2          (hosts of small ranges, max /22 by default)
    @targets.txt / -l targets.txt    -> one target per line; '#' comments and blank lines ignored

Targets are de-duplicated (case-insensitive host, trailing slash ignored) and keep their input order.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_RANGE_HOSTS = 1024
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$|^localhost$", re.I)


@dataclass(frozen=True)
class Target:
    raw: str
    value: str  # what the scanner receives: a URL or host[:port]
    kind: str  # url | domain | ip | host_port

    @property
    def host(self) -> str:
        v = self.value if "://" in self.value else f"http://{self.value}"
        return urlsplit(v).hostname or ""

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False


class TargetError(ValueError):
    pass


def _classify(item: str) -> Target:
    s = item.strip()
    if "://" in s:
        p = urlsplit(s)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise TargetError(f"unsupported target URL: {item!r} (http/https only)")
        return Target(item, s, "url")
    if s.startswith("["):  # [IPv6] or [IPv6]:port
        m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$", s)
        if not m:
            raise TargetError(f"invalid IPv6 target: {item!r}")
        ipaddress.IPv6Address(m.group(1))
        return Target(item, s, "host_port" if m.group(2) else "ip")
    try:
        ip = ipaddress.ip_address(s)
        return Target(item, f"[{ip}]" if ip.version == 6 else str(ip), "ip")
    except ValueError:
        pass
    host, _, port = s.partition(":")
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        raise TargetError(f"invalid port in {item!r}")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and not _HOST.match(host.rstrip(".")):
        raise TargetError(f"not a URL, domain or IP address: {item!r}")
    return Target(item, s.rstrip("/").lower() if not port else s.lower(), "host_port" if port else ("ip" if is_ip else "domain"))


def expand(item: str, max_hosts: int = MAX_RANGE_HOSTS) -> list[Target]:
    s = item.strip()
    if "/" in s and "://" not in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            pass
        else:
            if net.num_addresses > max_hosts + 2:
                raise TargetError(f"range {s} has {net.num_addresses} addresses (limit {max_hosts}); split it up")
            hosts = list(net.hosts()) or [net.network_address]
            return [Target(item, f"[{h}]" if h.version == 6 else str(h), "ip") for h in hosts]
    return [_classify(s)]


def read_file(path: str | Path) -> list[str]:
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip() if not line.strip().startswith("http") else line.strip()
        if line:
            out.append(line)
    return out


def parse(items: list[str], files: list[str] = (), max_hosts: int = MAX_RANGE_HOSTS) -> tuple[list[Target], list[str]]:
    """All targets from arguments and files. Returns (targets, errors); invalid lines do not abort."""
    raw: list[str] = []
    for item in items:
        if item.startswith("@"):
            raw += read_file(item[1:])
        else:
            raw += [x for x in re.split(r"[\s,]+", item) if x]
    for f in files:
        raw += read_file(f)
    targets: list[Target] = []
    errors: list[str] = []
    seen: set[str] = set()
    for item in raw:
        try:
            for t in expand(item, max_hosts):
                key = t.value.lower().rstrip("/")
                if key not in seen:
                    seen.add(key)
                    targets.append(t)
        except (TargetError, ValueError) as exc:
            errors.append(str(exc))
    return targets, errors
