"""Robust live-host checking: never drop a target just because it answered slowly once.

For each name: DNS -> TCP connect per port -> HTTP request with escalating timeouts -> fallbacks.

    status       meaning
    live         an HTTP response was received (any status code: 401/403/404/5xx still mean "live")
    unresponsive TCP port open but no HTTP answer even after the second-chance pass
    tls-error    port open, TLS handshake failed on https and plain http also failed
    refused      DNS resolves, every probed port refused the connection
    filtered     DNS resolves, connections time out (firewall drops)
    dns-fail     the name does not resolve

Robustness measures (slow / flaky applications are common, especially behind WAFs and cold-start
platforms):

* TCP is checked first, so "port open but the app is slow" is distinguished from "closed".
* HTTP timeouts escalate (6s -> 15s); GET falls back to HEAD; https on 443 falls back to http and
  vice versa (some hosts serve plain HTTP on 443 or redirect oddly).
* Hosts still unresponsive are retried in a **second-chance pass** after everything else, with long
  timeouts and low concurrency, so a temporarily overloaded host is not skipped.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field

from webguard.recon.active import resolve

DEFAULT_PORTS = (443, 80)
TIMEOUTS = (6.0, 15.0)
SECOND_CHANCE_TIMEOUT = 40.0


@dataclass
class Liveness:
    name: str
    status: str = "unknown"
    urls: list[str] = field(default_factory=list)  # base URLs that answered over HTTP
    http_status: int | None = None
    ips: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    attempts: int = 0
    reason: str = ""
    elapsed: float = 0.0

    @property
    def live(self) -> bool:
        return self.status == "live"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _split(name: str) -> tuple[str, int | None]:
    """'host', 'host:8443', '[::1]:8080', '10.0.0.1' -> (host, port|None)."""
    if name.startswith("["):
        host, _, rest = name[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else None
    if name.count(":") == 1:
        host, port = name.split(":")
        return host, int(port)
    return name, None


async def _tcp(host: str, port: int, timeout: float) -> str:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return "open"
    except asyncio.TimeoutError:
        return "filtered"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "error"


async def _http(client, base: str, timeout: float):
    for method in ("GET", "HEAD"):
        try:
            r = await client.request(method, base + "/", timeout=timeout, follow_redirects=True)
        except Exception:
            r = None
        if r is not None and r.status:  # status 0 = our own timeout marker
            return r
    return None


def _bases(host: str, port: int) -> list[str]:
    h = f"[{host}]" if ":" in host else host
    if port == 443:
        return [f"https://{h}", f"http://{h}:443"]
    if port == 80:
        return [f"http://{h}", f"https://{h}:80"]
    return [f"https://{h}:{port}", f"http://{h}:{port}"]


def _reset(client, base: str) -> None:
    """Forget earlier failures for this origin (circuit breaker) before a deliberate retry."""
    try:
        st = client.host(base)
        st.dead, st.open_until, st.consecutive_failures = False, 0.0, 0
    except Exception:
        pass


async def check(client, name: str, ports: tuple[int, ...] = DEFAULT_PORTS,
                timeouts: tuple[float, ...] = TIMEOUTS, reset: bool = False) -> Liveness:
    t0 = time.monotonic()
    host, port = _split(name)
    res = Liveness(name)
    try:
        ipaddress.ip_address(host)
        res.ips = [host]
    except ValueError:
        res.ips = await resolve(host)
        if not res.ips:
            res.status, res.reason = "dns-fail", "no A/AAAA record"
            return res
    ports = (port,) if port else ports
    tcp = {p: await _tcp(host, p, 5.0) for p in ports}
    for p, state in list(tcp.items()):
        if state == "filtered":  # one slow SYN is not a verdict
            tcp[p] = await _tcp(host, p, 12.0)
    res.open_ports = [p for p, s in tcp.items() if s == "open"]
    if not res.open_ports:
        states = set(tcp.values())
        res.status = "refused" if states == {"refused"} else "filtered"
        res.reason = ", ".join(f"{p}/{s}" for p, s in tcp.items())
        res.elapsed = round(time.monotonic() - t0, 2)
        return res
    for p in res.open_ports:
        for timeout in timeouts:
            got = False
            for base in _bases(host, p):
                if reset:
                    _reset(client, base)
                res.attempts += 1
                r = await _http(client, base, timeout)
                if r is not None:
                    res.urls.append(base)
                    res.http_status = res.http_status or r.status
                    got = True
                    break
            if got:
                break
    res.status = "live" if res.urls else "unresponsive"
    if not res.urls:
        res.reason = f"TCP open on {', '.join(map(str, res.open_ports))} but no HTTP answer within {max(timeouts):g}s"
    res.elapsed = round(time.monotonic() - t0, 2)
    return res


async def check_many(client, names: list[str], ports: tuple[int, ...] = DEFAULT_PORTS, concurrency: int = 30,
                     status=None) -> dict[str, Liveness]:
    sem = asyncio.Semaphore(concurrency)

    async def one(n: str) -> Liveness:
        async with sem:
            return await check(client, n, ports)

    results = {r.name: r for r in await asyncio.gather(*(one(n) for n in names))}
    slow = [n for n, r in results.items() if r.status == "unresponsive"]
    if slow:
        if status:
            status(f"  second-chance pass for {len(slow)} slow host(s) ({SECOND_CHANCE_TIMEOUT:g}s timeouts)")
        sem2 = asyncio.Semaphore(4)  # gentle: these hosts are already struggling

        async def retry(n: str) -> Liveness:
            async with sem2:
                r = await check(client, n, ports, timeouts=(SECOND_CHANCE_TIMEOUT,), reset=True)
                r.attempts += results[n].attempts
                if r.live:
                    r.reason = "answered on the second-chance pass (slow host)"
                return r

        for r in await asyncio.gather(*(retry(n) for n in slow)):
            results[r.name] = r
    return results
