"""Async HTTP engine: scope enforcement, adaptive per-host rate control, resilient retries.

Resilience model (per host):

* **Adaptive rate (AIMD)** - each host has its own token bucket. Healthy responses slowly raise the
  rate (additive increase, up to the configured maximum); 429 / 503 / timeouts halve it
  (multiplicative decrease). ``Retry-After`` (seconds or HTTP date) is always honoured.
* **Retries with jittered exponential backoff** for transient failures (connect errors, resets,
  read timeouts, 502/503/504, 429) - never for 4xx client errors.
* **Adaptive timeout** - the read timeout follows observed latency (p95-ish EWMA) so slow
  targets don't produce false "timeouts" and fast ones don't wait 10 s on dead requests.
* **Circuit breaker** - after repeated consecutive failures a host is paused (cool-down doubles);
  a half-open probe decides whether to resume; permanently dead hosts fail fast.
* **Error classification** - DNS / connect / TLS / timeout / reset / protocol errors are counted
  separately and surfaced in the report, so "no findings" can be told apart from "target was down".
"""

from __future__ import annotations

import asyncio
import email.utils
import logging
import random
import re
import shlex
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from webguard.config import ScanConfig
from webguard.scope import Scope

log = logging.getLogger("webguard.http")

RETRY_STATUS = {429, 502, 503, 504}
# transport headers that add nothing to evidence (kept out of reports/screenshots)
EVIDENCE_NOISE = {"host", "accept-encoding", "accept", "connection", "user-agent", "content-length"}
CONNECT_LEVEL = {"dns", "refused", "connect", "connect_timeout", "tls"}


class OutOfScopeError(Exception):
    pass


class TokenBucket:
    """Async token bucket rate limiter (requests per second, with small burst)."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        self.rate = max(rate, 0.1)
        self.capacity = burst or max(1, int(rate))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


def classify_error(exc: BaseException) -> str:
    text = str(exc).lower()
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        return "read_timeout"
    if isinstance(exc, httpx.ConnectError):
        if "name or service" in text or "nodename" in text or "getaddrinfo" in text or "name resolution" in text:
            return "dns"
        if "ssl" in text or "certificate" in text or "tls" in text:
            return "tls"
        if "refused" in text:
            return "refused"
        return "connect"
    if isinstance(exc, (httpx.RemoteProtocolError, httpx.LocalProtocolError)):
        return "protocol"
    if isinstance(exc, httpx.ReadError):
        return "reset"
    if isinstance(exc, httpx.DecodingError):
        return "decoding"
    return "transport"


def parse_retry_after(value: str | None, cap: float = 60.0) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(float(value), cap)
    try:
        when = email.utils.parsedate_to_datetime(value).timestamp()
        return max(0.0, min(when - time.time(), cap))
    except (TypeError, ValueError):
        return None


_SOFT_LIMIT = re.compile(r"(?i)too many requests|rate limit(?:ed| exceeded)|slow down|request limit|quota exceeded|"
                         r"try again in \d+ (?:seconds?|minutes?)")


_STRICT_LIMIT = re.compile(r"(?i)too many requests|rate limit(?:ed| exceeded)")


def parse_rate_headers(headers: Any) -> tuple[float | None, float | None, float | None]:
    """(limit, remaining, reset_seconds) from IETF RateLimit / RateLimit-* / X-RateLimit-* headers."""
    h = {k.lower(): v for k, v in headers.items()}
    limit = remaining = reset = None
    combined = h.get("ratelimit")  # draft-ietf-httpapi-ratelimit-headers: RateLimit: "default";r=50;t=30
    if combined:
        if (m := re.search(r"\br=(\d+)", combined)) or (m := re.search(r"remaining=(\d+)", combined)):
            remaining = float(m.group(1))
        if (m := re.search(r"\bt=(\d+)", combined)) or (m := re.search(r"reset=(\d+)", combined)):
            reset = float(m.group(1))
        if m := re.search(r"limit=(\d+)", combined):
            limit = float(m.group(1))
    policy = h.get("ratelimit-policy")
    if policy and (m := re.search(r"\bq=(\d+)", policy) or re.match(r"\s*(\d+)", policy)):
        limit = limit or float(m.group(1))
    for prefix in ("ratelimit-", "x-ratelimit-", "x-rate-limit-"):
        limit = limit if limit is not None else _num(h.get(prefix + "limit"))
        remaining = remaining if remaining is not None else _num(h.get(prefix + "remaining"))
        reset = reset if reset is not None else _num(h.get(prefix + "reset") or h.get(prefix + "reset-after"))
    if reset is not None and reset > 1e9:  # epoch timestamp (GitHub style)
        reset = max(0.0, reset - time.time())
    return limit, remaining, reset


def _num(v: str | None) -> float | None:
    try:
        return float(str(v).split(",")[0].strip()) if v not in (None, "") else None
    except ValueError:
        return None


@dataclass
class HostState:
    """Adaptive control state for one host."""

    max_rate: float
    bucket: TokenBucket = None  # type: ignore[assignment]
    latency_ewma: float = 0.0
    latency_dev: float = 0.0
    consecutive_failures: int = 0
    open_until: float = 0.0
    cooldown: float = 5.0
    trips: int = 0
    dead: bool = False
    paused_until: float = 0.0  # host-wide pause (rate-limit window / Retry-After)
    cap_rate: float | None = None  # ceiling derived from RateLimit headers ...
    cap_until: float = 0.0  # ... valid until the declared window resets
    consecutive_429: int = 0
    min_latency: float = 0.0
    samples: int = 0
    last_latency_backoff: float = 0.0
    policy: dict = field(default_factory=dict)  # last declared limit/remaining/reset
    pauses: int = 0
    adjustments: list[str] = field(default_factory=list)
    _half_open: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self.bucket = TokenBucket(self.max_rate)

    @property
    def rate(self) -> float:
        return self.bucket.rate

    def observe_latency(self, seconds: float) -> None:
        self.min_latency = seconds if self.min_latency <= 0 else min(self.min_latency, seconds)
        if self.latency_ewma == 0:
            self.latency_ewma, self.latency_dev = seconds, seconds / 2
        else:
            self.latency_dev = 0.75 * self.latency_dev + 0.25 * abs(seconds - self.latency_ewma)
            self.latency_ewma = 0.875 * self.latency_ewma + 0.125 * seconds

    def adaptive_timeout(self, base: float) -> float:
        """TCP-RTO style: mean + 4 x deviation, at least 2x mean, bounded by [base, 6 x base]."""
        if self.latency_ewma == 0:
            return base
        rto = max(self.latency_ewma * 2, self.latency_ewma + 4 * self.latency_dev)
        return min(max(base, rto), base * 6)

    def increase(self) -> None:
        ceiling = self.max_rate
        if self.cap_rate is not None and time.monotonic() < self.cap_until:
            ceiling = min(ceiling, self.cap_rate)  # never climb above a limit the server declared
        if self.bucket.rate < ceiling:
            self.bucket.rate = min(ceiling, self.bucket.rate + max(0.2, ceiling * 0.02))

    def note(self, text: str) -> None:
        if len(self.adjustments) < 50:
            self.adjustments.append(f"{time.strftime('%H:%M:%S')} {text}")

    def pause(self, seconds: float, reason: str) -> None:
        """Pause ALL requests to this host (not just the one that hit the limit)."""
        seconds = max(0.5, min(seconds, 120.0))
        until = time.monotonic() + seconds
        if until > self.paused_until:
            self.paused_until = until
            self.pauses += 1
            self.note(f"paused {seconds:.1f}s: {reason}")

    def observe_rate_headers(self, limit: float | None, remaining: float | None, reset: float | None) -> None:
        """Pace to stay under a limit the server declares, before it starts answering 429."""
        if remaining is None:
            return
        self.policy = {"limit": limit, "remaining": remaining, "reset_s": reset}
        window = reset if reset and reset > 0 else 60.0
        if remaining <= 0:
            self.pause(window, f"rate-limit quota exhausted (limit {limit or '?'})")
            return
        # spend what's left evenly over the rest of the window, with 20% headroom
        safe = max(0.2, remaining / window * 0.8)
        low = limit is None or remaining <= max(5, limit * 0.25)
        if low and safe < self.bucket.rate:
            old = self.bucket.rate
            self.bucket.rate = safe
            self.note(f"RateLimit headers ({int(remaining)} left / {window:.0f}s): {old:.1f} -> {safe:.1f} req/s")
        if low:
            self.cap_rate, self.cap_until = safe, time.monotonic() + window

    def observe_latency_trend(self) -> None:
        """Back off when responses get much slower than the best observed latency (server under load)."""
        self.samples += 1
        if self.samples < 8 or self.min_latency <= 0:
            return
        now = time.monotonic()
        if self.latency_ewma > max(1.0, self.min_latency * 4) and now - self.last_latency_backoff > 10:
            self.last_latency_backoff = now
            self.decrease(f"latency {self.latency_ewma * 1000:.0f} ms vs best {self.min_latency * 1000:.0f} ms", 0.7)

    def decrease(self, reason: str, factor: float = 0.5, floor: float = 0.5) -> None:
        old = self.bucket.rate
        self.bucket.rate = max(floor, old * factor)
        if len(self.adjustments) < 50:
            self.adjustments.append(f"{time.strftime('%H:%M:%S')} {reason}: {old:.1f} -> {self.bucket.rate:.1f} req/s")


@dataclass
class Resp:
    """Lightweight, fully-read response snapshot (safe to keep after the connection closes)."""

    url: str
    status: int
    headers: httpx.Headers
    text: str
    elapsed: float
    method: str
    request_body: str | None = None
    history: tuple[str, ...] = ()
    request_headers: dict[str, str] = field(default_factory=dict)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or (not self.content_type and "<html" in self.text[:500].lower())

    def raw_request(self, limit: int = 3000) -> str:
        """HTTP/1.1-style request text for evidence."""
        parts = urlsplit(self.url)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        lines = [f"{self.method} {target} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in self.request_headers.items() if k.lower() not in EVIDENCE_NOISE]
        text = "\r\n".join(lines) + "\r\n\r\n" + (self.request_body or "")
        return text[:limit]

    def raw_response(self, limit: int = 3000, around: str | None = None) -> str:
        """Status line, headers and a body excerpt (centred on ``around`` when given)."""
        head = [f"HTTP/1.1 {self.status}"] + [f"{k}: {v}" for k, v in self.headers.items()]
        body = self.text
        if around and around in body:
            i = body.index(around)
            start = max(0, i - limit // 3)
            body = ("…" if start else "") + body[start:start + limit // 2] + "…"
        else:
            body = body[: limit // 2] + ("…" if len(body) > limit // 2 else "")
        return "\r\n".join(head) + "\r\n\r\n" + body


_WAF_HINT = re.compile(r"(?i)request (?:was )?(?:blocked|rejected)|web application firewall|access denied|"
                       r"not acceptable|incident id|support id|ray id|mod_security|security policy|"
                       r"attention required|just a moment|cf-chl")


async def _guard_location(response: httpx.Response) -> None:
    """httpx builds the next redirect request eagerly, even with follow_redirects=False, and raises
    on malformed Location values (``C:\\x``, ``http://[bad``). Attack payloads produce exactly such
    headers, so stash invalid ones and restore them on the Resp snapshot instead of crashing."""
    loc = response.headers.get("location")
    if loc is None:
        return
    try:  # same steps as httpx.Client._redirect_url
        url = httpx.URL(loc)
        if url.scheme and not url.host:
            url = url.copy_with(host=response.request.url.host)
        if url.is_relative_url:
            response.request.url.join(url)
    except Exception:
        response.headers["x-webguard-location"] = loc
        del response.headers["location"]


class HttpClient:
    def __init__(self, config: ScanConfig, scope: Scope, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.scope = scope
        self._sem = asyncio.Semaphore(config.concurrency)
        self._global = TokenBucket(config.rate_limit)  # hard global ceiling across all hosts
        self.hosts: dict[str, HostState] = {}
        headers = {"User-Agent": config.user_agent, "Accept": "*/*"}
        headers.update(config.headers)
        kwargs: dict[str, Any] = dict(
            headers=headers,
            cookies=config.cookies,
            timeout=httpx.Timeout(config.timeout, connect=min(config.timeout, 10.0)),
            verify=config.verify_tls,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=config.concurrency * 2, max_keepalive_connections=config.concurrency),
        )
        kwargs["event_hooks"] = {"response": [_guard_location]}
        if transport is not None:
            kwargs["transport"] = transport
        elif config.proxy:
            kwargs["proxy"] = config.proxy
        self._client = httpx.AsyncClient(**kwargs)
        self._cache: dict[tuple, Resp] = {}
        self.errors: Counter[str] = Counter()
        self.stats = {"requests": 0, "errors": 0, "blocked_out_of_scope": 0, "cache_hits": 0, "rate_limited": 0,
                      "server_errors": 0, "waf_blocks": 0, "retries": 0, "circuit_trips": 0}

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ host state
    def host(self, url: str) -> HostState:
        netloc = urlsplit(url).netloc
        st = self.hosts.get(netloc)
        if st is None:
            st = self.hosts[netloc] = HostState(max_rate=self.config.rate_limit)
        return st

    def resilience_report(self) -> dict[str, Any]:
        return {
            "errors_by_kind": dict(self.errors),
            "hosts": {h: {"final_rate": round(s.rate, 2), "latency_ms": round(s.latency_ewma * 1000),
                          "circuit_trips": s.trips, "dead": s.dead, "pauses": s.pauses,
                          "declared_limit": s.policy or None, "rate_adjustments": s.adjustments[-10:]}
                      for h, s in self.hosts.items()},
        }

    async def _wait_circuit(self, st: HostState) -> bool:
        """Returns False if the host is considered dead."""
        if st.dead:
            return False
        wait = st.paused_until - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        now = time.monotonic()
        if st.open_until > now:
            async with st._half_open:  # one half-open probe at a time
                wait = st.open_until - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
        return not st.dead

    def _record_failure(self, st: HostState, kind: str) -> None:
        self.errors[kind] += 1
        st.consecutive_failures += 1
        if kind in ("read_timeout", "connect_timeout", "reset"):
            st.decrease(f"{kind}", 0.7)
        if st.consecutive_failures >= 8:
            st.trips += 1
            self.stats["circuit_trips"] += 1
            st.open_until = time.monotonic() + st.cooldown
            st.decrease("circuit open", 0.5)
            log.warning("host unhealthy (%s x%d) - pausing %.0fs", kind, st.consecutive_failures, st.cooldown)
            st.cooldown = min(st.cooldown * 2, 120 if kind in CONNECT_LEVEL else 20)
            st.consecutive_failures = 4  # half-open: a few more failures re-open quickly
            # only connection-level failures mean "host down"; resets / protocol errors / read timeouts are usually
            # caused by a specific payload and must never end the scan for the whole host
            if kind in CONNECT_LEVEL and (st.trips >= 3 or (kind in ("dns", "refused") and st.trips >= 2)):
                st.dead = True
                log.warning("giving up on unresponsive host")

    def _record_success(self, st: HostState, elapsed: float) -> None:
        st.consecutive_failures = 0
        st.cooldown = 5.0
        st.observe_latency(elapsed)
        st.increase()

    # ------------------------------------------------------------------ requests
    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: Any = None,
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        cache: bool = False,
        timeout: float | None = None,
    ) -> Resp | None:
        """Send a request. Returns ``None`` on network failure (never raises for transport errors).

        Redirects are followed manually (max 10 hops) so that every hop is scope-checked:
        an in-scope page redirecting to a third party never causes out-of-scope traffic.
        """
        if not self.scope.in_scope(url):
            self.stats["blocked_out_of_scope"] += 1
            raise OutOfScopeError(url)
        key = None
        if cache and method.upper() == "GET" and not headers:
            key = (url, tuple(sorted((params or {}).items())))
            if key in self._cache:
                self.stats["cache_hits"] += 1
                return self._cache[key]

        result = await self._send_once(method, url, params=params, data=data, json=json, content=content,
                                       headers=headers, timeout=timeout)
        history: list[str] = []
        while follow_redirects and result is not None and result.status in (301, 302, 303, 307, 308):
            location = result.headers.get("location")
            if not location or len(history) >= 10:
                break
            nxt = str(httpx.URL(result.url).join(location))
            if not self.scope.in_scope(nxt):
                self.stats["blocked_out_of_scope"] += 1
                break
            history.append(result.url)
            if result.status in (301, 302, 303) and method.upper() != "HEAD":
                method, data, json, content = "GET", None, None, None
            result = await self._send_once(method, nxt, data=data, json=json, content=content, headers=headers,
                                           timeout=timeout)
        if result is not None and history:
            result.history = tuple(history)
        if key is not None and result is not None:
            self._cache[key] = result
        return result

    async def _send_once(self, method: str, url: str, *, params=None, data=None, json=None, content=None,
                         headers=None, timeout: float | None = None) -> Resp | None:
        st = self.host(url)
        attempt = 0
        while True:
            attempt += 1
            if not await self._wait_circuit(st):
                self.errors["host_unavailable"] += 1
                return None
            await self._global.acquire()
            await st.bucket.acquire()
            req_timeout = timeout if timeout is not None else st.adaptive_timeout(self.config.timeout)
            async with self._sem:
                self.stats["requests"] += 1
                start = time.perf_counter()
                try:
                    resp = await self._client.request(
                        method, url, params=params, data=data, json=json, content=content, headers=headers,
                        follow_redirects=False,
                        timeout=httpx.Timeout(req_timeout, connect=min(req_timeout, 10.0)),
                    )
                    text = resp.text
                    elapsed = time.perf_counter() - start
                except (httpx.InvalidURL, httpx.UnsupportedProtocol, httpx.LocalProtocolError) as exc:
                    log.debug("unsendable request %s %s: %s", method, url, exc)
                    self.errors["unsendable"] += 1
                    return None
                except (httpx.TransportError, httpx.DecodingError) as exc:
                    elapsed = time.perf_counter() - start
                    if isinstance(exc, httpx.TimeoutException) and timeout is not None:
                        # caller asked for an explicit timeout (timing checks) - report it as a slow response
                        return Resp(url, 0, httpx.Headers(), "", elapsed, method.upper())
                    kind = classify_error(exc)
                    self._record_failure(st, kind)
                    if attempt <= self.config.retries and kind not in ("dns", "tls", "decoding"):
                        self.stats["retries"] += 1
                        await asyncio.sleep(_backoff(attempt))
                        continue
                    self.stats["errors"] += 1
                    log.debug("request failed %s %s: %s (%s)", method, url, kind, exc)
                    return None

            code = resp.status_code
            st.observe_rate_headers(*parse_rate_headers(resp.headers))
            soft_limit = len(text) < 5000 and (
                (code in (403, 503) and _SOFT_LIMIT.search(text) is not None)
                or (code == 200 and _STRICT_LIMIT.search(text) is not None))
            if code == 429 or soft_limit:
                self.stats["rate_limited"] += 1
                st.consecutive_429 += 1
                st.decrease("HTTP 429" if code == 429 else f"soft rate limit (HTTP {code} page)")
                retry_after = parse_retry_after(resp.headers.get("retry-after"))
                st.pause(retry_after if retry_after is not None else min(60.0, 2.0 ** st.consecutive_429),
                         "Retry-After" if retry_after is not None else f"backoff after {st.consecutive_429} limit response(s)")
                if attempt <= self.config.retries:
                    self.stats["retries"] += 1
                    continue  # the host-wide pause is honoured by _wait_circuit before the retry
            elif code == 503:
                self.stats["server_errors"] += 1
                st.decrease("HTTP 503", 0.7)
            elif code >= 500:
                self.stats["server_errors"] += 1
            elif code in (403, 406, 419, 501) and attempt == 1 and _WAF_HINT.search(text[:3000]):
                self.stats["waf_blocks"] += 1
            if code in RETRY_STATUS and attempt <= self.config.retries:
                self.stats["retries"] += 1
                wait = parse_retry_after(resp.headers.get("retry-after")) or _backoff(attempt, base=1.0)
                await asyncio.sleep(wait)
                continue
            if code < 500 and code != 429 and not soft_limit:
                self._record_success(st, elapsed)
                st.consecutive_429 = 0
                st.observe_latency_trend()
            try:
                body = resp.request.content.decode(errors="replace")[:4000] if resp.request.content else None
            except httpx.RequestNotRead:
                body = None
            rheaders = resp.headers
            if "x-webguard-location" in rheaders:
                rheaders = httpx.Headers(rheaders)
                rheaders["location"] = rheaders.pop("x-webguard-location")
            return Resp(
                url=str(resp.url), status=code, headers=rheaders, text=text, elapsed=elapsed,
                method=method.upper(), request_body=body,
                request_headers={k: v for k, v in resp.request.headers.items()},
            )

    async def get(self, url: str, **kw: Any) -> Resp | None:
        return await self.request("GET", url, **kw)

    async def safe_get(self, url: str, **kw: Any) -> Resp | None:
        """GET that silently returns None for out-of-scope URLs."""
        try:
            return await self.request("GET", url, **kw)
        except OutOfScopeError:
            return None

    def curl(self, method: str, url: str, params: dict | None = None, data: dict | None = None,
             json_body: Any = None, headers: dict | None = None, content: str | None = None) -> str:
        """Build a reproducible curl command (for bug reports)."""
        req = self._client.build_request(method, url, params=params, data=data, json=json_body, headers=headers,
                                         content=content)
        cmd = ["curl", "-sk", "-X", method.upper(), str(req.url)]
        for name, value in (headers or {}).items():
            cmd += ["-H", f"{name}: {value}"]
        for name, value in self.config.headers.items():
            cmd += ["-H", f"{name}: {value}"]
        if req.content:
            ctype = req.headers.get("content-type")
            if ctype and not any(k.lower() == "content-type" for k in (headers or {})):
                cmd += ["-H", f"Content-Type: {ctype}"]
            cmd += ["--data-raw", req.content.decode(errors="replace")]
        return " ".join(shlex.quote(c) for c in cmd)

    def slow_down(self, factor: float = 0.5, minimum: float = 1.0) -> float:
        """Reduce the request rate for every host (agent reaction to 429s / WAF blocks)."""
        for st in self.hosts.values():
            st.decrease("agent slow-down", factor, minimum)
        self._global.rate = max(minimum, self._global.rate * factor)
        return self._global.rate


def _backoff(attempt: int, base: float = 0.5, cap: float = 30.0) -> float:
    """Exponential backoff with full jitter."""
    return random.uniform(0, min(cap, base * 2 ** attempt))
