"""Async HTTP engine: scope enforcement, global rate limiting, retries, stats.

Built on httpx with HTTP/1.1 keep-alive connection pooling. All modules share one
:class:`HttpClient` so concurrency and rate limits are enforced globally.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
from dataclasses import dataclass
from typing import Any

import httpx

from webguard.config import ScanConfig
from webguard.scope import Scope

log = logging.getLogger("webguard.http")


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

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or (not self.content_type and "<html" in self.text[:500].lower())


class HttpClient:
    def __init__(self, config: ScanConfig, scope: Scope, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.scope = scope
        self._sem = asyncio.Semaphore(config.concurrency)
        self._bucket = TokenBucket(config.rate_limit)
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
        if transport is not None:
            kwargs["transport"] = transport
        elif config.proxy:
            kwargs["proxy"] = config.proxy
        self._client = httpx.AsyncClient(**kwargs)
        self._cache: dict[tuple, Resp] = {}
        self.stats = {"requests": 0, "errors": 0, "blocked_out_of_scope": 0, "cache_hits": 0}

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: Any = None,
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

        result = await self._send_once(method, url, params=params, data=data, json=json, headers=headers,
                                       timeout=timeout)
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
                method, data, json = "GET", None, None
            result = await self._send_once(method, nxt, headers=headers, timeout=timeout)
        if result is not None and history:
            result.history = tuple(history)
        if key is not None and result is not None:
            self._cache[key] = result
        return result

    async def _send_once(self, method: str, url: str, *, params=None, data=None, json=None, headers=None,
                         timeout: float | None = None) -> Resp | None:
        attempt = 0
        while True:
            attempt += 1
            await self._bucket.acquire()
            async with self._sem:
                self.stats["requests"] += 1
                start = time.perf_counter()
                try:
                    resp = await self._client.request(
                        method,
                        url,
                        params=params,
                        data=data,
                        json=json,
                        headers=headers,
                        follow_redirects=False,
                        timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
                    )
                    text = resp.text
                    elapsed = time.perf_counter() - start
                except (httpx.TransportError, httpx.DecodingError) as exc:
                    elapsed = time.perf_counter() - start
                    if isinstance(exc, httpx.TimeoutException) and timeout is not None:
                        # caller asked for an explicit timeout (timing checks) - report it as a slow response
                        return Resp(url, 0, httpx.Headers(), "", elapsed, method.upper())
                    if attempt <= self.config.retries:
                        await asyncio.sleep(0.5 * 2 ** (attempt - 1))
                        continue
                    self.stats["errors"] += 1
                    log.debug("request failed %s %s: %s", method, url, exc)
                    return None
            if resp.status_code == 429 and attempt <= self.config.retries:
                retry_after = resp.headers.get("retry-after", "")
                await asyncio.sleep(min(float(retry_after), 30.0) if retry_after.isdigit() else 2.0 * attempt)
                continue
            try:
                body = resp.request.content.decode(errors="replace")[:4000] if resp.request.content else None
            except httpx.RequestNotRead:
                body = None
            return Resp(
                url=str(resp.url),
                status=resp.status_code,
                headers=resp.headers,
                text=text,
                elapsed=elapsed,
                method=method.upper(),
                request_body=body,
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
             json_body: Any = None, headers: dict | None = None) -> str:
        """Build a reproducible curl command (for bug reports)."""
        req = self._client.build_request(method, url, params=params, data=data, json=json_body, headers=headers)
        cmd = ["curl", "-sk", "-X", method.upper(), str(req.url)]
        for name, value in (headers or {}).items():
            cmd += ["-H", f"{name}: {value}"]
        for name, value in self.config.headers.items():
            cmd += ["-H", f"{name}: {value}"]
        if req.content:
            ctype = req.headers.get("content-type")
            if ctype:
                cmd += ["-H", f"Content-Type: {ctype}"]
            cmd += ["--data-raw", req.content.decode(errors="replace")]
        return " ".join(shlex.quote(c) for c in cmd)
