"""Async, scope-aware crawler that maps the attack surface.

Collects pages, forms (with method/action/hidden values), query parameters and JavaScript
files. JS is mined for API endpoints. URL patterns are de-duplicated by
``(path-template, sorted-param-names)`` so infinite calendars / pagination do not explode.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from webguard.http import HttpClient, Resp

log = logging.getLogger("webguard.crawler")

SKIP_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|bmp|ico|svg|webp|avif|woff2?|ttf|eot|otf|mp[34]|avi|mov|webm|ogg|wav|pdf|zip|gz|tgz|"
    r"rar|7z|exe|dmg|iso|bin|docx?|xlsx?|pptx?|css|map)$",
    re.I,
)
JS_ENDPOINT = re.compile(
    r"""(?:"|'|`)((?:https?://[^\s"'`<>]{4,200})|(?:/(?:api|v\d|graphql|rest|internal|admin|auth|user|account)[^\s"'`<>]{0,150})|"""
    r"""(?:/[a-zA-Z0-9_\-]{2,}/[a-zA-Z0-9_\-/.]{1,150}\.(?:php|aspx?|jsp|json|action|do)(?:\?[^\s"'`<>]*)?))(?:"|'|`)"""
)
NUM_SEGMENT = re.compile(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,})(?=/|$)", re.I)


@dataclass
class Form:
    url: str  # resolved action URL
    method: str
    inputs: dict[str, str]
    enctype: str = "application/x-www-form-urlencoded"
    page: str = ""


@dataclass
class CrawlResult:
    pages: dict[str, Resp] = field(default_factory=dict)
    forms: list[Form] = field(default_factory=list)
    js_files: set[str] = field(default_factory=set)
    js_endpoints: set[str] = field(default_factory=set)
    urls_with_params: set[str] = field(default_factory=set)


def normalize_url(url: str) -> str:
    url, _ = urldefrag(url)
    p = urlsplit(url)
    path = re.sub(r"/{2,}", "/", p.path) or "/"
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))


def pattern_key(url: str) -> tuple[str, str, tuple[str, ...]]:
    p = urlsplit(url)
    return (p.netloc, NUM_SEGMENT.sub("/{id}", p.path), tuple(sorted(k for k, _ in parse_qsl(p.query, True))))


class Crawler:
    def __init__(self, client: HttpClient, max_depth: int = 3, max_urls: int = 500, max_per_pattern: int = 3):
        self.client = client
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_per_pattern = max_per_pattern
        self.result = CrawlResult()
        self._seen: set[str] = set()
        self._patterns: dict[tuple, int] = {}
        self._form_keys: set[tuple] = set()

    def _accept(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")) or SKIP_EXT.search(urlsplit(url).path):
            return False
        if url in self._seen or not self.client.scope.in_scope(url):
            return False
        key = pattern_key(url)
        if self._patterns.get(key, 0) >= self.max_per_pattern:
            return False
        if len(self._seen) >= self.max_urls:
            return False
        self._patterns[key] = self._patterns.get(key, 0) + 1
        self._seen.add(url)
        return True

    async def crawl(self, seeds: list[str]) -> CrawlResult:
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        for seed in seeds:
            seed = normalize_url(seed)
            if self._accept(seed):
                queue.put_nowait((seed, 0))
            root = "{0.scheme}://{0.netloc}".format(urlsplit(seed))
            for extra in await self._robots_and_sitemap(root):
                if self._accept(extra):
                    queue.put_nowait((extra, 1))

        async def worker() -> None:
            while True:
                url, depth = await queue.get()
                try:
                    for link in await self._fetch(url):
                        if depth + 1 <= self.max_depth and self._accept(link):
                            queue.put_nowait((link, depth + 1))
                except Exception as exc:  # never let one page kill the crawl
                    log.debug("crawl error %s: %s", url, exc)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(min(self.client.config.concurrency, 20))]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        return self.result

    async def _robots_and_sitemap(self, root: str) -> list[str]:
        urls: list[str] = []
        r = await self.client.safe_get(root + "/robots.txt")
        sitemaps = [root + "/sitemap.xml"]
        if r is not None and r.status == 200 and "html" not in r.content_type:
            for line in r.text.splitlines():
                m = re.match(r"(?i)\s*(?:dis)?allow:\s*(/\S*)", line)
                if m and "*" not in m.group(1):
                    urls.append(urljoin(root, m.group(1)))
                m = re.match(r"(?i)\s*sitemap:\s*(\S+)", line)
                if m:
                    sitemaps.append(m.group(1))
        for sm in sitemaps[:3]:
            s = await self.client.safe_get(sm)
            if s is not None and s.status == 200 and "<urlset" in s.text[:2000]:
                urls += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", s.text)[:200]
        return [normalize_url(u) for u in urls]

    async def _fetch(self, url: str) -> list[str]:
        r = await self.client.safe_get(url, follow_redirects=True)
        if r is None:
            return []
        final = normalize_url(r.url)
        self.result.pages[url] = r
        if urlsplit(url).query:
            self.result.urls_with_params.add(url)
        links: list[str] = []
        if final != url and self.client.scope.in_scope(final):
            links.append(final)
        ctype = r.content_type
        if "javascript" in ctype or url.endswith(".js"):
            self.result.js_files.add(url)
            links += self._mine_js(r.text, url)
            return links
        if "json" in ctype:
            links += self._mine_js(r.text, url)
            return links
        if not r.is_html:
            return links
        soup = BeautifulSoup(r.text, "html.parser")
        base_el = soup.find("base", href=True)
        base = urljoin(final, base_el["href"]) if base_el else final
        for tag, attr in (("a", "href"), ("link", "href"), ("area", "href"), ("iframe", "src"),
                          ("frame", "src"), ("script", "src"), ("form", "action")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val or val.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                    continue
                full = normalize_url(urljoin(base, val.strip()))
                if tag == "script":
                    self.result.js_files.add(full)
                links.append(full)
        for script in soup.find_all("script"):
            if script.string:
                links += self._mine_js(script.string, final)
        for form in soup.find_all("form"):
            self._add_form(form, base, final)
        return links

    def _add_form(self, form, base: str, page: str) -> None:
        action = normalize_url(urljoin(base, form.get("action") or page))
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "POST"
        inputs: dict[str, str] = {}
        for el in form.find_all(["input", "textarea", "select", "button"]):
            name = el.get("name")
            if not name:
                continue
            itype = (el.get("type") or "text").lower()
            if itype in ("file", "image", "reset"):
                continue
            if itype in ("checkbox", "radio") and name in inputs:
                continue
            if el.name == "select":
                opt = el.find("option", selected=True) or el.find("option")
                value = (opt.get("value") or opt.get_text(strip=True)) if opt else ""
            elif el.name == "textarea":
                value = el.get_text()
            else:
                value = el.get("value") or _default_for(itype, name)
            inputs[name] = value
        key = (action, method, tuple(sorted(inputs)))
        if inputs and key not in self._form_keys and self.client.scope.in_scope(action):
            self._form_keys.add(key)
            self.result.forms.append(Form(action, method, inputs, form.get("enctype") or "", page))

    def _mine_js(self, text: str, source: str) -> list[str]:
        out = []
        for m in JS_ENDPOINT.finditer(text[:2_000_000]):
            candidate = m.group(1)
            if "{" in candidate or "$" in candidate or " " in candidate:
                continue
            full = normalize_url(urljoin(source, candidate))
            if self.client.scope.in_scope(full):
                self.result.js_endpoints.add(full)
                out.append(full)
        return out


def _default_for(itype: str, name: str) -> str:
    lname = name.lower()
    if itype == "email" or "mail" in lname:
        return "test@example.com"
    if itype == "number" or lname in ("id", "page", "qty", "quantity") or lname.endswith("_id"):
        return "1"
    if itype == "url" or "url" in lname:
        return "https://example.com/"
    if itype == "date":
        return "2024-01-01"
    if itype == "password":
        return "Passw0rd!"
    return "test"

