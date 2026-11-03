"""Deliberately vulnerable test application (for WebGuard's own test-suite only).

Every vulnerable endpoint has a safe twin under /safe/... that must NOT be reported, so the
tests measure both detection rate and false positives. Nothing here executes real commands
or SQL: behaviour is simulated.
"""

from __future__ import annotations

import html
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
ITEMS = {"1": "Blue widget", "2": "Red widget", "3": "Green widget"}

INDEX = """<html><head><title>Shop</title>
<script src="/static/app.js"></script></head><body>
<a href="/search?q=hello">search</a> <a href="/safe/search?q=hello">safe search</a>
<a href="/item?id=1">item</a> <a href="/safe/item?id=1">safe item</a>
<a href="/view?file=about.txt">about</a> <a href="/safe/view?file=about.txt">safe about</a>
<a href="/greet?name=bob">greet</a> <a href="/safe/greet?name=bob">safe greet</a>
<a href="/go?next=/home">go</a> <a href="/safe/go?next=/home">safe go</a>
<a href="/ping?host=127.0.0.1">ping</a> <a href="/safe/ping?host=127.0.0.1">safe ping</a>
<a href="/profile?color=red">profile</a> <a href="/news?id=2">news</a> <a href="/logout">logout</a>
<form action="/comment" method="post"><input name="author" value="anon"><textarea name="body"></textarea>
<input type="hidden" name="csrf_token" value="abc123"><input type="submit" value="Send"></form>
</body></html>"""

APP_JS = """const API = "/api/v1/users?id=1"; const KEY = "AKIAIOSFODNN7ABCDXYZ";
fetch('/api/v1/status'); // internal endpoint
"""


def _render_template(name: str) -> str:
    # simulated Jinja2: evaluates {{ a*b }} and {{7*'7'}}
    def repl(m: re.Match) -> str:
        expr = m.group(1).strip()
        if re.fullmatch(r"\d+\*\d+", expr):
            a, b = expr.split("*")
            return str(int(a) * int(b))
        if expr == "7*'7'":
            return "7777777"
        return ""
    return re.sub(r"\{\{(.*?)\}\}", repl, name)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence
        pass

    def _send(self, body: str, status: int = 200, ctype: str = "text/html", headers: dict | None = None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        if urlsplit(self.path).path == "/comment":
            body = form.get("body", [""])[0]
            # vulnerable: raw HTML output
            return self._send(f"<html><body><p>Thanks! Your comment:</p><div>{body}</div></body></html>")
        self._send("not found", 404)

    def do_GET(self):  # noqa: C901 - test fixture
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        p = u.path
        page = lambda body, title="Shop": f"<html><head><title>{title}</title></head><body>{body}<p>Rendered at {time.time()}</p></body></html>"  # noqa: E731
        if p == "/":
            return self._send(INDEX, headers={"Set-Cookie": "sessionid=abc; Path=/", "Server": "nginx/1.18.0"})
        if p == "/static/app.js":
            return self._send(APP_JS, ctype="application/javascript")
        if p == "/api/v1/users":
            origin = self.headers.get("Origin")
            hdrs = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
            return self._send('{"id": 1, "name": "alice"}', ctype="application/json", headers=hdrs)
        if p == "/api/v1/status":
            return self._send('{"ok": true}', ctype="application/json")
        if p == "/.git/HEAD":
            return self._send("ref: refs/heads/main\n", ctype="text/plain")
        # --- XSS
        if p == "/search":
            return self._send(page(f"<h1>Results for {q.get('q', '')}</h1>"))
        if p == "/safe/search":
            return self._send(page(f"<h1>Results for {html.escape(q.get('q', ''))}</h1>"))
        if p == "/profile":  # attribute context
            return self._send(page(f'<div style="x" data-color="{q.get("color", "")}">profile</div>'))
        # --- SQLi (simulated)
        if p in ("/item", "/safe/item"):
            raw = q.get("id", "")
            if p == "/safe/item":
                item = ITEMS.get(raw) if raw.isdigit() else None
                return self._send(page(f"<h2>{html.escape(item or 'No such item')}</h2>"))
            if raw.count("'") % 2 == 1 or raw.count('"') % 2 == 1:
                return self._send(page("You have an error in your SQL syntax; check the manual that corresponds "
                                       "to your MySQL server version for the right syntax"), 500)
            m = re.fullmatch(r"(\d+)(?: AND (\d+)=(\d+))?", raw)
            if not m:
                return self._send(page("<h2>No such item</h2>"))
            if m.group(2) and m.group(2) != m.group(3):
                return self._send(page("<h2>No such item</h2>"))
            return self._send(page(f"<h2>{ITEMS.get(m.group(1), 'No such item')}</h2><p>In stock. Great product "
                                   "with many words describing it at length for differential testing.</p>"))
        if p == "/news":  # time-based (simulated MySQL SLEEP)
            m = re.search(r"SLEEP\((\d+)\)", q.get("id", ""))
            if m:
                time.sleep(int(m.group(1)))
            return self._send(page("<h2>News</h2>"))
        # --- LFI
        if p == "/view":
            if "etc/passwd" in q.get("file", ""):
                return self._send(page(f"<pre>{PASSWD}</pre>"))
            return self._send(page("<pre>About us</pre>"))
        if p == "/safe/view":
            return self._send(page("<pre>About us</pre>"))
        # --- SSTI
        if p == "/greet":
            return self._send(page(f"Hello {_render_template(html.escape(q.get('name', '')))}"))
        if p == "/safe/greet":
            return self._send(page(f"Hello {html.escape(q.get('name', ''))}"))
        # --- open redirect
        if p == "/go":
            return self._send("", 302, headers={"Location": q.get("next", "/")})
        if p == "/safe/go":
            nxt = q.get("next", "/")
            safe = re.fullmatch(r"/[A-Za-z0-9/_\-.]*", nxt) and not nxt.startswith("//")
            return self._send("", 302, headers={"Location": nxt if safe else "/"})
        # --- command injection (simulated shell arithmetic echo)
        if p == "/ping":
            host = q.get("host", "")
            m = re.search(r"[;|&`$\n]+\s*\(?echo (\w+)\$\(\((\d+)\*(\d+)\)\)", host)
            out = f"PING {html.escape(host.split(';')[0])}: 64 bytes"
            if m:
                out += f"\n{m.group(1)}{int(m.group(2)) * int(m.group(3))}"
            return self._send(page(f"<pre>{out}</pre>"))
        if p == "/safe/ping":
            return self._send(page(f"<pre>PING {html.escape(q.get('host', ''))}: 64 bytes</pre>"))
        if p == "/logout":
            raise AssertionError("scanner must never request /logout")
        self._send(page("<h1>Not Found</h1>"), 404)


class VulnServer:
    def __init__(self) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self) -> VulnServer:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    with VulnServer() as s:
        print(s.url, flush=True)
        threading.Event().wait()
