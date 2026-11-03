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
USERS = {1: {"id": 1, "email": "alice@shop.test", "phone": "555-0101", "password": "0192023a7bbd73250516f069df18b500"},
         2: {"id": 2, "email": "bob@shop.test", "phone": "555-0102", "password": "5f4dcc3b5aa765d61d8327deb882cf99"},
         3: {"id": 3, "email": "carol@shop.test", "phone": "555-0103", "password": "e10adc3949ba59abbe56e057f20f883e"}}


def _jwt(claims: dict, secret: str = "secret") -> str:
    import base64
    import hashlib
    import hmac
    import json as _json

    enc = lambda d: base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    head = enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), head.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return head + "." + sig


TOKEN = _jwt({"sub": "1", "role": "customer"})

INDEX = """<html><head><title>Shop</title>
<script src="/static/app.js"></script></head><body>
<a href="/search?q=hello">search</a> <a href="/safe/search?q=hello">safe search</a>
<a href="/item?id=1">item</a> <a href="/safe/item?id=1">safe item</a>
<a href="/view?file=about.txt">about</a> <a href="/safe/view?file=about.txt">safe about</a>
<a href="/greet?name=bob">greet</a> <a href="/safe/greet?name=bob">safe greet</a>
<a href="/go?next=/home">go</a> <a href="/safe/go?next=/home">safe go</a>
<a href="/ping?host=127.0.0.1">ping</a> <a href="/safe/ping?host=127.0.0.1">safe ping</a>
<a href="/profile?color=red">profile</a> <a href="/news?id=2">news</a> <a href="/logout">logout</a>
<a href="/users/search?name=alice">user search</a> <a href="/safe/users/search?name=alice">safe user search</a>
<a href="/reset?email=a@b.c">reset</a> <a href="/safe/reset?email=a@b.c">safe reset</a>
<a href="/admin">admin</a> <a href="/safe/admin">safe admin</a> <a href="/dom">dom</a> <a href="/safe/dom">safe dom</a>
<form action="/profile/update" method="post"><input name="nickname" value="bob"><input type="submit"></form>
<form action="/comment" method="post"><input name="author" value="anon"><textarea name="body"></textarea>
<input type="hidden" name="csrf_token" value="abc123"><input type="submit" value="Send"></form>
</body></html>"""

APP_JS = """const API = "/api/v1/users?id=1"; const KEY = "AKIAIOSFODNN7ABCDXYZ";
fetch('/api/v1/status'); // internal endpoint
const u1 = `${host}/api/users/1`, u2 = "/safe/api/users/1", gql = "/graphql";
const cfg1 = "/api/admin/config", cfg2 = "/safe/api/admin/config";
function login(b) { return http.post("/api/login", b) }
function safeLogin(b) { return http.post("/safe/api/login", b) }
function importXml(x) { return http.post("/api/xml", x) }
function safeImportXml(x) { return http.post("/safe/api/xml", x) }
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

    def do_POST(self):  # noqa: C901 - test fixture
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode(errors="replace")
        path = urlsplit(self.path).path
        if path in ("/api/login", "/safe/api/login"):
            import json as _json
            try:
                body = _json.loads(raw)
            except ValueError:
                return self._send('{"error": "bad json"}', 400, "application/json")
            email = body.get("email")
            ok = email == "alice@shop.test" and body.get("password") == "admin123"
            if path == "/api/login" and isinstance(email, str):
                # vulnerable: SELECT * FROM users WHERE email = '<email>' AND password = '...'
                if email.count("'") % 2 == 1 and re.search(r"(?i)'\s*(?:or\s+'?1'?\s*=\s*'?1|--|#)", email):
                    ok = True
                elif email.count("'") % 2 == 1:
                    return self._send("SQLITE_ERROR: unrecognized token", 500, "text/plain")
            if ok:
                return self._send(_json.dumps({"authentication": {"token": TOKEN, "umail": "alice@shop.test"}}),
                                  200, "application/json")
            return self._send('{"error": "Invalid email or password."}', 401, "application/json")
        if path in ("/api/xml", "/safe/api/xml"):
            if path == "/api/xml" and re.search(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"file:///etc/passwd"', raw):
                return self._send(f"<result>{PASSWD}</result>", 200, "application/xml")
            return self._send("<result>parsed</result>", 200, "application/xml")
        if path == "/graphql":
            import json as _json
            body = _json.loads(raw or "{}")
            def answer(q):
                if "__schema" in q.get("query", ""):
                    return {"data": {"__schema": {"queryType": {"name": "Query"},
                                                  "types": [{"name": "Query"}, {"name": "User"}, {"name": "AdminMutation"}]}}}
                return {"data": {"__typename": "Query"}}
            out = [answer(q) for q in body] if isinstance(body, list) else answer(body)
            return self._send(_json.dumps(out), 200, "application/json")
        if path == "/profile/update":
            return self._send("<html><body>Saved</body></html>")
        form = parse_qs(raw, keep_blank_values=True)
        if path == "/comment":
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
            if self.headers.get("X-Original-URL") == "/admin":  # vulnerable front-end ACL bypass
                return self._send(page("<h1>Admin panel</h1><table><tr><td>alice</td><td>delete</td></tr></table>", "Admin"))
            return self._send(INDEX, headers={"Set-Cookie": "sessionid=abc; Path=/", "Server": "nginx/1.18.0"})
        if p in ("/admin", "/safe/admin"):
            return self._send(page("<h1>403 Forbidden</h1>", "Forbidden"), 403)
        if p in ("/api/admin/config", "/safe/api/admin/config"):
            if p.startswith("/safe/"):
                return self._send('{"error": "authentication required"}', 401, "application/json")
            return self._send('{"smtp": {"host": "mail.internal", "user": "ops"}, "featureFlags": {"debug": true}}',
                              ctype="application/json")
        if p == "/graphql":
            return self._send('{"errors": [{"message": "use POST"}]}', 400, "application/json")
        if p in ("/users/search", "/safe/users/search"):
            import json as _json
            ne = q.get("name[$ne]")
            if p == "/users/search" and ne is not None:
                hits = [u for u in USERS.values() if u["email"].split("@")[0] != ne]
            else:
                hits = [u for u in USERS.values() if u["email"].split("@")[0] == q.get("name")]
            return self._send(_json.dumps([{"id": u["id"], "name": u["email"].split("@")[0]} for u in hits]),
                              ctype="application/json")
        if p.startswith(("/api/users/", "/safe/api/users/")):
            import json as _json
            try:
                uid = int(p.rsplit("/", 1)[1])
            except ValueError:
                return self._send("{}", 404, "application/json")
            if p.startswith("/safe/") and uid != 1:
                return self._send('{"error": "forbidden"}', 403, "application/json")
            user = USERS.get(uid)
            if user is None:
                return self._send("{}", 404, "application/json")
            data = dict(user) if not p.startswith("/safe/") else {k: v for k, v in user.items() if k != "password"}
            return self._send(_json.dumps(data), ctype="application/json")
        if p in ("/reset", "/safe/reset"):
            host = "shop.test"  # safe: canonical host from configuration
            if p == "/reset":  # vulnerable: trusts client-controlled host headers
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host")
            hdrs = {"Cache-Control": "public, max-age=60"} if p == "/reset" else {}
            return self._send(page(f'<p>Reset link sent. <a href="http://{html.escape(host)}/reset/confirm?t=1">confirm</a></p>'),
                              headers=hdrs)
        if p in ("/dom", "/safe/dom"):
            sink = "innerHTML" if p == "/dom" else "textContent"
            js = f"document.getElementById('out').{sink} = decodeURIComponent(location.hash.slice(1));"
            return self._send(f"<html><body><div id=out></div><script>{js}</script></body></html>",
                              headers={"Set-Cookie": f"auth={TOKEN}; Path=/; HttpOnly; SameSite=Lax"})
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
