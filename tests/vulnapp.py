"""Deliberately vulnerable test application (for WebGuard's own test-suite only).

Every vulnerable endpoint has a safe twin under /safe/... that must NOT be reported, so the
tests measure both detection rate and false positives. Nothing here executes real commands
or SQL: behaviour is simulated.
"""

from __future__ import annotations

import html
import json
import posixpath
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

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
CACHE: dict[str, str] = {}  # simulated CDN cache in front of /account (caches anything ending in .css)
PP_PARSER = ("function parse(q){const o={};q.replace(/^[?#]/,'').split('&').forEach(function(kv){"
             "const p=kv.split('=');const keys=decodeURIComponent(p[0]).replace(/\\]/g,'').split(/\\[|\\./);"
             "let cur=o;for(let i=0;i<keys.length-1;i++){%s cur[keys[i]]=cur[keys[i]]||{};cur=cur[keys[i]];}"
             "cur[keys[keys.length-1]]=decodeURIComponent(p[1]||'');});return o;}"
             "parse(location.search); parse(location.hash);")

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
<a href="/account">account</a> <a href="/safe/account">safe account</a> <a href="/pp">pp</a> <a href="/safe/pp">safe pp</a>
<a href="/oauth/authorize?client_id=web&redirect_uri=https://shop.test/callback&response_type=code">sso</a>
<a href="/safe/oauth/authorize?client_id=web&redirect_uri=https://shop.test/callback&response_type=code">safe sso</a>
<a href="/waf/search?q=shoes">protected search</a>
<a href="/filtered/item?id=1">filtered item</a>
<a href="/lfi/ext?file=about.png">lfi ext</a> <a href="/safe/lfi/ext?file=about.png">safe lfi ext</a>
<a href="/lfi/start?file=/var/www/images/about.png">lfi start</a> <a href="/xss/decode?q=hi">xss decode</a>
<a href="/safe/xss/decode?q=hi">safe xss decode</a> <a href="/data?data=MTAwMQ==">data</a> <a href="/safe/data?data=MTAwMQ==">safe data</a>
<a href="/cmd/filter?host=127.0.0.1">cmd filter</a> <a href="/safe/cmd/filter?host=127.0.0.1">safe cmd filter</a>
<a href="/fetch?url=https://trusted.example/logo.png">fetch</a> <a href="/safe/fetch?url=https://trusted.example/logo.png">safe fetch</a>
<a href="/webhook?callback=https://hooks.trusted.example/notify">webhook</a> <a href="/safe/webhook?callback=https://hooks.trusted.example/notify">safe webhook</a>
<a href="/directory?user=alice">directory</a> <a href="/safe/directory?user=alice">safe directory</a>
<a href="/lookup?name=alice">lookup</a> <a href="/safe/lookup?name=alice">safe lookup</a>
<a href="/stock?productId=1">stock</a> <a href="/safe/stock?productId=1">safe stock</a> <a href="/render?tpl=hello">render</a> <a href="/safe/filtered/item?id=1">safe filtered item</a>
<a href="/app">app</a> <a href="/safe/app">safe app</a> <a href="/track">track</a> <a href="/safe/track">safe track</a> <a href="/welcome">welcome</a> <a href="/safe/welcome">safe welcome</a>
<a href="/admin">admin</a> <a href="/safe/admin">safe admin</a> <a href="/dom">dom</a> <a href="/safe/dom">safe dom</a>
<form action="/profile/update" method="post"><input name="nickname" value="bob"><input type="submit"></form>
<form action="/comment" method="post"><input name="author" value="anon"><textarea name="body"></textarea>
<input type="hidden" name="csrf_token" value="abc123"><input type="submit" value="Send"></form>
</body></html>"""

LEGACY_JS = """function loadAdmin(){ return import("./chunks/admin.chunk.js"); }
//# sourceMappingURL=legacy.js.map
"""
SOURCE_MAP = json.dumps({"version": 3, "file": "legacy.js", "sources": ["src/config.ts", "src/admin.ts"], "sourcesContent": [
    'export const apiKey = "Q9f3kLm2Xz8RtYw4Vb7Nc1Hd6Js5Pa0E";  // TODO move to vault',
    'export const exportUrl = "/internal/export?format=csv";']})
ADMIN_CHUNK = 'fetch("/internal/reports?period=daily").then(r => r.json());'
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
            # like real frameworks: header values that aren't Latin-1 are percent-encoded, not a crash
            self.send_header(k, v if all(ord(c) < 256 for c in str(v)) else quote(str(v), safe=":/?&=#@%;,"))
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
        if p in ("/track", "/safe/track"):  # visit logging: INSERT INTO visits(ua) VALUES ('<User-Agent>')
            ua = self.headers.get("User-Agent", "")
            if p == "/track" and ua.count("'") % 2 == 1:
                return self._send(page("SQLITE_ERROR: unrecognized token: \"'\""), 500)
            return self._send(page("<p>Visit recorded.</p>"))
        if p in ("/welcome", "/safe/welcome"):  # renders Referer and the 'theme' cookie
            ref = self.headers.get("Referer", "")
            cookies = dict(c.strip().split("=", 1) for c in self.headers.get("Cookie", "").split(";") if "=" in c)
            theme = cookies.get("theme", "light")
            if p == "/safe/welcome":
                ref, theme = html.escape(ref), html.escape(theme)
            return self._send(f'<html><body class="{theme}"><p>You came from {ref}</p></body></html>',
                              headers={"Set-Cookie": "theme=light; Path=/; SameSite=Lax"})
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
        # ---- PortSwigger-style input filters (vulnerable) and their safe twins
        if p in ("/lfi/ext", "/safe/lfi/ext"):  # "validation of file extension with null byte bypass"
            f = q.get("file", "")
            if not f.split("\x00")[0].endswith(".png") and not f.endswith(".png"):
                return self._send(page("<p>Filename must end with .png</p>"), 400)
            if p == "/safe/lfi/ext":
                return self._send(page("<pre>PNG image</pre>"))
            path = posixpath.normpath("/var/www/images/" + f.split("\x00")[0])
            return self._send(page(f"<pre>{PASSWD if path == '/etc/passwd' else 'PNG image'}</pre>"))
        if p == "/lfi/start":  # "validation of start of path"
            f = q.get("file", "")
            if not f.startswith("/var/www/images/"):
                return self._send(page("<p>Path must start with /var/www/images/</p>"), 400)
            return self._send(page(f"<pre>{PASSWD if posixpath.normpath(f) == '/etc/passwd' else 'PNG image'}</pre>"))
        if p in ("/xss/decode", "/safe/xss/decode"):  # sanitise THEN decode again (vulnerable) / decode then escape
            v = q.get("q", "")
            out = unquote(html.escape(v)) if p == "/xss/decode" else html.escape(unquote(v))
            return self._send(page(f"<p>You searched: {out}</p>"))
        if p in ("/data", "/safe/data"):  # parameter carries base64 data; the decoded value reaches SQL
            import base64 as _b64
            try:
                raw = _b64.b64decode(q.get("data", "")).decode()
            except Exception:
                return self._send(page("<p>bad data</p>"), 400)
            if p == "/data" and raw.count("'") % 2 == 1:
                return self._send(page("You have an error in your SQL syntax; check the manual that corresponds "
                                       "to your MySQL server version"), 500)
            return self._send(page(f"<p>Record {html.escape(raw if raw.isdigit() else 'none')}</p>"))
        if p in ("/cmd/filter", "/safe/cmd/filter"):  # blocks spaces and ';' but runs the command through a shell
            host = q.get("host", "")
            if re.search(r"[ ;]", host):
                return self._send(page("<p>Invalid characters in host</p>"), 400)
            out = f"PING {html.escape(host.split('|')[0])}: 64 bytes"
            cmd = host.replace("${IFS}", " ")
            m = re.search(r"[|&`$\n]+\s*\(?echo (\w+)\$\(\((\d+)\*(\d+)\)\)", cmd)
            if m and p == "/cmd/filter":
                out += f"\n{m.group(1)}{int(m.group(2)) * int(m.group(3))}"
            return self._send(page(f"<pre>{out}</pre>"))
        if p in ("/fetch", "/safe/fetch"):  # "SSRF with whitelist-based input filter" (substring check)
            u = q.get("url", "")
            allowed = urlsplit(u).hostname == "trusted.example" if p == "/safe/fetch" else "trusted.example" in u
            if not allowed:
                return self._send(page("<p>URL not allowed</p>"), 400)
            if urlsplit(u).hostname == "example.com":  # simulated outbound fetch (no real network)
                return self._send("<html><head><title>Example Domain</title></head><body>This domain is for use "
                                  "in illustrative examples</body></html>")
            return self._send(page("<p>fetched image</p>"))
        if p in ("/webhook", "/safe/webhook"):  # blind SSRF: the callback is fetched, nothing is echoed
            u = q.get("callback", "")
            if p == "/webhook" and urlsplit(u).hostname in ("127.0.0.1", "localhost"):
                # loopback only: keeps the fixture offline while still making a real outbound request
                threading.Thread(target=_fetch_quietly, args=(u,), daemon=True).start()
            elif p == "/safe/webhook" and urlsplit(u).hostname != "hooks.trusted.example":
                return self._send(page("<p>callback host not allowed</p>"), 400)
            return self._send(page("<p>webhook queued</p>"))
        if p in ("/directory", "/safe/directory"):  # LDAP filter (&(uid=<user>)(objectClass=person))
            u = q.get("user", "")
            if p == "/directory" and (u.count("(") != u.count(")") or re.search(r"[*\\]\)|\)\(", u)):
                return self._send(page("javax.naming.directory.InvalidSearchFilterException: Bad search filter"), 500)
            return self._send(page("<p>1 entry</p>"))
        if p in ("/lookup", "/safe/lookup"):  # XPath //user[name='<name>']
            n = q.get("name", "")
            if p == "/lookup" and n.count("'") % 2 == 1:
                return self._send(page("javax.xml.xpath.XPathExpressionException: Invalid predicate"), 500)
            return self._send(page("<p>user found</p>"))
        if p in ("/stock", "/safe/stock"):  # productId embedded into a server-side XML document (XInclude on)
            v = q.get("productId", "")
            if p == "/stock" and "xi:include" in v and "file:///etc/passwd" in v:
                return self._send(f"<result>{PASSWD}</result>", ctype="application/xml")
            return self._send("<result>12 units</result>", ctype="application/xml")
        if p == "/render":  # template engine that errors on template syntax (no arithmetic reflection)
            t = q.get("tpl", "")
            if re.search(r"\{\{|\$\{|<%", t):
                return self._send(page("jinja2.exceptions.TemplateSyntaxError: unexpected '<'"), 500)
            return self._send(page(f"<p>{html.escape(t)}</p>"))
        if p in ("/filtered/item", "/safe/filtered/item"):  # application-level blacklist (not a WAF)
            raw = q.get("id", "")
            if re.search(r"[ '\"]", raw):
                return self._send(page("<h2>Invalid characters in input</h2>"), 400)
            sql = raw.replace("/**/", " ")  # the database treats comments as whitespace
            if p == "/safe/filtered/item":
                item = ITEMS.get(raw) if raw.isdigit() else None
                return self._send(page(f"<h2>{html.escape(item or 'No such item')}</h2>"))
            m = re.fullmatch(r"(\d+)(?: AND (\d+)=(\d+))?", sql)
            if not m or (m.group(2) and m.group(2) != m.group(3)):
                return self._send(page("<h2>No such item</h2>"))
            return self._send(page(f"<h2>{ITEMS.get(m.group(1), 'No such item')}</h2><p>In stock. Great product "
                                   "with many words describing it at length for differential testing.</p>"))
        if p == "/waf/search":  # simulated WAF in front of an (unreachable) search: blocks anything unusual
            if re.search(r"[^A-Za-z0-9 ]", q.get("q", "")):
                return self._send("<html><head><title>Attention Required! | Cloudflare</title></head><body>"
                                  "<h1>Sorry, you have been blocked</h1><p>Cloudflare Ray ID: 8a1b2c3d4e5f</p>"
                                  "</body></html>", 403, headers={"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f-AMS"})
            return self._send(page(f"<h1>{len(q.get('q', ''))} results</h1>"))
        if p.startswith(("/account", "/safe/account")):
            safe = p.startswith("/safe/")
            base = "/safe/account" if safe else "/account"
            raw_path = self.path.split("?")[0]
            if raw_path != base and (safe or not re.match(r"^/account(?:/|;|%23|%3f|\.|%00)", raw_path, re.I)):
                return self._send(page("<h1>Not Found</h1>"), 404)
            body = page("<h1>My account</h1><p>alice@shop.test - card ending 4242</p>", "Account")
            if not safe and raw_path.lower().endswith(".css"):
                if raw_path in CACHE:
                    return self._send(CACHE[raw_path], headers={"X-Cache": "HIT", "Age": "3"})
                CACHE[raw_path] = body
                return self._send(body, headers={"X-Cache": "MISS"})
            return self._send(body, headers={"Set-Cookie": "acct=1; Path=/; HttpOnly; SameSite=Lax",
                                             "Cache-Control": "private"})
        if p in ("/oauth/authorize", "/safe/oauth/authorize"):
            ru = q.get("redirect_uri", "")
            ok = ru == "https://shop.test/callback" if p.startswith("/safe/") else ru.startswith("https://shop.test")
            if not ok:
                return self._send('{"error": "invalid_request", "error_description": "redirect_uri mismatch"}', 400,
                                  "application/json")
            return self._send("", 302, headers={"Location": f"{ru}?code=SplxlOBeZQQYbYS6WxSbIA"})
        if p in ("/pp", "/safe/pp"):
            guard = "" if p == "/pp" else "if(keys[i]==='__proto__'||keys[i]==='constructor')return;"
            return self._send(f"<html><body>pp<script>{PP_PARSER % guard}</script></body></html>")
        if p in ("/app", "/safe/app"):
            sink = "innerHTML" if p == "/app" else "textContent"
            js = ("const params = new URLSearchParams(location.search); const msg = params.get('msg') || '';"
                  f"document.getElementById('o').{sink} = msg;"
                  "window.addEventListener('message', function (e) { document.getElementById('o').textContent = e.data; });")
            libs = '<script src="/static/jquery-1.8.3.min.js"></script><script src="/static/legacy.js"></script>' \
                if p == "/app" else ""
            return self._send(f"<html><head>{libs}</head><body><div id=o></div><script>{js}</script></body></html>")
        if p == "/static/jquery-1.8.3.min.js":
            return self._send("/*! jQuery v1.8.3 jquery.com | jquery.org/license */ window.jQuery = {};",
                              ctype="application/javascript")
        if p == "/static/legacy.js":
            return self._send(LEGACY_JS, ctype="application/javascript")
        if p == "/static/legacy.js.map":
            return self._send(SOURCE_MAP, ctype="application/json")
        if p == "/static/chunks/admin.chunk.js":
            return self._send(ADMIN_CHUNK, ctype="application/javascript")
        if p in ("/internal/export", "/internal/reports"):
            return self._send('{"rows": []}', ctype="application/json")
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


def _fetch_quietly(url: str) -> None:
    import urllib.request

    try:
        urllib.request.urlopen(url, timeout=3).read()
    except Exception:
        pass


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
