"""Web server configuration audit (OWASP WSTG-INFO-02, CONF-01, CONF-02, CONF-05, CONF-06).

All checks are read-only: they look at responses the server already gives to ordinary GET / OPTIONS
requests. Nothing is uploaded, changed or executed.

* software inventory: product/version from headers, generator tags and error pages, matched against the
  CVE / end-of-life knowledge base (version-based: "potential", confirm the patch level)
* directory listing on the root and on directories seen while crawling
* default installation pages (server installed but never configured)
* exposed administration / debug consoles (login page = LOW, open console = HIGH)
* dangerous HTTP methods or WebDAV advertised in OPTIONS (reported, never exercised)
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from webguard import cve
from webguard.detection.baseline import similarity
from webguard.detection.context import Context, token
from webguard.http import Resp
from webguard.models import PASSIVE, SIGNATURE, Confidence, Finding, Severity

MISCONF = "A05:2021-Security Misconfiguration"

# ----------------------------------------------------------------------------- software inventory

# product token in Server / X-Powered-By -> knowledge-base product key
SERVER_TOKENS = {
    "apache": "apache_httpd", "nginx": "nginx", "microsoft-iis": "microsoft_iis", "php": "php",
    "openssl": "openssl", "apache tomcat": "tomcat", "tomcat": "tomcat", "jetty": "jetty",
    "openssh": "openssh", "webmin": "webmin", "miniserv": "webmin", "screenconnect": "screenconnect",
    "exim": "exim", "lighttpd": "lighttpd",
}
TOKEN_RX = re.compile(r"([A-Za-z][A-Za-z0-9\- ]{1,30}?)/(\d[\w.\-]*)")
HEADER_PRODUCTS = {"x-jenkins": "jenkins", "kbn-version": "kibana", "x-teamcity-version": "teamcity"}
# (product, regex with the version in group 1) over page bodies (generator tags, footers, error pages)
BODY_VERSIONS = [
    ("tomcat", re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+(?:[-.]M\d+)?)")),
    ("wordpress", re.compile(r"<meta[^>]+generator[^>]+WordPress (\d+\.\d+(?:\.\d+)?)", re.I)),
    ("drupal", re.compile(r"<meta[^>]+generator[^>]+Drupal (\d+(?:\.\d+)+)", re.I)),
    ("joomla", re.compile(r"<meta[^>]+generator[^>]+Joomla!? (\d+\.\d+(?:\.\d+)?)", re.I)),
    ("confluence", re.compile(r"Atlassian Confluence (\d+\.\d+\.\d+)")),
    ("jira", re.compile(r"Atlassian Jira[^<]{0,80}?\(v(\d+\.\d+\.\d+)")),
    ("bitbucket", re.compile(r"Atlassian Bitbucket[^<]{0,40}?v(\d+\.\d+\.\d+)")),
    ("grafana", re.compile(r'"(?:buildInfo|build)"\s*:\s*\{[^}]{0,400}?"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"')),
    ("teamcity", re.compile(r"TeamCity[^<]{0,40}?Version (\d{4}\.\d+(?:\.\d+)?)")),
    ("vbulletin", re.compile(r"<meta[^>]+generator[^>]+vBulletin (\d+\.\d+\.\d+)", re.I)),
    ("cacti", re.compile(r"Cacti[^<]{0,30}?Version (\d+\.\d+\.\d+)")),
    ("openfire", re.compile(r"Openfire, Version: (\d+\.\d+\.\d+)")),
    ("papercut", re.compile(r"PaperCut (?:MF|NG)[^<]{0,20}?(\d{2}\.\d+\.\d+)")),
    ("liferay", re.compile(r"Liferay (?:Portal|DXP)[^<]{0,40}?(\d+\.\d+\.\d+)")),
    ("roundcube", re.compile(r'"rcversion"\s*:\s*(\d)(\d{2})(\d{2})')),
    ("jenkins", re.compile(r"Jenkins ver\. (\d+\.\d+(?:\.\d+)?)")),
]


def software_versions(resp: Resp) -> list[tuple[str, str, str, str]]:
    """(product, version, source, raw banner) found in one response."""
    out: list[tuple[str, str, str, str]] = []
    h = {k.lower(): v for k, v in resp.headers.items()}
    for name in ("server", "x-powered-by"):
        banner = h.get(name, "")
        for prod, ver in TOKEN_RX.findall(banner):
            key = SERVER_TOKENS.get(prod.strip().lower())
            if key:
                out.append((key, ver, f"{name.title()} header", banner))
    for name, key in HEADER_PRODUCTS.items():
        if h.get(name) and re.match(r"\d", h[name]):
            out.append((key, h[name], f"{name} header", h[name]))
    text = resp.text[:300000] if resp.text else ""
    for key, rx in BODY_VERSIONS:
        m = rx.search(text)
        if m:
            ver = ".".join(str(int(g)) for g in m.groups()) if key == "roundcube" else m.group(1)
            out.append((key, ver, "page content", m.group(0)[:120]))
    return out


def _root(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


async def inventory(ctx: Context, root: str, pages: list[Resp]) -> list[tuple[str, str]]:
    """Match every disclosed product version against the CVE / EOL knowledge base."""
    samples = list(pages)
    for path in ("/", f"/{token()}"):  # error pages often carry the exact version (Tomcat, Jetty, ...)
        r = await ctx.client.safe_get(root + path)
        if r is not None:
            samples.append(r)
    from webguard.nlp.fingerprint import extract

    seen: dict[tuple[str, str], tuple[str, str, float]] = {}
    for r in samples:
        for product, version, source, banner in software_versions(r):
            v = cve.normalize_version(version)
            if v and (product, v) not in seen:
                seen[(product, v)] = (source, banner, 1.0)
    known = {p for p, _ in seen}
    for r in samples:  # long tail: footers / about pages in free text (NLP, context-scored)
        if r.status == 200 and r.is_html:
            for product, version, conf in extract(r.text):
                v = cve.normalize_version(version)
                if v and product not in known and (product, v) not in seen:
                    seen[(product, v)] = (f"page text (NLP match, confidence {conf:.2f})", "", conf)
    for (product, v), (source, banner, conf) in seen.items():
        for f in cve.findings_for(product, v, root + "/", source, banner):
            if conf < 0.8:
                f.confidence = Confidence.TENTATIVE
            ctx.report(f)
        eol = cve.eol_finding(product, v, root + "/", source)
        if eol:
            ctx.report(eol)
    return list(seen)


# ----------------------------------------------------------------------------- directory listing

LISTING = re.compile(r"(?i)<title>\s*(?:Index of /|Directory listing for /|Directory Listing For /)|"
                     r"<h1>\s*Index of /|\[To Parent Directory\]")
SENSITIVE_ENTRY = re.compile(r"(?i)href=\"[^\"]+\.(?:sql|bak|old|zip|tar|gz|tgz|7z|rar|env|key|pem|p12|pfx|log|"
                             r"conf|config|ini|db|sqlite3?|swp|backup)\"")
COMMON_DIRS = ("/", "/images/", "/img/", "/uploads/", "/upload/", "/files/", "/static/", "/assets/", "/css/",
               "/js/", "/backup/", "/backups/", "/media/", "/docs/", "/tmp/", "/logs/", "/data/")


def _dirs_from(urls: list[str], root: str) -> list[str]:
    dirs: list[str] = []
    for u in urls:
        if not u.startswith(root):
            continue
        path = urlsplit(u).path
        parts = path.split("/")[1:-1]
        for i in range(1, len(parts) + 1):
            d = "/" + "/".join(parts[:i]) + "/"
            if d not in dirs:
                dirs.append(d)
    return dirs


async def directory_listing(ctx: Context, root: str, urls: list[str], limit: int = 25) -> None:
    candidates = list(dict.fromkeys([*COMMON_DIRS, *_dirs_from(urls, root)]))[:limit]
    listed: list[tuple[str, bool]] = []

    async def probe(d: str) -> None:
        r = await ctx.client.safe_get(root + d)
        if r is not None and r.status == 200 and LISTING.search(r.text[:5000]):
            listed.append((d, bool(SENSITIVE_ENTRY.search(r.text[:200000]))))

    await asyncio.gather(*(probe(d) for d in candidates))
    for d, sensitive in sorted(listed):
        ctx.report(Finding(
            check="server", title="Directory listing enabled" + (" (sensitive files listed)" if sensitive else ""),
            severity=Severity.MEDIUM if sensitive else Severity.LOW, confidence=Confidence.CERTAIN, url=root + d,
            evidence="Auto-generated index page" + (", including backup/config/key files" if sensitive else ""),
            description="The web server lists directory contents, revealing files that are not linked from the "
                        "application (backups, uploads, configuration).",
            remediation="Disable automatic indexes (Apache: Options -Indexes; nginx: autoindex off; IIS: "
                        "directoryBrowse enabled=false) and remove unneeded files.",
            cwe="CWE-548", owasp=MISCONF, detection=SIGNATURE, tags=["server", "directory-listing"],
            request=ctx.client.curl("GET", root + d)))


# ----------------------------------------------------------------------------- default pages

DEFAULT_PAGES = [
    ("Apache HTTP Server", re.compile(r"<title>(?:Apache2 \w+ Default Page|Test Page for the Apache HTTP Server)|"
                                      r"<h1>It works!</h1>", re.I)),
    ("nginx", re.compile(r"<title>Welcome to nginx!</title>", re.I)),
    ("Microsoft IIS", re.compile(r"<title>IIS Windows Server</title>|<img src=\"iisstart\.png\"", re.I)),
    ("Apache Tomcat", re.compile(r"If you're seeing this, you've successfully installed Tomcat", re.I)),
    ("lighttpd", re.compile(r"<title>lighttpd \w+ Default Page|Placeholder page", re.I)),
    ("Caddy", re.compile(r"<title>Caddy works!</title>", re.I)),
]


def default_page(ctx: Context, root: str, resp: Resp | None) -> None:
    if resp is None or resp.status != 200:
        return
    for product, rx in DEFAULT_PAGES:
        if rx.search(resp.text[:20000]):
            ctx.report(Finding(
                check="server", title=f"Default {product} page", severity=Severity.LOW, confidence=Confidence.CERTAIN,
                url=root + "/", evidence=f"The root serves the {product} default installation page.",
                description="A default page means the server was installed but not configured for this host: "
                            "default modules, samples and settings may still be active.",
                remediation="Remove default content, configure the virtual host explicitly and disable unused "
                            "modules and sample applications.",
                cwe="CWE-1188", owasp=MISCONF, detection=SIGNATURE, tags=["server", "default-page"]))
            return


# ----------------------------------------------------------------------------- admin / debug consoles

# (path, name, regex proving the console, severity when open, severity when only a login is exposed)
CONSOLES = [
    ("/manager/html", "Apache Tomcat Manager", r"Tomcat Web Application Manager", Severity.HIGH, Severity.LOW),
    ("/host-manager/html", "Apache Tomcat Host Manager", r"Tomcat Virtual Host Manager", Severity.HIGH, Severity.LOW),
    ("/phpmyadmin/", "phpMyAdmin", r"<title>[^<]*phpMyAdmin", Severity.MEDIUM, Severity.MEDIUM),
    ("/pma/", "phpMyAdmin", r"<title>[^<]*phpMyAdmin", Severity.MEDIUM, Severity.MEDIUM),
    ("/adminer.php", "Adminer database console", r"<title>[^<]*Adminer", Severity.MEDIUM, Severity.MEDIUM),
    ("/jmx-console/", "JBoss JMX console", r"JMX Agent View|jboss\.system", Severity.HIGH, Severity.LOW),
    ("/web-console/", "JBoss web console", r"JBoss Web Console|Administration Console", Severity.HIGH, Severity.LOW),
    ("/console", "Werkzeug interactive debugger", r"Werkzeug (?:powered traceback interpreter|Debugger)",
     Severity.HIGH, Severity.MEDIUM),
    ("/_profiler/", "Symfony profiler", r"Symfony Profiler", Severity.MEDIUM, Severity.MEDIUM),
    ("/druid/index.html", "Alibaba Druid monitor", r"Druid Stat Index|druid monitor", Severity.MEDIUM, Severity.LOW),
    ("/solr/", "Apache Solr admin UI", r"<title>Solr Admin</title>", Severity.MEDIUM, Severity.LOW),
    ("/wp-admin/install.php", "WordPress installer", r"WordPress[^<]{0,10}Installation", Severity.HIGH, Severity.HIGH),
]
LOGIN_ONLY = re.compile(r"(?i)type=[\"']?password|enter (?:the )?pin|console is locked")


async def admin_consoles(ctx: Context, root: str) -> None:
    from webguard.detection.checks.host import soft404

    fps = await soft404(ctx, root)

    async def probe(path: str, name: str, proof: str, open_sev: Severity, login_sev: Severity) -> None:
        r = await ctx.client.safe_get(root + path)
        if r is None:
            return
        realm = r.headers.get("www-authenticate", "")
        if r.status == 401 and name.split()[-1].lower() in realm.lower():
            state, sev = "login prompt (HTTP Basic realm)", login_sev
        elif r.status == 200 and re.search(proof, r.text[:100000]):
            if any(fp.status == 200 and similarity(fp.text, r.text) > 0.9 for fp in fps):
                return  # catch-all page that happens to match
            if "WordPress" in name and re.search(r"(?i)already installed", r.text):
                return
            login = bool(LOGIN_ONLY.search(r.text[:50000]))
            state, sev = ("login page", login_sev) if login else ("accessible without authentication", open_sev)
        else:
            return
        ctx.report(Finding(
            check="server", title=f"{name} exposed ({state})", severity=sev,
            confidence=Confidence.CERTAIN if r.status == 200 else Confidence.FIRM, url=root + path,
            evidence=f"HTTP {r.status} at {path}: {state}" + (f"; realm: {realm[:80]}" if realm else ""),
            description=f"The {name} is reachable from this network position. Administrative and debug consoles "
                        "are prime targets for credential attacks and, when open, give direct control.",
            remediation="Remove the console from production or restrict it to a management network / VPN, and "
                        "require strong authentication.",
            cwe="CWE-749" if sev >= Severity.HIGH else "CWE-284", owasp=MISCONF, detection=SIGNATURE,
            tags=["server", "admin-interface"], request=ctx.client.curl("GET", root + path)))

    await asyncio.gather(*(probe(*c) for c in CONSOLES))


# ----------------------------------------------------------------------------- methods / WebDAV

RISKY_METHODS = {"PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "CONNECT"}


async def methods(ctx: Context, root: str) -> None:
    """Report what OPTIONS advertises (the methods are not exercised)."""
    try:
        r = await ctx.client.request("OPTIONS", root + "/")
    except Exception:
        return
    if r is None or r.status >= 400:
        return
    allow = {m.strip().upper() for m in (r.headers.get("allow", "") + "," + r.headers.get("public", "")).split(",")
             if m.strip()}
    risky = sorted(allow & RISKY_METHODS)
    dav = r.headers.get("dav")
    if not risky and not dav:
        return
    ctx.report(Finding(
        check="server", title="WebDAV / write methods advertised" if dav or "PROPFIND" in risky
        else "Potentially dangerous HTTP methods advertised", severity=Severity.LOW, confidence=Confidence.FIRM,
        url=root + "/#options", evidence=f"OPTIONS / -> Allow: {', '.join(sorted(allow)) or '-'}"
                                         + (f"; DAV: {dav}" if dav else ""),
        description="The server advertises methods that modify server content. They were not exercised; verify "
                    "they require authentication or disable them.",
        remediation="Disable WebDAV and unused methods (Apache: <LimitExcept GET POST HEAD>; IIS: request "
                    "filtering verbs; nginx: limit_except).",
        cwe="CWE-650", owasp=MISCONF, detection=PASSIVE, tags=["server", "methods"]))


# ----------------------------------------------------------------------------- entry point

async def audit(ctx: Context, root: str, pages: dict[str, Resp]) -> None:
    """Full web server configuration audit for one origin."""
    host_pages = [r for u, r in pages.items() if u.startswith(root)]
    home = pages.get(root + "/") or await ctx.client.safe_get(root + "/")
    default_page(ctx, root, home)
    await asyncio.gather(inventory(ctx, root, host_pages[:50]), directory_listing(ctx, root, list(pages)),
                         admin_consoles(ctx, root), methods(ctx, root))
