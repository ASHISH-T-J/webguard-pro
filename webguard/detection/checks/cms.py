"""CMS-aware and technology-aware scanning (WPScan / droopescan / joomscan-style workflows, read-only).

Detection first (host technologies, page markers, fingerprint templates), then the CMS's own architecture:

WordPress   core version (generator, feed, readme.html) -> CVE; plugins and themes from page assets with
            ``?ver=`` and from ``readme.txt`` / ``style.css`` -> CVE per plugin; user enumeration via the REST
            API and ``?author=N``; XML-RPC enabled; REST namespaces (plugin hints); uploads listing;
            debug log and config backups
Drupal      version (CHANGELOG / generator) -> CVE; modules and themes from asset paths; user enumeration
            via ``/user/N``; install script reachable
Joomla      version (manifest) -> CVE; components from page paths; administrator login exposed;
            configuration backups
Magento     version hint (``/magento_version``); admin path; downloader / setup reachable

Technology probes add per-stack exposure checks (PHP, Java / Spring / Tomcat, ASP.NET / IIS, Node,
Python / Django / Flask, Ruby on Rails, Laravel) on top of the generic signature list.
Everything is a GET of a public URL; nothing is logged into, posted or modified.
"""

from __future__ import annotations

import asyncio
import json
import re

from webguard import cve
from webguard.detection.baseline import similarity
from webguard.detection.context import Context
from webguard.http import Resp
from webguard.models import PASSIVE, SIGNATURE, Confidence, Finding, Severity

MISCONF = "A05:2021-Security Misconfiguration"
MARKERS = {
    "wordpress": re.compile(r"/wp-content/|/wp-includes/|wp-json|content=\"WordPress", re.I),
    "drupal": re.compile(r"Drupal\.settings|/sites/default/files/|content=\"Drupal|drupal-settings-json", re.I),
    "joomla": re.compile(r"/media/jui/|/components/com_|content=\"Joomla|/media/system/js/", re.I),
    "magento": re.compile(r"Mage\.Cookies|/static/version\d+/frontend/|mage/cookies|Magento_", re.I),
}


def detect(pages: dict[str, Resp], technologies: list[str]) -> set[str]:
    tech = " ".join(technologies).lower()
    found = {c for c in MARKERS if c in tech}
    for r in list(pages.values())[:80]:
        if r.is_html:
            found |= {c for c, rx in MARKERS.items() if rx.search(r.text[:300000])}
    return found


def _f(title: str, sev: Severity, url: str, evidence: str, description: str, remediation: str, cwe: str,
       tags: list[str], conf: Confidence = Confidence.CERTAIN, detection: str = SIGNATURE, request: str | None = None
       ) -> Finding:
    return Finding(check="cms", title=title, severity=sev, confidence=conf, url=url, evidence=evidence,
                   description=description, remediation=remediation, cwe=cwe, owasp=MISCONF, detection=detection,
                   tags=["cms", *tags], request=request)


def _report_versions(ctx: Context, product: str, version: str | None, url: str, source: str) -> None:
    v = cve.normalize_version(version or "")
    if not v:
        return
    for f in cve.findings_for(product, v, url, source):
        ctx.report(f)


# ----------------------------------------------------------------------------- WordPress

ASSET = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9_-]{2,60})/[^\"'?\s]*(?:\?ver=([\d.]+))?", re.I)
STABLE = re.compile(r"(?im)^\s*Stable tag:\s*([\d.]+)")
THEME_VER = re.compile(r"(?im)^\s*Version:\s*([\d.]+)")


async def wordpress(ctx: Context, root: str, pages: dict[str, Resp]) -> dict:
    info: dict = {"plugins": {}, "themes": {}, "users": []}
    # components referenced by the pages (passive), with ?ver= when present
    for r in pages.values():
        for kind, slug, ver in ASSET.findall(r.text[:500000] if r.is_html else ""):
            bucket = info["plugins" if kind.lower() == "plugins" else "themes"]
            if ver and not bucket.get(slug):
                bucket[slug] = ver
            bucket.setdefault(slug, None)
    # versions from readme.txt / style.css (active, read-only)
    async def component_version(kind: str, slug: str) -> None:
        path = f"/wp-content/{kind}/{slug}/" + ("readme.txt" if kind == "plugins" else "style.css")
        r = await ctx.client.safe_get(root + path)
        if r is not None and r.status == 200:
            m = (STABLE if kind == "plugins" else THEME_VER).search(r.text[:20000])
            if m:
                info[kind][slug] = m.group(1)

    await asyncio.gather(*(component_version(k, s) for k in ("plugins", "themes") for s, v in
                           list(info[k].items())[:40] if not v))
    for kind, prefix in (("plugins", "wp-plugin"), ("themes", "wp-theme")):
        for slug, ver in info[kind].items():
            _report_versions(ctx, f"{prefix}:{slug}", ver, f"{root}/wp-content/{kind}/{slug}/", f"{kind[:-1]} {slug}")
    # core version: readme.html as an extra source (generator / feed are handled by fingerprints)
    r = await ctx.client.safe_get(root + "/readme.html")
    if r is not None and r.status == 200 and "WordPress" in r.text:
        m = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)?)", r.text)
        if m:
            info["core"] = m.group(1)
            _report_versions(ctx, "wordpress", m.group(1), root + "/readme.html", "readme.html")
    # user enumeration: REST API, then ?author=N redirects
    users: list[str] = []
    r = await ctx.client.safe_get(root + "/wp-json/wp/v2/users?per_page=100")
    if r is not None and r.status == 200 and "json" in r.content_type:
        try:
            users = [u.get("slug") for u in json.loads(r.text) if isinstance(u, dict) and u.get("slug")]
        except ValueError:
            users = []
        if users:
            ctx.report(_f("WordPress user enumeration via REST API", Severity.LOW, root + "/wp-json/wp/v2/users",
                          f"{len(users)} user slug(s): {', '.join(users[:10])}",
                          "Login names are listed publicly, which halves the work of credential attacks.",
                          "Restrict /wp-json/wp/v2/users to authenticated users (e.g. a REST API filter or a "
                          "security plugin).", "CWE-200", ["wordpress", "user-enumeration"],
                          request=ctx.client.curl("GET", root + "/wp-json/wp/v2/users")))
    if not users:
        for n in (1, 2):
            r = await ctx.client.safe_get(f"{root}/?author={n}")
            loc = r.headers.get("location", "") if r is not None else ""
            m = re.search(r"/author/([^/?#]+)", loc)
            if m:
                users.append(m.group(1))
        if users:
            ctx.report(_f("WordPress user enumeration via author archives", Severity.LOW, root + "/?author=1",
                          f"?author=N redirects reveal: {', '.join(users)}",
                          "Author archive redirects disclose login names.",
                          "Block ?author= enumeration or disable author archives for users who do not publish.",
                          "CWE-200", ["wordpress", "user-enumeration"], conf=Confidence.FIRM))
    info["users"] = users
    # XML-RPC enabled (credential-attack amplification via system.multicall, pingback abuse)
    r = await ctx.client.safe_get(root + "/xmlrpc.php")
    if r is not None and r.status in (200, 405) and "XML-RPC server accepts POST requests only" in r.text:
        ctx.report(_f("WordPress XML-RPC interface enabled", Severity.LOW, root + "/xmlrpc.php",
                      "GET /xmlrpc.php: 'XML-RPC server accepts POST requests only.'",
                      "XML-RPC allows many password guesses per request (system.multicall) and pingbacks that "
                      "can be abused for SSRF-like scanning and DDoS reflection.",
                      "Disable XML-RPC if unused (filter xmlrpc_enabled, or block /xmlrpc.php at the server).",
                      "CWE-307", ["wordpress", "xmlrpc"]))
    # REST namespaces hint at installed plugins (even those not referenced by pages)
    r = await ctx.client.safe_get(root + "/wp-json/")
    if r is not None and r.status == 200 and "json" in r.content_type:
        try:
            info["namespaces"] = [n for n in json.loads(r.text).get("namespaces", []) if isinstance(n, str)]
        except (ValueError, AttributeError):
            pass
    return info


# ----------------------------------------------------------------------------- Drupal / Joomla / Magento

async def drupal(ctx: Context, root: str, pages: dict[str, Resp]) -> dict:
    info: dict = {"modules": sorted({m for r in pages.values() if r.is_html
                                     for m in re.findall(r"/(?:sites/all/|)modules/(?:contrib/)?([a-z0-9_]{2,50})/",
                                                         r.text[:300000])})[:100]}
    for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
        r = await ctx.client.safe_get(root + path)
        if r is not None and r.status == 200:
            m = re.search(r"(?m)^Drupal (\d+\.\d+(?:\.\d+)?)", r.text[:5000])
            if m:
                info["core"] = m.group(1)
                _report_versions(ctx, "drupal", m.group(1), root + path, path)
                break
    r1, r2 = await ctx.client.safe_get(root + "/user/1"), await ctx.client.safe_get(root + "/user/999999")
    if r1 is not None and r2 is not None and r1.status == 200 and r2.status in (403, 404) \
            and similarity(r1.text, r2.text) < 0.8:
        ctx.report(_f("Drupal user enumeration via /user/N", Severity.LOW, root + "/user/1",
                      f"/user/1 HTTP 200 vs /user/999999 HTTP {r2.status}",
                      "User profile pages are public; user IDs and names can be enumerated.",
                      "Remove the 'View user information' permission from anonymous users.", "CWE-200",
                      ["drupal", "user-enumeration"], conf=Confidence.FIRM))
    for path in ("/install.php", "/core/install.php"):
        r = await ctx.client.safe_get(root + path)
        if r is not None and r.status == 200 and re.search(r"(?i)Choose language|Select an installation profile",
                                                            r.text):
            ctx.report(_f("Drupal installer reachable and not completed", Severity.HIGH, root + path,
                          f"{path} shows the installation wizard", "An unfinished installation can be completed "
                          "by anyone, giving them an administrator account.",
                          "Finish the installation or remove install.php.", "CWE-1188", ["drupal", "install"]))
    return info


async def joomla(ctx: Context, root: str, pages: dict[str, Resp]) -> dict:
    info: dict = {"components": sorted({c for r in pages.values() if r.is_html
                                        for c in re.findall(r"/components/(com_[a-z0-9_]{2,40})/", r.text[:300000])})}
    r = await ctx.client.safe_get(root + "/administrator/manifests/files/joomla.xml")
    if r is not None and r.status == 200:
        m = re.search(r"<version>([\d.]+)</version>", r.text)
        if m:
            info["core"] = m.group(1)
            _report_versions(ctx, "joomla", m.group(1), root + "/administrator/manifests/files/joomla.xml", "manifest")
    r = await ctx.client.safe_get(root + "/administrator/")
    if r is not None and r.status == 200 and re.search(r"(?i)mod-login-username|Joomla! Administration", r.text):
        ctx.report(_f("Joomla administrator login exposed", Severity.INFO, root + "/administrator/",
                      "Administrator login form reachable from this network position",
                      "The back-end login is a credential-attack target.",
                      "Restrict /administrator/ by IP / VPN and enforce MFA.", "CWE-284",
                      ["joomla", "admin-interface"], detection=PASSIVE))
    return info


async def magento(ctx: Context, root: str, pages: dict[str, Resp]) -> dict:
    info: dict = {}
    r = await ctx.client.safe_get(root + "/magento_version")
    if r is not None and r.status == 200 and r.text.startswith("Magento/"):
        info["version_hint"] = r.text.strip()[:60]
        ctx.report(_f("Magento version disclosed", Severity.INFO, root + "/magento_version", r.text.strip()[:60],
                      "The edition and major version are public, which narrows CVE matching for attackers.",
                      "Block /magento_version at the web server.", "CWE-200", ["magento", "version"],
                      detection=PASSIVE))
    for path in ("/downloader/", "/setup/"):
        r = await ctx.client.safe_get(root + path)
        if r is not None and r.status == 200 and re.search(r"(?i)Magento Connect Manager|Setup Wizard|Magento Setup",
                                                            r.text):
            ctx.report(_f(f"Magento {path.strip('/')} interface reachable", Severity.MEDIUM, root + path,
                          f"{path} answers with the Magento tool", "Installer / extension manager interfaces "
                          "should not be reachable on production.", "Remove or block the directory.",
                          "CWE-284", ["magento", "admin-interface"]))
    return info


CMS_SCANNERS = {"wordpress": wordpress, "drupal": drupal, "joomla": joomla, "magento": magento}


# ----------------------------------------------------------------------------- technology probes

# (technology keyword, path, proof regex, title, severity)
TECH_PROBES = [
    ("php", "/index.php~", r"<\?php", "PHP source backup (index.php~)", Severity.HIGH),
    ("php", "/index.php.bak", r"<\?php", "PHP source backup (index.php.bak)", Severity.HIGH),
    ("php", "/.user.ini", r"(?m)^\s*\w+\s*=", "PHP .user.ini exposed", Severity.LOW),
    ("php", "/composer.lock", r'"packages"\s*:', "composer.lock exposed (dependency versions)", Severity.LOW),
    ("wordpress", "/wp-config.php~", r"DB_PASSWORD", "WordPress config backup (wp-config.php~)", Severity.CRITICAL),
    ("wordpress", "/wp-config.php.save", r"DB_PASSWORD", "WordPress config backup (wp-config.php.save)", Severity.CRITICAL),
    ("joomla", "/configuration.php~", r"\$password|class JConfig", "Joomla config backup (configuration.php~)", Severity.CRITICAL),
    ("joomla", "/configuration.php.bak", r"\$password|class JConfig", "Joomla config backup", Severity.CRITICAL),
    ("drupal", "/sites/default/settings.php~", r"\$databases", "Drupal settings backup", Severity.CRITICAL),
    ("spring", "/actuator/health", r'"status"\s*:\s*"(?:UP|DOWN)"', "Spring Boot actuator reachable", Severity.INFO),
    ("spring", "/actuator/loggers", r'"levels"\s*:', "Spring Boot loggers actuator exposed", Severity.MEDIUM),
    ("spring", "/actuator/threaddump", r'"threads"\s*:', "Spring Boot threaddump actuator exposed", Severity.MEDIUM),
    ("java", "/jolokia/list", r'"value"\s*:\s*\{', "Jolokia JMX bridge exposed", Severity.HIGH),
    ("tomcat", "/examples/servlets/index.html", r"Servlet Examples", "Tomcat example applications deployed", Severity.LOW),
    ("asp.net", "/web.config.bak", r"<configuration", "web.config backup exposed", Severity.HIGH),
    ("iis", "/web.config.old", r"<configuration", "web.config backup exposed", Severity.HIGH),
    ("asp.net", "/Trace.axd", r"Application Trace", "ASP.NET trace viewer enabled", Severity.MEDIUM),
    ("node", "/.env.example", r"(?m)^[A-Z_]{3,}=", "Environment template exposed (.env.example)", Severity.INFO),
    ("express", "/server.js", r"require\(['\"]express", "Express server source exposed", Severity.HIGH),
    ("django", "/static/admin/css/base.css", r"Django", "Django admin static files (admin installed)", Severity.INFO),
    ("flask", "/console", r"Werkzeug", "Werkzeug debugger console", Severity.HIGH),
    ("rails", "/rails/info/properties", r"Rails version", "Rails development info page exposed", Severity.MEDIUM),
    ("rails", "/rails/info/routes", r"Routes", "Rails routes page exposed", Severity.MEDIUM),
    ("laravel", "/storage/logs/laravel.log", r"\[\d{4}-\d{2}-\d{2}", "Laravel log exposed", Severity.HIGH),
    ("laravel", "/telescope", r"Laravel Telescope|telescope", "Laravel Telescope reachable", Severity.MEDIUM),
]


async def tech_probes(ctx: Context, root: str, technologies: set[str], fps: list[Resp]) -> int:
    """Run stack-specific exposure probes for the detected technologies; returns the number run."""
    probes = [p for p in TECH_PROBES if any(p[0] in t for t in technologies)]

    async def one(tech: str, path: str, proof: str, title: str, sev: Severity) -> None:
        r = await ctx.client.safe_get(root + path)
        if r is None or r.status != 200 or not re.search(proof, r.text[:100000]):
            return
        if any(fp.status == 200 and similarity(fp.text, r.text) > 0.9 for fp in fps):
            return  # catch-all page
        ctx.report(Finding(
            check="exposure", title=title, severity=sev, confidence=Confidence.CERTAIN, url=root + path,
            evidence=f"HTTP 200, matched {proof!r} ({tech} detected)",
            description=f"A {tech}-specific file or endpoint is publicly reachable.",
            remediation="Remove the file / disable the endpoint in production, or restrict it to administrators.",
            cwe="CWE-538", owasp=MISCONF, detection=SIGNATURE, tags=["exposure", "tech-probe", tech],
            request=ctx.client.curl("GET", root + path)))

    await asyncio.gather(*(one(*p) for p in probes))
    return len(probes)
