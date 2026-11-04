"""Path classifier: what kind of resource does a discovered URL path name?

Multinomial naive Bayes over path segment words, file extension and character n-grams of the last
segment, trained at import on the seed corpus below. Used to

* order recursive content discovery (admin / api / backup / config directories before static assets),
* group discovered content in reports, and
* feed ``path_category`` to ML triage.

Categories: admin, api, auth, backup, config, source_control, log, debug, upload, docs, static, other.
"""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import urlsplit

from webguard.nlp.bayes import NaiveBayes
from webguard.nlp.text import char_ngrams, split_identifier

PATH_CORPUS: dict[str, list[str]] = {
    "admin": ["admin", "administrator", "admin panel", "adminpanel", "manage", "manager", "management", "console",
              "dashboard", "cpanel", "controlpanel", "backend", "backoffice", "staff", "moderator", "superuser",
              "sysadmin", "wp admin", "admin console", "admin area", "siteadmin", "panel", "portal admin"],
    "api": ["api", "api v1", "api v2", "rest", "graphql", "v1", "v2", "v3", "rpc", "jsonrpc", "services", "ws",
            "webservice", "endpoints", "odata", "soap", "api internal", "gateway"],
    "auth": ["login", "logout", "signin", "signup", "register", "auth", "oauth", "sso", "saml", "password reset",
             "forgot password", "account", "session", "token", "authorize", "callback", "mfa", "otp"],
    "backup": ["backup", "backups", "bak", "old", "orig", "archive", "dump", "db dump", "site backup zip",
               "backup tar gz", "copy", "website old", "export", "sql dump", "database backup", "snapshot",
               "www zip", "release zip", "temp old"],
    "config": ["config", "configuration", "settings", "env", "dotenv", "conf", "ini", "web config", "app settings",
               "application properties", "application yml", "database yml", "secrets", "credentials", "parameters",
               "local settings", "wp config", "htaccess", "htpasswd"],
    "source_control": ["git", "git head", "git config", "svn", "svn entries", "hg", "bzr", "cvs", "gitignore",
                       "gitlab ci", "github workflows"],
    "log": ["log", "logs", "error log", "access log", "debug log", "laravel log", "trace", "audit log",
            "error_log", "server log", "app log"],
    "debug": ["debug", "test", "testing", "phpinfo", "info", "status", "server status", "health", "metrics",
              "actuator", "profiler", "console debug", "dev", "staging", "sandbox", "trace axd", "elmah"],
    "upload": ["upload", "uploads", "files", "file upload", "attachments", "media upload", "userfiles", "documents",
               "import", "tmp", "temp"],
    "docs": ["docs", "documentation", "swagger", "swagger ui", "openapi", "api docs", "redoc", "help", "manual",
             "readme", "changelog", "license"],
    "static": ["static", "assets", "css", "js", "images", "img", "fonts", "icons", "vendor", "dist", "build",
               "public", "media", "styles", "scripts", "favicon", "lib", "node modules"],
    "other": ["about", "contact", "blog", "news", "products", "shop", "cart", "search", "home", "index", "page",
              "category", "faq", "team", "careers", "privacy", "terms"],
}
EXT_HINT = {
    "backup": {"bak", "old", "orig", "zip", "tar", "gz", "tgz", "7z", "rar", "sql", "dump", "swp", "backup"},
    "config": {"env", "ini", "conf", "config", "cfg", "yml", "yaml", "properties", "xml", "toml"},
    "log": {"log"},
    "static": {"css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "map"},
    "docs": {"md", "txt", "pdf"},
}
# recursion order (lower first): where hidden, sensitive content most often lives
PRIORITY = {"admin": 0, "backup": 1, "config": 1, "source_control": 1, "api": 2, "debug": 2, "log": 3, "auth": 3,
            "upload": 4, "docs": 5, "other": 6, "static": 9}


def _features(path: str) -> list[str]:
    segs = [s for s in path.strip("/").split("/") if s]
    last = segs[-1] if segs else ""
    words = [w for s in segs for w in split_identifier(s)]
    feats = [f"w:{w}" for w in words] + [f"last:{w}" for w in split_identifier(last)] * 2
    m = re.search(r"\.([a-z0-9]{1,10})$", last.lower())
    if m:
        feats += [f"ext:{m.group(1)}"] * 3
    feats += char_ngrams(last.lower().lstrip("."), 3, 4)
    return feats


@lru_cache(maxsize=1)
def path_model() -> NaiveBayes:
    samples = [(t.replace(" ", "/"), label) for label, texts in PATH_CORPUS.items() for t in texts]
    samples += [(f"file.{ext}", label) for label, exts in EXT_HINT.items() for ext in exts]
    return NaiveBayes(_features, alpha=0.3).fit(samples)


def classify_path(url: str) -> tuple[str, float]:
    path = urlsplit(url).path if "://" in url else url
    if not path.strip("/"):
        return "other", 1.0
    last = path.rstrip("/").rsplit("/", 1)[-1].lower()
    ext = last.rsplit(".", 1)[-1] if "." in last.lstrip(".") else ""
    for label, exts in EXT_HINT.items():  # the extension is the strongest single signal
        if ext in exts and label != "docs":
            return label, 0.95
    if last.startswith((".git", ".svn", ".hg")):
        return "source_control", 0.95
    if last.startswith(".env"):
        return "config", 0.95
    return path_model().predict(path)


def recursion_priority(url: str) -> tuple[int, int, str]:
    label, conf = classify_path(url)
    return PRIORITY.get(label, 6), -int(conf * 100), url
