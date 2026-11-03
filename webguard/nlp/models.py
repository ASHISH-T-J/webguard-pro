"""Pre-trained NLP models used by the assessment engine.

* **PageClassifier** - what kind of page/response is this? (login, admin, error, stack trace,
  WAF block, API JSON, docs, upload, search, registration, password reset, directory listing,
  default/placeholder, not-found, content). Drives which tests the planner prioritises.
* **ParamClassifier** - what does a parameter *mean*? (id, file, url, redirect, command/host,
  template/name, search, email, auth/token, sort/order, json/data, flag/debug, number, lang).
  This is how a human tester decides "this looks like a file path -> try traversal".

Both are multinomial naive Bayes models trained at import time on the seed corpora below
(word unigrams for pages; character n-grams + identifier tokens for parameter names).
They are small, fast, deterministic and dependency-free; extend the corpora to improve them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache

from webguard.nlp.bayes import NaiveBayes
from webguard.nlp.text import char_ngrams, html_to_text, split_identifier, tokens

# --------------------------------------------------------------------------- page corpus
PAGE_CORPUS: dict[str, list[str]] = {
    "login": [
        "login sign in username password remember me forgot password submit",
        "log in to your account email password sign in",
        "please sign in email address password keep me signed in",
        "authentication required enter your credentials username password login",
        "welcome back sign in continue with google password forgot",
    ],
    "registration": [
        "create account sign up register email password confirm password terms",
        "register new user username email password repeat password security question",
        "join now create your free account first name last name email",
    ],
    "password_reset": [
        "forgot your password reset password enter email we will send link",
        "password recovery security question answer new password repeat",
        "reset your password token new password confirm",
    ],
    "admin": [
        "admin dashboard administration users settings manage roles statistics",
        "control panel administrator manage users delete edit configuration",
        "administration panel system settings logs users permissions",
        "jenkins dashboard manage jenkins build history nodes",
        "phpmyadmin databases sql import export server variables",
    ],
    "error": [
        "internal server error 500 something went wrong please try again later",
        "an error occurred while processing your request bad request",
        "service unavailable 503 temporarily unable to service your request",
        "unexpected error occurred error id request failed",
    ],
    "stack_trace": [
        "traceback most recent call last file line in module error",
        "exception at java lang nullpointerexception at org springframework",
        "error at object anonymous node modules express lib router layer js",
        "fatal error uncaught exception stack trace php line",
        "system nullreferenceexception stack trace aspnet server error in application",
        "sqlite error unrecognized token sequelize database error stack",
    ],
    "waf_block": [
        "access denied you don't have permission to access this server reference",
        "request blocked web application firewall security policy incident id",
        "attention required cloudflare ray id sorry you have been blocked",
        "the requested url was rejected please consult with your administrator support id",
        "forbidden mod security not acceptable",
    ],
    "not_found": [
        "404 not found the requested url was not found on this server",
        "page not found the page you are looking for does not exist",
        "cannot get not found error 404",
        "oops this page could not be found",
    ],
    "api_json": [
        "status success data id name created updated",
        "error message code unauthorized token",
        "data items total page limit offset results",
        "id email role createdat updatedat deletedat",
    ],
    "docs": [
        "swagger ui api documentation openapi endpoints try it out schemas",
        "graphql playground query mutation schema docs",
        "api reference endpoints parameters responses authentication",
    ],
    "upload": [
        "upload file choose file browse select file to upload max size",
        "drag and drop files here upload document attachment",
    ],
    "search": [
        "search results for showing results no results found search again",
        "search products query filter sort by relevance",
    ],
    "directory_listing": [
        "index of parent directory name last modified size description",
        "directory listing for listing directory files",
    ],
    "default_page": [
        "welcome to nginx if you see this page the nginx web server is successfully installed",
        "apache2 ubuntu default page it works",
        "iis windows server welcome internet information services",
        "test page for the apache http server",
    ],
    "content": [
        "about us our company team mission contact news blog article",
        "products shop cart price add to basket checkout description",
        "home welcome latest news featured products contact us privacy policy",
        "terms of service privacy policy cookies copyright all rights reserved",
    ],
}

# --------------------------------------------------------------------------- parameter corpus
PARAM_CORPUS: dict[str, list[str]] = {
    "id": ["id", "uid", "user_id", "userId", "pid", "item", "itemId", "product_id", "order_id", "oid", "cid",
           "account", "accountId", "doc_id", "record", "rid", "basketId", "invoice", "ticket", "no", "num", "key"],
    "file": ["file", "filename", "path", "filepath", "document", "doc", "folder", "dir", "attachment", "include",
             "inc", "page", "template_file", "load", "read", "download", "img_path", "log", "conf", "config_file"],
    "url": ["url", "uri", "link", "href", "src", "source", "feed", "fetch", "proxy", "webhook", "endpoint",
            "image_url", "imageUrl", "avatar", "site", "domain", "host_url", "remote", "api_url", "callback_url"],
    "redirect": ["redirect", "redirect_uri", "redirectUrl", "return", "returnUrl", "return_to", "next", "continue",
                 "dest", "destination", "goto", "to", "out", "forward", "back", "success_url", "target", "redir"],
    "command": ["cmd", "exec", "command", "run", "ping", "host", "ip", "address", "hostname", "daemon", "process",
                "shell", "arg", "args", "execute", "system", "query_host"],
    "template": ["name", "template", "tpl", "view", "layout", "theme", "greeting", "message", "msg", "title",
                 "subject", "content", "body", "text", "comment", "description", "bio", "note", "preview"],
    "search": ["q", "query", "search", "s", "keyword", "keywords", "term", "find", "filter", "lookup", "searchTerm"],
    "email": ["email", "mail", "e_mail", "emailAddress", "user_email", "contact", "recipient", "from", "cc"],
    "auth": ["token", "access_token", "api_key", "apikey", "auth", "session", "sid", "jwt", "password", "pass",
             "pwd", "secret", "key_id", "code", "otp", "nonce", "csrf", "signature", "hash", "current"],
    "sort": ["sort", "order", "orderby", "order_by", "sortBy", "dir", "direction", "asc", "desc", "column", "field",
             "group", "groupby"],
    "data": ["data", "json", "xml", "payload", "input", "object", "config", "settings", "options", "params",
             "state", "filter_json", "body_json", "raw"],
    "flag": ["debug", "test", "admin", "is_admin", "isAdmin", "role", "enabled", "active", "verbose", "dev",
             "preview_mode", "internal", "beta", "trace", "show_errors", "mode"],
    "number": ["page", "limit", "offset", "count", "size", "amount", "qty", "quantity", "price", "total", "start",
               "end", "per_page", "rating", "max", "min", "year", "age"],
    "lang": ["lang", "language", "locale", "l", "hl", "lng", "country", "region", "i18n", "translation"],
}

# Which vulnerability checks a parameter category suggests (planner priors)
PARAM_HYPOTHESES: dict[str, list[str]] = {
    "id": ["sqli", "nosqli", "idor"],
    "file": ["lfi", "ssrf"],
    "url": ["ssrf", "redirect"],
    "redirect": ["redirect", "crlf", "xss"],
    "command": ["cmdi", "ssrf"],
    "template": ["ssti", "xss"],
    "search": ["xss", "sqli", "nosqli"],
    "email": ["sqli", "nosqli", "xss"],
    "auth": ["sqli", "nosqli"],
    "sort": ["sqli"],
    "data": ["xxe", "ssti", "nosqli"],
    "flag": ["anomaly"],
    "number": ["sqli", "anomaly"],
    "lang": ["lfi", "xss"],
}


def _page_features(text: str) -> list[str]:
    return tokens(text)


def _param_features(name: str) -> list[str]:
    parts = split_identifier(name)
    feats = [f"w:{p}" for p in parts] + [f"w:{p}" for p in parts]  # word features weighted x2
    feats += char_ngrams(name.lower().replace("_", "").replace("-", ""), 2, 4)
    return feats


@lru_cache(maxsize=1)
def page_model() -> NaiveBayes:
    return NaiveBayes(_page_features).fit((t, label) for label, texts in PAGE_CORPUS.items() for t in texts)


@lru_cache(maxsize=1)
def param_model() -> NaiveBayes:
    return NaiveBayes(_param_features, alpha=0.3).fit(
        (t, label) for label, names in PARAM_CORPUS.items() for t in names
    )


@dataclass
class PageInfo:
    label: str
    confidence: float
    signals: list[str]


_PASSWORD_INPUT = re.compile(r"<input[^>]+type=[\"']?password", re.I)
_FILE_INPUT = re.compile(r"<input[^>]+type=[\"']?file", re.I)


def classify_page(status: int, content_type: str, body: str, title: str = "") -> PageInfo:
    """Combine hard signals (status, content type, form fields) with the NB text model."""
    signals = []
    if "json" in content_type:
        try:
            data = json.loads(body)
            if isinstance(data, dict) and any(k in data for k in ("error", "message")) and status >= 400:
                return PageInfo("error", 0.9, ["json error object"])
        except ValueError:
            pass
        return PageInfo("api_json", 0.95, ["json content-type"])
    if status == 404:
        signals.append("HTTP 404")
    if _PASSWORD_INPUT.search(body):
        signals.append("password field")
    if _FILE_INPUT.search(body):
        signals.append("file input")
    text = f"{title} {title} " + html_to_text(body)[:4000]
    label, conf = page_model().predict(text)
    if "password field" in signals and label not in ("registration", "password_reset", "login"):
        label, conf = "login", max(conf, 0.7)
    if "file input" in signals and label == "content":
        label, conf = "upload", 0.7
    if status == 404 and label == "content":
        label, conf = "not_found", 0.8
    if status in (401, 403) and label == "content":
        label, conf = "waf_block" if status == 403 else "login", 0.6
    return PageInfo(label, round(conf, 3), signals)


def classify_param(name: str) -> tuple[str, float]:
    label, conf = param_model().predict(name)
    return label, round(conf, 3)


def hypotheses_for_param(name: str, value: str = "") -> list[str]:
    """Ordered list of checks a tester would try first for this parameter."""
    label, conf = classify_param(name)
    hyps = list(PARAM_HYPOTHESES.get(label, []))
    v = value or ""
    if v.startswith(("http://", "https://", "//")):
        hyps = ["ssrf", "redirect"] + hyps
    elif re.search(r"\.(?:php|html?|txt|pdf|jpg|png|xml|json|ya?ml|conf|log)$", v, re.I) or "/" in v:
        hyps = ["lfi"] + hyps
    elif v.lstrip("-").isdigit():
        hyps = ["sqli", "idor"] + hyps
    elif v.strip().startswith(("{", "[")):
        hyps = ["nosqli", "ssti"] + hyps
    elif v.strip().startswith("<"):
        hyps = ["xxe", "xss"] + hyps
    return list(dict.fromkeys(hyps + ["xss", "sqli", "ssti"]))
