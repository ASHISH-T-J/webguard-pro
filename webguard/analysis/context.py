"""Response context analysis.

A professional never reads a response in isolation: "is this the application answering, or a WAF /
CDN challenge / rate limiter / login wall / generic error page?" Every active check consults this
classifier so that, for example,

* a WAF block page is never mistaken for the FALSE branch of a boolean SQL injection,
* a 429 page is never an "anomaly",
* a database error teaches the agent that a parameter reaches SQL (a lead even if no check confirms),
* a page behind a CDN challenge is reported as "not tested", not "not vulnerable".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from webguard.http import Resp

# kind -> severity of "this response is not the application's normal answer"
NON_APP = {"waf_block", "challenge", "rate_limited", "maintenance"}

CHALLENGE = re.compile(
    r"(?i)<title>\s*(?:just a moment|attention required|please wait|checking your browser|ddos-guard|"
    r"one more step|access denied)|cf-chl-|cf_chl_opt|/cdn-cgi/challenge-platform|_Incapsula_Resource|"
    r"px-captcha|geo\.captcha-delivery\.com|hcaptcha\.com/1/api|challenges\.cloudflare\.com"
)
BLOCK = re.compile(
    r"(?i)request (?:was )?(?:blocked|rejected)|web application firewall|you have been blocked|"
    r"blocked by (?:the )?(?:security|firewall)|incident id|support id[: ]|ray id[: ]|mod_?security|"
    r"not acceptable!|security polic(?:y|ies)|malicious (?:request|input)|forbidden: suspicious|"
    r"the requested url was rejected|access denied.{0,80}reference #|unauthorized activity has been detected"
)
RATE = re.compile(r"(?i)too many requests|rate limit(?:ed)?|slow down|try again (?:later|in \d+)|quota exceeded")
MAINT = re.compile(r"(?i)under maintenance|temporarily unavailable|scheduled maintenance|be right back")
AUTH = re.compile(r"(?i)\b(?:unauthori[sz]ed|authentication required|login required|please (?:log|sign) in|"
                  r"invalid (?:token|credentials)|access token)")

ERROR_TYPES: list[tuple[str, re.Pattern[str]]] = [
    ("database", re.compile(r"(?i)sql syntax|sqlite_error|ORA-\d{5}|PG::|psql|pdoexception|sqlstate|mysql|"
                            r"unclosed quotation|syntax error at or near|odbc|jdbc|sequelize|mongo(?:db)?error|"
                            r"cast to objectid|bson")),
    ("template", re.compile(r"(?i)jinja2|TemplateSyntaxError|twig_error|freemarker|velocity|thymeleaf|"
                            r"mako\.exceptions|smarty|handlebars|liquid error|ejs:|pug:|undefined (?:variable|method) in template")),
    ("xml", re.compile(r"(?i)SAXParseException|XMLSyntaxError|lxml|libxml|xml parsing error|DOCTYPE|entity")),
    ("ldap", re.compile(r"(?i)LDAPException|javax\.naming|ldap_search|invalid dn syntax|Bad search filter")),
    ("xpath", re.compile(r"(?i)XPathException|xpath (?:syntax|error)|SimpleXMLElement::xpath|Invalid predicate")),
    ("path", re.compile(r"(?i)no such file or directory|failed to open stream|FileNotFoundException|"
                        r"ENOENT|include\(\)|open_basedir|path traversal")),
    ("command", re.compile(r"(?i)sh: \d+:|/bin/sh|command not found|is not recognized as an internal or external")),
    ("deserialization", re.compile(r"(?i)unserialize\(\)|ObjectInputStream|pickle|InvalidClassException|"
                                   r"TypeNameHandling|BinaryFormatter")),
    ("framework", re.compile(r"(?i)traceback \(most recent call last\)|stack trace|exception in thread|"
                             r"at [\w$.]+\([\w.]+:\d+\)|whitelabel error page|<ul id=\"stacktrace\">|"
                             r"fatal error:|uncaught exception")),
]
# which bug class an error type is evidence for (fed back to the planner as a lead)
ERROR_HINTS = {"database": ["sqli", "nosqli"], "template": ["ssti"], "xml": ["xxe"], "ldap": ["ldapi"],
               "xpath": ["xpathi"], "path": ["lfi"], "command": ["cmdi"], "deserialization": ["deserialization"]}


@dataclass
class ResponseContext:
    kind: str  # ok | waf_block | challenge | rate_limited | auth_required | login_redirect | not_found |
    #             server_error | client_error | redirect | maintenance
    error_type: str | None = None
    signals: list[str] = field(default_factory=list)

    @property
    def is_app_response(self) -> bool:
        """False when something in front of the app answered instead (WAF, CDN, rate limiter)."""
        return self.kind not in NON_APP

    @property
    def hints(self) -> list[str]:
        return ERROR_HINTS.get(self.error_type or "", [])


def classify(resp: Resp | None, waf_fingerprint: Resp | None = None) -> ResponseContext:
    if resp is None:
        return ResponseContext("no_response")
    status, head, body = resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.text[:20000]
    sig: list[str] = []
    if head.get("cf-mitigated") == "challenge" or (status in (403, 503) and CHALLENGE.search(body)):
        return ResponseContext("challenge", signals=["CDN/bot challenge page"])
    if status == 429 or (status in (403, 503) and RATE.search(body[:3000])):
        return ResponseContext("rate_limited", signals=[f"HTTP {status}", "rate-limit wording"])
    if status in (403, 406, 419, 501, 400, 500) and BLOCK.search(body):
        return ResponseContext("waf_block", signals=[f"HTTP {status}", "block-page wording"])
    if waf_fingerprint is not None and status == waf_fingerprint.status and status >= 400:
        from webguard.detection.baseline import similarity

        if similarity(body, waf_fingerprint.text[:20000]) > 0.85:
            return ResponseContext("waf_block", signals=["matches learned block page"])
    if status == 503 and MAINT.search(body):
        return ResponseContext("maintenance")
    err = next((name for name, rx in ERROR_TYPES if rx.search(body)), None)
    if status >= 500:
        return ResponseContext("server_error", err, sig)
    if status in (401, 407) or (status == 403 and AUTH.search(body[:3000])):
        return ResponseContext("auth_required", err)
    if status in (301, 302, 303, 307, 308):
        loc = head.get("location", "")
        if re.search(r"(?i)log[-_]?in|sign[-_]?in|auth|sso|account/", loc):
            return ResponseContext("login_redirect", signals=[loc])
        return ResponseContext("redirect", signals=[loc])
    if status == 404:
        return ResponseContext("not_found")
    if status >= 400:
        return ResponseContext("client_error", err)
    return ResponseContext("ok", err, sig)


ENV_PATTERNS = [
    ("development", re.compile(r"(?i)(?:^|[.-])(?:dev|develop|local|sandbox)(?:[.-]|\d|$)|localhost|127\.0\.0\.1")),
    ("staging", re.compile(r"(?i)(?:^|[.-])(?:stag(?:e|ing)|uat|qa|test|preprod|pre-prod)(?:[.-]|\d|$)")),
]


def environment(host: str, pages_text: str = "") -> str:
    """production / staging / development - affects FP heuristics and severity context in reports."""
    for name, rx in ENV_PATTERNS:
        if rx.search(host):
            return name
    if re.search(r"(?i)debug toolbar|DEBUG = True|APP_ENV=(?:local|dev)|NODE_ENV=development", pages_text[:200000]):
        return "development"
    return "production"
