"""Product / version extraction from free text (footers, about pages, banners, error pages).

Regular expressions catch the well-known formats; this extractor generalises to the long tail:

    "Powered by Atlassian Confluence 7.13.0"   -> ("confluence", "7.13.0", 0.95)
    "Grafana v8.2.0 (abc123)"                  -> ("grafana", "8.2.0", 0.8)
    "Requires PHP 7.4 or newer"                -> rejected (talks about *another* version)

Each alias occurrence is paired with the nearest version token within a short window and scored on
context: introducer phrases ("powered by", "running", "version", "v") raise confidence; requirement /
compatibility / upgrade phrasing lowers it, because those sentences mention versions that are not the
one running. Only matches with confidence >= ``MIN_CONFIDENCE`` are returned.
"""

from __future__ import annotations

import re

from webguard.nlp.text import html_to_text

MIN_CONFIDENCE = 0.6
PRODUCTS: dict[str, tuple[str, ...]] = {
    "apache_httpd": ("apache http server", "apache httpd", "apache/"),
    "nginx": ("nginx",), "tomcat": ("apache tomcat", "tomcat"), "php": ("php",), "openssl": ("openssl",),
    "microsoft_iis": ("microsoft-iis", "internet information services"),
    "confluence": ("atlassian confluence", "confluence"), "jira": ("atlassian jira", "jira software", "jira"),
    "bitbucket": ("atlassian bitbucket", "bitbucket server", "bitbucket data center"),
    "jenkins": ("jenkins",), "gitlab": ("gitlab community edition", "gitlab enterprise edition", "gitlab"),
    "grafana": ("grafana",), "kibana": ("kibana",), "elasticsearch": ("elasticsearch",), "solr": ("apache solr", "solr"),
    "teamcity": ("teamcity",), "webmin": ("webmin",), "zabbix": ("zabbix",), "cacti": ("cacti",),
    "roundcube": ("roundcube webmail", "roundcube"), "openfire": ("openfire",), "liferay": ("liferay portal", "liferay dxp"),
    "wordpress": ("wordpress",), "drupal": ("drupal",), "joomla": ("joomla!", "joomla"), "vbulletin": ("vbulletin",),
    "geoserver": ("geoserver",), "ofbiz": ("apache ofbiz", "ofbiz"), "papercut": ("papercut mf", "papercut ng"),
    "craftcms": ("craft cms",), "langflow": ("langflow",), "superset": ("apache superset", "superset"),
    "activemq": ("apache activemq", "activemq"), "struts": ("apache struts", "struts"),
    "screenconnect": ("screenconnect", "connectwise control"), "crushftp": ("crushftp",),
    "goanywhere": ("goanywhere mft", "goanywhere"), "nextjs": ("next.js",),
}
VERSION = r"v?(\d+(?:\.\d+){1,3}(?:[-.]?(?:beta|rc|m)\d*|p\d+|[a-z])?)\b"
INTRO = re.compile(r"(?i)(powered by|running|built (?:with|on)|server:|©|\(c\)|copyright|version|release|ver\.|build)\s*$")
NEG = re.compile(r"(?i)\b(requires?|required|minimum|compatible|compatibility|support(?:s|ed)?|upgrade to|update to|"
                 r"or (?:newer|later|higher|above)|at least|recommended|deprecated in|since|before|prior to|"
                 r"migrat\w+|download|available)\b")
_ALIAS = sorted(((a, p) for p, aliases in PRODUCTS.items() for a in aliases), key=lambda x: -len(x[0]))
_ALIAS_RX = re.compile("|".join(r"(?<![\w-])" + re.escape(a) + (r"(?![\w])" if a[-1].isalnum() else "")
                                for a, _ in _ALIAS), re.I)
_BY_ALIAS = {a: p for a, p in _ALIAS}


def extract(text: str, is_html: bool = True, limit: int = 200000) -> list[tuple[str, str, float]]:
    """[(product, version, confidence)] found in ``text`` (best match per product)."""
    plain = html_to_text(text[:limit]) if is_html else text[:limit]
    best: dict[str, tuple[str, float]] = {}
    for m in _ALIAS_RX.finditer(plain):
        product = _BY_ALIAS[m.group(0).lower()]
        after = plain[m.end(): m.end() + 40]
        vm = re.match(r"[\s/:,(]*(?:(version|ver\.|release|build|v)\s*:?\s*)?" + VERSION, after, re.I)
        if not vm:
            continue
        version = vm.group(2)
        conf = 0.55
        before = plain[max(0, m.start() - 30): m.start()]
        if INTRO.search(before):
            conf += 0.25
        if vm.group(1) or after.lstrip().lower().startswith(("v", "/")):
            conf += 0.15
        elif re.match(r"[ /]\d", after):
            conf += 0.1  # "Webmin 1.910": the version directly follows the product name
        sentence = plain[max(0, m.start() - 60): m.end() + 60]
        if NEG.search(sentence):
            conf -= 0.4
        if "." not in version:
            conf -= 0.3
        conf = round(max(0.0, min(conf, 0.95)), 2)
        if conf >= MIN_CONFIDENCE and conf > best.get(product, ("", 0.0))[1]:
            best[product] = (version, conf)
    return [(p, v, c) for p, (v, c) in best.items()]
