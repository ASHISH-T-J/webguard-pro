"""Assessment methodology: phases, OWASP WSTG test mapping and rules of engagement.

Mirrors how a professional web application assessment is run:

0. Pre-engagement     - confirm authorisation and scope, agree rules of engagement (rate, no destructive tests)
1. Recon & mapping    - fingerprint, crawl, mine JS/API specs, classify pages and parameters, grep for leads
2. Configuration      - headers/TLS policy, HTTP methods, exposed files & admin interfaces, CORS, 403 bypass
3. Identity & session - cookies, JWTs, CSRF, authentication bypass on login endpoints
4. Input validation   - hypothesis-driven injection testing, most likely bug class per parameter first
5. Authz & client     - IDOR heuristics, DOM XSS in a real browser, host header / cache poisoning
6. Verification       - independent re-test of every active finding; unreproducible ones are downgraded
7. Analysis & report  - root-cause clustering, attack chains, risk scoring, narrative, WSTG coverage
"""

from __future__ import annotations

PHASES = [
    ("recon", "Reconnaissance & mapping"),
    ("config", "Configuration & deployment management"),
    ("identity", "Identity, authentication & session management"),
    ("input", "Input validation"),
    ("authz_client", "Authorization & client-side"),
    ("verify", "Verification"),
]

WSTG = {
    "WSTG-INFO-02": "Fingerprint web server",
    "WSTG-INFO-03": "Review webserver metafiles for information leakage",
    "WSTG-INFO-05": "Review webpage content for information leakage",
    "WSTG-INFO-06": "Identify application entry points",
    "WSTG-INFO-07": "Map execution paths through application",
    "WSTG-INFO-08": "Fingerprint web application framework",
    "WSTG-INFO-10": "Map application architecture (WAF/CDN)",
    "WSTG-CONF-04": "Review old backup and unreferenced files",
    "WSTG-CONF-05": "Enumerate infrastructure and admin interfaces",
    "WSTG-CONF-06": "Test HTTP methods",
    "WSTG-CONF-07": "Test HTTP Strict Transport Security",
    "WSTG-CONF-12": "Test for Content Security Policy",
    "WSTG-ATHN-04": "Testing for bypassing authentication schema",
    "WSTG-ATHN-06": "Testing for browser cache weaknesses (incl. web cache deception)",
    "WSTG-ATHZ-01": "Testing directory traversal / file include",
    "WSTG-ATHZ-02": "Testing for bypassing authorization schema",
    "WSTG-ATHZ-04": "Testing for insecure direct object references",
    "WSTG-SESS-02": "Testing for cookies attributes",
    "WSTG-SESS-05": "Testing for cross site request forgery",
    "WSTG-SESS-10": "Testing JSON Web Tokens",
    "WSTG-INPV-01": "Testing for reflected cross site scripting",
    "WSTG-INPV-05": "Testing for SQL injection",
    "WSTG-INPV-05.6": "Testing for NoSQL injection",
    "WSTG-INPV-06": "Testing for LDAP injection",
    "WSTG-INPV-07": "Testing for XML injection (XXE)",
    "WSTG-INPV-09": "Testing for XPath injection",
    "WSTG-INPV-12": "Testing for command injection",
    "WSTG-INPV-15": "Testing for HTTP splitting/smuggling (CRLF)",
    "WSTG-INPV-17": "Testing for host header injection",
    "WSTG-INPV-18": "Testing for server-side template injection",
    "WSTG-INPV-19": "Testing for server-side request forgery",
    "WSTG-ERRH-01": "Testing for improper error handling",
    "WSTG-CLNT-01": "Testing for DOM-based cross site scripting",
    "WSTG-CLNT-04": "Testing for client-side URL redirect",
    "WSTG-CLNT-07": "Testing cross origin resource sharing",
    "WSTG-APIT-01": "Testing GraphQL",
}

# check / action name -> WSTG ids it covers
CHECK_WSTG = {
    "fingerprint": ["WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-10"],
    "crawl": ["WSTG-INFO-03", "WSTG-INFO-06", "WSTG-INFO-07"],
    "passive": ["WSTG-INFO-05", "WSTG-ERRH-01", "WSTG-SESS-02", "WSTG-SESS-05", "WSTG-SESS-10"],
    "headers": ["WSTG-CONF-07", "WSTG-CONF-12", "WSTG-CONF-06"],
    "exposure": ["WSTG-CONF-04", "WSTG-CONF-05"],
    "cors": ["WSTG-CLNT-07"],
    "access": ["WSTG-ATHZ-02"],
    "auth": ["WSTG-ATHN-04"],
    "sqli": ["WSTG-INPV-05"],
    "nosqli": ["WSTG-INPV-05.6"],
    "xss": ["WSTG-INPV-01"],
    "lfi": ["WSTG-ATHZ-01"],
    "cmdi": ["WSTG-INPV-12"],
    "crlf": ["WSTG-INPV-15"],
    "ssti": ["WSTG-INPV-18"],
    "ssrf": ["WSTG-INPV-19"],
    "redirect": ["WSTG-CLNT-04"],
    "xxe": ["WSTG-INPV-07"],
    "host_header": ["WSTG-INPV-17"],
    "idor": ["WSTG-ATHZ-04"],
    "dom_xss": ["WSTG-CLNT-01"],
    "graphql": ["WSTG-APIT-01"],
    "jwt": ["WSTG-SESS-10"],
    "csrf": ["WSTG-SESS-05"],
    "data_exposure": ["WSTG-INFO-05"],
    "disclosure": ["WSTG-ERRH-01"],
    "secrets": ["WSTG-INFO-05"],
    "js_analysis": ["WSTG-CLNT-01", "WSTG-INFO-05"],
    "ldapi": ["WSTG-INPV-06"],
    "xpathi": ["WSTG-INPV-09"],
    "xinclude": ["WSTG-INPV-07"],
    "vulnerable_component": ["WSTG-INFO-08"],
    "dom_flow": ["WSTG-CLNT-01"],
    "prototype_pollution": ["WSTG-CLNT-01"],
    "cache_deception": ["WSTG-ATHN-06"],
}

RULES_OF_ENGAGEMENT = [
    "Only in-scope hosts/paths are contacted (every request and redirect hop is scope-checked; the headless "
    "browser aborts out-of-scope loads).",
    "No destructive verbs are fuzzed automatically (DELETE is skipped; logout/delete paths are deny-listed).",
    "Payloads prove impact with harmless markers (arithmetic, file reads of /etc/passwd, random canaries) - "
    "no data is modified, no shells are spawned, no persistence.",
    "Global rate limit and concurrency cap; the agent slows down automatically on HTTP 429 / WAF blocks.",
    "Cache-poisoning probes always use a cache-buster parameter so real users are never served poisoned content.",
]
