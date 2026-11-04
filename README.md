# WebGuard Pro 3

**An autonomous, methodology-driven web application security assessment framework** for authorised
penetration tests, red-team engagements and bug bounty programs.

WebGuard works the way a professional tester does: it maps the application, forms hypotheses about
each input ("this parameter looks like a file path → try traversal first"), tests the most likely
weaknesses first, verifies every finding independently, chains related issues into attack paths and
writes the report - logging the reasoning behind every step. The planning brain can be the built-in
local reasoner, **Claude** (Anthropic API) or any **local LLM via Ollama**.

> ⚠️ **Authorised use only.** Only test systems you own or have explicit written permission to assess.
> WebGuard enforces scope on every request, redirect hop and headless-browser load, never fuzzes
> destructive verbs and uses harmless proof markers - but staying within your rules of engagement is
> your responsibility.

---

## Contents

- [Quick start](#quick-start)
- [Console, progress and resume](#console-progress-and-resume)
- [How an assessment runs](#how-an-assessment-runs)
- [What it detects](#what-it-detects)
- [AI / LLM reasoning engines](#ai--llm-reasoning-engines)
- [NLP and machine learning](#nlp-and-machine-learning)
- [Grep, analysis and natural-language queries](#grep-analysis-and-natural-language-queries)
- [Bug bounty and red-team workflows](#bug-bounty-and-red-team-workflows)
- [Reports](#reports)
- [Benchmarks](#benchmarks)
- [Command reference](#command-reference)
- [Architecture](#architecture)
- [Development](#development)

---

## Quick start

```bash
pip install -e ".[all]"            # core + ML, DNS, SOCKS, Claude SDK, Playwright
webguard tools                     # which optional tools/components are available

# Autonomous assessment with the built-in reasoner, showing the reasoning trace
webguard assess https://app.example.com --scope scope.yml --show-trace

# Same, with Claude planning the tests (credentials from ANTHROPIC_API_KEY / `ant auth login`)
webguard assess https://app.example.com --llm claude

# Fully offline with a local model
ollama pull qwen2.5:7b && webguard assess https://app.example.com --llm ollama:qwen2.5:7b

# Time-boxed engagement: stop active testing after 3000 requests or 20 minutes
webguard assess https://app.example.com --budget-requests 3000 --budget-minutes 20

# Authenticated testing through Burp
webguard assess https://app.example.com -H "Authorization: Bearer …" --cookie session=… \
    --proxy http://127.0.0.1:8080 --rate 5
```

New to security testing? `webguard wizard` asks a few plain-language questions (target, permission,
goal, production or not, login, proxy, time limit), prints the equivalent command so you can learn the
switches, and runs it. `webguard --help` and `webguard <command> --help` show usage examples.

Core dependencies are only `httpx`, `beautifulsoup4` and `pyyaml`. Everything else is optional and
degrades gracefully: no scikit-learn → robust z-score anomaly model; no Playwright → no DOM-XSS
browser verification; no LLM → local reasoner. Docker: `docker build -t webguard . && docker run --rm
-v "$PWD:/reports" webguard assess https://target`.

---

## Console, progress and resume

```
━━━ [stage 4/7] Input validation ━━━
[05:19:12] [PAYLOAD] sqli · GET http://shop.test/data [data] (query)
           raw     : 1001'
           encoded : MTAwMSc%3D
           value encoding: base64
[HIGH] SQL injection (error-based, MySQL) (inside base64-encoded value)  (firm confidence)
    URL       : http://shop.test/data
    Parameter : data (query)
    Payload   : 1001'
    Encoded   : MTAwMSc%3D  (base64 value, then URL-encoded)
    Evidence  : DBMS error triggered by payload: SQL syntax; check the manual ...
[stage 4/7 Input validation] ███████░░░░░░░░░░░░░ 41/118 tests · 2210 req (96.1/s) · 1C 6H · 00:23 · inject:GET /search [query] q
```

- **Stages of testing**: 1 Reconnaissance & mapping · 2 Configuration · 3 Identity & sessions ·
  4 Input validation · 5 Authorization & client-side · 6 Verification · 7 Analysis & reporting.
- **Live progress line** (terminal only): stage, tests done/total, requests and rate, findings by
  severity, elapsed time, current test. `--no-progress` turns it off.
- **Colours**: CRITICAL / HIGH red, MEDIUM yellow, LOW blue, INFO green. `--no-color` or `NO_COLOR=1`
  turns them off (automatic when output is redirected).
- **Findings**: MEDIUM+ as a block (URL, parameter, payload, encoded payload, evidence, CWE/OWASP),
  LOW/INFO on one line, then a severity-sorted table at the end.
- **Verbosity** (`-v N`, like sqlmap; `-vv` / `-vvv` also work):

| `-v` | Shows |
|---|---|
| 0 | findings, warnings and the summary only |
| 1 | + stages and progress (default) |
| 2 | + debug: each test as it starts, reasoner decisions, rate-control changes |
| 3 | + every payload: bug class, method, URL, parameter and location, **raw** and **encoded** (wire) value, tamper/variant and value encoding |
| 4 | + every HTTP request (method, URL, headers, body) |
| 5 | + response status, size, time and headers |
| 6 | + response bodies |

- **Save and resume**: progress is saved after every round of tests and on Ctrl+C or a crash
  (`<db dir>/sessions/`, or `--session-dir`). Running the **same command** again resumes: the
  application is mapped again (fast, and it may have changed), completed tests are skipped, and the
  findings confirmed earlier are restored and re-verified. A finished scan deletes its session;
  `--fresh` (alias `--flush-session`) starts over. `hunt` keeps one session per host.

---

## How an assessment runs

`webguard assess` follows the OWASP Web Security Testing Guide (WSTG) in phases. Each phase the
agent builds a list of *candidate tests* from what it knows, the reasoner ranks them (likelihood ×
impact ÷ cost), the agent runs them, observes the results and adapts.

| Phase | What happens | WSTG |
|---|---|---|
| **0. Rules of engagement** | Scope rules, rate limit, non-destructive policy printed and enforced | - |
| **1. Recon & mapping** | Fingerprint tech + WAF · crawl (forms, robots, sitemap) · JS bundle mining with a real JS tokenizer (template literals, `http.post(...)` calls, SPA routes) · OpenAPI/Swagger import · NLP classification of every page and parameter · grep packs for DOM sinks, internal hosts, debug flags | INFO-02/03/06/07/08/10 |
| **2. Configuration** | Security headers/CSP/methods · 56 sensitive-file signatures · soft-404-calibrated content discovery · CORS · 401/403 bypass · GraphQL | CONF-04/05/06/07/12, CLNT-07, ATHZ-02, APIT-01 |
| **3. Identity & session** | Cookie flags · JWT analysis + offline weak-secret cracking · CSRF · serialized objects · password hashes/PII in APIs · **login auth-bypass (SQL/NoSQL)** | ATHN-04, SESS-02/05/10 |
| **4. Input validation** | Per parameter, hypothesis-ordered: SQLi, NoSQLi, XSS, SSTI, LFI, command injection, SSRF, open redirect, CRLF, ML anomaly fuzzing · XXE · host-header/cache poisoning | INPV-01/05/07/12/15/17/18/19, ATHZ-01, CLNT-04 |
| **5. Authz & client-side** | IDOR heuristics · **DOM XSS verified in headless Chromium** | ATHZ-04, CLNT-01 |
| **6. Verification** | Every active finding is re-tested in a fresh context; unreproducible results are downgraded, never silently kept | - |
| **7. Analysis & report** | Root-cause clustering · attack chains · CVSS + risk scoring · ML triage · narrative · WSTG coverage matrix | - |

**Adaptive behaviour** (like a human tester): on HTTP 429 the agent halves its rate; on repeated WAF
blocks it slows down and enables payload tampering; endpoints that answer 401/403 are not fuzzed
blindly but listed as a coverage gap ("re-run with credentials"); with a budget, each phase gets a
share and the highest-value tests run first.

Example reasoning-trace step (verbatim from `benchmarks/results/juice-shop_local_2000.json`):

```
▸ step [input] (local)
  thought:  Input validation: 62 candidate test(s). Prioritising by expected value per request (budgeted).
            [xxe .../rest/continue-code-findIt/apply/] endpoint accepts a request body - check whether it
            parses XML with external entities. [host_header .../walletNFTVerify] page builds absolute URLs
            from the request host - test password-reset/cache poisoning via X-Forwarded-Host. ...
  observed: 25 test(s), 933 requests; 3 new finding(s): LOW Anomalous input handling (server errors)
            @ /api/Challenges/ [key]; HIGH SQL injection (error-based, SQLite) @ /rest/products/search [q]; ...
```

`webguard scan` runs the same engine exhaustively (every applicable test, no budget, local reasoner).

---

## What it detects

Every active check needs **proof the server acted on the input**, not mere reflection:

| Class | Technique |
|---|---|
| SQL injection | Error-based (130+ DBMS signatures), boolean differential with two random TRUE/FALSE pairs + junk-input control, time-based slow→fast→slow |
| Authentication bypass | SQL/NoSQL payloads on login endpoints (forms, JSON APIs found in JS/OpenAPI); success = status flip + session/token issued |
| NoSQL injection | `$ne`/`$eq`/`$regex` operator differential + MongoDB error signatures |
| XSS | Canary → reflection-context analysis → context-specific break-out confirmed by **parsing the DOM** |
| DOM XSS | Payload sets a random global in **headless Chromium**; reported only if it executed (SPA routes ranked by name) |
| SSTI | Random-number arithmetic in 10 template syntaxes + engine fingerprint (Jinja2 vs Twig) |
| Command injection | Shell arithmetic echo (`$((a*b))`) + timing |
| LFI / XXE | File contents (`root:x:0:0:`, `win.ini`, PHP filter base64), XML external entities |
| SSRF | Server fetches `example.com` content in-band; OOB tokens for interactsh/Collaborator |
| Open redirect | Location/meta/JS redirects to a random host, incl. **allow-list bypasses** (`evil/?trusted`, `trusted.evil`) |
| CRLF | Injected response header appears |
| Host header / cache poisoning | `X-Forwarded-Host` & co. reflected in links/Location (always with a cache buster); cacheable → poisoning |
| Access control | 401/403 bypass via path normalisation and `X-Original-URL`/IP headers (soft-404 aware); IDOR heuristic on sequential ids with PII |
| JWT | `alg=none`, **offline HMAC secret cracking**, sensitive claims, missing `exp`, `jku/x5u/kid` |
| Data exposure | Password hashes (MD5/SHA-1/bcrypt typed), secrets and bulk PII in JSON APIs; 40 secret/key patterns with entropy filtering |
| Configuration | Headers, CSP weaknesses, cookie flags, CORS (reflection, `null`, prefix/suffix bypass, `*`), TRACE, exposures, directory listing, GraphQL introspection & batching, SRI, CSRF, serialized objects, secrets in URLs, verbose errors |
| Unknowns | ML anomaly fuzzing (IsolationForest + robust z-scores) flags inputs whose handling deviates from benign behaviour |
| Infrastructure | Subdomain takeover (28 services), exposed risky ports/services, nuclei templates (imported as findings) |

### Techniques from bug bounty and red-team research

| Technique | Source / rationale | How WebGuard tests it |
|---|---|---|
| Web cache deception | PortSwigger "Gotta cache 'em all" (Black Hat USA 2024): delimiter & normalisation discrepancies | Appends `/x.css`, `;x.css`, `%23x.css`, `%3fx.css`, `.x.css`, `%00x.css` to dynamic pages; reported only if the origin serves the dynamic page **and** a cache stores it. Unique random file names, so only our own response is ever cached; HIGH with a session, LOW (re-test advice) without |
| Exposed JavaScript source maps | Recurring high-payout writeups (keys and internal routes in original sources) | Finds `sourceMappingURL` / `*.js.map`, reports the exposure, mines original sources for endpoints and secrets |
| Lazy-loaded chunks | Admin/feature-flagged code lives in chunks the UI never loads | Fetches chunk files referenced from bundles and analyses them |
| Static DOM-XSS flows & `postMessage` | Classic client-side bug classes | Source→variable→sink taint-lite analysis; message listeners without `origin` checks; client-read URL params become browser tests |
| Vulnerable JS libraries | retire.js-style component analysis | `js_libs.json`: jQuery, jQuery UI, AngularJS, lodash, underscore, Bootstrap, moment, Handlebars, DOMPurify, axios, Vue 2, Prototype |
| Header & cookie injection | SQLi via logged `User-Agent`/`X-Forwarded-For`, XSS via rendered `Referer`/cookies | Header/cookie injection points on a focused sample (root, header-reflecting pages, cookie-setting pages, logging-style paths) |
| OAuth `redirect_uri` validation | Token-theft writeups | Allow-list bypass payloads on `redirect_uri`; hits on authorize endpoints are HIGH ("OAuth redirect_uri validation bypass") |
| Client-side prototype pollution | Gadget-chain writeups | `?__proto__[k]=v`, `#constructor[prototype][k]=v` … verified by reading `Object.prototype` in headless Chromium |

### Context analysis & false-positive control

Every response is classified before it is used as evidence: application answer, **WAF block page,
CDN/bot challenge, rate limiter**, auth wall, login redirect, soft-404, maintenance, or a typed error
(database, template, XML, LDAP, XPath, path, command, deserialization, framework).

- Responses produced by a WAF, challenge or rate limiter are **never** evidence. The affected inputs are
  listed in the report as **NOT TESTED**, so "nothing found" is never confused with "not vulnerable".
- Time-based checks scale their delay with measured network jitter (noisy targets need a bigger, clearer signal).
- Cache-deception, exposure and 403-bypass checks compare against the page's own variability and the site's
  soft-404 / SPA fallback fingerprint.
- The environment (production / staging / development) is detected and attached to every finding, with a
  note when impact should be confirmed in production.

**WAF policy:** WebGuard detects and fingerprints WAFs/CDNs, adapts its request rate, and reports which
inputs could not be tested because a defence answered. It deliberately does **not** include WAF-evasion
payload obfuscation, CDN challenge solving, fingerprint spoofing, IP rotation or rate-limit evasion. For
assessments behind a WAF, ask the owner to allow-list your source IP or provide an origin/staging
endpoint, which is the standard practice in authorised engagements and tests the application itself.

### Technique catalogue (OWASP WSTG · PortSwigger Academy · HackTricks)

For every input the agent first runs the **basic** proof-based test. If it fails, the application (not a
WAF/CDN/rate limiter) answered, and there is a reason to suspect a filter, the same test is re-run through
the **bypass variants that make sense for that bug class**. A hit is reported with the variant and its
source, e.g. *"Path traversal / local file inclusion - input filter bypassed (null-byte-extension)"*, and
is re-verified with the same variant.

| Class | WSTG | Proof (basic test) | Bypass / encoding variants | Technique sources |
|---|---|---|---|---|
| Path traversal / LFI | ATHZ-01 | `/etc/passwd`, `win.ini`, `php://filter` contents | nested `....//`, double URL encoding, overlong UTF-8 `..%c0%af` (sent raw), required path prefix, null byte + required extension, `\` separators | PortSwigger path-traversal labs (non-recursive strip, superfluous decode, start-of-path, extension + null byte); HackTricks |
| SQL injection | INPV-05 | DBMS errors, boolean differential, time-based | sqlmap tamper chains (`space2comment`, `randomcase`, `space2tab`, `equaltolike`, `symboliclogical`, `versioned`, …), double URL, full-width Unicode, `\uXXXX` | sqlmap, OWASP SQLi filter evasion |
| XSS | INPV-01 | new DOM node/attribute parsed from the response | double URL encoding, HTML entities (decode-after-sanitise), full-width Unicode (NFKC), JS `\uXXXX`, case variation | PortSwigger XSS contexts, OWASP XSS Filter Evasion, HackTricks |
| OS command injection | INPV-12 | shell arithmetic echo / timing | `${IFS}` for spaces, quote insertion (`e''cho`), double URL | HackTricks command injection |
| SSTI | INPV-18 | random arithmetic in 10 syntaxes; error polyglot `${{<%[%'"}}%\` | double URL, HTML entities, full-width | PortSwigger SSTI methodology |
| SSRF | INPV-19 | server fetches `example.com` (in-band) / OOB token | allow-list parsing: `trusted@evil`, `evil#trusted`, `evil?trusted`, double URL | PortSwigger SSRF whitelist/blacklist labs, HackTricks URL format bypass |
| Open redirect / OAuth | CLNT-04 | `Location`/meta/JS to a random host | allow-list bypasses, double URL, backslash, full-width | PortSwigger OAuth labs, HackTricks |
| CRLF | INPV-15 | injected response header present | CR/LF/`\u560a`, double URL | OWASP |
| LDAP injection | INPV-06 | LDAP filter errors | - | OWASP WSTG |
| XPath injection | INPV-09 | XPath errors | - | OWASP WSTG |
| XXE / XInclude | INPV-07 | external entity / `xi:include` file read | - | PortSwigger XXE labs |
| NoSQL injection | INPV-05.6 | `$ne`/`$eq`/`$regex` differential, Mongo errors | - | OWASP, PortSwigger NoSQLi |

**Encoded parameter values.** Parameters whose value is base64, base64url, hex or URL-encoded (e.g.
`?data=MTAwMQ==`) are tested *inside* the decoded value and re-encoded - findings are labelled
"(inside base64-encoded value)". This fixes a common false negative rather than bypassing anything.

**When variants run** (keeps them fast and quiet): never when a WAF/CDN/rate limiter answered; for
classes the parameter's meaning strongly suggests (file → LFI, URL → SSRF, redirect → open redirect,
command → command injection, first two variants only); for XSS when reflections come back HTML-escaped
(decode-order bugs, two variants); and for any plausible class once the application showed filtering
(validation errors such as "must end with .png", or dangerous characters stripped from an echo).

### Automatic tamper chains (application input filters)

When the basic SQL injection tests fail **and the application itself** reacts like an input blacklist
(HTTP 400/422 or "invalid characters"-style messages from the app), the SQLi check re-runs its error- and
boolean-based tests through sqlmap-style tamper chains: `space2comment`, `randomcase`, `space2tab`,
`space2newline`, `equaltolike`, `symboliclogical`, `versioned`, `between`, `charencode`. A hit is reported
as e.g. *"SQL injection (boolean-based blind) - input filter bypassed with tamper space2comment"* because a
defeatable blacklist is itself the vulnerability. Tamper chains are never used when a WAF / CDN challenge
/ rate limiter answered (those inputs stay NOT TESTED, see WAF policy). Use `--tamper a,b` to force a chain.

### Web server configuration and TLS audit

Runs in the configuration stage (checks `server` and `tls`; select with `--checks server,tls`). Every
probe is read-only: ordinary GET/OPTIONS requests and TLS handshakes. Nothing is uploaded, changed or
executed.

| Area | What is checked | WSTG |
|---|---|---|
| Software inventory | product and version from `Server` / `X-Powered-By` / `X-Jenkins` / `kbn-version` headers, generator tags, footers and error pages (Apache, nginx, IIS, PHP, OpenSSL, Tomcat, WordPress, Drupal, Joomla, Confluence, Jira, Grafana, TeamCity, ...) matched against the CVE / end-of-life knowledge base (`webguard/data/cve/`, ~95 CVEs, KEV and RCE flagged) | INFO-02, CONF-01/02 |
| Directory listing | root, common directories and every directory seen while crawling; MEDIUM when backups, keys or configs are listed | CONF-02 |
| Default pages | Apache / nginx / IIS / Tomcat / lighttpd / Caddy install pages | CONF-02 |
| Admin & debug consoles | Tomcat Manager, phpMyAdmin, Adminer, JBoss consoles, Werkzeug debugger, Symfony profiler, Solr, Druid, unfinished WordPress installer; login page = LOW, open console = HIGH | CONF-05 |
| HTTP methods | write / WebDAV methods advertised in `OPTIONS` (reported, never exercised) | CONF-06 |
| TLS protocols & ciphers | TLS 1.0 / 1.1 accepted; NULL, anonymous, EXPORT, RC4, 3DES and static-RSA suites accepted | CRYP-01 |
| Certificate | expired / not yet valid / expiring within 30 days, self-signed, untrusted or incomplete chain, host name mismatch, RSA < 2048 bits, SHA-1 / MD5 signature | CRYP-01 |
| HTTPS enforcement | plain-HTTP access without redirect; HSTS max-age under 180 days | CONF-07 |

Version-based CVE matches are *potential* findings (FIRM confidence at most). When the banner carries a
distribution patch tag (`Ubuntu`, `deb`, `el8`, ...) confidence drops to TENTATIVE, because distributions
back-port fixes without changing the upstream version. Only TLS options the server *accepts* are
reported: if this machine's TLS library cannot offer a legacy protocol or cipher, that item is recorded
as not tested. TLS handshakes connect directly to the target, so they are skipped when `--proxy` is set
(the HSTS and redirect checks still run through the proxy). Certificate details (key size, signature)
need the optional `cryptography` package.

### Targets

`scan` and `assess` accept any number of targets as arguments and/or `-l FILE` (repeatable):
URLs, domains (probed on https and http), IPv4/IPv6 addresses, `host:port`, CIDR ranges (up to 1024
hosts each), comma-separated lists, and `@file`. Files take one target per line with `#` comments.
Duplicates are removed and invalid entries are reported without stopping the run.

```bash
webguard scan https://shop.example.com api.example.com 10.0.0.5:8443 10.0.1.0/28 -l more-targets.txt
webguard assess @targets.txt --profile safe
```

### Reflection-guided testing and parameter extraction

Before an input is tested, one request with a unique marker followed by `'"<` shows where the value comes
back: HTML text, attribute, script, comment, JSON, a response header or `Location`, and whether special
characters were escaped. The test plan for that input follows from it:

- reflected into markup: XSS and SSTI first
- reflected into `Location` / headers: open redirect and CRLF injection first
- not reflected: XSS is demoted (it can still be stored or second-order), or skipped for GET inputs under
  a tight budget; blind classes (SQLi, command injection, SSRF, ...) are unaffected

The reflection profile is attached to XSS / SSTI / redirect / CRLF findings. Hidden-parameter discovery
tries this site's own names first: JSON keys, form fields and `searchParams.get(...)` / `?name=` usage in
JavaScript, then the generic wordlist.

### API testing

| Test | What it shows | OWASP API Top 10 |
|---|---|---|
| Unauthenticated access | with `--cookie` / `-H Authorization`, API endpoints that returned account data are requested again without credentials; same data = no authentication | API2 / API5 |
| API version inventory | `/api/v2/...` also answering as `v1`, `v3`, `v0`, `beta`, `internal`, `dev` (extra fields raise severity) | API9 |
| Content-type confusion | a JSON write endpoint that parses form-encoded bodies too (reachable by cross-site forms, CSRF with cookie auth); requires the body to be parsed (malformed JSON must change the answer) | API8 |

These are read-only or repeat a request the application already makes. GraphQL, IDOR, mass data
exposure, JWT and OpenAPI import are covered by the existing checks.

### Fuzzing

`webguard fuzz` is an ffuf-style fuzzer inside the scanner's scope enforcement and rate control: `FUZZ` in
the URL path or query, a header (`-H`) or the body (`-d`); wordlist file or built-in `dirs`, `dirs-large`,
`params`. Filters: `-mc`/`-fc` status, `-fs` size, `-fw` words, `-fl` lines, `-fr`/`-mr` regex. Automatic
calibration filters soft-404 / catch-all responses (`--no-calibrate` to disable). `-o hits.json` saves
the results.

### Network services and fingerprint templates

`--ports` (`top` or e.g. `22,80,8000-8100`) adds a network service audit to `scan` / `assess`: TCP connect
scan, a passive banner read (SSH, FTP, SMTP, POP3/IMAP, MySQL, VNC and ActiveMQ greet first) or a single
`HEAD /` on HTTP(S) ports. No logins or protocol commands are sent. Banners are matched against service
fingerprints and the CVE / end-of-life data. Findings cover version-based CVEs (distro back-port tags
lower confidence), exposed risky services, cleartext FTP/Telnet/POP3/IMAP and version disclosure. Skipped
with `--proxy` (raw TCP would bypass it).

Fingerprint templates (`webguard/data/fingerprints/*.yml`, 77 templates) use a nuclei-style format:
`path`, `matchers` (word / regex / status / header, `and` / `or`, `negative`) and `extractors` (regex or
header with a capture group). They only **identify** products and versions from public pages, headers,
version endpoints and service greetings. Templates with `requires:` run only after a product they depend
on was detected (workflow gating). For example, the WordPress plugin templates read
`/wp-content/plugins/<slug>/readme.txt` only on WordPress sites. Results feed the CVE matcher.

The NLP models train on the built-in seed corpora plus the extension corpora in
`webguard/data/nlp/*.yml` (about 330 parameter names and 33 page samples, merged at load). A held-out
parameter-name test keeps accuracy in check.

### Out-of-band (blind) detection

`--oob` spawns an interaction server for the scan and gives every blind probe its own single-use
callback id. A background poller correlates interactions with the exact test, URL and parameter that
caused them, and keeps polling for `--oob-wait` seconds (default 10) after testing for late callbacks.

| `--oob` value | Provider |
|---|---|
| `auto` (or bare `--oob`) | public interactsh server (`oast.*`), falling back to a local listener |
| `interactsh[:server]` | interactsh (public or self-hosted with `--oob-token`); interactions are encrypted for the session (RSA-OAEP + AES), needs `cryptography` |
| `local[:ip[:port]]` | HTTP listener spawned on this machine for the scan (labs / internal networks) |
| `your.collaborator.domain` | payloads recorded for manual correlation (no polling) |

Used for **blind SSRF** (URL-like inputs whose fetch result is not shown) and **blind XXE** (XML
endpoints that resolve external entities without echoing them). An HTTP callback is CERTAIN; a DNS-only
lookup is FIRM, because resolvers and link scanners on the way can also resolve a host.

### Recursive content discovery and 403 bypass

Content discovery recurses into every directory it finds (redirect to `dir/`, listing, 401/403), up to
`--discovery-depth` levels (profile default: safe 0, standard 1, thorough 2). Each directory gets its
own soft-404 calibration, and an NLP path classifier orders the recursion (admin, backup, config and
source-control directories before static assets) and groups results by category. Every 401/403 path
it finds goes to the access-control bypass check: 27 path-normalisation and header variants
(`..;/`, `/%2e/`, `/./`, `/;/`, `%20`, case changes, encoded slashes, `X-Original-URL`, client-IP headers,
...). Dot-segment variants are sent as raw request targets so the client does not normalise them away.
With a request budget, recursion is limited and the 12 most productive variants are used.

### NLP and ML identification

- **Path classifier** (naive Bayes over path words, extension and character n-grams): admin, api, auth,
  backup, config, source_control, log, debug, upload, docs, static, other.
- **Product/version extractor** for free text (footers, about pages): context-scored. "Powered by"
  and "version" raise confidence; "requires", "upgrade to" and "or newer" reject the match. It feeds the
  CVE inventory for products the fixed patterns miss; matches below 0.8 are TENTATIVE.
- **ML triage** context features: version-only CVE match, KEV, RCE, distribution back-port, NLP-derived
  version, OOB protocol, re-verified, filter bypass, encoded value, path category. Priors penalise
  banner-only CVE matches and favour OOB HTTP callbacks and re-verified findings.

### Resilience

Per-host adaptive rate control (AIMD: halve on 429/503/timeouts, recover gradually), `Retry-After`
(seconds or HTTP date) honoured, jittered exponential retries for transient failures only, latency-based
adaptive timeouts, and a circuit breaker that pauses unhealthy hosts and fails fast on dead ones. Error
kinds (DNS, TLS, refused, timeouts, resets, protocol) and every rate adjustment appear in the report.

**Dynamic rate limiting** - the scanner slows down to respect the target's limits:

- **Declared limits** - `RateLimit` / `RateLimit-Policy` (IETF draft, both the combined and the
  `r=`/`t=`/`q=` forms), `RateLimit-*`, `X-RateLimit-*` and `X-Rate-Limit-*` headers (reset as seconds
  or epoch) are read on every response. When the quota runs low the rate is set to spend what is left
  evenly over the rest of the window (20% headroom) and capped until the window resets. When the quota
  is exhausted, the **whole host pauses** until the reset.
- **429 / soft limits** - on a 429, or a short 403/503/200 page saying "too many requests" or "rate
  limit exceeded", the rate is halved and the host pauses for `Retry-After` (or exponential backoff),
  then the request is retried. Ordinary pages that merely mention "slow down" are not treated as limits.
- **Latency backoff** - if response times climb well above the best observed latency (server under
  load), the rate is reduced (at most once every 10 s).
- Pauses, the declared policy and each adjustment are listed under *test conditions* in the report.

This is about being a good guest on the target, not about evading limits: nothing rotates IPs or
identities.

### Profiles

| `--profile` | Use | Behaviour |
|---|---|---|
| `safe` | production | ≤ 5 req/s, 5 concurrent, no time-based payloads, no anomaly fuzzing |
| `standard` (default) | most engagements | balanced |
| `thorough` | lab / staging | hidden-parameter discovery, full 4.6k-path content discovery |

### PoC screenshots

After a scan, WebGuard captures evidence for every MEDIUM+ finding in headless Chromium (scope-locked:
every request and **every redirect hop** is checked; background browser traffic is disabled):

| Kind | When | What the image shows |
|---|---|---|
| `browser-execution` | reflected XSS, DOM XSS, prototype pollution | the page after loading an executing PoC (`alert(document.domain)` adapted to the confirmed context); the red banner is added only if execution was actually observed |
| `live-response` | GET-reproducible server-side findings (SQL errors, file reads, SSTI, command output, exposures) | the real response with the evidence string highlighted |
| `http-evidence` | POST/JSON/header-based findings | the exact HTTP request/response pair (the recorded non-destructive request is replayed if needed) |

Images are embedded in the HTML report, linked from the Markdown submissions and saved under
`<output>/poc/`. Disable with `--no-screenshots`.

Screenshots are clean evidence: banners state only what was observed and when (no tool branding).
Before capture, **personal data on the page is blurred**: e-mail addresses, phone numbers, names,
postal addresses, dates of birth, national IDs, Luhn-valid card numbers, IBANs / bank details, and
personal form fields (by type, `autocomplete` or field name). Technical evidence (tokens, hashes, keys,
headers, payloads) stays visible because it is the proof. Field names stay readable.

---

## AI / LLM reasoning engines

| Engine | Use | How |
|---|---|---|
| `local` (default) | Deterministic, offline | Expected-value ranking from NLP parameter/page priors, technology priors (PHP→LFI, Express→NoSQLi, Flask→SSTI, Java→XXE…), knowledge-base facts and cost |
| `claude` | Strongest planning and report writing | Official `anthropic` SDK, default model `claude-opus-5-5`, JSON-schema structured output, server-side refusal fallback (`fallbacks="default"`), `--llm-effort` |
| `ollama[:model]` | Air-gapped engagements | Any local model via Ollama `/api/chat` with JSON-schema output |

Guardrails: the LLM only **chooses and orders** pre-built, non-destructive tests from the candidate
list - ids it invents are discarded - and all traffic still passes the scope guard. Any error,
timeout, refusal or invalid output falls back to the local reasoner for that step (recorded in the
trace). LLMs also write the executive summary, key risks and next steps (grounded in the findings;
the local NLP narrative is used otherwise), and `webguard ask --llm claude "..."` answers free-form
questions about results.

---

## NLP and machine learning

- **Parameter semantics classifier** (naive Bayes over char n-grams + identifier tokens): `returnUrl` →
  redirect, `imgPath` → file, `cmd`/`host` → command, `q` → search, … mapped to the bug classes a tester
  would try first. Value shape refines it (URL-looking → SSRF/redirect, numeric → SQLi/IDOR).
- **Page classifier**: login, registration, password reset, admin, error, stack trace, WAF block,
  not-found, API JSON, docs, upload, search, directory listing, default page, content.
- **Natural-language queries**: `"high sql injection on api"`, `"everything high except xss"`,
  `"critical or high cross-site scripting with certain confidence"`.
- **Narrative generation**: executive and technical summaries from findings and chains.
- **Anomaly detection**: IsolationForest (scikit-learn) + robust z-scores over 14 response features.
- **Triage model**: logistic regression trained on *your* tp/fp labels (`webguard db label`, `webguard ml train`).

---

## Grep, analysis and natural-language queries

Every response a scan sees is stored (compressed) in the SQLite database, so you can keep hunting
after the scan:

```bash
webguard grep 12 --pack dom-sinks                    # innerHTML, bypassSecurityTrust*, eval(location...)
webguard grep 12 --pack infrastructure --pack debug  # internal hosts, buckets, debug flags, TODOs
webguard grep 12 --regex 'api/v[0-9]+/admin' --in js
webguard ask "critical sql injection or authentication bypass"
webguard analyze 12                                  # root-cause issues, attack chains, reasoning trace
```

Packs: `dom-sinks`, `dom-sources`, `endpoints`, `infrastructure`, `debug`, `identity`, `versions`,
`secrets`. Hits are de-duplicated across responses and ranked (sensitive + rare first).

Analysis groups findings by **root cause** (ten XSS hits from one template = one issue), scores risk
(severity × confidence × ML true-positive probability × breadth, plus a CVSS 3.1 base vector per
class) and detects **attack chains**, e.g. *XSS + session cookie without HttpOnly → account
takeover*, *cracked JWT secret → privilege escalation*, *exposed MD5 hashes → credential compromise*,
*open redirect + OAuth → token theft*, *host header injection on reset page → password reset poisoning*.

---

## Bug bounty and red-team workflows

```bash
# Bug bounty: recon → rank assets → active scan of the top subdomains in parallel → nuclei → ML triage
# → PoC screenshots → submission drafts. The --rate budget is split across the parallel hosts.
webguard hunt example.com --scope program.yml -H "X-Bug-Bounty: yourhandle" --content-discovery \
    --parallel-hosts 4 --rate 20

# Continuous monitoring: run on a schedule, look only at what's new
webguard db new example.com

# Red team: subdomains, ports/services, takeover, ranked attack surface, MITRE ATT&CK mapping
webguard surface example.com --scope engagement.yml

# Recon only (no traffic to the target with --passive)
webguard recon example.com --passive
```

Integrations (used when installed): subfinder, assetfinder, amass, gau, waybackurls, katana, nuclei,
nmap, ffuf; sqlmap/dalfox hand-off commands are generated in reports. Recon sources: crt.sh,
AlienVault OTX, Wayback CDX.

Scope files (`examples/scope.yml`): hosts, `.domain` (apex+subs), `*.wildcards`, CIDRs, regex, URL
prefixes, excludes and a path deny-list (`/logout`, `/delete`, …).

---

## Reports

`-f json,html,sarif,md` (default `json,html,md`):

- **HTML** - executive summary, key risks, next steps, attack chains, root-cause issues with CVSS,
  **test conditions** (environment, defences detected, NOT-TESTED inputs, network errors, adaptive rate
  changes, JS-analysis summary), WSTG coverage matrix, reasoning trace (technical style), and findings filterable by
  text, severity and "verified only". Each finding shows its **context** (environment, page type, WAF,
  verification status, review notes) and, for re-verified findings, the **exact HTTP request/response**
  (excerpt centred on the payload). Every value is escaped (payloads are attacker strings).
- **Markdown** - bug-bounty-ready submissions: summary, steps to reproduce (curl / browser link),
  HTTP request/response evidence, verification/environment notes, impact, remediation, references,
  sqlmap/dalfox follow-ups.
- **SARIF 2.1.0** - GitHub code scanning / CI. `scan`, `assess` and `hunt` exit with `2` when a
  HIGH/CRITICAL finding exists, so they can gate pipelines.
- **JSON** - findings, summary and assessment metadata (trace, facts and OOB tokens in technical style).

**Report style and hygiene**

| Option | Effect |
|---|---|
| `--report-style client` (default) | deliverable for the client / programme: no tool branding, ML scores, reasoning trace, raw stats or internal review notes |
| `--report-style technical` | everything, including the reasoning trace, ML triage scores, reasoner, grep highlights and tool metadata |
| `--report-author "ACME Security"` | "prepared by" line in the header (and SARIF driver name in client style) |
| `--report-title "…"` | report title (default "Security Assessment Report") |
| `--no-redact` | keep personal data unmasked (default: mask) |

By default every report format **masks personal information only**:

| Masked (personal) | Example | Not masked (technical evidence) |
|---|---|---|
| e-mail, phone | `a***@example.com`, `***-***1` | URLs, parameters, payloads |
| names, postal address, date of birth (`firstName`, `address`, `dob`, ... fields) | `"lastName":"[redacted]"` | hashes, JWTs, API keys, cookies, headers |
| card numbers (Luhn), IBAN, account / routing numbers, CVV | `**** **** **** 4242`, `DE** **** 3000` | IPs, hostnames, versions, dates |
| SSN, passport, national / tax ID | `***-**-****` | fingerprints, CWE / OWASP references |

**Recon results are never masked**: recon-phase findings and the recon inventory (hosts, titles,
technologies, URLs) are reported exactly as collected. Only the assessment findings and the narrative
are masked. **Terminal output is never masked**: it is the tester's own console.

---

## Benchmarks

Measured in this repository's CI-equivalent environment (Python 3.13, local Docker), using the
local reasoner. Reproduce with `python benchmarks/juice_shop.py` and `pytest`.

**OWASP Juice Shop** (third-party, `bkimminich/juice-shop:latest`) - ground truth = 16 documented
vulnerabilities reachable without an account in classes WebGuard tests (see
`benchmarks/juice_shop.py`):

| Run | Ground truth found | Requests | Time | MEDIUM+ findings outside ground truth |
|---|---|---|---|---|
| `assess`, no budget | **15 / 15** | 5,718 | 235 s | 0 |
| `assess --budget-requests 2000` | 13 / 15 | 2,029 | 181 s | 0 |
| `assess --budget-requests 1000` | 12 / 15 (all critical/high found) | 1,141 | 161 s | 0 |
| v2 scanner (before the agent) | 3 / 15 (metrics, headers, the leaked hashes - reported as 5 separate "generic password" secrets); only 3 injectable inputs mapped | 440 | 11 s | 0 |

The full run is ~40% more requests than the previous release (3,715) because it now also tests header/cookie
injection, JS source maps and chunks, cache deception and prototype pollution; with a 2,000-request budget
those extra tests cost two ground-truth items (13/15 vs 15/15 before) - a deliberate breadth/budget trade-off.
Beyond the list, the run also found password hashes in `/support/logs/audit.json` (reached via content
discovery) and real directory listings under `/.well-known`.

Found: login SQLi auth bypass, product-search SQLi, DOM XSS (`#/search?q`, verified in Chromium),
open-redirect allow-list bypass, `/ftp` listing, `/metrics`, password hashes in `/rest/memories`, Swagger
docs, CORS `*`, verbose errors, password hash inside the issued JWT, unlinked `/encryptionkeys` and
`/support/logs` (content discovery), anonymous admin configuration API, missing hardening headers.
The agent also detected Juice Shop's rate limiting and halved its request rate automatically.

Caveats, stated plainly: the ground-truth list was written by us and several detection fixes were made
while studying this same target (see the git history), so this is a development benchmark, not a blind
evaluation. Authenticated-only Juice Shop vulnerabilities are out of scope for an anonymous run (the
agent lists those endpoints as a coverage gap). The order-tracking XSS is excluded because the container
build strips `<`/`>` from that input (verified manually). Run your own targets before trusting numbers.
The Claude/Ollama engines were exercised against a mocked SDK / unreachable server in tests only (no API
key in the build environment); the numbers above use the local reasoner.

**Built-in vulnerable app** (`tests/vulnapp.py`) - 45 vulnerable test cases across 27 finding classes
(including header/cookie injection, source maps, cache deception, OAuth, prototype pollution, PortSwigger-
style input filters defeated by encoding variants, a base64-encoded parameter, LDAP/XPath/XInclude and a
simulated Cloudflare-style WAF), with 29 *safe twins* that must not be reported. Full assessment: all
detected, 0 false positives on the safe twins, WAF-blocked inputs reported as NOT TESTED, every injection
finding independently re-verified with HTTP evidence attached.

Budget-aware planning on the same app (high/critical finding classes found, out of the 16 a full run finds):

| Request budget | Requests used | High/critical classes found |
|---|---|---|
| 400 | 435 | 9 / 16 |
| 1,000 | 968 | 12 / 16 |
| unlimited | 6,723 | 16 / 16 |

Planning matters: on Juice Shop with a 1,000-request budget, recall went from 7/15 to 12/15 by fixing
budget allocation (shares apply after mapping), ranking by expected value per request, discounting
guessed API bodies vs. inputs observed to respond, treating 401 vs 403 differently and adding
diminishing returns for repeated test types - all visible in the reasoning trace.

---

## Command reference

| Command | Purpose |
|---|---|
| `webguard assess <url>` | Autonomous methodology-driven assessment (`--llm`, `--budget-*`, `--show-trace`, `--no-browser`) |
| `webguard scan <url>...` | Exhaustive scan with the same engine (`-l targets.txt`) |
| `webguard recon <domain>` | Subdomains, DNS, live hosts, takeover, historical URLs (`--passive`) |
| `webguard hunt <domain>` | Bug bounty pipeline: active scan of subdomains in parallel (`--parallel-hosts`, `--max-hosts`, `--content-discovery`, `--no-nuclei`) |
| `webguard surface <domain>` | Red-team external attack surface + ATT&CK mapping |
| `webguard grep <scan-id>` | Pattern packs / regex over stored responses |
| `webguard ask "<question>"` | Natural-language query over findings (`--llm claude` for free-form answers) |
| `webguard analyze <scan-id>` | Root-cause issues, attack chains, reasoning trace |
| `webguard report <scan-id>` | Re-generate reports from the database |
| `webguard db scans\|findings\|assets\|new\|label` | Query history, label tp/fp |
| `webguard ml train\|status` | Train / inspect the triage model |
| `webguard tools` | External tools and signature database status |
| `webguard fuzz <url-with-FUZZ> -w <wordlist>` | ffuf-style fuzzing (URL, header or body), filters and auto-calibration |
| `webguard wizard` (or `webguard --wizard`) | Guided mode: plain-language questions, prints the equivalent command, then runs it |

Common options: `--profile safe|standard|thorough`, `--scope`, `--subdomains`, `-H`, `--cookie`, `--proxy`, `--rate`, `-c`, `--timeout`,
`--depth`, `--max-urls`, `--checks`/`--skip`, `--no-timing`, `--time-delay`, `--param-discovery`,
`--oob`, `--tamper`, `--signatures`, `--wordlist`, `--no-discovery`, `--no-screenshots`, `-o`, `-f`, `--db`,
`--report-style client|technical`, `--report-author`, `--report-title`, `--no-redact`, `--model`,
`-v 0-6`, `--no-color`, `--no-progress`, `--fresh`, `--session-dir`, `--ports`, `--discovery-depth`,
`--oob`, `--oob-token`, `--oob-wait`, `-l FILE` (repeatable).

Legacy entry points `python3 webguard.py -d example.com -m passive|active|vulnerability` and
`python3 scanner.py -d …` still work (translated to the commands above).

---

## Architecture

```
webguard/
  cli.py                 command line, help examples, guided wizard
  ui.py                  console: colours, stages, live progress, -v 0-6 payload/HTTP tracing
  session.py             save progress and resume interrupted scans
  engine.py              `scan` = agent in exhaustive mode
  assessment/            agent.py (plan→act→observe→verify loop, knowledge base, budget, adaptation)
                         methodology.py (phases, WSTG mapping, rules of engagement)
  ai/reasoner.py         Local / Claude / Ollama reasoning engines with guardrails + fallback
  nlp/                   tokenizer, naive Bayes, page & parameter classifiers, NL query, narratives
  analysis/              grep packs, root-cause clustering, attack chains, CVSS/risk
  detection/             baseline & similarity, anomaly ML, request context, tamper
    checks/              server.py (server config audit), tls.py (TLS audit),
                         sqli, xss, server_side (ssti/lfi/cmdi/ssrf), client_side (redirect/crlf),
                         advanced (xxe/nosqli/auth/host-header/403/idor/graphql), analyzers (jwt/csrf/
                         data exposure/deserialization/sri), dom (headless Chromium), host, passive, hunting
  crawler.py             async scope-aware crawler + JS tokenizer/endpoint miner
  http.py                httpx engine: scope guard, token-bucket rate limit, retries, stats, safe redirects
  recon/                 passive sources, probing/fingerprinting/takeover/ports, OpenAPI import, tool integrations
  workflows/             recon, hunt (bug bounty), redteam (attack surface + ATT&CK)
  db.py                  SQLite: scans, assets (first/last seen), findings, labels, responses, trace
  ml/triage.py           logistic-regression triage model
  reporting/             JSON, HTML, SARIF, Markdown · client/technical styles · redact.py (PII/secret masking, screenshot blur) · poc.py
  data/                  signatures/*.json (SQL errors, tech, WAF, secrets, exposures, takeover,
                         disclosure) · wordlists (quick, common, params)
```

Extend detection without code: drop JSON files into a directory and pass `--signatures DIR` (or set
`WEBGUARD_SIGNATURES`); same-named entries override the built-ins.

---

## Development

```bash
pip install -e ".[all,dev]"
pytest -q                       # 198 tests: e2e detection + safe twins, server/TLS audit, resilience/rate limits, context, agent, reporting/redaction, console/resume, NLP, CLI
ruff check webguard tests
python tests/vulnapp.py         # run the vulnerable test app locally
python benchmarks/juice_shop.py # benchmark against a running Juice Shop
```

## License

GPL-3.0 - see [LICENSE](LICENSE).
