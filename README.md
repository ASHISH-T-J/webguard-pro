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

Core dependencies are only `httpx`, `beautifulsoup4` and `pyyaml`. Everything else is optional and
degrades gracefully: no scikit-learn → robust z-score anomaly model; no Playwright → no DOM-XSS
browser verification; no LLM → local reasoner. Docker: `docker build -t webguard . && docker run --rm
-v "$PWD:/reports" webguard assess https://target`.

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

### Automatic tamper chains (application input filters)

When the basic SQL injection tests fail **and the application itself** reacts like an input blacklist
(HTTP 400/422 or "invalid characters"-style messages from the app), the SQLi check re-runs its error- and
boolean-based tests through sqlmap-style tamper chains: `space2comment`, `randomcase`, `space2tab`,
`space2newline`, `equaltolike`, `symboliclogical`, `versioned`, `between`, `charencode`. A hit is reported
as e.g. *"SQL injection (boolean-based blind) - input filter bypassed with tamper space2comment"* because a
defeatable blacklist is itself the vulnerability. Tamper chains are never used when a WAF / CDN challenge
/ rate limiter answered (those inputs stay NOT TESTED, see WAF policy). Use `--tamper a,b` to force a chain.

### Resilience

Per-host adaptive rate control (AIMD: halve on 429/503/timeouts, recover gradually), `Retry-After`
(seconds or HTTP date) honoured, jittered exponential retries for transient failures only, latency-based
adaptive timeouts, and a circuit breaker that pauses unhealthy hosts and fails fast on dead ones. Error
kinds (DNS, TLS, refused, timeouts, resets, protocol) and every rate adjustment appear in the report.

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
  changes, JS-analysis summary), WSTG coverage matrix, full reasoning trace, and findings filterable by
  text, severity and "verified only". Each finding shows its **context** (environment, page type, WAF,
  verification status, review notes) and, for re-verified findings, the **exact HTTP request/response**
  (excerpt centred on the payload). Every value is escaped (payloads are attacker strings).
- **Markdown** - bug-bounty-ready submissions: summary, steps to reproduce (curl / browser link),
  HTTP request/response evidence, verification/environment notes, impact, remediation, references,
  sqlmap/dalfox follow-ups.
- **SARIF 2.1.0** - GitHub code scanning / CI. `scan`, `assess` and `hunt` exit with `2` when a
  HIGH/CRITICAL finding exists, so they can gate pipelines.
- **JSON** - everything, including trace, facts, coverage and OOB tokens.

---

## Benchmarks

Measured in this repository's CI-equivalent environment (Python 3.13, local Docker), using the
local reasoner. Reproduce with `python benchmarks/juice_shop.py` and `pytest`.

**OWASP Juice Shop** (third-party, `bkimminich/juice-shop:latest`) - ground truth = 16 documented
vulnerabilities reachable without an account in classes WebGuard tests (see
`benchmarks/juice_shop.py`):

| Run | Ground truth found | Requests | Time | MEDIUM+ findings outside ground truth |
|---|---|---|---|---|
| `assess`, no budget | **15 / 15** | 5,248 | 239 s | 0 |
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

**Built-in vulnerable app** (`tests/vulnapp.py`) - 34 vulnerable test cases across 24 finding classes
(including header/cookie injection, source maps, cache deception, OAuth, prototype pollution and a
simulated Cloudflare-style WAF), with 20 *safe twins* that must not be reported. Full assessment: all
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
| `webguard wizard` | Interactive guided mode |

Common options: `--profile safe|standard|thorough`, `--scope`, `--subdomains`, `-H`, `--cookie`, `--proxy`, `--rate`, `-c`, `--timeout`,
`--depth`, `--max-urls`, `--checks`/`--skip`, `--no-timing`, `--time-delay`, `--param-discovery`,
`--oob`, `--tamper`, `--signatures`, `--wordlist`, `--no-discovery`, `--no-screenshots`, `-o`, `-f`, `--db`,
`--model`, `-v`.

Legacy entry points `python3 webguard.py -d example.com -m passive|active|vulnerability` and
`python3 scanner.py -d …` still work (translated to the commands above).

---

## Architecture

```
webguard/
  cli.py                 command line
  engine.py              `scan` = agent in exhaustive mode
  assessment/            agent.py (plan→act→observe→verify loop, knowledge base, budget, adaptation)
                         methodology.py (phases, WSTG mapping, rules of engagement)
  ai/reasoner.py         Local / Claude / Ollama reasoning engines with guardrails + fallback
  nlp/                   tokenizer, naive Bayes, page & parameter classifiers, NL query, narratives
  analysis/              grep packs, root-cause clustering, attack chains, CVSS/risk
  detection/             baseline & similarity, anomaly ML, request context, tamper
    checks/              sqli, xss, server_side (ssti/lfi/cmdi/ssrf), client_side (redirect/crlf),
                         advanced (xxe/nosqli/auth/host-header/403/idor/graphql), analyzers (jwt/csrf/
                         data exposure/deserialization/sri), dom (headless Chromium), host, passive, hunting
  crawler.py             async scope-aware crawler + JS tokenizer/endpoint miner
  http.py                httpx engine: scope guard, token-bucket rate limit, retries, stats, safe redirects
  recon/                 passive sources, probing/fingerprinting/takeover/ports, OpenAPI import, tool integrations
  workflows/             recon, hunt (bug bounty), redteam (attack surface + ATT&CK)
  db.py                  SQLite: scans, assets (first/last seen), findings, labels, responses, trace
  ml/triage.py           logistic-regression triage model
  reporting/             JSON, HTML, SARIF, Markdown
  data/                  signatures/*.json (SQL errors, tech, WAF, secrets, exposures, takeover,
                         disclosure) · wordlists (quick, common, params)
```

Extend detection without code: drop JSON files into a directory and pass `--signatures DIR` (or set
`WEBGUARD_SIGNATURES`); same-named entries override the built-ins.

---

## Development

```bash
pip install -e ".[all,dev]"
pytest -q                       # 128 tests: e2e detection + safe twins, resilience, context, agent, budget, NLP, reasoners, CLI
ruff check webguard tests
python tests/vulnapp.py         # run the vulnerable test app locally
python benchmarks/juice_shop.py # benchmark against a running Juice Shop
```

## License

GPL-3.0 - see [LICENSE](LICENSE).
