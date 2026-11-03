# WebGuard Pro 2

Async web reconnaissance, vulnerability detection and hunting framework for **authorized**
penetration tests, red-team engagements and bug bounty programs.

> Only test systems you own or have explicit written permission to assess. WebGuard enforces a
> scope on every request (including redirects), but staying inside your program's rules is your
> responsibility.

## What it does

| Area | Highlights |
|---|---|
| **Engine** | `asyncio` + `httpx` with connection pooling, global token-bucket rate limiting, retries/backoff, 429 handling, HTTP/SOCKS proxy (Burp, Tor), custom headers/cookies for authenticated scans |
| **Scope** | Hosts, `.domain` (apex+subs), `*.wildcards`, CIDRs, regex, URL prefixes, excludes, path deny-list (logout/delete never requested). Redirects are followed manually and every hop is scope-checked |
| **Crawler** | Scope-aware BFS, forms (method/action/hidden values), robots.txt + sitemap seeding, JS endpoint mining, URL-pattern de-duplication |
| **Signature detection** | JSON signature DB: 120 DBMS error patterns, 65 technologies, 25 WAFs, 40 secret types (entropy-filtered), 56 sensitive files/endpoints, 28 takeover services, 17 disclosure patterns. Add your own directories with `--signatures` or `WEBGUARD_SIGNATURES` |
| **Differential / timing detection** | Multi-sample baselines that strip dynamic tokens; boolean SQLi confirmed with 2 random TRUE/FALSE pairs + junk-input control; time-based SQLi/CMDi confirmed slow → fast → slow |
| **Proof-based checks** | SQLi, context-aware XSS (confirmed by parsing the DOM, not string matching), SSTI (random arithmetic + engine fingerprint), LFI, OS command injection, SSRF (in-band + OOB tokens), open redirect, CRLF, CORS, security headers/CSP/cookies, exposures with soft-404 detection |
| **ML** | IsolationForest + robust z-score anomaly fuzzing (surfaces unknown bug classes as hunting leads); logistic-regression **triage model trained on your tp/fp labels** to score every finding |
| **Database** | SQLite inventory of scans, assets (subdomains, hosts, endpoints, params, JS, ports) and findings with first/last-seen → *new attack surface* and *new/fixed findings* between runs |
| **Recon** | crt.sh, AlienVault OTX, Wayback CDX, DNS, HTTP probing, tech + WAF fingerprinting, subdomain takeover, interesting-URL triage |
| **Integrations** | subfinder, assetfinder, amass, gau, waybackurls, katana, nuclei (results imported as findings), nmap (XML parsed), ffuf; sqlmap/dalfox hand-off commands in reports |
| **Reports** | JSON, self-contained HTML (escaped, filterable, dark mode), SARIF 2.1.0 (GitHub code scanning / CI), Markdown bug-bounty submissions with curl reproduction, impact and remediation |

## Install

```bash
pip install -e ".[all]"        # httpx, bs4, pyyaml + scikit-learn, dnspython, SOCKS support
webguard tools                 # shows which optional tools/components are available
```

Core dependencies are only `httpx`, `beautifulsoup4` and `pyyaml`; everything else degrades
gracefully (e.g. without scikit-learn the anomaly detector uses robust z-scores only).
Docker: `docker build -t webguard . && docker run --rm -v "$PWD:/reports" webguard scan https://target`.

## Usage

```bash
# Scan one application (crawl + all checks), reports in ./reports
webguard scan https://app.example.com

# Authenticated, through Burp, slower and without time-based payloads
webguard scan https://app.example.com -H "Authorization: Bearer …" --cookie session=… \
    --proxy http://127.0.0.1:8080 --rate 5 --no-timing

# Hunting extras: hidden-parameter discovery, OOB SSRF tokens, WAF-aware payload tampering
webguard scan https://app.example.com --param-discovery --oob abc123.oast.fun --tamper space2comment

# Recon only (no traffic to the target with --passive)
webguard recon example.com --passive

# Bug bounty pipeline: recon → rank assets → scan top hosts → nuclei → ML triage → reports
webguard hunt example.com --scope examples/scope.yml -H "X-Bug-Bounty: yourhandle" --content-discovery

# Red-team external attack surface: subdomains, ports/services, takeover, ATT&CK mapping
webguard surface example.com --scope examples/scope.yml
```

### Continuous hunting & ML triage

```bash
webguard db scans                       # history
webguard db new example.com             # assets first seen in the latest run + fixed findings
webguard db findings --target example.com
webguard db label 42 fp                 # teach the triage model
webguard db label 43 tp
webguard ml train                       # logistic regression on your labels (k-fold CV reported)
webguard report 7 -f html,md,sarif      # regenerate reports from the DB
```

Schedule `webguard hunt` (cron / CI) and focus on what `webguard db new` reports — new
subdomains, endpoints and parameters are where fresh bugs usually are.

### Exit codes

`scan` and `hunt` exit with `2` when a HIGH/CRITICAL finding exists, so they can gate CI
pipelines (upload the `.sarif` file to GitHub code scanning).

### Legacy entry points

`python3 webguard.py -d example.com -m passive|active|vulnerability` and `python3 scanner.py -d …`
still work and are translated to the new commands. `--tor` now maps to a real SOCKS proxy
(`socks5://127.0.0.1:9050`) — the old "simulated Tor" mode, which silently sent traffic
without anonymisation, was removed.

## How detection avoids false positives

* Every active check compares against a **baseline** of several benign requests and ignores
  dynamic content (timestamps, CSRF tokens, hashes) and reflected input (raw, HTML-escaped and
  URL-encoded forms).
* Confirmation relies on values the server must **compute or fetch** — products of random
  numbers (SSTI, command injection), file contents (LFI), remote page content (SSRF), new DOM
  nodes/attributes with random names (XSS), injected headers (CRLF).
* Patterns already present in the baseline (e.g. an SQL error on every page) are not reported.
* Exposure checks compare against a soft-404 fingerprint of the site.
* The test suite runs every check against a deliberately vulnerable app **and** a safe twin of
  each endpoint, asserting detection and zero false positives.

## Development

```bash
pip install -e ".[all,dev]"
pytest -q                 # 38 tests: e2e detection, false-positive twins, workflows, DB, ML, reports, CLI
ruff check webguard tests
python tests/vulnapp.py   # run the vulnerable test app to experiment locally
```

Project layout:

```
webguard/
  cli.py  engine.py  crawler.py  http.py  scope.py  db.py  models.py  signatures.py
  detection/  baseline.py anomaly.py context.py tamper.py checks/{sqli,xss,server_side,client_side,host,passive,hunting}.py
  recon/      passive.py active.py tools.py
  workflows/  recon.py hunt.py redteam.py
  ml/         triage.py
  reporting/  JSON / HTML / SARIF / Markdown writers
  data/       signatures/*.json  wordlists/{common,params}.txt
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
