"""Scan configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_DB = Path.home() / ".webguard" / "webguard.db"
DEFAULT_MODEL = Path.home() / ".webguard" / "triage_model.json"

ALL_CHECKS = (
    # injection (per parameter)
    "sqli", "nosqli", "xss", "ssti", "lfi", "cmdi", "redirect", "crlf", "ssrf", "ldapi", "xpathi", "xinclude",
    # endpoint / host level
    "xxe", "auth", "host_header", "access", "idor", "graphql", "cors", "headers", "exposure", "server", "tls", "cms",
    # passive analysis
    "disclosure", "secrets", "jwt", "csrf", "deserialization", "data_exposure", "js_analysis",
    # browser + hunting
    "dom_xss", "prototype_pollution", "cache_deception", "anomaly",
)


@dataclass
class ScanConfig:
    concurrency: int = 20
    rate_limit: float = 20.0  # requests per second (global)
    timeout: float = 10.0
    retries: int = 2
    max_depth: int = 3
    max_urls: int = 500
    proxy: str | None = None  # e.g. http://127.0.0.1:8080 (Burp) or socks5://127.0.0.1:9050 (Tor)
    verify_tls: bool = False
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) WebGuard/3.0 (+authorized-security-testing)"
    headers: dict[str, str] = field(default_factory=dict)  # e.g. bug bounty identification header
    cookies: dict[str, str] = field(default_factory=dict)
    checks: tuple[str, ...] = ALL_CHECKS
    time_delay: int = 5  # seconds for time-based payloads
    timing_checks: bool = True
    param_discovery: bool = False
    oob_domain: str | None = None  # legacy alias of ``oob`` (a static Collaborator/interactsh domain)
    oob: str | None = None  # auto | interactsh[:server] | local[:ip[:port]] | <domain>  (see webguard.oob)
    oob_token: str | None = None  # auth token for a self-hosted interactsh server
    oob_wait: float = 10.0  # seconds to keep polling for late interactions after testing
    tamper: tuple[str, ...] = ()
    bypass_variants: bool = True  # per-class encoding/normalisation variants against application filters
    auto_tamper: bool = True  # sqlmap-style tamper chains when an *application* input filter blocks basics
    wordlist: Path = DATA_DIR / "wordlists" / "common.txt"  # ffuf / large brute force
    discovery_wordlist: Path | None = DATA_DIR / "wordlists" / "quick.txt"  # built-in content discovery (None = off)
    history: bool = False  # seed the crawl with archived URLs (Wayback / gau) for the target host
    expand_scope: bool = False  # add hosts under the target's registrable domain found in content to the scope
    max_new_hosts: int = 10  # cap on hosts added from content discovery per assessment
    skip_phases: tuple[str, ...] = ()  # methodology phases to skip (config, identity, input, authz_client, verify)
    waf_retest: bool = True  # re-test inputs a WAF/rate limiter blocked, after a cooldown at a lower rate
    waf_cooldown: float = 15.0  # seconds to wait before the re-test pass
    ports: str | None = None  # network service audit: None = off, "top" = common ports, or "22,80,8000-8100"
    discovery_depth: int | None = None  # recursion levels below the root (None = profile default: 0/1/2)
    db_path: Path = DEFAULT_DB
    model_path: Path = DEFAULT_MODEL
    verbose: int = 0
    browser: bool = True  # headless Chromium for DOM XSS (needs playwright)

    def enabled(self, check: str) -> bool:
        return check in self.checks


PROFILES = {
    "safe": "production-friendly: <=5 req/s, 5 concurrent, no time-based payloads, no anomaly fuzzing",
    "standard": "balanced defaults",
    "thorough": "lab/staging: hidden-parameter discovery and the full content-discovery wordlist",
}


def apply_profile(cfg: ScanConfig, profile: str, explicit_wordlist: bool = False) -> ScanConfig:
    if profile == "safe":
        cfg.rate_limit = min(cfg.rate_limit, 5.0)
        cfg.concurrency = min(cfg.concurrency, 5)
        cfg.timing_checks = False
        cfg.checks = tuple(c for c in cfg.checks if c != "anomaly")
        cfg.discovery_depth = 0 if cfg.discovery_depth is None else cfg.discovery_depth
    elif profile == "thorough":
        cfg.param_discovery = True
        cfg.discovery_depth = 2 if cfg.discovery_depth is None else cfg.discovery_depth
        if not explicit_wordlist and cfg.discovery_wordlist is not None:
            cfg.discovery_wordlist = DATA_DIR / "wordlists" / "common.txt"
    elif profile == "standard":
        cfg.discovery_depth = 1 if cfg.discovery_depth is None else cfg.discovery_depth
    else:
        raise ValueError(f"unknown profile {profile!r}: {', '.join(PROFILES)}")
    return cfg
