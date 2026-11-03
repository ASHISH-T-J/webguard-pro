"""Scan configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_DB = Path.home() / ".webguard" / "webguard.db"
DEFAULT_MODEL = Path.home() / ".webguard" / "triage_model.json"

ALL_CHECKS = (
    # injection (per parameter)
    "sqli", "nosqli", "xss", "ssti", "lfi", "cmdi", "redirect", "crlf", "ssrf",
    # endpoint / host level
    "xxe", "auth", "host_header", "access", "idor", "graphql", "cors", "headers", "exposure",
    # passive analysis
    "disclosure", "secrets", "jwt", "csrf", "deserialization", "data_exposure",
    # browser + hunting
    "dom_xss", "anomaly",
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
    oob_domain: str | None = None  # interactsh/collaborator domain for blind SSRF
    tamper: tuple[str, ...] = ()
    wordlist: Path = DATA_DIR / "wordlists" / "common.txt"  # ffuf / large brute force
    discovery_wordlist: Path | None = DATA_DIR / "wordlists" / "quick.txt"  # built-in content discovery (None = off)
    db_path: Path = DEFAULT_DB
    model_path: Path = DEFAULT_MODEL
    verbose: int = 0
    browser: bool = True  # headless Chromium for DOM XSS (needs playwright)

    def enabled(self, check: str) -> bool:
        return check in self.checks
