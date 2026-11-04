"""CVE identification by product / version (application and web-server level).

    product + version (from headers, banners, pages, tech templates, NLP fingerprinting)
        -> knowledge base (``data/cve/*.yml``: affected ranges, CVSS, CISA KEV, RCE flag)
        -> findings, optionally confirmed by an active, non-destructive verification template

Version-only matches are reported as *potential* (FIRM confidence at most): distributions back-port
security fixes without changing the upstream version string (``OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`` is
patched for CVE-2024-6387), so a banner carrying a distro patch tag lowers confidence to TENTATIVE.
A CVE whose verification template matches is CERTAIN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from webguard.config import DATA_DIR
from webguard.models import SIGNATURE, Confidence, Finding, Severity

CVE_DIR = DATA_DIR / "cve"
PRERELEASE = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "pre": 2, "rc": 3, "cr": 3, "m": 1, "milestone": 1,
              "dev": -1, "snapshot": -1}
DISTRO_TAG = re.compile(r"(?i)ubuntu|debian|deb\d|\+deb|el\d|centos|rhel|red ?hat|fedora|amzn|suse|alpine|bpo")
VERSION_RX = re.compile(r"(?i)\d+(?:\.\d+)+(?:[a-z]\d*)?(?:[-.]?(?:alpha|beta|rc|m|milestone)\.?\d*)?|\d+[a-z]\d+|\d+")


def normalize_version(raw: str) -> str | None:
    """'Apache/2.4.49 (Unix)' -> '2.4.49'; 'OpenSSH_9.6p1 Ubuntu-3' -> '9.6p1'."""
    m = VERSION_RX.search(raw or "")
    return m.group(0).rstrip(".-") if m else None


def version_key(v: str) -> tuple:
    """Total order over real-world version strings.

    pre-releases (8.0.0-beta1, 11.0.0-M1, 2.0rc2) < release (8.0.0 == 8.0) < letter post-releases
    (OpenSSL 1.0.1f, OpenSSH 9.6p1) < the next number.
    """
    toks = re.findall(r"\d+|[a-z]+", v.lower())
    release: list[int] = []
    i = 0
    while i < len(toks) and toks[i].isdigit():
        release.append(int(toks[i]))
        i += 1
    rest = toks[i:]
    nums = tuple(int(t) for t in rest[1:] if t.isdigit())
    if not rest:
        tail: tuple = (1,)
    elif rest[0] in PRERELEASE:
        tail = (0, PRERELEASE[rest[0]], nums)
    else:
        tail = (2, rest[0], nums)
    return tuple((release + [0] * 8)[:8]), tail


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


OPS = {"==": lambda c: c == 0, "<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0,
       ">=": lambda c: c >= 0}


def in_range(version: str, spec: str) -> bool:
    """``spec``: comma-separated AND of constraints, e.g. ``>=2.4.0,<2.4.56`` or ``==2.4.49``."""
    for cons in spec.split(","):
        cons = cons.strip()
        if not cons:
            continue
        m = re.match(r"(==|<=|>=|<|>)?\s*(.+)", cons)
        op, ver = m.group(1) or "==", m.group(2)
        if not OPS[op](_cmp(version, ver)):
            return False
    return True


@dataclass
class CVE:
    id: str
    product: str
    title: str
    severity: str
    cvss: float = 0.0
    affected: list[str] = field(default_factory=list)
    fixed: str = ""
    kev: bool = False
    rce: bool = False
    year: int = 0
    template: str = ""
    description: str = ""
    references: list[str] = field(default_factory=list)
    note: str = ""

    def affects(self, version: str) -> bool:
        return any(in_range(version, spec) for spec in self.affected)


@lru_cache(maxsize=4)
def load(directory: Path = CVE_DIR) -> dict[str, list[CVE]]:
    """product -> CVEs, from every YAML file in the knowledge base directory."""
    db: dict[str, list[CVE]] = {}
    for path in sorted(Path(directory).glob("*.yml")):
        for item in yaml.safe_load(path.read_text()) or []:
            item = dict(item)
            item.setdefault("year", int(item["id"].split("-")[1]) if item["id"].startswith("CVE-") else 0)
            if isinstance(item.get("affected"), str):
                item["affected"] = [item["affected"]]
            refs = item.pop("ref", None)
            item.setdefault("references", [refs] if refs else [])
            cve = CVE(**{k: v for k, v in item.items() if k in CVE.__dataclass_fields__})
            db.setdefault(cve.product, []).append(cve)
    return db


def stats() -> dict[str, int]:
    db = load()
    every = [c for cves in db.values() for c in cves]
    return {"cves": len(every), "products": len(db), "kev": sum(c.kev for c in every),
            "rce": sum(c.rce for c in every), "since_2023": sum(c.year >= 2023 for c in every)}


def lookup(product: str, version: str | None) -> list[CVE]:
    if not version:
        return []
    v = normalize_version(version)
    if not v:
        return []
    return [c for c in load().get(product, []) if c.affects(v)]


def findings_for(product: str, version: str, url: str, source: str, banner: str = "") -> list[Finding]:
    """CVE findings for a detected product version (version-based, i.e. potential)."""
    out = []
    v = normalize_version(version) or version
    backport = bool(DISTRO_TAG.search(banner or ""))
    for c in lookup(product, v):
        sev = Severity.parse(c.severity)
        conf = Confidence.TENTATIVE if backport else Confidence.FIRM
        flags = ", ".join(x for x in ("CISA KEV" if c.kev else "", "remote code execution" if c.rce else "") if x)
        out.append(Finding(
            check=f"cve:{c.id}", title=f"{c.id}: {c.title} ({product.replace('_', ' ')} {v})", severity=sev,
            confidence=conf, url=url,
            evidence=f"{source} reports {product} {v}; affected: {' or '.join(c.affected)}"
                     + (f"; fixed in {c.fixed}" if c.fixed else "") + (f" [{flags}]" if flags else "")
                     + ("; distribution patch tag present - the fix may be back-ported" if backport else ""),
            description=(c.description or c.title) + (f" {c.note}" if c.note else "")
                        + " Detected by version: confirm the patch level before reporting.",
            remediation=f"Upgrade {product.replace('_', ' ')} to {c.fixed or 'a fixed release'} or later "
                        "(or apply the vendor patch / mitigation).",
            cwe="CWE-1395", owasp="A06:2021-Vulnerable and Outdated Components", detection=SIGNATURE,
            references=[f"https://nvd.nist.gov/vuln/detail/{c.id}", *c.references],
            tags=["cve", c.id, product] + (["kev"] if c.kev else []) + (["rce"] if c.rce else []),
            context={"cve": {"id": c.id, "cvss": c.cvss, "kev": c.kev, "rce": c.rce, "product": product,
                             "version": v, "verification_template": c.template or None}},
        ))
    return out


# end-of-life releases (no more security fixes) as of late 2026: product -> (ranges, note)
EOL: dict[str, tuple[list[str], str]] = {
    "php": (["<8.2"], "PHP 8.1 and older no longer receive security fixes (8.1 ended 31 Dec 2025)."),
    "apache_httpd": (["<2.4.0"], "Apache HTTP Server 2.2 reached end of life in 2018."),
    "openssl": (["<3.0"], "OpenSSL 1.1.1 and older reached end of life in September 2023."),
    "tomcat": (["<9.0", ">=10.0.0-M1,<10.1"], "Apache Tomcat 8.5 and 10.0 and older are end of life."),
    "drupal": (["<10"], "Drupal 7, 8 and 9 are end of life."),
    "mysql": (["<8.0"], "MySQL 5.7 and older reached end of life in October 2023."),
    "microsoft_iis": (["<10.0"], "IIS older than 10.0 ships with Windows Server releases that are out of support."),
    "jenkins": (["<2.0"], "Jenkins 1.x is end of life."),
}


def eol_finding(product: str, version: str, url: str, source: str) -> Finding | None:
    v = normalize_version(version)
    entry = EOL.get(product)
    if not v or not entry or not any(in_range(v, spec) for spec in entry[0]):
        return None
    return Finding(
        check="eol", title=f"End-of-life software: {product.replace('_', ' ')} {v}", severity=Severity.MEDIUM,
        confidence=Confidence.FIRM, url=url, evidence=f"{source} reports {product} {v}. {entry[1]}",
        description="The component no longer receives security updates; newly disclosed vulnerabilities will "
                    "stay unpatched.",
        remediation=f"Upgrade {product.replace('_', ' ')} to a supported release.",
        cwe="CWE-1104", owasp="A06:2021-Vulnerable and Outdated Components", detection=SIGNATURE,
        tags=["eol", product], context={"cve": {"product": product, "version": v}})
