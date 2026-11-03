"""Core data models shared across the framework."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any
from urllib.parse import urlsplit


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]


class Confidence(IntEnum):
    TENTATIVE = 0  # anomaly / heuristic, needs manual verification
    FIRM = 1  # differential evidence
    CERTAIN = 2  # deterministic proof (computed canary, file contents, ...)

    @classmethod
    def parse(cls, value: str | int | Confidence) -> Confidence:
        if isinstance(value, Confidence):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]


# Detection method labels
SIGNATURE = "signature"
DIFFERENTIAL = "differential"
TIMING = "timing"
ANOMALY = "anomaly"
PASSIVE = "passive"
EXTERNAL = "external"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class InjectionPoint:
    """A single place where user input reaches the application."""

    url: str  # URL without the injected parameter's value applied
    method: str  # GET / POST
    location: str  # query | form | json | header | cookie
    name: str  # parameter name
    params: dict[str, str] = field(default_factory=dict)  # all params with original values
    source: str = "crawl"  # where it was discovered (crawl, form, js, wayback, param-discovery)

    @property
    def original(self) -> str:
        return self.params.get(self.name, "")

    @property
    def key(self) -> tuple[str, str, str, str]:
        parts = urlsplit(self.url)
        return (self.method.upper(), f"{parts.scheme}://{parts.netloc}{parts.path}", self.location, self.name)

    def with_value(self, value: str) -> dict[str, str]:
        data = dict(self.params)
        data[self.name] = value
        return data


@dataclass
class Finding:
    check: str
    title: str
    severity: Severity
    confidence: Confidence
    url: str
    method: str = "GET"
    parameter: str | None = None
    location: str | None = None
    payload: str | None = None
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    detection: str = SIGNATURE
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    request: str | None = None  # reproducible curl command
    features: dict[str, float] = field(default_factory=dict)  # numeric evidence for ML triage
    ml_score: float | None = None  # probability of true positive from triage model
    timestamp: str = field(default_factory=utcnow)

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc

    @property
    def fingerprint(self) -> str:
        """Stable identity used to de-duplicate findings across requests and scans."""
        parts = urlsplit(self.url)
        ident = "|".join(
            [self.check, parts.scheme, parts.netloc, parts.path, parts.fragment, self.location or "",
             self.parameter or "", self.title if self.check in ("exposure", "disclosure", "headers") else ""]
        )
        return hashlib.sha1(ident.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["confidence"] = self.confidence.name
        data["fingerprint"] = self.fingerprint
        data["host"] = self.host
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        data = dict(data)
        data.pop("fingerprint", None)
        data.pop("host", None)
        data.pop("id", None)
        data["severity"] = Severity.parse(data["severity"])
        data["confidence"] = Confidence.parse(data["confidence"])
        known = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Host:
    url: str
    status: int
    title: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    waf: list[str] = field(default_factory=list)
    content_length: int = 0
    ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
