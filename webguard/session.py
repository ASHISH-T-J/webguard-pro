"""Scan sessions: save progress and resume where a scan left off (like sqlmap's session files).

A session is a small JSON file per (target, mode, test selection). It is written after every round of
tests and when a scan is interrupted (Ctrl+C, crash, budget). Re-running the same command resumes:

* the application is mapped again (fast, and the site may have changed),
* every test that already completed is skipped,
* findings already confirmed are restored (and re-verified in the verification stage).

A finished scan deletes its session. ``--fresh`` ignores and replaces an existing session.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from webguard.models import Finding

VERSION = 1


@dataclass
class Session:
    path: Path
    target: str
    mode: str
    done: set[str] = field(default_factory=set)
    findings: list[dict] = field(default_factory=list)
    stage: str = ""
    requests: int = 0
    created: float = field(default_factory=time.time)
    updated: float = 0.0
    resumed: bool = False

    @staticmethod
    def key(target: str, mode: str, selection: str = "") -> str:
        norm = target.strip().rstrip("/").lower()
        return hashlib.sha1(f"{norm}|{mode}|{selection}".encode()).hexdigest()[:16]

    @classmethod
    def open(cls, directory: Path, target: str, mode: str, selection: str = "", fresh: bool = False) -> Session:
        """Load the unfinished session for this scan, or start a new one."""
        directory = Path(directory)
        host = "".join(ch if ch.isalnum() or ch in ".-" else "_"
                       for ch in target.strip().rstrip("/").split("://")[-1])[:60]
        path = directory / f"{host}-{mode}-{cls.key(target, mode, selection)}.json"
        if fresh or not path.exists():
            return cls(path, target, mode)
        try:
            data = json.loads(path.read_text())
            if data.get("version") != VERSION:
                raise ValueError("old session format")
        except (OSError, ValueError):
            return cls(path, target, mode)
        return cls(path, target, mode, done=set(data.get("done", [])), findings=data.get("findings", []),
                   stage=data.get("stage", ""), requests=int(data.get("requests", 0)),
                   created=data.get("created", time.time()), updated=data.get("updated", 0.0), resumed=True)

    def restored_findings(self) -> list[Finding]:
        out = []
        for d in self.findings:
            try:
                out.append(Finding.from_dict(d))
            except (KeyError, TypeError, ValueError):
                continue
        return out

    def save(self, done: set[str], findings: list[Finding], stage: str, requests: int) -> None:
        self.done, self.stage, self.requests = set(done), stage, requests
        self.findings = [f.to_dict() for f in findings]
        self.updated = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "version": VERSION, "target": self.target, "mode": self.mode, "created": self.created,
            "updated": self.updated, "stage": stage, "requests": requests, "done": sorted(self.done),
            "findings": self.findings}, default=str))
        os.replace(tmp, self.path)  # atomic: an interrupt never leaves a half-written session

    def finish(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def describe(self) -> str:
        age = time.strftime("%Y-%m-%d %H:%M", time.localtime(self.updated or self.created))
        return (f"{len(self.done)} test(s) already completed, {len(self.findings)} finding(s) restored, "
                f"last stage '{self.stage or '?'}', saved {age}")
