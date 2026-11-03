"""SQLite persistence: scan history, asset inventory, findings and triage labels.

The database is what turns one-off scans into continuous hunting:

* ``assets`` keeps every subdomain/host/endpoint/parameter/JS file ever seen per target with
  first/last-seen scan ids -> "what is new since the last run" (new attack surface = new bugs).
* ``findings`` keeps every finding per scan with a stable fingerprint -> new vs. recurring
  vs. fixed issues, and analyst labels (tp/fp) that train the ML triage model.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webguard.models import Finding

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    started TEXT NOT NULL,
    finished TEXT,
    stats TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    meta TEXT DEFAULT '{}',
    first_scan INTEGER NOT NULL,
    last_scan INTEGER NOT NULL,
    UNIQUE(target, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target, kind);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    target TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    check_name TEXT NOT NULL,
    title TEXT NOT NULL,
    severity INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT,
    detection TEXT,
    ml_score REAL,
    data TEXT NOT NULL,
    UNIQUE(scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(target, fingerprint);
CREATE TABLE IF NOT EXISTS labels (
    fingerprint TEXT PRIMARY KEY,
    label TEXT NOT NULL CHECK(label IN ('tp','fp')),
    note TEXT,
    labeled_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ---------------------------------------------------------------- scans
    def start_scan(self, target: str, mode: str) -> int:
        cur = self.conn.execute("INSERT INTO scans(target, mode, started) VALUES (?,?,?)", (target, mode, _now()))
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, stats: dict[str, Any]) -> None:
        self.conn.execute("UPDATE scans SET finished=?, stats=? WHERE id=?", (_now(), json.dumps(stats), scan_id))
        self.conn.commit()

    def scans(self, target: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
        q = "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS n_findings FROM scans s"
        args: tuple = ()
        if target:
            q += " WHERE target=?"
            args = (target,)
        return self.conn.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()

    def last_scan_id(self, target: str) -> int | None:
        row = self.conn.execute("SELECT MAX(id) FROM scans WHERE target=?", (target,)).fetchone()
        return row[0] if row and row[0] is not None else None

    # ---------------------------------------------------------------- assets
    def upsert_assets(self, scan_id: int, target: str, kind: str,
                      items: Iterable[str | tuple[str, dict[str, Any]]]) -> list[str]:
        """Insert/refresh assets; returns values never seen before for this target."""
        new: list[str] = []
        for item in items:
            value, meta = (item, {}) if isinstance(item, str) else item
            cur = self.conn.execute(
                "UPDATE assets SET last_scan=?, meta=CASE WHEN ?='{}' THEN meta ELSE ? END "
                "WHERE target=? AND kind=? AND value=?",
                (scan_id, json.dumps(meta), json.dumps(meta), target, kind, value),
            )
            if cur.rowcount == 0:
                self.conn.execute(
                    "INSERT INTO assets(target, kind, value, meta, first_scan, last_scan) VALUES (?,?,?,?,?,?)",
                    (target, kind, value, json.dumps(meta), scan_id, scan_id),
                )
                new.append(value)
        self.conn.commit()
        return new

    def assets(self, target: str, kind: str | None = None) -> list[sqlite3.Row]:
        if kind:
            return self.conn.execute("SELECT * FROM assets WHERE target=? AND kind=? ORDER BY value",
                                     (target, kind)).fetchall()
        return self.conn.execute("SELECT * FROM assets WHERE target=? ORDER BY kind, value", (target,)).fetchall()

    def new_assets(self, target: str, scan_id: int) -> list[sqlite3.Row]:
        prior = self.conn.execute("SELECT COUNT(*) FROM scans WHERE target=? AND id<?", (target, scan_id)).fetchone()[0]
        if not prior:
            return []
        return self.conn.execute("SELECT * FROM assets WHERE target=? AND first_scan=? ORDER BY kind, value",
                                 (target, scan_id)).fetchall()

    # ---------------------------------------------------------------- findings
    def save_findings(self, scan_id: int, target: str, findings: Iterable[Finding]) -> list[Finding]:
        """Store findings; returns those never reported for this target in earlier scans."""
        new = []
        for f in findings:
            seen = self.conn.execute(
                "SELECT 1 FROM findings WHERE target=? AND fingerprint=? AND scan_id<? LIMIT 1",
                (target, f.fingerprint, scan_id),
            ).fetchone()
            self.conn.execute(
                "INSERT OR REPLACE INTO findings(scan_id, target, fingerprint, check_name, title, severity, confidence,"
                " url, parameter, detection, ml_score, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, target, f.fingerprint, f.check, f.title, int(f.severity), int(f.confidence), f.url,
                 f.parameter, f.detection, f.ml_score, json.dumps(f.to_dict())),
            )
            if not seen:
                new.append(f)
        self.conn.commit()
        return new

    def findings(self, scan_id: int | None = None, target: str | None = None, min_severity: int = 0) -> list[Finding]:
        q = "SELECT f.data, l.label FROM findings f LEFT JOIN labels l ON l.fingerprint=f.fingerprint WHERE severity>=?"
        args: list[Any] = [min_severity]
        if scan_id is not None:
            q += " AND scan_id=?"
            args.append(scan_id)
        if target is not None:
            q += " AND target=?"
            args.append(target)
        out = []
        for row in self.conn.execute(q + " ORDER BY severity DESC, confidence DESC", args):
            f = Finding.from_dict(json.loads(row["data"]))
            if row["label"]:
                f.tags = [*f.tags, f"label:{row['label']}"]
            out.append(f)
        return out

    def finding_rows(self, scan_id: int | None = None, target: str | None = None) -> list[sqlite3.Row]:
        q = ("SELECT f.id, f.scan_id, f.fingerprint, f.check_name, f.title, f.severity, f.confidence, f.url, "
             "f.parameter, f.ml_score, l.label FROM findings f LEFT JOIN labels l ON l.fingerprint=f.fingerprint WHERE 1=1")
        args: list[Any] = []
        if scan_id is not None:
            q += " AND f.scan_id=?"
            args.append(scan_id)
        if target is not None:
            q += " AND f.target=?"
            args.append(target)
        return self.conn.execute(q + " ORDER BY f.severity DESC, f.id", args).fetchall()

    def fixed_findings(self, target: str, scan_id: int) -> list[sqlite3.Row]:
        """Findings present in the previous scan of ``target`` but not in ``scan_id``."""
        prev = self.conn.execute("SELECT MAX(id) FROM scans WHERE target=? AND id<?", (target, scan_id)).fetchone()[0]
        if prev is None:
            return []
        return self.conn.execute(
            "SELECT * FROM findings WHERE scan_id=? AND fingerprint NOT IN (SELECT fingerprint FROM findings WHERE scan_id=?)",
            (prev, scan_id),
        ).fetchall()

    # ---------------------------------------------------------------- labels (ML training data)
    def label(self, finding_id: int, label: str, note: str = "") -> bool:
        row = self.conn.execute("SELECT fingerprint FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return False
        self.conn.execute("INSERT OR REPLACE INTO labels(fingerprint, label, note, labeled_at) VALUES (?,?,?,?)",
                          (row["fingerprint"], label, note, _now()))
        self.conn.commit()
        return True

    def labeled(self) -> list[tuple[Finding, int]]:
        rows = self.conn.execute(
            "SELECT f.data, l.label FROM labels l JOIN findings f ON f.fingerprint=l.fingerprint "
            "WHERE f.id IN (SELECT MAX(id) FROM findings GROUP BY fingerprint)"
        ).fetchall()
        return [(Finding.from_dict(json.loads(r["data"])), 1 if r["label"] == "tp" else 0) for r in rows]
