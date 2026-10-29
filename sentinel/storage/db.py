"""SQLite persistence for analysis history, evidence blobs and the audit log.

All statements use bound parameters; no SQL is ever built from user input.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sentinel.core.models import AnalysisRecord, utcnow
from sentinel.core.security import redact, redact_json, sha256_bytes

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    name          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    result        TEXT,
    policy        TEXT,
    demo          INTEGER NOT NULL DEFAULT 0,
    demo_scenario TEXT,
    components    INTEGER,
    vulns         INTEGER,
    record_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE TABLE IF NOT EXISTS evidence (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    media_type  TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    content     BLOB NOT NULL,
    PRIMARY KEY (analysis_id, name)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    event       TEXT NOT NULL,
    actor       TEXT NOT NULL,
    analysis_id TEXT,
    details     TEXT
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ writes

    def save(
        self, record: AnalysisRecord, evidence: dict[str, tuple[bytes, str]], actor: str = "local"
    ) -> None:
        record_json = redact_json(record.model_dump_json())
        vulns = (
            len(record.vulnerability_scan.vulnerabilities) if record.vulnerability_scan else None
        )
        components = len(record.inventory.components) if record.inventory else None
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO analyses (id, kind, name, created_at, result, policy, demo,"
                " demo_scenario, components, vulns, record_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id,
                    record.kind,
                    record.name,
                    record.created_at.isoformat(),
                    record.decision.result.value if record.decision else None,
                    f"{record.decision.policy_name}@{record.decision.policy_version}"
                    if record.decision
                    else None,
                    int(record.demo),
                    record.demo_scenario,
                    components,
                    vulns,
                    record_json,
                ),
            )
            for name, (content, media_type) in evidence.items():
                conn.execute(
                    "INSERT OR REPLACE INTO evidence (analysis_id, name, media_type, sha256, content)"
                    " VALUES (?,?,?,?,?)",
                    (record.id, name, media_type, sha256_bytes(content), content),
                )
        self.audit(
            "analysis.saved",
            actor,
            record.id,
            {
                "kind": record.kind,
                "name": record.name,
                "result": record.decision.result.value if record.decision else None,
                "demo": record.demo,
            },
        )

    def audit(
        self, event: str, actor: str, analysis_id: str | None, details: dict[str, Any] | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, event, actor, analysis_id, details) VALUES (?,?,?,?,?)",
                (
                    utcnow().isoformat(),
                    event,
                    actor,
                    analysis_id,
                    redact(json.dumps(details or {}, default=str)),
                ),
            )

    def delete_demo_data(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM analyses WHERE demo = 1")
            count = cur.rowcount
        self.audit("demo.cleared", "local", None, {"deleted": count})
        return count

    # ------------------------------------------------------------------- reads

    def list(self, limit: int = 200, kind: str | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        query = (
            "SELECT id, kind, name, created_at, result, policy, demo, demo_scenario, "
            "components, vulns FROM analyses"
        )
        params: tuple[Any, ...] = ()
        if kind:
            query += " WHERE kind = ?"
            params = (kind,)
        query += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(query, (*params, limit)).fetchall()
        return [dict(r) for r in rows]

    def get(self, analysis_id: str) -> AnalysisRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT record_json FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        return AnalysisRecord.model_validate_json(row["record_json"]) if row else None

    def evidence_list(self, analysis_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name, media_type, sha256, length(content) AS size FROM evidence "
                "WHERE analysis_id = ? ORDER BY name",
                (analysis_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def evidence(self, analysis_id: str, name: str) -> tuple[bytes, str] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT content, media_type FROM evidence WHERE analysis_id = ? AND name = ?",
                (analysis_id, name),
            ).fetchone()
        return (bytes(row["content"]), row["media_type"]) if row else None

    def audit_entries(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)
            ).fetchall()
        return [dict(r) for r in rows]
