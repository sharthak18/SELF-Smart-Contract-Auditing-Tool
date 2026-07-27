"""SQLite-backed feedback store under ``~/.self-auditor/feedback.sqlite3``."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from self_tool.core import audit_log
from self_tool.core.versions import FEEDBACK_SCHEMA_VERSION
from self_tool.feedback.schema import (
    DISPOSITIONS,
    FeedbackEntry,
    content_hash,
)


def default_path() -> Path:
    base = Path(os.environ.get("SELF_DATA_DIR") or Path.home() / ".self-auditor")
    base.mkdir(parents=True, exist_ok=True)
    return base / "feedback.sqlite3"


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        fingerprint TEXT PRIMARY KEY,
        root_hint TEXT,
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_fingerprint TEXT NOT NULL,
        detector_id TEXT NOT NULL,
        semantic_fingerprint TEXT NOT NULL,
        source_hash TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        disposition TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        author TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        target_file TEXT NOT NULL DEFAULT '',
        target_line INTEGER NOT NULL DEFAULT 0,
        UNIQUE (project_fingerprint, detector_id, semantic_fingerprint,
                source_hash, rule_version, disposition)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        action TEXT NOT NULL,
        feedback_id INTEGER,
        details TEXT NOT NULL DEFAULT '{}'
    )
    """,
]


class FeedbackStore:
    """Persistent feedback store.

    A single instance holds a connection. The schema is created on
    first use. The store is safe to instantiate multiple times — each
    ``FeedbackStore(path)`` uses its own SQLite file.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._ensure_schema_version()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                yield cur
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def _init_schema(self) -> None:
        with self._cursor() as cur:
            for stmt in SCHEMA:
                cur.execute(stmt)

    def _ensure_schema_version(self) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES (?, ?)",
                ("schema_version", str(FEEDBACK_SCHEMA_VERSION)),
            )

    def _record_event(self, action: str, feedback_id: Optional[int], details: dict) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO events(ts, action, feedback_id, details) "
                "VALUES (?, ?, ?, ?)",
                (time.time(), action, feedback_id, json.dumps(details, sort_keys=True)),
            )

    def add(
        self,
        *,
        project_fingerprint: str,
        detector_id: str,
        semantic_fingerprint: str,
        source_hash: str,
        rule_version: str,
        disposition: str,
        reason: str = "",
        author: str = "",
        target_file: str = "",
        target_line: int = 0,
    ) -> int:
        if disposition not in DISPOSITIONS:
            raise ValueError(f"unknown disposition {disposition!r}")
        now = time.time()
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO projects(fingerprint, root_hint, created_at) "
                "VALUES (?, '', ?)",
                (project_fingerprint, now),
            )
            cur.execute(
                """
                INSERT INTO feedback (
                    project_fingerprint, detector_id, semantic_fingerprint, source_hash,
                    rule_version, disposition, reason, author,
                    created_at, updated_at, active, target_file, target_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    project_fingerprint, detector_id, semantic_fingerprint, source_hash,
                    rule_version, disposition, reason, author, now, now, target_file, target_line,
                ),
            )
            new_id = cur.lastrowid
        self._record_event("feedback.add", new_id, {
            "disposition": disposition, "detector_id": detector_id,
            "project_fingerprint": project_fingerprint,
        })
        audit_log.record("feedback.add", details={
            "id": new_id, "detector_id": detector_id, "disposition": disposition,
        })
        return new_id

    def list(
        self,
        project_fingerprint: Optional[str] = None,
        include_inactive: bool = False,
    ) -> List[FeedbackEntry]:
        with self._cursor() as cur:
            if project_fingerprint is None:
                rows = cur.execute(
                    "SELECT * FROM feedback "
                    + ("" if include_inactive else "WHERE active = 1 ")
                    + "ORDER BY id"
                ).fetchall()
            else:
                rows = cur.execute(
                    "SELECT * FROM feedback WHERE project_fingerprint = ? "
                    + ("" if include_inactive else "AND active = 1 ")
                    + "ORDER BY id",
                    (project_fingerprint,),
                ).fetchall()
        return [_entry(row) for row in rows]

    def get(self, feedback_id: int) -> Optional[FeedbackEntry]:
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT * FROM feedback WHERE id = ?", (feedback_id,)
            ).fetchone()
        return _entry(row) if row else None

    def remove(self, feedback_id: int) -> bool:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE feedback SET active = 0, updated_at = ? WHERE id = ?",
                (time.time(), feedback_id),
            )
            changed = cur.rowcount
        if changed:
            self._record_event("feedback.remove", feedback_id, {})
            audit_log.record("feedback.remove", details={"id": feedback_id})
            return True
        return False

    def export_entries(self, project_fingerprint: Optional[str] = None) -> dict:
        entries = [
            entry.to_dict()
            for entry in self.list(project_fingerprint=project_fingerprint,
                                   include_inactive=True)
        ]
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "project_fingerprint": project_fingerprint,
            "entries": entries,
        }

    def import_entries(self, payload: dict, *, replace: bool = False) -> int:
        if payload.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported feedback schema version {payload.get('schema_version')}"
            )
        inserted = 0
        with self._cursor() as cur:
            for raw in payload.get("entries", []):
                self._record_event("feedback.import", None, {"hash": raw.get("id")})
                try:
                    cur.execute(
                        """
                        INSERT INTO feedback (
                            project_fingerprint, detector_id, semantic_fingerprint,
                            source_hash, rule_version, disposition, reason, author,
                            created_at, updated_at, active, target_file, target_line
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            raw["project_fingerprint"], raw["detector_id"],
                            raw["semantic_fingerprint"], raw["source_hash"],
                            raw["rule_version"], raw["disposition"],
                            raw.get("reason", ""), raw.get("author", ""),
                            raw.get("created_at", time.time()),
                            raw.get("updated_at", time.time()),
                            int(bool(raw.get("active", True))),
                            raw.get("target_file", ""),
                            int(raw.get("target_line", 0)),
                        ),
                    )
                    inserted += 1
                except sqlite3.IntegrityError as exc:
                    if not replace:
                        continue
                    cur.execute(
                        """
                        UPDATE feedback SET disposition = ?, reason = ?, updated_at = ?
                        WHERE project_fingerprint = ? AND detector_id = ?
                          AND semantic_fingerprint = ? AND source_hash = ?
                          AND rule_version = ? AND id = (
                            SELECT id FROM feedback WHERE project_fingerprint = ?
                              AND detector_id = ? AND semantic_fingerprint = ?
                              AND source_hash = ? AND rule_version = ?
                              ORDER BY id DESC LIMIT 1)
                        """,
                        (
                            raw["disposition"], raw.get("reason", ""), time.time(),
                            raw["project_fingerprint"], raw["detector_id"],
                            raw["semantic_fingerprint"], raw["source_hash"],
                            raw["rule_version"], raw["project_fingerprint"],
                            raw["detector_id"], raw["semantic_fingerprint"],
                            raw["source_hash"], raw["rule_version"],
                        ),
                    )
        audit_log.record("feedback.import", details={"inserted": inserted})
        return inserted


def _entry(row: sqlite3.Row) -> FeedbackEntry:
    return FeedbackEntry(
        id=row["id"],
        project_fingerprint=row["project_fingerprint"],
        detector_id=row["detector_id"],
        semantic_fingerprint=row["semantic_fingerprint"],
        source_hash=row["source_hash"],
        rule_version=row["rule_version"],
        disposition=row["disposition"],
        reason=row["reason"],
        author=row["author"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        active=bool(row["active"]),
        target_file=row["target_file"],
        target_line=row["target_line"],
    )
