"""Audit run history backed by SQLite.

Database lives at ``~/.cache/auditor/history.db``.  Every completed audit run
is persisted here so users can browse, re-view, and re-export any previous run
directly from the Streamlit sidebar.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_DB_PATH = Path.home() / ".cache" / "auditor" / "history.db"


# ── Connection / schema ──────────────────────────────────────────────────────


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            artifacts   TEXT    NOT NULL,   -- JSON array of artifact names
            total       INTEGER NOT NULL,
            severities  TEXT    NOT NULL,   -- JSON {"critical":1,"high":2,...}
            report_md   TEXT    NOT NULL,
            oscal_json  TEXT,               -- may be NULL for compliance-only runs
            target_key  TEXT,               -- stable id of the assessed target set
            findings_json TEXT              -- compact finding snapshot for run-to-run diff
        )
        """
    )
    # Migrate older databases that predate the lifecycle columns.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(audit_runs)")}
    for col in ("target_key", "findings_json"):
        if col not in existing:
            conn.execute(f"ALTER TABLE audit_runs ADD COLUMN {col} TEXT")
    conn.commit()


# ── Public API ───────────────────────────────────────────────────────────────


def save_run(
    artifact_names: list[str],
    total: int,
    severities: dict[str, int],
    report_md: str,
    oscal_json: str | None = None,
    target_key: str | None = None,
    findings_json: str | None = None,
) -> int:
    """Persist a completed audit run.  Returns the new row id."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO audit_runs"
            " (timestamp, artifacts, total, severities, report_md, oscal_json, target_key, findings_json)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                ts,
                json.dumps(artifact_names),
                total,
                json.dumps(severities),
                report_md,
                oscal_json,
                target_key,
                findings_json,
            ),
        )
        return cur.lastrowid  # type: ignore[return-value]


def latest_run_for_target(target_key: str) -> dict | None:
    """Return the most recent prior run that assessed the same target set.

    Used by the run-to-run remediation diff: ``findings_json`` is the snapshot we
    compare the current run against. Returns ``None`` when this is a target's
    first audit.
    """
    if not target_key:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, timestamp, findings_json FROM audit_runs"
            " WHERE target_key=? AND findings_json IS NOT NULL"
            " ORDER BY id DESC LIMIT 1",
            (target_key,),
        ).fetchone()
    return dict(row) if row else None


def list_runs(limit: int = 20, offset: int = 0) -> list[dict]:
    """Return metadata for runs ordered newest-first, optionally paginated."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, artifacts, total, severities"
            " FROM audit_runs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def count_runs() -> int:
    """Total number of audit runs persisted."""
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM audit_runs").fetchone()[0]


def clear_all() -> int:
    """Delete every audit run.  Returns the number of rows removed."""
    with _connect() as conn:
        cur = conn.execute("DELETE FROM audit_runs")
        return cur.rowcount


def get_run(run_id: int) -> dict | None:
    """Return the full record for a run, or ``None`` if not found."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM audit_runs WHERE id=?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


def delete_run(run_id: int) -> None:
    """Delete a run record permanently."""
    with _connect() as conn:
        conn.execute("DELETE FROM audit_runs WHERE id=?", (run_id,))
