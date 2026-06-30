"""Finding suppression / accepted-risk register — the triage layer.

Real assessment is iterative: a professional reviews findings and dispositions
some as **false positives** or **accepted risks** (with a reason, an owner, and
often an expiry). Those shouldn't keep dominating every subsequent report, but
they must remain *visible and auditable* — not silently dropped.

This module persists those dispositions (SQLite, like :mod:`auditor.history`)
keyed by the same finding *fingerprint* the run-to-run diff uses
(:func:`auditor.diff.fingerprint`), so "the same finding" is suppressed exactly
the way it is matched across runs. A suppression may be scoped to one target
(``target_key``) or global (``target_key is None``), and may expire.

The graph stays pure: :func:`apply_suppressions` is a pure split over a list of
suppression *records*. The UI layer (``app.py``) loads the active records for a
target and threads them into the graph state; the reporting node renders the
suppressed set in its own section.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from auditor.diff import fingerprint
from auditor.models import Finding

_DB_PATH = Path.home() / ".cache" / "auditor" / "suppressions.db"

SuppressionKind = Literal["accepted-risk", "false-positive"]
_KINDS: tuple[str, ...] = ("accepted-risk", "false-positive")


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
        CREATE TABLE IF NOT EXISTS suppressions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT    NOT NULL,
            target_key  TEXT,                 -- NULL = global (all targets)
            kind        TEXT    NOT NULL,      -- accepted-risk | false-positive
            reason      TEXT    NOT NULL,
            title       TEXT,                  -- finding title at suppression time (for display)
            created_at  TEXT    NOT NULL,
            expires_at  TEXT,                  -- NULL = never expires
            created_by  TEXT
        )
        """
    )
    conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Public API ───────────────────────────────────────────────────────────────


def add_suppression(
    finding: Finding,
    kind: SuppressionKind,
    reason: str,
    target_key: str | None = None,
    expires_at: str | None = None,
    created_by: str | None = None,
) -> int:
    """Record a disposition for *finding*. Returns the new row id."""
    if kind not in _KINDS:
        raise ValueError(f"kind must be one of {_KINDS}, got {kind!r}")
    if not (reason or "").strip():
        raise ValueError("a reason is required to suppress a finding")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO suppressions"
            " (fingerprint, target_key, kind, reason, title, created_at, expires_at, created_by)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                fingerprint(finding),
                target_key,
                kind,
                reason.strip(),
                finding.title,
                _now(),
                expires_at,
                created_by,
            ),
        )
        return cur.lastrowid  # type: ignore[return-value]


def list_suppressions(target_key: str | None = None, include_global: bool = True) -> list[dict]:
    """List suppressions. With *target_key*, returns that target's rows (plus
    global rows when *include_global*); without one, returns every row."""
    with _connect() as conn:
        if target_key is None:
            rows = conn.execute("SELECT * FROM suppressions ORDER BY id DESC").fetchall()
        elif include_global:
            rows = conn.execute(
                "SELECT * FROM suppressions WHERE target_key = ? OR target_key IS NULL"
                " ORDER BY id DESC",
                (target_key,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM suppressions WHERE target_key = ? ORDER BY id DESC",
                (target_key,),
            ).fetchall()
    return [dict(r) for r in rows]


def active_records(target_key: str | None = None) -> list[dict]:
    """The currently-effective suppressions for a target (non-expired, global +
    target-scoped). These are what the graph applies."""
    now = _now()
    return [
        r
        for r in list_suppressions(target_key)
        if not r.get("expires_at") or r["expires_at"] > now
    ]


def delete_suppression(suppression_id: int) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
        conn.commit()


def clear_all() -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM suppressions")
        conn.commit()


def apply_suppressions(
    findings: list[Finding], records: list[dict]
) -> tuple[list[Finding], list[dict]]:
    """Split *findings* into (active, suppressed) using suppression *records*.

    Pure — no DB access — so the audit graph can run it on records handed in via
    state. A suppressed entry carries the finding's display fields plus the
    disposition (kind + reason) for the report's "Accepted Risks" section.
    """
    by_fp: dict[str, dict] = {}
    for r in records:
        fp = r.get("fingerprint")
        if fp and fp not in by_fp:
            by_fp[fp] = r

    active: list[Finding] = []
    suppressed: list[dict] = []
    for f in findings:
        rec = by_fp.get(fingerprint(f))
        if rec is None:
            active.append(f)
            continue
        suppressed.append(
            {
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "control_id": f.control_id,
                "kind": rec.get("kind", "accepted-risk"),
                "reason": rec.get("reason", ""),
                "expires_at": rec.get("expires_at"),
            }
        )
    return active, suppressed
