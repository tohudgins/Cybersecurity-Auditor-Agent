"""Run-to-run remediation tracking — the audit *lifecycle* layer.

A scan is a snapshot. An audit is a process: you assess, remediate, then
re-assess and *prove* the posture moved. This module diffs the current run's
findings against the most recent prior run of the **same target**, classifying
each finding as resolved, newly introduced, persisting, or regressed, and rolls
the change up into a one-line posture delta the report leads with.

Findings are matched across runs using the same signature de-duplication uses
within a run (:func:`auditor.enrichment.risk.finding_signature`), so "the same
issue" means the same thing whether two scanners report it once or one scanner
reports it across two weeks.

The UI layer (`app.py`) owns persistence: it serializes a run's findings via
:func:`serialize_findings`, stores them keyed by :func:`target_key`, and on the
next run of that target feeds the prior snapshot back in for the diff. The graph
stays pure — it renders whatever prior snapshot it is handed.
"""
from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from auditor.enrichment.risk import finding_signature
from auditor.models import Finding

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Findings at/above this rank count toward the "open issues" posture headline.
_OPEN_MIN_RANK = _SEVERITY_RANK["low"]


def fingerprint(f: Finding) -> str:
    """A stable, storable string identity for a finding across runs."""
    sig = finding_signature(f)
    raw = "|".join(str(part) for part in sig)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def target_key(artifacts) -> str:
    """A stable key identifying the *set of targets* a run assessed.

    Two runs share a key when they point at the same artifacts (by kind + name),
    so "re-audit my repo" matches the previous audit of that repo and not an
    unrelated cloud scan. Order-independent.
    """
    parts = sorted(f"{a.kind}:{a.name}" for a in artifacts)
    raw = "\n".join(parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def serialize_findings(findings: list[Finding]) -> list[dict]:
    """Compact, JSON-serializable snapshot of a run's findings for storage."""
    return [
        {
            "fp": fingerprint(f),
            "title": f.title,
            "severity": f.severity,
            "risk_score": f.risk_score,
        }
        for f in findings
    ]


class DiffEntry(BaseModel):
    """A single finding's status change between two runs."""

    title: str
    severity: str = "medium"
    previous_severity: str | None = None  # set only for regressed/improved entries


class RunDiff(BaseModel):
    """The classified delta between a prior run and the current one."""

    previous_run_at: str | None = None
    resolved: list[DiffEntry] = Field(default_factory=list)   # were open, now gone
    new: list[DiffEntry] = Field(default_factory=list)        # not seen before
    regressed: list[DiffEntry] = Field(default_factory=list)  # still open, severity up
    persisting: list[DiffEntry] = Field(default_factory=list) # still open, unchanged/down
    previous_open: int = 0
    current_open: int = 0

    @property
    def net_open_delta(self) -> int:
        """Change in open (>= low) issues; negative is improvement."""
        return self.current_open - self.previous_open

    @property
    def has_changes(self) -> bool:
        return bool(self.resolved or self.new or self.regressed)


def _open_count(severities) -> int:
    return sum(1 for s in severities if _SEVERITY_RANK.get(s, 2) >= _OPEN_MIN_RANK)


def diff_findings(
    previous: list[dict],
    current: list[Finding],
    previous_run_at: str | None = None,
) -> RunDiff:
    """Classify the current findings against a prior run's serialized snapshot."""
    prev_by_fp: dict[str, dict] = {p["fp"]: p for p in previous if p.get("fp")}
    cur_by_fp: dict[str, Finding] = {}
    for f in current:
        # Keep the highest-severity instance if a fingerprint somehow recurs.
        fp = fingerprint(f)
        existing = cur_by_fp.get(fp)
        if existing is None or _SEVERITY_RANK.get(f.severity, 2) > _SEVERITY_RANK.get(existing.severity, 2):
            cur_by_fp[fp] = f

    diff = RunDiff(
        previous_run_at=previous_run_at,
        previous_open=_open_count(p.get("severity", "medium") for p in prev_by_fp.values()),
        current_open=_open_count(f.severity for f in cur_by_fp.values()),
    )

    for fp, prev in prev_by_fp.items():
        if fp not in cur_by_fp:
            diff.resolved.append(
                DiffEntry(title=prev.get("title", "(untitled)"), severity=prev.get("severity", "medium"))
            )

    for fp, f in cur_by_fp.items():
        prev = prev_by_fp.get(fp)
        if prev is None:
            diff.new.append(DiffEntry(title=f.title, severity=f.severity))
            continue
        prev_sev = prev.get("severity", "medium")
        if _SEVERITY_RANK.get(f.severity, 2) > _SEVERITY_RANK.get(prev_sev, 2):
            diff.regressed.append(
                DiffEntry(title=f.title, severity=f.severity, previous_severity=prev_sev)
            )
        else:
            diff.persisting.append(
                DiffEntry(title=f.title, severity=f.severity, previous_severity=prev_sev)
            )

    # Most severe first within each bucket.
    for bucket in (diff.resolved, diff.new, diff.regressed, diff.persisting):
        bucket.sort(key=lambda e: -_SEVERITY_RANK.get(e.severity, 2))
    return diff


def render_remediation_section(diff: RunDiff) -> str:
    """Render the run-to-run delta as a Markdown 'Remediation Progress' section."""
    when = f" (since {diff.previous_run_at})" if diff.previous_run_at else ""
    delta = diff.net_open_delta
    if delta < 0:
        trend = f"⬇ {abs(delta)} fewer open issue{'s' if abs(delta) != 1 else ''}"
    elif delta > 0:
        trend = f"⬆ {delta} more open issue{'s' if delta != 1 else ''}"
    else:
        trend = "→ no net change in open issues"

    headline = (
        f"**{len(diff.resolved)} resolved · {len(diff.new)} new · "
        f"{len(diff.regressed)} regressed · {len(diff.persisting)} persisting** "
        f"— open issues {diff.previous_open} → {diff.current_open} ({trend})"
    )

    lines = [f"## Remediation Progress{when}\n", headline, ""]

    def _block(title: str, entries: list[DiffEntry], show_prev: bool = False) -> None:
        if not entries:
            return
        lines.append(f"**{title}**")
        for e in entries[:15]:
            sev = e.severity.upper()
            if show_prev and e.previous_severity:
                lines.append(f"- [{e.previous_severity.upper()} → {sev}] {e.title}")
            else:
                lines.append(f"- [{sev}] {e.title}")
        if len(entries) > 15:
            lines.append(f"- …and {len(entries) - 15} more")
        lines.append("")

    _block("✅ Resolved", diff.resolved)
    _block("⚠️ Regressed (severity increased)", diff.regressed, show_prev=True)
    _block("🆕 Newly introduced", diff.new)
    if not diff.has_changes:
        lines.append("_No change from the previous run — same findings persist._\n")
    return "\n".join(lines)
