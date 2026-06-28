"""Tests for the run-to-run remediation diff layer."""
from __future__ import annotations

from auditor.diff import (
    diff_findings,
    fingerprint,
    render_remediation_section,
    serialize_findings,
    target_key,
)
from auditor.models import Artifact, Finding


def _f(title, severity="high", evidence="x", control_id=None):
    return Finding(
        title=title,
        severity=severity,
        evidence=evidence,
        recommendation="fix it",
        control_id=control_id,
    )


def test_fingerprint_stable_for_same_cve():
    a = _f("openssl: CVE-2022-0778 infinite loop", evidence="pkg openssl")
    b = _f("CVE-2022-0778 in libssl", severity="critical", evidence="another desc")
    # Same CVE → same fingerprint regardless of wording/severity/scanner.
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_for_distinct_findings():
    assert fingerprint(_f("Root SSH login enabled")) != fingerprint(_f("Password auth enabled"))


def test_target_key_order_independent():
    a1 = Artifact(kind="config", name="sshd_config", content="x")
    a2 = Artifact(kind="codebase", name="/repo", content="/repo")
    assert target_key([a1, a2]) == target_key([a2, a1])


def test_target_key_distinguishes_targets():
    a = Artifact(kind="codebase", name="/repo-a", content="/repo-a")
    b = Artifact(kind="codebase", name="/repo-b", content="/repo-b")
    assert target_key([a]) != target_key([b])


def test_diff_classifies_resolved_new_and_persisting():
    previous = serialize_findings([
        _f("Root SSH login enabled"),
        _f("Password authentication enabled", severity="medium"),
    ])
    current = [
        _f("Password authentication enabled", severity="medium"),  # persisting
        _f("World-writable secrets file", severity="critical"),     # new
    ]
    diff = diff_findings(previous, current, previous_run_at="2026-06-01T00:00:00Z")

    resolved_titles = {e.title for e in diff.resolved}
    new_titles = {e.title for e in diff.new}
    persisting_titles = {e.title for e in diff.persisting}

    assert "Root SSH login enabled" in resolved_titles
    assert "World-writable secrets file" in new_titles
    assert "Password authentication enabled" in persisting_titles
    assert diff.previous_run_at == "2026-06-01T00:00:00Z"
    assert diff.has_changes


def test_diff_detects_regression():
    previous = serialize_findings([_f("Outdated TLS config", severity="low")])
    current = [_f("Outdated TLS config", severity="high")]  # same finding, worse
    diff = diff_findings(previous, current)
    assert len(diff.regressed) == 1
    entry = diff.regressed[0]
    assert entry.previous_severity == "low"
    assert entry.severity == "high"


def test_open_delta_improvement():
    previous = serialize_findings([
        _f("a", severity="high"),
        _f("b", severity="high"),
        _f("c", severity="high"),
    ])
    current = [_f("a", severity="high")]  # fixed two
    diff = diff_findings(previous, current)
    assert diff.previous_open == 3
    assert diff.current_open == 1
    assert diff.net_open_delta == -2


def test_info_findings_excluded_from_open_count():
    previous = serialize_findings([_f("scanner not installed", severity="info")])
    current = [_f("scanner not installed", severity="info")]
    diff = diff_findings(previous, current)
    assert diff.previous_open == 0
    assert diff.current_open == 0


def test_render_section_contains_headline_and_buckets():
    previous = serialize_findings([_f("Root SSH login enabled")])
    current = [_f("New secret leaked", severity="critical")]
    md = render_remediation_section(diff_findings(previous, current, "2026-06-01T00:00:00Z"))
    assert "## Remediation Progress" in md
    assert "2026-06-01T00:00:00Z" in md
    assert "Resolved" in md
    assert "Newly introduced" in md


def test_render_section_no_changes_message():
    previous = serialize_findings([_f("Persistent issue")])
    current = [_f("Persistent issue")]
    md = render_remediation_section(diff_findings(previous, current))
    assert "No change from the previous run" in md
