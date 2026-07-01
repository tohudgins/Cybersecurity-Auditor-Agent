"""Tests for scope completeness (#1) and unified coverage merge (#2)."""
from __future__ import annotations

from auditor.assessment import assess_controls, merge_interview_verdicts
from auditor.models import Artifact, Asset, AuditScope, Finding
from auditor.scope import assess_scope_coverage

# ── #1 Scope completeness ────────────────────────────────────────────────────


def _art(kind, name):
    return Artifact(kind=kind, name=name, content="x")


def test_scope_coverage_matches_by_kind_and_name():
    scope = AuditScope(assets=[
        Asset(name="prod-web-01", kind="host"),
        Asset(name="payments-api", kind="codebase"),
        Asset(name="billing-db", kind="database"),  # nothing assesses it
    ])
    artifacts = [_art("host", "prod-web-01"), _art("codebase", "some-repo")]
    cov = assess_scope_coverage(scope, artifacts)
    assert cov.total == 3 and cov.assessed == 2
    by = {a.asset.name: a for a in cov.assets}
    assert by["prod-web-01"].assessed and by["prod-web-01"].covered_by == "prod-web-01"
    assert by["payments-api"].assessed  # matched by kind=codebase
    assert not by["billing-db"].assessed  # in-scope gap


def test_scope_coverage_kind_aliases():
    scope = AuditScope(assets=[Asset(name="marketing site", kind="web_app")])
    # web_app aliases to target_url.
    cov = assess_scope_coverage(scope, [_art("target_url", "https://x")])
    assert cov.assessed == 1


def test_empty_scope_is_empty_coverage():
    assert assess_scope_coverage(None, []).total == 0
    assert assess_scope_coverage(AuditScope(), []).total == 0


# ── #2 Unified coverage merge ────────────────────────────────────────────────


class _V:  # stand-in for _OrgVerdict (duck-typed)
    def __init__(self, control, status, rationale="r", title=""):
        self.control, self.status, self.rationale, self.title = control, status, rationale, title


def test_merge_fills_not_assessed_controls_via_interview():
    # Technical run: IA-5 not-satisfied (finding), IR-8 not-assessed (process control).
    findings = [Finding(title="t", severity="high", framework="NIST SP 800-53 Rev. 5",
                        control_id="IA-5", evidence="e", recommendation="r")]
    assessments, coverage = assess_controls(findings, ["config"], AuditScope(baseline="moderate"))
    ir8_before = next(a for a in assessments if a.control_id == "IR-8")
    assert ir8_before.status == "not-assessed"

    verdicts = [
        _V("NIST 800-53 IR-8 Incident Response Plan", "satisfied"),
        _V("NIST 800-53 IA-5 Authenticator Management", "satisfied"),  # already technically assessed
    ]
    merged, new_cov = merge_interview_verdicts(assessments, coverage, verdicts)
    by = {a.control_id: a for a in merged}
    # IR-8 was not-assessed → takes the interview verdict.
    assert by["IR-8"].status == "satisfied" and by["IR-8"].method == "interview"
    # IA-5 was technically assessed → its scanner verdict stands (not overwritten).
    assert by["IA-5"].method != "interview"
    assert new_cov.assessed == coverage.assessed + 1  # one process control newly covered


def test_merge_ignores_non_nist_and_not_assessed_verdicts():
    assessments, coverage = assess_controls([], ["config"], AuditScope(baseline="moderate"))
    verdicts = [_V("SOC 2 CC6.1", "satisfied"), _V("NIST 800-53 IR-8", "not-assessed")]
    merged, new_cov = merge_interview_verdicts(assessments, coverage, verdicts)
    # SOC 2 id doesn't resolve to a NIST control; not-assessed verdict is skipped.
    assert new_cov.assessed == coverage.assessed
