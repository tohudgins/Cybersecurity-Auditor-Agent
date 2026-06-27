"""Tests for the control-coverage assessment layer."""
from __future__ import annotations

from auditor.assessment import assess_controls, baseline_controls
from auditor.enrichment.mappings import reset_cache
from auditor.models import AuditScope, Finding


def setup_function():
    reset_cache()


def _f(**overrides) -> Finding:
    defaults = {
        "title": "t",
        "evidence": "e",
        "recommendation": "r",
        "framework": "NIST SP 800-53 Rev. 5",
        "control_id": "SI-2",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_marks_control_not_satisfied():
    assessments, _ = assess_controls([_f(control_id="SI-2", severity="high")], ["codebase"])
    si2 = next(a for a in assessments if a.control_id == "SI-2")
    assert si2.status == "not-satisfied"
    assert si2.method == "test"  # codebase scanners execute
    assert si2.related_findings == ["t"]


def test_low_severity_finding_is_partial():
    assessments, _ = assess_controls([_f(control_id="SI-2", severity="low")], ["codebase"])
    si2 = next(a for a in assessments if a.control_id == "SI-2")
    assert si2.status == "partial"


def test_covered_control_without_finding_is_satisfied():
    # codebase covers RA-5; no finding implicates it → satisfied.
    assessments, _ = assess_controls([_f(control_id="SI-2", severity="high")], ["codebase"])
    ra5 = next(a for a in assessments if a.control_id == "RA-5")
    assert ra5.status == "satisfied"
    assert ra5.method == "test"


def test_uncovered_control_is_not_assessed():
    # AT-2 (awareness training) isn't exercised by a codebase scan.
    assessments, _ = assess_controls([_f(control_id="SI-2")], ["codebase"])
    at2 = next(a for a in assessments if a.control_id == "AT-2")
    assert at2.status == "not-assessed"
    assert at2.method is None


def test_cwe_finding_resolves_to_anchor_control():
    """A SAST CWE finding (mapped to SI-10) marks SI-10 not-satisfied."""
    f = _f(framework="OWASP ASVS 5.0", control_id="CWE-89", severity="high")
    f.mapped_controls = {"NIST SP 800-53 Rev. 5": ["SI-10"]}
    assessments, _ = assess_controls([f], ["codebase"])
    si10 = next(a for a in assessments if a.control_id == "SI-10")
    assert si10.status == "not-satisfied"


def test_coverage_summary_counts_and_pct():
    findings = [_f(control_id="SI-2", severity="high")]
    assessments, coverage = assess_controls(findings, ["codebase"])
    assert coverage.total_controls == len(assessments)
    assert coverage.assessed == coverage.total_controls - coverage.not_assessed
    assert coverage.not_satisfied >= 1
    assert coverage.satisfied >= 1
    assert 0.0 <= coverage.coverage_pct <= 100.0


def test_no_artifacts_means_nothing_assessed():
    assessments, coverage = assess_controls([], [])
    assert coverage.assessed == 0
    assert all(a.status == "not-assessed" for a in assessments)


def test_baseline_defaults_to_catalog():
    controls = baseline_controls(AuditScope())
    assert "SI-2" in controls and "AC-3" in controls
    assert len(controls) > 30
