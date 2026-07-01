"""Tests for selectable framework baselines (CIS / PCI / CSF / SOC 2).

The assessment projects findings from their NIST 800-53 anchor onto the chosen
framework via the crosswalk, then reduces to the framework's natural granularity.
"""
from __future__ import annotations

from auditor.assessment import assess_controls
from auditor.enrichment.catalog import (
    framework_control_ids,
    framework_keys,
    framework_title,
    is_framework_baseline,
    project_framework_id,
    reset_cache,
)
from auditor.enrichment.mappings import project_to_framework
from auditor.enrichment.mappings import reset_cache as reset_mappings
from auditor.models import AuditScope, Finding


def setup_function():
    reset_cache()
    reset_mappings()


def _nist_finding(control_id: str, severity: str = "high") -> Finding:
    return Finding(
        title=f"issue {control_id}", severity=severity,
        framework="NIST SP 800-53 Rev. 5", control_id=control_id,
        evidence="ev", recommendation="fix",
    )


def test_frameworks_are_registered():
    assert set(framework_keys()) >= {"cis", "pci", "csf", "soc2"}
    assert is_framework_baseline("cis")
    assert not is_framework_baseline("moderate")  # NIST, not a projected framework


def test_framework_catalogs_have_expected_sizes():
    assert len(framework_control_ids("cis")) == 18   # CIS v8.1 controls
    assert len(framework_control_ids("pci")) == 12   # PCI DSS v4 requirements
    assert framework_title("cis", "5") == "Account Management"
    assert framework_title("pci", "1").startswith("Install and Maintain")


def test_projection_rules():
    assert project_framework_id("cis", "5.4") == "5"        # before_dot
    assert project_framework_id("pci", "10.2.2") == "10"    # before_dot (nested)
    assert project_framework_id("csf", "PR.AA-05") == "PR.AA"  # before_dash
    assert project_framework_id("soc2", "CC6.1") == "CC6"


def test_project_to_framework_uses_crosswalk():
    # IA-5 (Authenticator Management) maps into CIS account/credential safeguards.
    cis_ids = project_to_framework({"IA-5"}, "CIS Controls v8.1")
    assert cis_ids  # non-empty
    assert all("." in i or i.isalnum() for i in cis_ids)


def test_cis_assessment_projects_findings_to_native_controls():
    findings = [_nist_finding("IA-5", "critical")]  # authenticator mgmt
    assessments, cov = assess_controls(findings, ["config"], AuditScope(baseline="cis"))
    assert cov.baseline == "CIS Controls v8.1"
    assert cov.total_controls == 18
    # IA-5 projects onto CIS Control 5 (Account Management).
    c5 = next(a for a in assessments if a.control_id == "5")
    assert c5.status == "not-satisfied"
    assert c5.framework == "CIS Controls v8.1"


def test_pci_assessment_denominator_is_twelve_requirements():
    findings = [_nist_finding("SC-7")]  # boundary protection
    assessments, cov = assess_controls(findings, ["config"], AuditScope(baseline="pci"))
    assert cov.total_controls == 12
    # SC-7 projects onto PCI Requirement 1 (network security controls).
    assert any(a.control_id == "1" and a.status == "not-satisfied" for a in assessments)


def test_unknown_finding_control_does_not_break_framework_assessment():
    # A finding whose anchor isn't in the crosswalk simply doesn't project.
    findings = [_nist_finding("ZZ-99")]
    assessments, cov = assess_controls(findings, ["config"], AuditScope(baseline="csf"))
    assert cov.total_controls == 22  # full CSF category denominator still shown
    assert all(a.status in ("satisfied", "not-assessed", "partial", "not-satisfied") for a in assessments)
