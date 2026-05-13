"""Tests for cross-framework control mappings."""
from __future__ import annotations

from auditor.enrichment.mappings import (
    control_title,
    enrich_with_mappings,
    lookup_control,
    reset_cache,
)
from auditor.models import Finding


def setup_function():
    reset_cache()


def _f(**overrides) -> Finding:
    defaults = {
        "title": "t",
        "evidence": "e",
        "recommendation": "r",
        "framework": "NIST SP 800-53 Rev. 5",
        "control_id": "AC-2",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_lookup_returns_cross_framework_ids():
    mappings = lookup_control("AC-2")
    assert mappings is not None
    assert "NIST CSF 2.1" in mappings
    assert "PR.AA-01" in mappings["NIST CSF 2.1"]
    assert "CIS Controls v8.1" in mappings
    assert "SOC 2 TSC" in mappings


def test_lookup_strips_enhancement_suffix():
    """AC-2(1) and AC-2 should both resolve to the AC-2 entry."""
    assert lookup_control("AC-2(1)") == lookup_control("AC-2")


def test_lookup_unknown_control_returns_none():
    assert lookup_control("ZZ-99") is None
    assert lookup_control("") is None


def test_control_title_returns_human_name():
    assert control_title("SI-2") == "Flaw Remediation"
    assert control_title("AC-2") == "Account Management"


def test_enrich_skips_non_nist_findings():
    f = _f(framework="OWASP ASVS 5.0", control_id="V2.1.1")
    enrich_with_mappings([f])
    assert f.mapped_controls == {}


def test_enrich_populates_for_nist_findings():
    f = _f(control_id="SI-2")
    enrich_with_mappings([f])
    assert f.mapped_controls
    assert "CIS Controls v8.1" in f.mapped_controls
    assert "7.3" in f.mapped_controls["CIS Controls v8.1"]


def test_enrich_handles_empty_control_id():
    f = _f(control_id=None)
    enrich_with_mappings([f])
    assert f.mapped_controls == {}
