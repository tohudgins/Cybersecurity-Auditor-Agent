"""Tests for the 800-53 control catalog + named baselines (enrichment.catalog)."""
from __future__ import annotations

from auditor.assessment import baseline_controls
from auditor.enrichment.catalog import (
    baseline_control_ids,
    baseline_label,
    catalog_title,
    list_baselines,
    reset_cache,
)
from auditor.enrichment.mappings import control_title
from auditor.models import AuditScope


def setup_function():
    reset_cache()


def test_catalog_titles_resolve_controls_outside_the_crosswalk():
    # These appear from LLM/policy findings but aren't in the curated crosswalk.
    assert catalog_title("IR-2") == "Incident Response Training"
    assert catalog_title("PE-6") == "Monitoring Physical Access"
    assert catalog_title("IR-1") == "Policy and Procedures"


def test_enhancement_falls_back_to_base_control_title():
    assert catalog_title("AC-16(4)") == "Security and Privacy Attributes"
    assert catalog_title("AC-2(1)") == "Account Management"


def test_control_title_uses_catalog_fallback():
    # control_title prefers the crosswalk, then falls back to the catalog.
    assert control_title("AC-2") == "Account Management"  # crosswalk
    assert control_title("PE-6") == "Monitoring Physical Access"  # catalog fallback


def test_baselines_compose_additively():
    low = set(baseline_control_ids("low"))
    moderate = set(baseline_control_ids("moderate"))
    high = set(baseline_control_ids("high"))
    assert low and moderate and high
    assert low < moderate < high  # strict supersets


def test_every_baseline_control_is_titled():
    # No dangling controls — each baseline member must exist in the catalog.
    for name in ("low", "moderate", "high"):
        for cid in baseline_control_ids(name):
            assert catalog_title(cid), f"{cid} in {name} baseline has no title"


def test_unknown_baseline_is_empty():
    assert baseline_control_ids("does-not-exist") == []


def test_baseline_label():
    assert "Moderate" in baseline_label("moderate")
    assert list_baselines() == ["low", "moderate", "high"]


def test_assessment_baseline_controls_selects_named_baseline():
    moderate = baseline_controls(AuditScope(baseline="moderate"))
    curated = baseline_controls(AuditScope(baseline="auditor-curated"))
    assert len(moderate) > len(curated)  # 800-53B Moderate is the bigger denominator
    assert "SC-28" in moderate


def test_unknown_baseline_falls_back_to_curated():
    # An unrecognized baseline name must not yield an empty denominator.
    assert baseline_controls(AuditScope(baseline="bogus")) == baseline_controls(
        AuditScope(baseline="auditor-curated")
    )
