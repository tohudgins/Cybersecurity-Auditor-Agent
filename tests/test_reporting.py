"""Tests for the reporting agent's Markdown rendering (focused on enrichment fields)."""
from __future__ import annotations

from auditor.agents.reporting_agent import _cvss_qualifier, _render_finding
from auditor.models import Finding


def _f(**overrides) -> Finding:
    defaults = {
        "title": "Some finding",
        "evidence": "ev",
        "recommendation": "rec",
        "framework": "NIST SP 800-53 Rev. 5",
        "control_id": "SI-2",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_cvss_qualifier_boundaries():
    assert _cvss_qualifier(0.0) == "None"
    assert _cvss_qualifier(0.1) == "Low"
    assert _cvss_qualifier(3.9) == "Low"
    assert _cvss_qualifier(4.0) == "Medium"
    assert _cvss_qualifier(6.9) == "Medium"
    assert _cvss_qualifier(7.0) == "High"
    assert _cvss_qualifier(8.9) == "High"
    assert _cvss_qualifier(9.0) == "Critical"
    assert _cvss_qualifier(10.0) == "Critical"


def test_render_includes_cvss_line():
    md = _render_finding(
        1,
        _f(cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    )
    assert "CVSS v3 base score" in md
    assert "9.8 (Critical)" in md
    assert "CVSS:3.1/" in md


def test_render_omits_cvss_when_absent():
    md = _render_finding(1, _f())
    assert "CVSS" not in md


def test_render_includes_kev_badge():
    md = _render_finding(1, _f(kev=True))
    assert "[KEV - actively exploited]" in md


def test_render_includes_attack_techniques():
    md = _render_finding(1, _f(attack_techniques=["T1078", "T1190"]))
    assert "T1078" in md
    assert "T1190" in md
    assert "MITRE ATT&CK" in md


def test_render_includes_epss_line():
    md = _render_finding(1, _f(epss_score=0.97432, epss_percentile=0.99988))
    assert "EPSS" in md
    assert "0.9743" in md
    assert "top 0.0%" in md or "top 0.01%" in md or "top 0.0" in md  # percentile rendering


def test_render_omits_epss_when_absent():
    md = _render_finding(1, _f())
    assert "EPSS" not in md


def test_render_includes_mapped_controls():
    md = _render_finding(
        1,
        _f(mapped_controls={"NIST CSF 2.0": ["PR.AA-05"], "CIS Controls v8.1": ["5.4", "6.8"]}),
    )
    assert "Cross-framework" in md
    assert "PR.AA-05" in md
    assert "5.4, 6.8" in md
