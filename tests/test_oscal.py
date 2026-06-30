"""Tests for OSCAL Assessment Results export."""
from __future__ import annotations

from auditor.models import ControlAssessment, CoverageSummary, Finding
from auditor.oscal.exporter import to_oscal_assessment_results, to_oscal_poam


def _make_finding(**overrides) -> Finding:
    defaults = {
        "title": "Test finding",
        "evidence": "Some evidence",
        "recommendation": "Do the thing",
        "framework": "NIST SP 800-53 Rev. 5",
        "control_id": "SI-2",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_empty_findings_produces_valid_oscal():
    doc = to_oscal_assessment_results([])
    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert len(ar["results"]) == 1
    assert ar["results"][0]["observations"] == []
    assert ar["results"][0]["findings"] == []


def test_finding_becomes_observation_plus_finding():
    f = _make_finding(title="Root SSH login is enabled", control_id="5.4", severity="high")
    doc = to_oscal_assessment_results([f])
    run = doc["assessment-results"]["results"][0]

    assert len(run["observations"]) == 1
    assert len(run["findings"]) == 1

    obs = run["observations"][0]
    finding = run["findings"][0]

    # Each finding references its observation
    related = [r["observation-uuid"] for r in finding["related-observations"]]
    assert obs["uuid"] in related

    # Severity surfaces as a prop
    severities = [p["value"] for p in finding["props"] if p["name"] == "severity"]
    assert severities == ["high"]

    # Control ID becomes target-id
    assert finding["target"]["target-id"] == "5.4"
    assert finding["target"]["status"]["state"] == "not-satisfied"


def test_cvss_and_kev_emit_oscal_props():
    f = _make_finding(
        title="[KEV] log4j 2.0: CVE-2021-44228",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        kev=True,
        attack_techniques=["T1190"],
    )
    doc = to_oscal_assessment_results([f])
    finding = doc["assessment-results"]["results"][0]["findings"][0]
    prop_names = {p["name"]: p["value"] for p in finding["props"]}

    assert prop_names["cvss-v3-base-score"] == "10.0"
    assert prop_names["cvss-v3-vector"].startswith("CVSS:3.1/")
    assert prop_names["cisa-kev"] == "true"
    assert prop_names["mitre-attack-technique"] == "T1190"


def test_observation_uuid_is_stable_across_runs():
    """Same finding content → same UUID, so downstream tools can dedupe across runs."""
    f1 = _make_finding(title="X", evidence="Y")
    f2 = _make_finding(title="X", evidence="Y")
    doc1 = to_oscal_assessment_results([f1])
    doc2 = to_oscal_assessment_results([f2])
    uuid1 = doc1["assessment-results"]["results"][0]["observations"][0]["uuid"]
    uuid2 = doc2["assessment-results"]["results"][0]["observations"][0]["uuid"]
    assert uuid1 == uuid2


def test_missing_control_id_falls_back_to_unspecified():
    f = _make_finding(control_id=None)
    doc = to_oscal_assessment_results([f])
    finding = doc["assessment-results"]["results"][0]["findings"][0]
    assert finding["target"]["target-id"] == "unspecified"


def test_multiple_attack_techniques_get_separate_props():
    f = _make_finding(attack_techniques=["T1078", "T1110.001"])
    doc = to_oscal_assessment_results([f])
    finding = doc["assessment-results"]["results"][0]["findings"][0]
    techniques = [p["value"] for p in finding["props"] if p["name"] == "mitre-attack-technique"]
    assert sorted(techniques) == ["T1078", "T1110.001"]


def test_epss_emits_oscal_props():
    f = _make_finding(epss_score=0.97432, epss_percentile=0.99988)
    doc = to_oscal_assessment_results([f])
    props = {p["name"]: p["value"] for p in doc["assessment-results"]["results"][0]["findings"][0]["props"]}
    assert props["epss-score"] == "0.97432"
    assert props["epss-percentile"] == "0.99988"


def test_mapped_controls_emit_props_with_class():
    f = _make_finding(
        mapped_controls={"NIST CSF 2.1": ["PR.AA-05"], "CIS Controls v8.1": ["5.4", "6.8"]},
    )
    doc = to_oscal_assessment_results([f])
    props = doc["assessment-results"]["results"][0]["findings"][0]["props"]
    mapped = [p for p in props if p["name"] == "mapped-control"]
    assert len(mapped) == 3
    by_class = {(p["class"], p["value"]) for p in mapped}
    assert ("NIST CSF 2.1", "PR.AA-05") in by_class
    assert ("CIS Controls v8.1", "5.4") in by_class
    assert ("CIS Controls v8.1", "6.8") in by_class


# ── Coverage + reviewed-controls + POA&M (assessment layer) ───────────────────

def _assessment(control_id="SI-2", status="not-satisfied", method="test"):
    return ControlAssessment(control_id=control_id, status=status, method=method)


def _coverage():
    return CoverageSummary(
        baseline="auditor-curated",
        total_controls=40,
        assessed=10,
        satisfied=6,
        not_satisfied=3,
        partial=1,
        not_assessed=30,
    )


def test_results_carry_coverage_props_and_reviewed_controls():
    f = _make_finding(control_id="SI-2")
    doc = to_oscal_assessment_results(
        [f],
        assessments=[_assessment("SI-2", "not-satisfied"), _assessment("RA-5", "satisfied")],
        coverage=_coverage(),
    )
    result = doc["assessment-results"]["results"][0]
    props = {p["name"]: p["value"] for p in result["props"]}
    assert props["coverage-percent"] == "25.0"
    assert props["controls-not-assessed"] == "30"

    reviewed = result["reviewed-controls"]
    included = {c["control-id"] for c in reviewed["control-selections"][0]["include-controls"]}
    assert included == {"SI-2", "RA-5"}
    status_props = {(p["class"], p["value"]) for p in reviewed["props"]}
    assert ("SI-2", "not-satisfied") in status_props
    assert ("RA-5", "satisfied") in status_props


def test_backward_compatible_without_assessment_args():
    doc = to_oscal_assessment_results([_make_finding()])
    result = doc["assessment-results"]["results"][0]
    assert "reviewed-controls" not in result
    assert "props" not in result


def test_poam_emits_item_per_open_finding():
    findings = [
        _make_finding(title="open high", severity="high", control_id="SI-2"),
        _make_finding(title="info notice", severity="info"),
    ]
    doc = to_oscal_poam(findings)
    poam = doc["plan-of-action-and-milestones"]
    assert poam["metadata"]["oscal-version"] == "1.1.2"
    items = poam["poam-items"]
    assert len(items) == 1  # info notice excluded
    assert items[0]["title"] == "open high"
    prop_names = {p["name"] for p in items[0]["props"]}
    assert "associated-control" in prop_names and "severity" in prop_names


def test_poam_items_carry_governance_fields():
    findings = [_make_finding(title="open high", severity="high", control_id="SI-2")]
    poam = to_oscal_poam(findings)["plan-of-action-and-milestones"]
    item = poam["poam-items"][0]
    props = {p["name"]: p["value"] for p in item["props"]}
    assert props["remediation-owner"] == "Unassigned"
    assert props["remediation-sla-days"] == "30"  # high → 30-day SLA
    assert "scheduled-completion-date" in props
    # Each item links to a risk that carries a remediation milestone.
    assert item["related-risks"]
    risk = poam["risks"][0]
    assert item["related-risks"][0]["risk-uuid"] == risk["uuid"]
    assert risk["status"] == "open"
    milestone = risk["remediations"][0]["tasks"][0]
    assert milestone["type"] == "milestone"


def test_sla_days_scale_with_severity():
    crit = to_oscal_poam([_make_finding(severity="critical")])["plan-of-action-and-milestones"]
    low = to_oscal_poam([_make_finding(severity="low")])["plan-of-action-and-milestones"]
    crit_sla = {p["name"]: p["value"] for p in crit["poam-items"][0]["props"]}["remediation-sla-days"]
    low_sla = {p["name"]: p["value"] for p in low["poam-items"][0]["props"]}["remediation-sla-days"]
    assert int(crit_sla) < int(low_sla)  # critical remediated faster than low


def test_assessment_results_emit_risks_with_deadlines():
    findings = [
        _make_finding(title="open", severity="high", risk_score=70.0),
        _make_finding(title="info", severity="info"),
    ]
    result = to_oscal_assessment_results(findings)["assessment-results"]["results"][0]
    assert "risks" in result
    assert len(result["risks"]) == 1  # info excluded
    props = {p["name"]: p["value"] for p in result["risks"][0]["props"]}
    assert props["risk-status"] == "open" and "scheduled-completion-date" in props
