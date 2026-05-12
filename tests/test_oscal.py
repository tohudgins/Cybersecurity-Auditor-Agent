"""Tests for OSCAL Assessment Results export."""
from __future__ import annotations

from auditor.models import Finding
from auditor.oscal.exporter import to_oscal_assessment_results


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
        mapped_controls={"NIST CSF 2.0": ["PR.AA-05"], "CIS Controls v8.1": ["5.4", "6.8"]},
    )
    doc = to_oscal_assessment_results([f])
    props = doc["assessment-results"]["results"][0]["findings"][0]["props"]
    mapped = [p for p in props if p["name"] == "mapped-control"]
    assert len(mapped) == 3
    by_class = {(p["class"], p["value"]) for p in mapped}
    assert ("NIST CSF 2.0", "PR.AA-05") in by_class
    assert ("CIS Controls v8.1", "5.4") in by_class
    assert ("CIS Controls v8.1", "6.8") in by_class
