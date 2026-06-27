"""Tests for the NIST OLIR / CPRT importer (parsing + merge, no network)."""
from __future__ import annotations

import json

from auditor.ingest import olir_import as oi

_SRC = oi.OlirSource(
    name="csf",
    url="https://example/csf",
    framework="NIST CSF 2.1",
    id_pattern=r"[A-Z]{2}\.[A-Z]{2}-\d{2}",
)


def test_parse_is_orientation_agnostic():
    """800-53 control is found by ID shape regardless of which key holds it."""
    payload = {
        "relationships": [
            {"focal_element": "PR.AA-09", "reference_element": "AC-2"},
            {"reference_element": "PR.AA-09", "focal_element": "AC-3"},
        ]
    }
    parsed = oi.parse_relationships(payload, _SRC)
    assert parsed == {"AC-2": ["PR.AA-09"], "AC-3": ["PR.AA-09"]}


def test_csf_id_not_mistaken_for_nist_control():
    """'PR.AA-09' contains 'AA-09' — it must not be parsed as a 800-53 control."""
    payload = {"relationships": [{"a": "PR.AA-09", "b": "AC-2"}]}
    parsed = oi.parse_relationships(payload, _SRC)
    assert list(parsed.keys()) == ["AC-2"]


def test_enhancement_suffix_normalized_to_base():
    payload = {"relationships": [{"a": "AC-2(1)", "b": "PR.AA-01"}]}
    parsed = oi.parse_relationships(payload, _SRC)
    assert parsed == {"AC-2": ["PR.AA-01"]}


def test_records_nested_under_response():
    payload = {"response": {"relationships": [{"x": "AC-7", "y": "PR.AA-04"}]}}
    assert oi.parse_relationships(payload, _SRC) == {"AC-7": ["PR.AA-04"]}


def test_merge_unions_and_never_invents_controls():
    curated = {
        "mappings": {
            "AC-2": {"title": "Account Management", "NIST CSF 2.1": ["PR.AA-01"]},
        }
    }
    touched, added = oi.merge_into_curated(
        curated,
        {"AC-2": ["PR.AA-01", "PR.AA-09"], "ZZ-9": ["X.X-01"]},
        "NIST CSF 2.1",
    )
    assert (touched, added) == (1, 1)
    assert curated["mappings"]["AC-2"]["NIST CSF 2.1"] == ["PR.AA-01", "PR.AA-09"]
    assert "ZZ-9" not in curated["mappings"]  # importer augments, never invents


def test_import_olir_merge_roundtrip(tmp_path):
    mf = tmp_path / "control_mappings.json"
    mf.write_text(json.dumps({"mappings": {"AC-2": {"title": "x", "NIST CSF 2.1": ["PR.AA-01"]}}}))

    results = oi.import_olir(
        sources=(_SRC,),
        fetcher=lambda _url: {"relationships": [{"a": "AC-2", "b": "PR.AA-09"}]},
        merge=True,
        mapping_file=mf,
    )
    assert results["csf"] == (1, 1)
    reloaded = json.loads(mf.read_text())
    assert "PR.AA-09" in reloaded["mappings"]["AC-2"]["NIST CSF 2.1"]


def test_import_olir_fetch_failure_is_skipped(tmp_path):
    mf = tmp_path / "control_mappings.json"
    mf.write_text(json.dumps({"mappings": {}}))

    def _boom(_url):
        raise TimeoutError("network down")

    results = oi.import_olir(sources=(_SRC,), fetcher=_boom, merge=False, mapping_file=mf)
    assert results["csf"] == (0, 0)
