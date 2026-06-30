"""Tests for the authoritative NIST 800-53B importer (offline, injected fetcher)."""
from __future__ import annotations

from auditor.ingest import baseline_import as bi

# Minimal OSCAL-shaped catalog: one family, a base control + an enhancement.
_CATALOG = {
    "catalog": {
        "groups": [
            {
                "id": "ac",
                "class": "family",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-2",
                        "title": "Account Management",
                        "controls": [
                            {"id": "ac-2.1", "title": "Automated System Account Management"}
                        ],
                    },
                    {"id": "ac-3", "title": "Access Enforcement"},
                ],
            }
        ]
    }
}
_LOW = {"catalog": {"groups": [{"id": "ac", "controls": [{"id": "ac-2"}, {"id": "ac-3"}]}]}}
_MOD = {
    "catalog": {
        "groups": [
            {"id": "ac", "controls": [{"id": "ac-2", "controls": [{"id": "ac-2.1"}]}, {"id": "ac-3"}]}
        ]
    }
}
_HIGH = _MOD


def _fake_fetcher(url: str) -> dict:
    if url == bi.CATALOG_URL:
        return _CATALOG
    return {"low": _LOW, "moderate": _MOD, "high": _HIGH}[
        next(k for k, v in bi.BASELINE_URLS.items() if v == url)
    ]


def test_canonical_id_conversion():
    assert bi._canonical_id("ac-2") == "AC-2"
    assert bi._canonical_id("ac-2.1") == "AC-2(1)"
    assert bi._canonical_id("sc-7.3") == "SC-7(3)"


def test_parse_catalog_includes_enhancements():
    titles = bi.parse_catalog(_CATALOG)
    assert titles["AC-2"] == "Account Management"
    assert titles["AC-2(1)"] == "Automated System Account Management"
    assert titles["AC-3"] == "Access Enforcement"


def test_parse_baseline_returns_sorted_canonical_ids():
    assert bi.parse_baseline(_MOD) == ["AC-2", "AC-2(1)", "AC-3"]


def test_import_baselines_dry_run_counts_without_writing(tmp_path, monkeypatch):
    # Point the writers at a temp dir to prove a dry run never touches the files.
    monkeypatch.setattr(bi, "_CATALOG_FILE", tmp_path / "control_catalog.json")
    monkeypatch.setattr(bi, "_BASELINES_FILE", tmp_path / "baselines.json")
    counts = bi.import_baselines(fetcher=_fake_fetcher, write=False)
    assert counts == {"catalog": 3, "low": 2, "moderate": 3, "high": 3}
    assert not (tmp_path / "control_catalog.json").exists()


def test_import_baselines_write_emits_loadable_files(tmp_path, monkeypatch):
    monkeypatch.setattr(bi, "_CATALOG_FILE", tmp_path / "control_catalog.json")
    monkeypatch.setattr(bi, "_BASELINES_FILE", tmp_path / "baselines.json")
    bi.import_baselines(fetcher=_fake_fetcher, write=True)
    import json

    cat = json.loads((tmp_path / "control_catalog.json").read_text())
    base = json.loads((tmp_path / "baselines.json").read_text())
    assert cat["controls"]["AC-2(1)"] == "Automated System Account Management"
    assert base["baselines"]["moderate"]["controls"] == ["AC-2", "AC-2(1)", "AC-3"]
    assert base["baselines"]["moderate"]["extends"] is None
