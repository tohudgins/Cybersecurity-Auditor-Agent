"""Tests for EPSS catalog lookup."""
from __future__ import annotations

from auditor.enrichment import epss as epss_mod

# Capture the real function before conftest stubs it out.
_real_epss_score = epss_mod.epss_score

_FAKE_CSV = (
    "#model_version:v2025.03.14,score_date:2026-05-12T00:00:00+00:00\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97432,0.99988\n"
    "CVE-2024-12345,0.00112,0.42500\n"
)


def test_epss_score_hits_known_cve(monkeypatch):
    monkeypatch.setattr(epss_mod, "_load_csv_text", lambda: _FAKE_CSV)
    epss_mod.reset_cache()

    score, pct = _real_epss_score("CVE-2021-44228")
    assert score == 0.97432
    assert pct == 0.99988


def test_epss_score_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(epss_mod, "_load_csv_text", lambda: _FAKE_CSV)
    epss_mod.reset_cache()

    result = _real_epss_score("cve-2024-12345")
    assert result is not None
    score, _ = result
    assert score == 0.00112


def test_epss_score_returns_none_for_unknown_cve(monkeypatch):
    monkeypatch.setattr(epss_mod, "_load_csv_text", lambda: _FAKE_CSV)
    epss_mod.reset_cache()

    assert _real_epss_score("CVE-9999-99999") is None
    assert _real_epss_score("") is None


def test_epss_score_returns_none_when_catalog_empty(monkeypatch):
    monkeypatch.setattr(epss_mod, "_load_csv_text", lambda: "")
    epss_mod.reset_cache()

    assert _real_epss_score("CVE-2021-44228") is None
