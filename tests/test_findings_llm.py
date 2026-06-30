"""Tests for the shared LLM-findings helper (schema slimming + control-id cleanup)."""
from __future__ import annotations

from auditor.tools._findings_llm import _clean_nist_control_id
from auditor.tools._findings_llm import run_findings_chain as _real_run_findings_chain

# Captured at import time, before conftest's autouse fixture stubs the module
# attribute — so the fast-mode gate test exercises the real function.


def test_strips_page_refs_from_nist_ids():
    assert _clean_nist_control_id("AC-16(4) (p.71)", "NIST SP 800-53 Rev. 5") == "AC-16(4)"
    assert _clean_nist_control_id("IR-1/IR-7 (pp.176,185)", "NIST SP 800-53 Rev. 5") == "IR-1"
    assert _clean_nist_control_id("SC-7", "NIST SP 800-53 Rev. 5") == "SC-7"


def test_leaves_non_nist_frameworks_untouched():
    # CSF / CIS IDs have different shapes and must not be rewritten.
    assert _clean_nist_control_id("PR.AA-01", "NIST CSF 2.1") == "PR.AA-01"
    assert _clean_nist_control_id("5.2", "CIS Controls v8.1") == "5.2"


def test_handles_none_and_unmatched():
    assert _clean_nist_control_id(None, "NIST SP 800-53 Rev. 5") is None
    assert _clean_nist_control_id("freeform text", "NIST SP 800-53 Rev. 5") == "freeform text"


def test_fast_mode_skips_llm_and_returns_empty():
    # The gate short-circuits before any LLM construction, so a disabled context
    # yields no findings without touching the network (passing prompt=None would
    # crash if the gate didn't fire first).
    from auditor.tools import _findings_llm as fl

    fl.set_llm_analysis(False)
    try:
        assert _real_run_findings_chain(prompt=None, inputs={}, source_artifact="x") == []
        assert fl.llm_analysis_enabled() is False
    finally:
        fl.set_llm_analysis(True)  # restore default for other tests


def test_llm_analysis_enabled_by_default():
    from auditor.tools import _findings_llm as fl

    fl.set_llm_analysis(True)
    assert fl.llm_analysis_enabled() is True
