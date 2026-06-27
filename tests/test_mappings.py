"""Tests for cross-framework control mappings."""
from __future__ import annotations

import json
import re
from pathlib import Path

from auditor.enrichment.mappings import (
    _CROSSWALK_FRAMEWORKS,
    _MAPPING_FILE,
    control_title,
    enrich_with_mappings,
    lookup_control,
    reset_cache,
    resolve_finding,
)
from auditor.models import Finding

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TOOLS_DIR = _REPO_ROOT / "src" / "auditor" / "tools"
_CWE_FILE = _REPO_ROOT / "data" / "mappings" / "cwe_mappings.json"


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


# ── Coverage guard — no scanner control_id may go unmapped ───────────────────

def _control_ids_emitted_by_tools() -> set[str]:
    """Static-scan the audit tools for the NIST 800-53 control IDs they emit."""
    ids: set[str] = set()
    for py in _TOOLS_DIR.glob("*.py"):
        for m in re.finditer(r'"([A-Z]{2}-\d{1,2})"', py.read_text(encoding="utf-8")):
            ids.add(m.group(1))
    return ids


def test_every_scanner_control_id_is_mapped():
    """Regression guard: AU-9 / SI-7 (and any future addition) must be mapped."""
    emitted = _control_ids_emitted_by_tools()
    assert emitted, "expected to find control_id literals in the tools dir"
    missing = sorted(c for c in emitted if lookup_control(c) is None)
    assert not missing, f"control IDs emitted by scanners with no mapping: {missing}"


# ── Schema integrity ─────────────────────────────────────────────────────────

def test_mapping_schema_is_complete():
    data = json.loads(_MAPPING_FILE.read_text(encoding="utf-8"))
    for cid, entry in data["mappings"].items():
        assert entry.get("title"), f"{cid} missing title"
        for fw in _CROSSWALK_FRAMEWORKS:
            ids = entry.get(fw)
            assert isinstance(ids, list) and ids, f"{cid} missing/empty {fw}"


def test_cwe_anchors_all_exist_in_control_mappings():
    cwe = json.loads(_CWE_FILE.read_text(encoding="utf-8"))["mappings"]
    for c, entry in cwe.items():
        anchor = entry.get("nist")
        assert lookup_control(anchor) is not None, f"{c} anchors on unmapped {anchor}"


# ── CWE → ASVS → NIST bridge ─────────────────────────────────────────────────

def test_cwe_finding_resolves_to_asvs_nist_and_full_crosswalk():
    f = _f(framework="OWASP ASVS 5.0", control_id="CWE-89")
    enrich_with_mappings([f])
    mc = f.mapped_controls
    assert mc["NIST SP 800-53 Rev. 5"] == ["SI-10"]
    assert "OWASP ASVS 5.0" in mc  # ASVS domain carried from the CWE entry
    # Inherits SI-10's crosswalk so a SAST finding now has full GRC context.
    assert "CIS Controls v8.1" in mc
    assert "NIST CSF 2.1" in mc


def test_cwe_detected_even_without_asvs_framework_label():
    f = _f(framework=None, control_id="CWE-798")
    enrich_with_mappings([f])
    assert f.mapped_controls["NIST SP 800-53 Rev. 5"] == ["IA-5"]


# ── Bidirectional reverse resolution ─────────────────────────────────────────

def test_reverse_resolution_from_csf_subcategory():
    f = _f(framework="NIST CSF 2.1", control_id="PR.AA-04")
    enrich_with_mappings([f])
    mc = f.mapped_controls
    assert "AC-7" in mc["NIST SP 800-53 Rev. 5"]
    assert "NIST CSF 2.1" not in mc  # don't echo the finding's own framework
    assert "CIS Controls v8.1" in mc


def test_reverse_resolution_from_cis_safeguard():
    f = _f(framework="CIS Controls v8.1", control_id="7.3")
    enrich_with_mappings([f])
    assert "SI-2" in f.mapped_controls["NIST SP 800-53 Rev. 5"]


def test_resolve_finding_unknown_returns_empty():
    assert resolve_finding(_f(framework="OWASP ASVS 5.0", control_id="V2.1.1")) == {}
    assert resolve_finding(_f(framework="CIS Controls v8.1", control_id="99.99")) == {}
