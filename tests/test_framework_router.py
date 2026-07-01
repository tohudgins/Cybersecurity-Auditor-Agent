"""Tests for query→framework routing (retrieval scoping) and the re-ranker."""
from __future__ import annotations

from langchain_core.documents import Document

from auditor.retrieval.framework_router import detect_frameworks
from auditor.retrieval.retriever import _rerank


def test_detects_named_frameworks():
    assert detect_frameworks("PCI DSS Requirement 8") == ["PCI DSS v4.0.1"]
    assert detect_frameworks("assess our SOC 2 CC6.1") == ["SOC 2 Trust Services Criteria"]
    assert "HIPAA Security Rule (45 CFR Part 164)" in detect_frameworks("HIPAA 164.312")
    assert detect_frameworks("CMMC Level 3 requirements") == ["CMMC 2.0 Level 3 (Assessment Guide)"]


def test_nist_number_routing_includes_assessment_procedures():
    got = detect_frameworks("what does 800-53 AC-2 require")
    assert "NIST SP 800-53 Rev. 5" in got
    assert "NIST SP 800-53A Rev. 5 (Assessment Procedures)" in got
    # 800-53A alone should not pull in the base catalog's *primary* slot only.
    assert detect_frameworks("800-53A assessment objective") == [
        "NIST SP 800-53A Rev. 5 (Assessment Procedures)"
    ]


def test_topic_only_queries_do_not_scope():
    # No explicit framework name → corpus-wide (empty).
    assert detect_frameworks("what controls prevent ransomware") == []
    assert detect_frameworks("how do I harden access control") == []
    assert detect_frameworks("") == []


def test_cmmc_generic_returns_all_levels():
    got = detect_frameworks("CMMC certification scope")
    assert len(got) == 3 and all("CMMC" in g for g in got)


def _doc(fw, cid="", text="some text about access control"):
    return Document(page_content=text, metadata={"framework": fw, "control_id": cid})


def test_rerank_floats_exact_control_id_match():
    docs = [
        _doc("NIST SP 800-53 Rev. 5", "AC-3", "access enforcement"),
        _doc("NIST SP 800-53 Rev. 5", "AC-2", "AC-2 account management define and document accounts"),
    ]
    # Query names AC-2 → the AC-2 chunk should be re-ranked to the top.
    out = _rerank("what does AC-2 account management require", docs, None, k=2)
    assert out[0].metadata["control_id"] == "AC-2"


def test_rerank_boosts_named_framework():
    docs = [
        _doc("CMMC 2.0 Level 2 (Assessment Guide)", text="logical access controls"),
        _doc("SOC 2 Trust Services Criteria", text="logical access controls CC6.1"),
    ]
    out = _rerank("SOC 2 logical access", docs, ["SOC 2 Trust Services Criteria"], k=2)
    assert out[0].metadata["framework"] == "SOC 2 Trust Services Criteria"
