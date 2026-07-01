"""Tests for multi-turn memory, crosswalk-mapping injection, and advisory assessment."""
from __future__ import annotations

from auditor.enrichment.mappings import crosswalk_context, reset_cache
from auditor.intake import looks_like_responses
from auditor.tools.compliance_qa import _format_history, _retrieval_query
from auditor.tools.control_advisor import (
    OrganizationalAssessment,
    _OrgVerdict,
    render_organizational_assessment_markdown,
)


def setup_function():
    reset_cache()


# ── Crosswalk injection (mapping questions) ──────────────────────────────────


def test_crosswalk_context_on_mapping_intent():
    ctx = crosswalk_context("how does AC-2 map to CIS and PCI?")
    assert "AC-2" in ctx and ("CIS" in ctx or "PCI" in ctx) and "[crosswalk]" in ctx


def test_crosswalk_context_empty_without_mapping_intent():
    assert crosswalk_context("what does AC-2 require?") == ""   # no mapping intent
    assert crosswalk_context("compare our two firewalls") == ""  # intent but no control ID


# ── Multi-turn memory ────────────────────────────────────────────────────────


def test_format_history_bounded():
    hist = [("user", "q1"), ("assistant", "a1"), ("user", "q2")]
    out = _format_history(hist)
    assert "Conversation so far" in out and "User: q2" in out
    assert _format_history(None) == "" and _format_history([]) == ""


def test_retrieval_query_expands_terse_followups():
    hist = [("user", "What does NIST 800-53 IA-5 require?"), ("assistant", "…")]
    # Terse follow-up gets the prior user turn prepended for retrieval.
    assert "IA-5" in _retrieval_query("what about the enhancement?", hist)
    # A full question is used as-is.
    q = "What does PCI DSS Requirement 8 require for MFA?"
    assert _retrieval_query(q, hist) == q


# ── Advisory assessment (closing the loop) ───────────────────────────────────


def test_looks_like_responses():
    assert looks_like_responses(
        "We have a documented incident response plan tested annually with defined roles, "
        "but we do not perform post-incident reviews."
    )
    assert not looks_like_responses("assess our incident response process")  # a request
    assert not looks_like_responses("we have a plan")  # too short


def test_render_organizational_assessment():
    a = OrganizationalAssessment(
        topic="Incident Response",
        summary="Partially mature; IR plan exists but untested reviews.",
        verdicts=[
            _OrgVerdict(control="NIST 800-53 IR-8", title="IR Plan", status="satisfied",
                        rationale="Documented plan exists [NIST SP 800-61 r3, p.12].", evidence_gap=""),
            _OrgVerdict(control="NIST 800-53 IR-4", title="Incident Handling", status="partial",
                        rationale="No post-incident review.", evidence_gap="Add lessons-learned process."),
        ],
    )
    md = render_organizational_assessment_markdown(a)
    assert "Organizational Control Assessment — Incident Response" in md
    assert "interview + examine" in md.lower()
    assert "IR-8" in md and "Satisfied" in md and "Partial" in md
    assert "lessons-learned" in md


def test_render_organizational_assessment_none():
    assert "No relevant framework excerpts" in render_organizational_assessment_markdown(None)
