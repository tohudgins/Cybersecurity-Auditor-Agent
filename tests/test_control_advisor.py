"""Tests for the organizational-control advisory path (intent + rendering)."""
from __future__ import annotations

from auditor.intake import is_advisory_request
from auditor.tools.control_advisor import ControlAdvisory, render_advisory_markdown

# ── Intent detection ─────────────────────────────────────────────────────────


def test_advisory_intent_positive():
    assert is_advisory_request("Help me audit our incident response process")
    assert is_advisory_request("assess our vendor risk management program")
    assert is_advisory_request("interview questions for security awareness training")
    assert is_advisory_request("gap analysis for our access review policy")


def test_advisory_intent_negative_leaves_plain_qa_alone():
    # Plain compliance questions must NOT be hijacked into the advisory worksheet.
    assert not is_advisory_request("What does NIST 800-53 AC-2 require?")
    assert not is_advisory_request("Explain the difference between DAC and MAC")
    # An audit verb with no organizational signal is a scan/compliance concern.
    assert not is_advisory_request("audit this repo for CVEs")
    assert not is_advisory_request("")


# ── Rendering ────────────────────────────────────────────────────────────────


def test_render_advisory_worksheet():
    adv = ControlAdvisory(
        topic="Incident Response Process",
        applicable_controls=["NIST 800-53 IR-8", "CIS 17", "SOC 2 CC7.4"],
        objective="Determine whether a documented, tested IR plan exists. [NIST SP 800-61 r3, p.12]",
        interview_questions=["Who declares an incident?", "How often is the plan tested?"],
        evidence_to_request=["The IR plan", "Post-incident review records"],
        common_gaps=["Plan never tested", "No defined roles"],
        citations=["[NIST SP 800-61 r3, p.12]"],
    )
    md = render_advisory_markdown(adv)
    assert "Advisory Assessment — Incident Response Process" in md
    assert "examined and interviewed" in md  # methodology note
    assert "NIST 800-53 IR-8" in md
    assert "Interview questions" in md and "Who declares an incident?" in md
    assert "Evidence to request" in md and "The IR plan" in md
    assert "Common gaps" in md and "Plan never tested" in md
    assert "[NIST SP 800-61 r3, p.12]" in md


def test_render_advisory_none_returns_guidance():
    md = render_advisory_markdown(None)
    assert "No relevant framework excerpts" in md


def test_render_handles_empty_lists():
    adv = ControlAdvisory(topic="X", objective="obj")
    md = render_advisory_markdown(adv)
    assert "_(none identified)_" in md
