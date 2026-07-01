"""Advisory auditor for organizational / process controls (the RAG-grounded path).

The technical scanners assess configuration and code. But most of a real audit —
governance, personnel security, awareness training, incident-response *process*,
vendor risk, physical security, contingency planning — is examined and
interviewed, not scanned (NIST SP 800-53A methods "Examine" / "Interview").

This module is that second **way to audit**: given a topic, it retrieves the
relevant framework text and turns it into an auditor's worksheet — the
assessment objective, interview questions for the control owners, the evidence
to request, and the common deficiencies — all grounded in and cited to the
corpus. It complements the technical assessment; it does not scan anything.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from auditor.config import settings
from auditor.enrichment.corpus_coverage import caveat_for
from auditor.prompts.advisory import CONTROL_ADVISORY_PROMPT, CONTROL_ASSESSMENT_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve

_NO_DOCS_MSG = (
    "No relevant framework excerpts were found for that topic. Try naming a "
    "control area (e.g. \"incident response process\", \"vendor risk management\", "
    "\"security awareness training\", \"access reviews\")."
)


class ControlAdvisory(BaseModel):
    """An auditor's worksheet for one organizational/process control topic."""

    topic: str = Field(..., description="The control area being assessed.")
    applicable_controls: list[str] = Field(
        default_factory=list, description="Controls this topic maps to (framework IDs/labels)."
    )
    objective: str = Field(..., description="What an assessor is trying to determine, cited.")
    interview_questions: list[str] = Field(
        default_factory=list, description="Questions to ask the control owners."
    )
    evidence_to_request: list[str] = Field(
        default_factory=list, description="Documents/records to collect as evidence."
    )
    common_gaps: list[str] = Field(
        default_factory=list, description="Typical deficiencies auditors find here."
    )
    citations: list[str] = Field(
        default_factory=list, description="Distinct [Framework, p.N] sources relied on."
    )
    coverage_note: str = Field(
        default="", description="Honesty caveat when the topic names an un-indexed framework."
    )


def advise_controls(
    topic: str,
    frameworks: Sequence[str] | None = None,
) -> ControlAdvisory | None:
    """Produce a RAG-grounded advisory worksheet for an organizational-control topic.

    Returns ``None`` when the corpus has nothing relevant (the caller renders the
    no-docs guidance message).
    """
    docs = retrieve(topic, frameworks=frameworks)
    if not docs:
        return None

    llm = ChatOpenAI(
        model=settings.audit_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.synthesis_reasoning_effort,
    ).with_structured_output(ControlAdvisory)
    chain = CONTROL_ADVISORY_PROMPT | llm
    advisory: ControlAdvisory = chain.invoke({"context": format_docs(docs), "topic": topic})
    if not advisory.topic:
        advisory.topic = topic
    advisory.coverage_note = caveat_for(topic)
    return advisory


class _OrgVerdict(BaseModel):
    """One control's interview-method verdict."""

    control: str = Field(..., description="Framework ID + short name, e.g. 'NIST 800-53 IR-8'.")
    title: str = Field(default="", description="Control title.")
    status: Literal["satisfied", "partial", "not-satisfied", "not-assessed"] = "not-assessed"
    rationale: str = Field(..., description="Verdict basis: requirement (cited) vs the response.")
    evidence_gap: str = Field(default="", description="What to provide/implement to reach satisfied.")


class OrganizationalAssessment(BaseModel):
    """Interview/examine assessment of process controls from auditee responses."""

    topic: str
    verdicts: list[_OrgVerdict] = Field(default_factory=list)
    summary: str = ""
    coverage_note: str = ""


def assess_organizational_controls(
    topic: str,
    responses: str,
    frameworks: Sequence[str] | None = None,
) -> OrganizationalAssessment | None:
    """Close the advisory loop: given the auditee's *responses*, produce an
    interview/examine assessment (per-control verdicts). Returns ``None`` when the
    corpus has nothing relevant to assess against."""
    docs = retrieve(topic, frameworks=frameworks)
    if not docs:
        return None
    llm = ChatOpenAI(
        model=settings.audit_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.synthesis_reasoning_effort,
    ).with_structured_output(OrganizationalAssessment)
    chain = CONTROL_ASSESSMENT_PROMPT | llm
    result: OrganizationalAssessment = chain.invoke(
        {"context": format_docs(docs), "topic": topic, "responses": responses}
    )
    if not result.topic:
        result.topic = topic
    result.coverage_note = caveat_for(topic)
    return result


_STATUS_BADGE = {
    "satisfied": "🟢 Satisfied",
    "partial": "🟡 Partial",
    "not-satisfied": "🔴 Not Satisfied",
    "not-assessed": "⚪ Not Assessed",
}


def render_organizational_assessment_markdown(a: OrganizationalAssessment | None) -> str:
    """Render an :class:`OrganizationalAssessment` as a Markdown workpaper."""
    if a is None:
        return _NO_DOCS_MSG
    counts: dict[str, int] = {}
    for v in a.verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    tally = " · ".join(f"{n} {_STATUS_BADGE.get(s, s)}" for s, n in counts.items()) or "—"

    lines = [
        f"## Organizational Control Assessment — {a.topic}\n",
        "_Interview + examine assessment (NIST SP 800-53A) based on your stated practices — the "
        "process-control counterpart to the technical scan._\n",
    ]
    if a.coverage_note:
        lines.append(a.coverage_note + "\n")
    if a.summary:
        lines.append(f"**Summary:** {a.summary}\n")
    lines.append(f"**Verdicts:** {tally}\n")
    lines.append("| Control | Status | Rationale | Evidence gap |")
    lines.append("|---|---|---|---|")
    for v in a.verdicts:
        ctrl = f"{v.control}" + (f" — {v.title}" if v.title else "")
        rat = (v.rationale or "").replace("\n", " ").replace("|", "\\|")
        gap = (v.evidence_gap or "—").replace("\n", " ").replace("|", "\\|")
        lines.append(f"| {ctrl} | {_STATUS_BADGE.get(v.status, v.status)} | {rat} | {gap} |")
    return "\n".join(lines) + "\n"


def render_advisory_markdown(advisory: ControlAdvisory | None) -> str:
    """Render a :class:`ControlAdvisory` as a Markdown audit worksheet."""
    if advisory is None:
        return _NO_DOCS_MSG

    def _bullets(items: list[str]) -> str:
        return "\n".join(f"- {i}" for i in items) if items else "_(none identified)_"

    parts = [
        f"## Advisory Assessment — {advisory.topic}\n",
        "_Organizational / process controls are **examined and interviewed**, not scanned "
        "(NIST SP 800-53A). Use this worksheet to assess them manually; it complements the "
        "technical scan._\n",
    ]
    if advisory.coverage_note:
        parts.append(advisory.coverage_note + "\n")
    parts += [
        "**Applicable controls:** "
        + (", ".join(advisory.applicable_controls) if advisory.applicable_controls else "—"),
        f"\n**Assessment objective:** {advisory.objective}\n",
        "### Interview questions (ask the control owners)",
        _bullets(advisory.interview_questions),
        "\n### Evidence to request",
        _bullets(advisory.evidence_to_request),
        "\n### Common gaps auditors find",
        _bullets(advisory.common_gaps),
    ]
    if advisory.citations:
        parts.append("\n**Sources:** " + "; ".join(advisory.citations))
    parts.append(
        "\n---\n_**Reply with your answers** to these questions and I'll produce an "
        "interview-method assessment — a satisfied / partial / not-satisfied verdict per "
        "control, with the evidence gaps._"
    )
    return "\n".join(parts)
