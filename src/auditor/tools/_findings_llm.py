"""Shared helper: invoke an LLM with structured output and return list[Finding]."""
from __future__ import annotations

from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from auditor.config import settings
from auditor.models import Finding, Severity


class _LLMFinding(BaseModel):
    """The descriptive subset of ``Finding`` the LLM is asked to produce.

    Enrichment fields (kev / cvss / epss / mapped_controls / risk_score /
    attack_techniques) are populated by deterministic downstream code, not the
    model — so they're deliberately excluded here. Keeping the schema to plain
    scalar/string fields also keeps it valid under OpenAI strict structured
    outputs (a ``dict`` field like ``mapped_controls`` is not representable there).
    """

    title: str = Field(..., description="Short, human-readable summary of the issue.")
    severity: Severity = Field("medium", description="info | low | medium | high | critical.")
    framework: str | None = Field(None, description="Framework, e.g. 'NIST SP 800-53 Rev. 5'.")
    control_id: str | None = Field(None, description="Control identifier, e.g. 'AC-7'.")
    evidence: str = Field(..., description="The specific text / line / event the finding is based on.")
    recommendation: str = Field(..., description="What the user should change to remediate.")


class _FindingList(BaseModel):
    findings: list[_LLMFinding]


def run_findings_chain(
    prompt: PromptTemplate,
    inputs: dict,
    model: str | None = None,
    source_artifact: str | None = None,
) -> list[Finding]:
    llm = ChatOpenAI(
        model=model or settings.synthesis_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.audit_reasoning_effort,
    ).with_structured_output(_FindingList)

    chain = prompt | llm
    result: _FindingList = chain.invoke(inputs)
    findings: list[Finding] = []
    for item in result.findings:
        # Promote the descriptive LLM output to a full Finding. Enrichment fields
        # stay at their defaults here; ATT&CK / mapping / risk enrichment fills
        # them downstream. These are AI-generated, so we mark the source and a
        # default confidence so the report can treat them as advisory.
        findings.append(
            Finding(
                title=item.title,
                severity=item.severity,
                framework=item.framework,
                control_id=item.control_id,
                evidence=item.evidence,
                recommendation=item.recommendation,
                source_artifact=source_artifact,
                detection_source="llm",
                confidence="medium",
            )
        )
    return findings
