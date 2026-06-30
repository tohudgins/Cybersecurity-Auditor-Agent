"""Shared helper: invoke an LLM with structured output and return list[Finding]."""
from __future__ import annotations

import contextvars
import re

from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from auditor.config import settings
from auditor.models import Finding, Severity

# Per-run toggle for the AI narrative layer. Fast/deterministic mode flips this
# off so every audit tool returns only its scanner/heuristic findings — no LLM
# call, sub-second per tool. A ContextVar (not a global) so it's set per audit
# run and propagates into the audit ThreadPoolExecutor via copy_context().
_llm_analysis: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "audit_llm_analysis", default=True
)


def set_llm_analysis(enabled: bool) -> None:
    """Enable/disable the LLM narrative layer for the current context."""
    _llm_analysis.set(enabled)


def llm_analysis_enabled() -> bool:
    return _llm_analysis.get()


_NIST_FRAMEWORK = "NIST SP 800-53 Rev. 5"
# A clean 800-53 control ID, optionally with an enhancement: AC-2, AC-2(1), SC-7.
_NIST_ID_RE = re.compile(r"[A-Z]{2}-\d+(?:\(\d+\))?")


def _clean_nist_control_id(control_id: str | None, framework: str | None) -> str | None:
    """Strip page refs / extra text from an LLM-extracted 800-53 control ID.

    The LLM sometimes copies control IDs out of policy text with surrounding
    noise (``"AC-16(4) (p.71)"``, ``"IR-1/IR-7 (pp.176,185)"``). Reduce those to
    the first canonical control ID so the assessment table stays clean. Only
    applied to 800-53-framed findings — other frameworks (CSF "PR.AA-01", CIS
    numeric) have different ID shapes and are left untouched.
    """
    if not control_id or framework != _NIST_FRAMEWORK:
        return control_id
    m = _NIST_ID_RE.search(control_id.upper())
    return m.group(0) if m else control_id


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
    # Fast/deterministic mode: skip the LLM entirely; the tool keeps only its
    # scanner/heuristic findings.
    if not _llm_analysis.get():
        return []

    llm = ChatOpenAI(
        model=model or settings.audit_model,
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
                control_id=_clean_nist_control_id(item.control_id, item.framework),
                evidence=item.evidence,
                recommendation=item.recommendation,
                source_artifact=source_artifact,
                detection_source="llm",
                confidence="medium",
            )
        )
    return findings
