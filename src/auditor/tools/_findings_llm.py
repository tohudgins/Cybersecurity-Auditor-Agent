"""Shared helper: invoke an LLM with structured output and return list[Finding]."""
from __future__ import annotations

from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from auditor.config import settings
from auditor.models import Finding


class _FindingList(BaseModel):
    findings: list[Finding]


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
    findings = list(result.findings)
    for f in findings:
        # These are AI-generated; mark them so the report can separate them from
        # deterministic scanner/heuristic evidence and treat them as advisory.
        f.detection_source = "llm"
        if f.confidence is None:
            f.confidence = "medium"
        if source_artifact and f.source_artifact is None:
            f.source_artifact = source_artifact
    return findings
