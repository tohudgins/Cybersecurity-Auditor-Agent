"""Shared helper: invoke an LLM with structured output and return list[Finding]."""
from __future__ import annotations

from pydantic import BaseModel
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

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
    ).with_structured_output(_FindingList)

    chain = prompt | llm
    result: _FindingList = chain.invoke(inputs)
    findings = list(result.findings)
    if source_artifact:
        for f in findings:
            if f.source_artifact is None:
                f.source_artifact = source_artifact
    return findings
