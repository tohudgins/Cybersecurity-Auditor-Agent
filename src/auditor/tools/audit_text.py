"""Audit a free-text system description against the framework corpus."""
from __future__ import annotations

from typing import Sequence

from auditor.models import Finding
from auditor.prompts.audit import SYSTEM_DESCRIPTION_AUDIT_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve
from auditor.tools._findings_llm import run_findings_chain


def audit_system_description(
    description: str,
    frameworks: Sequence[str] | None = None,
    source_artifact: str | None = "system description",
) -> list[Finding]:
    docs = retrieve(description, frameworks=frameworks, k=15)
    return run_findings_chain(
        SYSTEM_DESCRIPTION_AUDIT_PROMPT,
        {
            "description": description,
            "context": format_docs(docs),
            "frameworks": ", ".join(frameworks) if frameworks else "all configured frameworks",
        },
        source_artifact=source_artifact,
    )
