"""Audit a user-uploaded internal policy PDF against framework requirements."""
from __future__ import annotations

from collections.abc import Sequence
from io import BytesIO
from pathlib import Path

from pypdf import PdfReader

from auditor.models import Finding
from auditor.prompts.audit import POLICY_PDF_AUDIT_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve
from auditor.tools._findings_llm import run_findings_chain

_MAX_POLICY_CHARS = 60_000  # rough guard so we don't blow the context window


def extract_pdf_text(source: bytes | Path) -> str:
    reader = PdfReader(BytesIO(source) if isinstance(source, bytes | bytearray) else str(source))
    return "\n\n".join((page.extract_text() or "") for page in reader.pages).strip()


def audit_policy_text(
    policy_text: str,
    frameworks: Sequence[str] | None = None,
    source_artifact: str | None = "internal policy",
) -> list[Finding]:
    if not policy_text.strip():
        return []

    if len(policy_text) > _MAX_POLICY_CHARS:
        policy_text = policy_text[:_MAX_POLICY_CHARS]

    # Pull broad framework guidance — let the LLM judge gaps.
    probe = "security policy required topics access control incident response logging encryption"
    docs = retrieve(probe, frameworks=frameworks, k=20)

    return run_findings_chain(
        POLICY_PDF_AUDIT_PROMPT,
        {
            "policy_text": policy_text,
            "context": format_docs(docs),
            "frameworks": ", ".join(frameworks) if frameworks else "all configured frameworks",
        },
        source_artifact=source_artifact,
    )


def audit_policy_pdf(
    pdf_bytes: bytes,
    frameworks: Sequence[str] | None = None,
    source_artifact: str | None = "policy.pdf",
) -> list[Finding]:
    return audit_policy_text(
        extract_pdf_text(pdf_bytes),
        frameworks=frameworks,
        source_artifact=source_artifact,
    )
