"""Shared data models used across audit tools and agents."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
ArtifactKind = Literal["text", "policy_pdf", "config", "log", "codebase"]


class Finding(BaseModel):
    """A single audit observation produced by an audit tool."""

    title: str = Field(..., description="Short, human-readable summary of the issue.")
    severity: Severity = "medium"
    framework: str | None = Field(
        default=None,
        description="Framework the finding maps to (e.g., 'NIST SP 800-53 Rev. 5').",
    )
    control_id: str | None = Field(
        default=None,
        description="Control identifier within the framework (e.g., 'AC-7', 'CIS 6.5').",
    )
    evidence: str = Field(..., description="The specific text / line / event the finding is based on.")
    recommendation: str = Field(..., description="What the user should change to remediate.")
    source_artifact: str | None = Field(
        default=None,
        description="Filename or label of the artifact this finding came from.",
    )


class Artifact(BaseModel):
    """A user-uploaded artifact to be audited."""

    kind: ArtifactKind
    name: str = Field(..., description="Original filename or 'pasted text'.")
    content: str = Field(
        ...,
        description=(
            "Raw text content; PDFs are pre-extracted before reaching here. "
            "Exception: for kind='codebase', this holds the directory path to scan."
        ),
    )
