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
    kev: bool = Field(
        default=False,
        description="True if the underlying CVE is in CISA's Known Exploited Vulnerabilities catalog.",
    )
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs this finding maps to (e.g., 'T1110.001').",
    )
    cvss_score: float | None = Field(
        default=None,
        description="CVSS v3 base score (0.0-10.0) for CVE findings. None if not applicable.",
    )
    cvss_vector: str | None = Field(
        default=None,
        description="CVSS v3 vector string (e.g., 'CVSS:3.1/AV:N/AC:L/...'). None if not applicable.",
    )
    epss_score: float | None = Field(
        default=None,
        description="EPSS probability (0.0-1.0) that the underlying CVE will be exploited in the next 30 days.",
    )
    epss_percentile: float | None = Field(
        default=None,
        description="EPSS percentile (0.0-1.0) — fraction of CVEs this one outranks today.",
    )
    mapped_controls: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Cross-framework mappings populated by enrichment, e.g. "
            "{'NIST CSF 2.1': ['PR.AA-05'], 'CIS Controls v8.1': ['5.4']}."
        ),
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
