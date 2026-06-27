"""Shared data models used across audit tools and agents."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
ArtifactKind = Literal["text", "policy_pdf", "config", "log", "codebase"]

# Where a finding came from. The scanner/heuristic sources are deterministic and
# reproducible; the llm source is AI-assisted analysis and should be presented as
# advisory. `is_deterministic_source()` is the split the report uses.
DetectionSource = Literal["scanner", "heuristic", "llm", "manual"]
Confidence = Literal["high", "medium", "low"]

# Assessment vocabulary modelled on NIST SP 800-53A. A control assessment renders
# one of these states per in-scope control, with the method used to reach it.
ControlStatus = Literal[
    "satisfied", "not-satisfied", "partial", "not-applicable", "not-assessed"
]
AssessmentMethod = Literal["examine", "test", "interview"]


def is_deterministic_source(source: str | None) -> bool:
    """True for scanner/heuristic/manual evidence; False for LLM-generated."""
    return source in ("scanner", "heuristic", "manual")


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
    risk_score: float | None = Field(
        default=None,
        description=(
            "Normalized 0-100 prioritization score blending severity, CVSS, EPSS, and CISA KEV. "
            "Populated by enrichment.risk.normalize_findings; used to rank the report."
        ),
    )
    detection_source: DetectionSource = Field(
        default="scanner",
        description=(
            "Origin of the finding: 'scanner' (external tool), 'heuristic' (built-in "
            "rule), 'llm' (AI-assisted analysis), or 'manual'. Drives the report's "
            "deterministic-vs-AI separation and assessment reproducibility."
        ),
    )
    confidence: Confidence | None = Field(
        default=None,
        description="Optional confidence in the finding (high/medium/low). LLM findings default to medium.",
    )


class ControlAssessment(BaseModel):
    """A verdict on a single in-scope control, modelled on NIST SP 800-53A.

    Real audits assess each control in the selected baseline — not just surface
    problems. A control with findings is 'not-satisfied' (or 'partial'); a control
    a scanner exercised cleanly is 'satisfied'; a control nothing covered is
    'not-assessed'. The honest denominator is what makes a report an audit.
    """

    control_id: str = Field(..., description="Anchor control ID, e.g. 'AC-3'.")
    title: str | None = Field(default=None, description="Human-readable control title.")
    framework: str = Field(default="NIST SP 800-53 Rev. 5", description="Framework the control belongs to.")
    status: ControlStatus = "not-assessed"
    method: AssessmentMethod | None = Field(
        default=None,
        description="How the verdict was reached: examine (config inspection), test (scanner run), interview.",
    )
    rationale: str = Field(default="", description="Why this status — coverage + finding summary.")
    related_findings: list[str] = Field(
        default_factory=list,
        description="Titles of findings that drove a not-satisfied/partial verdict.",
    )


class AuditScope(BaseModel):
    """The engagement scope that drives coverage and risk context."""

    system_name: str = Field(default="Target system", description="Name/label of the system under assessment.")
    baseline: str = Field(
        default="auditor-curated",
        description="Control baseline selected for the engagement (e.g. 'auditor-curated', 'moderate').",
    )
    data_classification: str | None = Field(
        default=None,
        description="Highest data sensitivity handled (e.g. 'PII', 'PHI', 'public'). Modulates impact.",
    )
    internet_facing: bool | None = Field(
        default=None,
        description="Whether the system is internet-facing. Raises likelihood for exposure-related controls.",
    )


class CoverageSummary(BaseModel):
    """Roll-up of a control assessment: the headline coverage numbers."""

    baseline: str
    total_controls: int
    assessed: int
    satisfied: int = 0
    not_satisfied: int = 0
    partial: int = 0
    not_applicable: int = 0
    not_assessed: int = 0

    @property
    def coverage_pct(self) -> float:
        return round(100.0 * self.assessed / self.total_controls, 1) if self.total_controls else 0.0


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
