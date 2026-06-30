"""Reporting agent: turn Findings into a Markdown audit report."""
from __future__ import annotations

from collections import defaultdict

from langchain_core.messages import AIMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from auditor.agents.state import AuditorState
from auditor.config import settings
from auditor.diff import diff_findings, render_remediation_section
from auditor.enrichment.risk import compute_risk_score
from auditor.models import (
    ControlAssessment,
    CoverageSummary,
    Finding,
    is_deterministic_source,
)
from auditor.prompts.reporting import EXECUTIVE_SUMMARY_PROMPT

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_BADGE = {
    "critical": "**[CRITICAL]**",
    "high": "**[HIGH]**",
    "medium": "**[MEDIUM]**",
    "low": "**[LOW]**",
    "info": "**[INFO]**",
}


def _render_finding(idx: int, f: Finding) -> str:
    badge = _SEVERITY_BADGE.get(f.severity, f"**[{f.severity.upper()}]**")
    if f.kev:
        badge = "**[KEV - actively exploited]** " + badge

    score = f.risk_score if f.risk_score is not None else compute_risk_score(f)
    risk_line = f"- **Risk score:** {score:.0f} / 100\n"

    framework_line = ""
    if f.framework or f.control_id:
        framework_line = f"- **Mapped control:** {f.framework or 'unspecified'}"
        if f.control_id:
            framework_line += f" — {f.control_id}"
        framework_line += "\n"
    cvss_line = ""
    if f.cvss_score is not None:
        qual = _cvss_qualifier(f.cvss_score)
        cvss_line = f"- **CVSS v3 base score:** {f.cvss_score:.1f} ({qual})"
        if f.cvss_vector:
            cvss_line += f" — `{f.cvss_vector}`"
        cvss_line += "\n"
    epss_line = ""
    if f.epss_score is not None:
        pct_label = f"top {(1 - f.epss_percentile) * 100:.1f}%" if f.epss_percentile is not None else ""
        epss_line = f"- **EPSS:** {f.epss_score:.4f}"
        if pct_label:
            epss_line += f" ({pct_label} most likely to be exploited)"
        epss_line += "\n"
    attack_line = ""
    if f.attack_techniques:
        attack_line = f"- **MITRE ATT&CK:** {', '.join(f.attack_techniques)}\n"
    mappings_line = ""
    if f.mapped_controls:
        rendered = "; ".join(
            f"{fw}: {', '.join(ids)}" for fw, ids in f.mapped_controls.items()
        )
        mappings_line = f"- **Cross-framework:** {rendered}\n"
    source_line = f"- **Source artifact:** `{f.source_artifact}`\n" if f.source_artifact else ""
    det = "deterministic" if is_deterministic_source(f.detection_source) else "AI-assisted"
    conf = f", {f.confidence} confidence" if f.confidence else ""
    detection_line = f"- **Detection:** {f.detection_source} ({det}{conf})\n"
    return (
        f"### {idx}. {badge} {f.title}\n"
        f"{risk_line}"
        f"{framework_line}"
        f"{cvss_line}"
        f"{epss_line}"
        f"{attack_line}"
        f"{mappings_line}"
        f"{detection_line}"
        f"{source_line}"
        f"- **Evidence:** {f.evidence}\n"
        f"- **Recommendation:** {f.recommendation}\n"
    )


_STATUS_LABEL = {
    "satisfied": "Satisfied",
    "not-satisfied": "Not Satisfied",
    "partial": "Partial",
    "not-applicable": "Not Applicable",
    "not-assessed": "Not Assessed",
}


def _render_coverage(coverage: CoverageSummary) -> str:
    """Headline control-coverage table — the part that makes this an audit."""
    rows = [
        ("Satisfied", coverage.satisfied),
        ("Not Satisfied", coverage.not_satisfied),
        ("Partial", coverage.partial),
        ("Not Applicable", coverage.not_applicable),
        ("Not Assessed", coverage.not_assessed),
    ]
    body = "\n".join(f"| {label} | {count} |" for label, count in rows)
    return (
        "## Control Coverage\n\n"
        f"**Baseline:** {coverage.baseline} — "
        f"**{coverage.assessed} of {coverage.total_controls} controls assessed "
        f"({coverage.coverage_pct:.0f}%)**\n\n"
        "| Status | Controls |\n|---|---|\n"
        f"{body}\n\n"
        "_\"Satisfied\" means the automated checks that exercise a control surfaced "
        "no findings for the aspect tested — not a full control attestation. "
        "\"Not Assessed\" controls had no in-scope artifact exercising them; supply "
        "additional artifacts (config, logs, codebase, policy) to broaden coverage._\n"
    )


def _render_assessment_detail(assessments: list[ControlAssessment]) -> str:
    """Per-control verdict table for controls that were actually assessed."""
    assessed = [a for a in assessments if a.status != "not-assessed"]
    if not assessed:
        return ""
    order = {"not-satisfied": 0, "partial": 1, "satisfied": 2, "not-applicable": 3}
    assessed.sort(key=lambda a: (order.get(a.status, 9), a.control_id))
    rows = []
    for a in assessed:
        title = a.title or ""
        method = a.method or "—"
        rows.append(
            f"| {a.control_id} | {title} | {_STATUS_LABEL.get(a.status, a.status)} | {method} |"
        )
    return (
        "## Control Assessment\n\n"
        "| Control | Title | Status | Method |\n|---|---|---|---|\n"
        + "\n".join(rows)
        + "\n"
    )


# 800-53 families dominated by management/operational (process) controls that
# automated scanning can't test — they need document examination + personnel
# interviews (per SP 800-53A). Surfaced in the limitations so coverage gaps in
# these families read as "out of automated scope", not "missed".
_PROCESS_FAMILIES = {
    "AT": "Awareness & Training",
    "CA": "Assessment, Authorization & Monitoring",
    "CP": "Contingency Planning",
    "IR": "Incident Response (process)",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical & Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing & Transparency",
    "SA": "System & Services Acquisition",
    "SR": "Supply Chain Risk Management",
}


def _render_limitations(
    findings: list[Finding],
    coverage: CoverageSummary | None,
    assessments: list[ControlAssessment] | None,
    artifact_kinds: list[str] | None,
) -> str:
    """A Scope & Limitations section — what was assessed, how, and what an
    automated audit cannot attest to. This is what makes the output read like a
    real assessor wrote it rather than a scanner dump."""
    deterministic = sum(1 for f in findings if is_deterministic_source(f.detection_source))
    ai_assisted = len(findings) - deterministic

    lines: list[str] = ["## Scope & Limitations\n"]

    if artifact_kinds:
        kinds = ", ".join(sorted(set(artifact_kinds)))
        lines.append(f"- **Artifacts assessed:** {kinds}.")
    if coverage:
        lines.append(
            f"- **Assessment baseline:** {coverage.baseline} — "
            f"{coverage.assessed} of {coverage.total_controls} controls assessed "
            f"({coverage.coverage_pct:.0f}%); {coverage.not_assessed} not assessed."
        )

    # Which process-heavy families went unassessed → explicitly out of automated scope.
    unassessed_process: dict[str, str] = {}
    for a in assessments or []:
        if a.status == "not-assessed":
            fam = a.control_id.split("-")[0]
            if fam in _PROCESS_FAMILIES:
                unassessed_process[fam] = _PROCESS_FAMILIES[fam]
    if unassessed_process:
        fams = ", ".join(f"{name} ({fam})" for fam, name in sorted(unassessed_process.items()))
        lines.append(
            "- **Organizational & process controls were not technically tested.** "
            "Automated scanning evaluates technical configuration and code; it cannot "
            "examine governance evidence or interview personnel. Controls in these "
            f"families need manual examination/interview to assess: {fams}."
        )

    lines.append(
        f"- **Evidence basis:** {deterministic} deterministic (scanner/heuristic) and "
        f"{ai_assisted} AI-assisted finding(s). AI-assisted findings are advisory — "
        "validate each against the source before remediation or attestation."
    )
    lines.append(
        "- **Point-in-time:** results reflect the state of the supplied artifacts at "
        "scan time and are not a continuous-monitoring attestation."
    )
    lines.append(
        "- **\"Satisfied\" is scoped to the aspect tested** — it indicates the automated "
        "check found no issue, not a full control attestation."
    )
    return "\n".join(lines) + "\n"


def _cvss_qualifier(score: float) -> str:
    """Map a CVSS v3 base score to its qualitative rating per spec."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def _executive_summary(findings: list[Finding], frameworks: list[str] | None) -> str:
    if not findings:
        return "No compliance findings were produced. The provided artifacts did not surface any issues against the selected frameworks."

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.title} (framework: {f.framework or 'n/a'}, control: {f.control_id or 'n/a'})"
        for f in findings
    )
    llm = ChatOpenAI(
        model=settings.fast_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.audit_reasoning_effort,
    )
    chain = EXECUTIVE_SUMMARY_PROMPT | llm | StrOutputParser()
    return chain.invoke(
        {
            "findings_text": findings_text,
            "frameworks": ", ".join(frameworks) if frameworks else "all configured frameworks",
        }
    )


_SUPPRESSION_LABEL = {
    "accepted-risk": "Accepted Risk",
    "false-positive": "False Positive",
}


def _render_suppressions(suppressed: list[dict] | None) -> str:
    """Render dispositioned findings (accepted risk / false positive).

    Suppressed findings are kept out of the active findings + assessment, but
    surfaced here for auditability — a real register shows what was accepted, by
    what rationale, never silently hides it."""
    if not suppressed:
        return ""
    lines = [
        "## Accepted Risks & Suppressed Findings\n",
        "_These findings were previously dispositioned and are excluded from the "
        "active findings and control assessment above. They remain recorded for "
        "auditability._\n",
    ]
    for s in suppressed:
        label = _SUPPRESSION_LABEL.get(s.get("kind", ""), s.get("kind", "suppressed"))
        sev = str(s.get("severity", "")).upper()
        cid = f" — {s['control_id']}" if s.get("control_id") else ""
        expiry = f" (expires {s['expires_at']})" if s.get("expires_at") else ""
        lines.append(f"- **[{label}]** [{sev}] {s.get('title', '(untitled)')}{cid}{expiry}")
        if s.get("reason"):
            lines.append(f"  - _Rationale:_ {s['reason']}")
    return "\n".join(lines) + "\n"


def _render_plan(notes: list[str] | None) -> str:
    """Render the adaptive scope-planning notes as an 'Audit Plan' section."""
    if not notes:
        return ""
    body = "\n".join(f"- {n}" for n in notes)
    return (
        "## Audit Plan\n\n"
        "_The agent expanded the assessment scope beyond the targets you named:_\n\n"
        f"{body}\n"
    )


def _render_recommendations(recommendations: list[str] | None) -> str:
    """Render advisory next steps the agent surfaced but deliberately did not run."""
    if not recommendations:
        return ""
    body = "\n".join(f"- {r}" for r in recommendations)
    return (
        "## Recommended Next Steps\n\n"
        "_Adjacent assessments the agent did **not** run on its own because they "
        "touch live, credentialed, or personal systems — run them yourself if "
        "appropriate:_\n\n"
        f"{body}\n"
    )


def _build_report(
    findings: list[Finding],
    frameworks: list[str] | None,
    assessments: list[ControlAssessment] | None = None,
    coverage: CoverageSummary | None = None,
    previous_findings: list[dict] | None = None,
    previous_run_at: str | None = None,
    plan_notes: list[str] | None = None,
    recommendations: list[str] | None = None,
    artifact_kinds: list[str] | None = None,
    suppressed_findings: list[dict] | None = None,
) -> str:
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -(f.risk_score if f.risk_score is not None else compute_risk_score(f)),
            _SEVERITY_ORDER.get(f.severity, 99),
            f.title.lower(),
        ),
    )

    sev_counts: dict[str, int] = defaultdict(int)
    for f in sorted_findings:
        sev_counts[f.severity] += 1
    counts_line = ", ".join(
        f"{sev_counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if sev_counts.get(s)
    ) or "no findings"

    deterministic = sum(1 for f in sorted_findings if is_deterministic_source(f.detection_source))
    ai_assisted = len(sorted_findings) - deterministic
    provenance_line = (
        f"**Evidence basis:** {deterministic} deterministic (scanner/heuristic), "
        f"{ai_assisted} AI-assisted\n"
    )

    summary = _executive_summary(sorted_findings, frameworks)

    findings_md = "\n".join(_render_finding(i + 1, f) for i, f in enumerate(sorted_findings)) or "_No findings._"

    plan_md = _render_plan(plan_notes)
    plan_md = plan_md + "\n" if plan_md else ""

    recommendations_md = _render_recommendations(recommendations)
    recommendations_md = recommendations_md + "\n" if recommendations_md else ""

    remediation_md = ""
    if previous_findings is not None:
        diff = diff_findings(previous_findings, sorted_findings, previous_run_at)
        remediation_md = render_remediation_section(diff) + "\n"

    coverage_md = _render_coverage(coverage) + "\n" if coverage else ""
    assessment_md = _render_assessment_detail(assessments) + "\n" if assessments else ""
    limitations_md = (
        _render_limitations(sorted_findings, coverage, assessments, artifact_kinds) + "\n"
        if (coverage or assessments)
        else ""
    )
    suppressed_md = _render_suppressions(suppressed_findings)
    suppressed_md = suppressed_md + "\n" if suppressed_md else ""

    return (
        "# Cybersecurity Audit Report\n\n"
        f"**Target frameworks:** {', '.join(frameworks) if frameworks else 'all configured'}\n"
        f"**Findings count:** {counts_line}\n"
        f"{provenance_line}\n"
        "## Executive Summary\n\n"
        f"{summary}\n\n"
        f"{plan_md}"
        f"{recommendations_md}"
        f"{remediation_md}"
        f"{coverage_md}"
        f"{assessment_md}"
        f"{limitations_md}"
        f"{suppressed_md}"
        "## Findings\n\n"
        f"{findings_md}"
    )


def reporting_node(state: AuditorState) -> dict:
    # If we came from the compliance branch, the answer is already in `final_report`.
    if state.get("route") == "compliance" and state.get("final_report"):
        return {}

    findings = state.get("findings") or []
    frameworks = state.get("target_frameworks") or None
    assessments = state.get("assessments") or None
    coverage = state.get("coverage") or None
    previous_findings = state.get("previous_findings")
    previous_run_at = state.get("previous_run_at")
    plan_notes = state.get("plan_notes")
    recommendations = state.get("recommendations")
    artifact_kinds = [a.kind for a in (state.get("artifacts") or [])]
    suppressed_findings = state.get("suppressed_findings")
    report = _build_report(
        findings, frameworks, assessments, coverage,
        previous_findings=previous_findings, previous_run_at=previous_run_at,
        plan_notes=plan_notes, recommendations=recommendations,
        artifact_kinds=artifact_kinds, suppressed_findings=suppressed_findings,
    )
    return {
        "final_report": report,
        "messages": [AIMessage(content=report)],
    }
