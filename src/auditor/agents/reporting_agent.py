"""Reporting agent: turn Findings into a Markdown audit report."""
from __future__ import annotations

from collections import defaultdict

from langchain_core.messages import AIMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from auditor.agents.state import AuditorState
from auditor.config import settings
from auditor.models import Finding
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
    attack_line = ""
    if f.attack_techniques:
        attack_line = f"- **MITRE ATT&CK:** {', '.join(f.attack_techniques)}\n"
    source_line = f"- **Source artifact:** `{f.source_artifact}`\n" if f.source_artifact else ""
    return (
        f"### {idx}. {badge} {f.title}\n"
        f"{framework_line}"
        f"{cvss_line}"
        f"{attack_line}"
        f"{source_line}"
        f"- **Evidence:** {f.evidence}\n"
        f"- **Recommendation:** {f.recommendation}\n"
    )


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
    llm = ChatOpenAI(model=settings.fast_model, api_key=settings.openai_api_key)
    chain = EXECUTIVE_SUMMARY_PROMPT | llm | StrOutputParser()
    return chain.invoke(
        {
            "findings_text": findings_text,
            "frameworks": ", ".join(frameworks) if frameworks else "all configured frameworks",
        }
    )


def _build_report(findings: list[Finding], frameworks: list[str] | None) -> str:
    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    sev_counts: dict[str, int] = defaultdict(int)
    for f in sorted_findings:
        sev_counts[f.severity] += 1
    counts_line = ", ".join(
        f"{sev_counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if sev_counts.get(s)
    ) or "no findings"

    summary = _executive_summary(sorted_findings, frameworks)

    findings_md = "\n".join(_render_finding(i + 1, f) for i, f in enumerate(sorted_findings)) or "_No findings._"

    return (
        "# Cybersecurity Audit Report\n\n"
        f"**Target frameworks:** {', '.join(frameworks) if frameworks else 'all configured'}\n"
        f"**Findings count:** {counts_line}\n\n"
        "## Executive Summary\n\n"
        f"{summary}\n\n"
        "## Findings\n\n"
        f"{findings_md}"
    )


def reporting_node(state: AuditorState) -> dict:
    # If we came from the compliance branch, the answer is already in `final_report`.
    if state.get("route") == "compliance" and state.get("final_report"):
        return {}

    findings = state.get("findings") or []
    frameworks = state.get("target_frameworks") or None
    report = _build_report(findings, frameworks)
    return {
        "final_report": report,
        "messages": [AIMessage(content=report)],
    }
