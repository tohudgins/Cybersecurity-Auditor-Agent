"""Audit a sample of system logs for compliance-relevant events."""
from __future__ import annotations

import re
from collections import Counter
from typing import Sequence

from auditor.models import Finding
from auditor.prompts.audit import LOG_AUDIT_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve
from auditor.tools._findings_llm import run_findings_chain


_FAILED_LOGIN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)", re.IGNORECASE)
_ROOT_LOGIN = re.compile(r"Accepted (?:password|publickey) for root from", re.IGNORECASE)
_SUDO = re.compile(r"sudo:\s+(\S+)\s*:.*COMMAND=(.+)$", re.IGNORECASE)
_BRUTE_THRESHOLD = 5


def _heuristic_log_findings(log_text: str) -> list[Finding]:
    findings: list[Finding] = []

    failed_by_ip: Counter[str] = Counter()
    for m in _FAILED_LOGIN.finditer(log_text):
        failed_by_ip[m.group(2)] += 1
    for ip, count in failed_by_ip.items():
        if count >= _BRUTE_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Brute-force pattern: {count} failed logins from {ip}",
                    severity="high",
                    framework="NIST SP 800-53 Rev. 5",
                    control_id="AC-7",
                    evidence=f"{count} `Failed password` events from {ip} in the sample.",
                    recommendation=(
                        "Enforce automatic account lockout after consecutive failures and consider "
                        "fail2ban / IP-based rate limiting at the firewall."
                    ),
                )
            )

    if _ROOT_LOGIN.search(log_text):
        findings.append(
            Finding(
                title="Direct root SSH login observed",
                severity="high",
                framework="CIS Controls v8.1",
                control_id="5.4",
                evidence=_ROOT_LOGIN.search(log_text).group(0),  # type: ignore[union-attr]
                recommendation=(
                    "Disable direct root login (`PermitRootLogin no`) and require named accounts "
                    "with sudo for privileged actions."
                ),
            )
        )

    sudo_count = sum(1 for _ in _SUDO.finditer(log_text))
    if sudo_count > 0 and not re.search(r"audit|auditd|rsyslog", log_text, re.IGNORECASE):
        findings.append(
            Finding(
                title="Privileged commands executed without visible audit trail",
                severity="medium",
                framework="NIST SP 800-53 Rev. 5",
                control_id="AU-2",
                evidence=f"{sudo_count} sudo invocations present; no auditd / rsyslog markers in sample.",
                recommendation=(
                    "Confirm auditd is enabled and that sudo invocations are forwarded to a "
                    "tamper-resistant log store."
                ),
            )
        )

    return findings


def audit_logs(
    log_text: str,
    frameworks: Sequence[str] | None = None,
    source_artifact: str | None = "log sample",
) -> list[Finding]:
    if not log_text.strip():
        return []

    heuristic = _heuristic_log_findings(log_text)
    for f in heuristic:
        f.source_artifact = source_artifact

    probe = "audit logging account lockout failed login monitoring detection"
    docs = retrieve(probe, frameworks=frameworks, k=10)

    heuristic_summary = (
        "\n".join(f"- {f.title} ({f.severity}): {f.evidence}" for f in heuristic)
        or "(no heuristic findings)"
    )

    llm_findings = run_findings_chain(
        LOG_AUDIT_PROMPT,
        {
            "log_text": log_text[:30_000],
            "context": format_docs(docs),
            "frameworks": ", ".join(frameworks) if frameworks else "all configured frameworks",
            "heuristic_findings": heuristic_summary,
        },
        source_artifact=source_artifact,
    )

    seen_titles = {f.title.lower() for f in heuristic}
    deduped = [f for f in llm_findings if f.title.lower() not in seen_titles]
    return heuristic + deduped
