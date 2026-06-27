"""Audit a sample of system logs for compliance-relevant events."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from auditor.models import Finding
from auditor.prompts.audit import LOG_AUDIT_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve
from auditor.tools._findings_llm import run_findings_chain

_FAILED_LOGIN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)", re.IGNORECASE)
_ROOT_LOGIN = re.compile(r"Accepted (?:password|publickey) for root from", re.IGNORECASE)
_ACCEPTED_LOGIN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\S+)", re.IGNORECASE
)
_SUDO = re.compile(r"sudo:\s+(\S+)\s*:.*COMMAND=(.+)$", re.IGNORECASE)
_BRUTE_THRESHOLD = 5

# Web-attack signatures commonly seen in access logs: (pattern, label, NIST control).
_WEB_ATTACK_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"(?i)\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1\b|\bselect\b.+\bfrom\b.+--"),
        "SQL injection attempt",
        "SI-10",
    ),
    (
        re.compile(r"(?i)<script\b|javascript:|onerror\s*=|onload\s*="),
        "Cross-site scripting (XSS) attempt",
        "SI-10",
    ),
    (
        re.compile(r"(?:\.\./){2,}|\.\.%2[fF]|/etc/passwd\b|%2e%2e%2f"),
        "Path-traversal / LFI attempt",
        "AC-3",
    ),
    (
        re.compile(r"(?i);\s*(?:cat|wget|curl|nc|bash|sh|chmod|rm)\b|\$\([^)]*\)"),
        "OS command-injection attempt",
        "SI-10",
    ),
]

# Anti-forensics / log-tampering indicators.
_LOG_TAMPER = re.compile(
    r"(?i)audit(?:d)?\s+(?:log\s+)?(?:cleared|stopped|disabled)"
    r"|\bhistory\s+-c\b"
    r"|truncate[^\n]*(?:wtmp|btmp|auth\.log|secure)"
    r"|\brm\b[^\n]*(?:auth\.log|/var/log/secure|/var/log/syslog|wtmp|btmp)"
)


def _line_containing(text: str, start: int) -> str:
    """Return the (stripped) log line that contains the match at offset `start`."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


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

    # Successful login from an IP that also brute-forced — likely account compromise.
    for m in _ACCEPTED_LOGIN.finditer(log_text):
        user, ip = m.group(1), m.group(2)
        if failed_by_ip.get(ip, 0) >= _BRUTE_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Successful login from brute-forcing source {ip} (user {user})",
                    severity="critical",
                    framework="NIST SP 800-53 Rev. 5",
                    control_id="AC-7",
                    evidence=(
                        f"`Accepted` login for `{user}` from {ip}, which also produced "
                        f"{failed_by_ip[ip]} failed attempts — consistent with a successful brute force."
                    ),
                    recommendation=(
                        "Treat the account as potentially compromised: force a credential reset, "
                        "review session activity from this IP, and block the source pending investigation."
                    ),
                )
            )

    # Web-attack signatures (SQLi / XSS / traversal / command injection) — one finding per category.
    for pattern, label, control in _WEB_ATTACK_SIGNATURES:
        first = pattern.search(log_text)
        if first:
            hits = sum(1 for _ in pattern.finditer(log_text))
            findings.append(
                Finding(
                    title=f"{label} detected in logs ({hits} occurrence{'s' if hits != 1 else ''})",
                    severity="high",
                    framework="NIST SP 800-53 Rev. 5",
                    control_id=control,
                    evidence=f"e.g. `{_line_containing(log_text, first.start())[:200]}`",
                    recommendation=(
                        "Validate and parameterize inputs, deploy a WAF rule for this pattern, and "
                        "review whether any matching request succeeded (2xx) against sensitive endpoints."
                    ),
                )
            )

    # Anti-forensics: clearing or disabling audit logs.
    tamper = _LOG_TAMPER.search(log_text)
    if tamper:
        findings.append(
            Finding(
                title="Possible log tampering / anti-forensics activity",
                severity="high",
                framework="NIST SP 800-53 Rev. 5",
                control_id="AU-9",
                evidence=f"`{_line_containing(log_text, tamper.start())[:200]}`",
                recommendation=(
                    "Protect audit logs from modification: ship them off-host to a write-once / "
                    "tamper-resistant store and restrict who can stop auditing or delete log files."
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
        f.detection_source = "heuristic"  # regex log signatures, deterministic

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
