"""Machine / OS hardening audit via Lynis.

"Audit our machines" — Lynis runs hundreds of host hardening checks (SSH, auth,
firewall, logging, kernel, packages, file permissions, ...) against a running
system. We invoke it, parse its machine-readable report, and map each warning /
suggestion to a NIST SP 800-53 control by the Lynis test-ID category.

The `host` artifact's content is the target:
- ``localhost`` (or empty) → audit the local machine.
- ``user@server`` → audit a remote host over SSH (Lynis must be installed there;
  the report is streamed back over the SSH connection).

Lynis: https://github.com/CISOfy/lynis
"""
from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from pathlib import Path

from auditor.models import Finding

log = logging.getLogger(__name__)

# A safe SSH target: optional user@, then host. No leading '-' (which ssh would
# parse as an option, e.g. -oProxyCommand=… → remote code execution), no shell
# metacharacters. Validated before the value ever reaches `ssh`.
_SAFE_SSH_TARGET = re.compile(r"^(?!-)[A-Za-z0-9._-]+(@(?!-)[A-Za-z0-9._-]+)?$")

_LYNIS_INSTALL_HINT = (
    "Lynis is not installed. Install: `brew install lynis` (macOS), "
    "`apt install lynis` (Debian/Ubuntu), or see https://github.com/CISOfy/lynis. "
    "For remote audits, Lynis must be installed on the target host."
)

# Lynis test-ID category prefix → NIST SP 800-53 anchor control.
_CATEGORY_CONTROL = {
    "AUTH": "IA-2", "ACCT": "AU-2", "SSH": "AC-17", "FIRE": "SC-7",
    "NETW": "SC-7", "LOGG": "AU-2", "KRNL": "CM-6", "PKGS": "SI-2",
    "MALW": "SI-3", "HRDN": "CM-6", "CRYP": "SC-13", "TIME": "AU-8",
    "FILE": "AC-6", "STRG": "AC-6", "USB": "AC-6", "BANN": "CM-6",
    "BOOT": "CM-6", "CONT": "CM-6", "TOOL": "CM-6", "PROC": "CM-7",
    "HTTP": "SC-8", "NAME": "SC-7", "SQD": "CM-6", "PHP": "CM-6",
    "FINT": "SI-7", "DBS": "SC-28",
}


def _control_for_test(test_id: str) -> str:
    m = re.match(r"([A-Z]+)", test_id or "")
    return _CATEGORY_CONTROL.get(m.group(1), "CM-6") if m else "CM-6"


def _finding_from_entry(kind: str, fields: list[str], target: str) -> Finding | None:
    """Build a Finding from a Lynis report `warning[]` / `suggestion[]` entry.

    Format: ``<test_id>|<description>|<details>|<solution>`` (trailing fields
    optional). Warnings are weighted higher than suggestions.
    """
    if not fields or not fields[0]:
        return None
    test_id = fields[0].strip()
    description = fields[1].strip() if len(fields) > 1 and fields[1] not in ("", "-") else test_id
    details = fields[2].strip() if len(fields) > 2 and fields[2] not in ("", "-") else ""

    if kind == "vulnerable_package":
        severity, control, title = "high", "SI-2", f"Vulnerable package: {test_id}"
        description = f"Package {test_id} reported as vulnerable by Lynis."
    elif kind == "warning":
        severity = "medium"
        control = _control_for_test(test_id)
        title = f"[{test_id}] {description}"
    else:  # suggestion
        severity = "low"
        control = _control_for_test(test_id)
        title = f"[{test_id}] {description}"

    evidence = f"{target}: {description}"
    if details:
        evidence += f" ({details})"

    return Finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        framework="NIST SP 800-53 Rev. 5",
        control_id=control,
        evidence=evidence,
        recommendation=details or "Apply the Lynis hardening guidance for this test.",
        source_artifact=f"host:{target}",
        detection_source="scanner",
    )


def _parse_lynis_report(text: str, target: str) -> list[Finding]:
    """Parse a Lynis report.dat into findings (warnings, suggestions, vuln packages)."""
    findings: list[Finding] = []
    for line in (text or "").splitlines():
        line = line.strip()
        for key in ("warning", "suggestion", "vulnerable_package"):
            prefix = f"{key}[]="
            if line.startswith(prefix):
                fields = line[len(prefix):].split("|")
                f = _finding_from_entry(key, fields, target)
                if f:
                    findings.append(f)
                break
    return findings


def _info(title: str, evidence: str, recommendation: str, target: str) -> Finding:
    return Finding(
        title=title, severity="info", evidence=evidence, recommendation=recommendation,
        source_artifact=f"host:{target}", detection_source="scanner",
    )


def _run_local(target: str) -> tuple[str, subprocess.CompletedProcess | None]:
    """Run Lynis locally and return (report_text, proc)."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "lynis-report.dat"
        cmd = [
            "lynis", "audit", "system", "--quickmode", "--no-colors",
            "--quiet", "--report-file", str(report),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return "", None
        try:
            return report.read_text(encoding="utf-8", errors="replace"), proc
        except OSError:
            return "", proc


def _run_remote(spec: str) -> tuple[str, subprocess.CompletedProcess | None]:
    """Run Lynis on a remote host over SSH and stream the report back via stdout."""
    remote_cmd = (
        "lynis audit system --quickmode --no-colors --quiet "
        "--report-file /tmp/auditor-lynis-report.dat >/dev/null 2>&1; "
        "cat /tmp/auditor-lynis-report.dat"
    )
    cmd = ["ssh", "-o", "BatchMode=yes", spec, remote_cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return "", None
    return proc.stdout or "", proc


def audit_host(content: str) -> list[Finding]:
    """Run a Lynis OS-hardening audit against the local or a remote host."""
    target = (content or "localhost").strip()
    is_local = target in ("", "localhost", "127.0.0.1") or target.lower() == "this machine"
    label = "localhost" if is_local else target

    # Reject SSH targets that could inject `ssh` options (arg-injection → RCE).
    if not is_local and not _SAFE_SSH_TARGET.match(target):
        return [_info(
            "Invalid host target",
            f"'{target}' is not a valid SSH target (expected host or user@host, no leading '-').",
            "Use a plain host or user@host (alphanumerics, dots, hyphens).",
            label,
        )]

    text, proc = (_run_local(label) if is_local else _run_remote(target))

    if proc is None:
        return [_info("Lynis not available", _LYNIS_INSTALL_HINT, _LYNIS_INSTALL_HINT, label)]

    findings = _parse_lynis_report(text, label)
    if not findings:
        if not is_local and proc.returncode != 0:
            stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
            return [_info(
                "Remote host audit failed",
                "\n".join(stderr_tail) or f"ssh exit code {proc.returncode}",
                "Verify SSH access (BatchMode keys) and that Lynis is installed on the target.",
                label,
            )]
        return [_info(
            "Host audit produced no findings",
            "Lynis ran but reported no warnings or suggestions (or the report was empty).",
            "Re-run `lynis audit system` manually to inspect the full report.",
            label,
        )]
    return findings
