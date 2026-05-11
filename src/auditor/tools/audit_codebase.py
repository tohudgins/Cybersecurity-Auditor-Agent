"""Audit a codebase for known-vulnerable dependencies via Trivy.

Shells out to the `trivy` CLI (https://aquasecurity.github.io/trivy/), parses
its JSON output, and maps each CVE to a Finding tied to NIST SP 800-53 SI-2
(Flaw Remediation).

No LLM involvement here — Trivy's output is structured and authoritative.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from auditor.enrichment import kev
from auditor.models import Finding

log = logging.getLogger(__name__)


_TRIVY_INSTALL_HINT = (
    "Trivy is not installed (or not on PATH). Install: "
    "Windows `scoop install trivy`, macOS `brew install trivy`, "
    "or download from https://github.com/aquasecurity/trivy/releases"
)

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

_TRIVY_CMD_PREFIX = ["trivy", "fs", "--format", "json", "--quiet", "--severity", "HIGH,CRITICAL"]


def _info(title: str, evidence: str, recommendation: str, source: str | None = None) -> Finding:
    return Finding(
        title=title,
        severity="info",
        evidence=evidence,
        recommendation=recommendation,
        source_artifact=source,
    )


def _vuln_to_finding(vuln: dict, target: str, scanned_path: str) -> Finding:
    pkg = vuln.get("PkgName", "?")
    installed = vuln.get("InstalledVersion", "?")
    cve = vuln.get("VulnerabilityID", "?")
    trivy_severity = (vuln.get("Severity") or "UNKNOWN").upper()
    severity = _SEVERITY_MAP.get(trivy_severity, "info")
    fixed = vuln.get("FixedVersion")
    title_summary = vuln.get("Title") or vuln.get("Description") or "(no description)"

    if fixed:
        recommendation = f"Upgrade {pkg} to {fixed}."
    else:
        recommendation = (
            "No fix available; apply compensating controls (network isolation, "
            "WAF rules, or mitigations from the CVE advisory)."
        )

    in_kev = kev.is_kev(cve)
    if in_kev:
        severity = "critical"
        title = f"[KEV] {pkg} {installed}: {cve}"
    else:
        title = f"{pkg} {installed}: {cve}"

    return Finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        framework="NIST SP 800-53 Rev. 5",
        control_id="SI-2",
        evidence=f"{title_summary} (affected: {target})",
        recommendation=recommendation,
        source_artifact=scanned_path,
        kev=in_kev,
    )


def audit_codebase(path: str | Path) -> list[Finding]:
    scanned_path = str(path)

    if not Path(scanned_path).exists():
        return [
            _info(
                title=f"Codebase path not found: {scanned_path}",
                evidence="The path does not exist on the local filesystem.",
                recommendation="Provide an absolute path to a directory that exists.",
                source=scanned_path,
            )
        ]

    cmd = [*_TRIVY_CMD_PREFIX, scanned_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [
            _info(
                title="Trivy not installed",
                evidence=_TRIVY_INSTALL_HINT,
                recommendation=_TRIVY_INSTALL_HINT,
                source=scanned_path,
            )
        ]

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
        return [
            _info(
                title="Trivy scan failed",
                evidence="\n".join(stderr_tail) or f"exit code {proc.returncode}",
                recommendation="Re-run `trivy fs <path>` manually to diagnose.",
                source=scanned_path,
            )
        ]

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        log.exception("Failed to parse Trivy JSON")
        return [
            _info(
                title="Trivy returned non-JSON output",
                evidence=f"{type(e).__name__}: {e}",
                recommendation="Re-run Trivy manually; check that the installed version supports --format json.",
                source=scanned_path,
            )
        ]

    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "?")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_vuln_to_finding(vuln, target, scanned_path))

    return findings
