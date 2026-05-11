"""Audit a codebase via Trivy (CVEs in deps) + Bandit (Python SAST).

Two industry-standard scanners, both invoked via subprocess. Trivy always runs;
Bandit only runs if `*.py` files are present in the path.

References:
- Trivy: https://aquasecurity.github.io/trivy/
- Bandit: https://bandit.readthedocs.io/
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

_BANDIT_INSTALL_HINT = "Bandit is not installed. Install: `pip install bandit`."

_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

_BANDIT_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNDEFINED": "info",
}

_TRIVY_CMD_PREFIX = ["trivy", "fs", "--format", "json", "--quiet", "--severity", "HIGH,CRITICAL"]
_BANDIT_CMD_PREFIX = ["bandit", "-r", "-f", "json", "--severity-level", "medium"]


def _info(title: str, evidence: str, recommendation: str, source: str | None = None) -> Finding:
    return Finding(
        title=title,
        severity="info",
        evidence=evidence,
        recommendation=recommendation,
        source_artifact=source,
    )


# ---- Trivy -----------------------------------------------------------------


def _vuln_to_finding(vuln: dict, target: str, scanned_path: str) -> Finding:
    pkg = vuln.get("PkgName", "?")
    installed = vuln.get("InstalledVersion", "?")
    cve = vuln.get("VulnerabilityID", "?")
    trivy_severity = (vuln.get("Severity") or "UNKNOWN").upper()
    severity = _TRIVY_SEVERITY_MAP.get(trivy_severity, "info")
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


def _run_trivy(scanned_path: str) -> list[Finding]:
    cmd = [*_TRIVY_CMD_PREFIX, scanned_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [_info("Trivy not installed", _TRIVY_INSTALL_HINT, _TRIVY_INSTALL_HINT, scanned_path)]

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
        return [
            _info(
                "Trivy scan failed",
                "\n".join(stderr_tail) or f"exit code {proc.returncode}",
                "Re-run `trivy fs <path>` manually to diagnose.",
                scanned_path,
            )
        ]

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        log.exception("Failed to parse Trivy JSON")
        return [
            _info(
                "Trivy returned non-JSON output",
                f"{type(e).__name__}: {e}",
                "Re-run Trivy manually; check that the installed version supports --format json.",
                scanned_path,
            )
        ]

    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "?")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_vuln_to_finding(vuln, target, scanned_path))
    return findings


# ---- Bandit ----------------------------------------------------------------


def _bandit_issue_to_finding(issue: dict, scanned_path: str) -> Finding:
    test_id = issue.get("test_id", "?")
    test_name = issue.get("test_name", "?")
    severity = _BANDIT_SEVERITY_MAP.get((issue.get("issue_severity") or "MEDIUM").upper(), "medium")

    cwe = (issue.get("issue_cwe") or {}).get("id")
    control_id = f"CWE-{cwe}" if cwe else test_id

    filename = issue.get("filename", "?")
    line = issue.get("line_number", "?")
    code_snippet = (issue.get("code") or "").strip()
    issue_text = issue.get("issue_text", "")
    more_info = issue.get("more_info") or "https://bandit.readthedocs.io/"

    evidence = f"{filename}:{line} — {issue_text}"
    if code_snippet:
        evidence += f"\n```\n{code_snippet}\n```"

    return Finding(
        title=f"[{test_id}] {test_name}",
        severity=severity,  # type: ignore[arg-type]
        framework="OWASP ASVS 4.0.3",
        control_id=control_id,
        evidence=evidence,
        recommendation=f"See Bandit docs: {more_info}",
        source_artifact=scanned_path,
    )


def _has_python_files(path: Path) -> bool:
    try:
        return next(path.rglob("*.py"), None) is not None
    except OSError:
        return False


def _run_bandit(scanned_path: str) -> list[Finding]:
    cmd = [*_BANDIT_CMD_PREFIX, scanned_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [_info("Bandit not installed", _BANDIT_INSTALL_HINT, _BANDIT_INSTALL_HINT, scanned_path)]

    # Bandit exits 1 when issues are found — that's expected, not an error.
    # An empty stdout AND non-zero exit means a real failure.
    if not proc.stdout.strip():
        if proc.returncode != 0:
            stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
            return [
                _info(
                    "Bandit scan failed",
                    "\n".join(stderr_tail) or f"exit code {proc.returncode}",
                    "Re-run `bandit -r <path>` manually to diagnose.",
                    scanned_path,
                )
            ]
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        log.exception("Failed to parse Bandit JSON")
        return [
            _info(
                "Bandit returned non-JSON output",
                f"{type(e).__name__}: {e}",
                "Re-run Bandit manually; check version compatibility.",
                scanned_path,
            )
        ]

    return [_bandit_issue_to_finding(issue, scanned_path) for issue in data.get("results") or []]


# ---- Public entry point ----------------------------------------------------


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

    findings = _run_trivy(scanned_path)

    if _has_python_files(Path(scanned_path)):
        findings.extend(_run_bandit(scanned_path))

    return findings
