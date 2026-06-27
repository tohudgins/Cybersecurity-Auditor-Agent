"""Audit a codebase via Trivy + Semgrep + Bandit + secrets scan.

Four scanners, all invoked via subprocess or regex fallback:
- Trivy   — CVEs in dependency manifests + IaC/Dockerfile/Helm misconfigurations (always runs)
- Semgrep — multi-language SAST (always runs; covers JS/TS, Go, Java, Ruby, ...)
- Bandit  — Python SAST (only when *.py files are present)
- Secrets — gitleaks if installed, else regex patterns for common secret formats

References:
- Trivy:    https://aquasecurity.github.io/trivy/
- Semgrep:  https://semgrep.dev/docs/
- Bandit:   https://bandit.readthedocs.io/
- gitleaks: https://github.com/gitleaks/gitleaks
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from auditor.enrichment import epss, kev
from auditor.models import Finding

log = logging.getLogger(__name__)


_TRIVY_INSTALL_HINT = (
    "Trivy is not installed (or not on PATH). Install: "
    "Windows `scoop install trivy`, macOS `brew install trivy`, "
    "or download from https://github.com/aquasecurity/trivy/releases"
)

_BANDIT_INSTALL_HINT = "Bandit is not installed. Install: `pip install bandit`."

_SEMGREP_INSTALL_HINT = (
    "Semgrep is not installed. Install: `pip install semgrep` "
    "or `brew install semgrep` (macOS)."
)

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

# Semgrep severities are ERROR / WARNING / INFO.
_SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# `vuln` finds CVEs in dependency manifests; `misconfig` finds IaC / Dockerfile /
# Helm / CloudFormation misconfigurations across the tree. (`secret` is left to
# gitleaks.) One invocation loads the Trivy DB once and returns both in `Results`.
_TRIVY_CMD_PREFIX = [
    "trivy", "fs",
    "--scanners", "vuln,misconfig",
    "--format", "json",
    "--quiet",
    "--severity", "HIGH,CRITICAL",
]
_BANDIT_CMD_PREFIX = ["bandit", "-r", "-f", "json", "--severity-level", "medium"]
# `--config auto` selects rulesets by detected language (fetched from the registry,
# cached under ~/.semgrep). `--metrics off` keeps project metadata local.
_SEMGREP_CMD_PREFIX = [
    "semgrep", "scan",
    "--config", "auto",
    "--json",
    "--quiet",
    "--metrics", "off",
    "--disable-version-check",
]


def _info(title: str, evidence: str, recommendation: str, source: str | None = None) -> Finding:
    return Finding(
        title=title,
        severity="info",
        evidence=evidence,
        recommendation=recommendation,
        source_artifact=source,
    )


# ---- Trivy -----------------------------------------------------------------


def _extract_cvss(vuln: dict) -> tuple[float | None, str | None]:
    """Pick the best available CVSS v3 score + vector from Trivy's CVSS dict.

    Trivy reports per-vendor (nvd, redhat, ghsa, ...). NVD is the canonical
    source; fall back to whatever is present.
    """
    cvss_data = vuln.get("CVSS") or {}
    vendor_order = ("nvd", "ghsa", "redhat", "bitnami")
    candidates = [cvss_data[v] for v in vendor_order if v in cvss_data]
    candidates.extend(v for k, v in cvss_data.items() if k not in vendor_order)

    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        score = entry.get("V3Score") or entry.get("V31Score")
        vector = entry.get("V3Vector") or entry.get("V31Vector")
        if score is not None:
            return float(score), vector
    return None, None


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

    cvss_score, cvss_vector = _extract_cvss(vuln)
    epss_pair = epss.epss_score(cve)
    epss_value, epss_pct = epss_pair if epss_pair else (None, None)

    return Finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        framework="NIST SP 800-53 Rev. 5",
        control_id="SI-2",
        evidence=f"{title_summary} (affected: {target})",
        recommendation=recommendation,
        source_artifact=scanned_path,
        kev=in_kev,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        epss_score=epss_value,
        epss_percentile=epss_pct,
    )


def _misconfig_to_finding(mis: dict, target: str, scanned_path: str) -> Finding:
    """Map one Trivy misconfiguration (IaC / Dockerfile / Helm / etc.) to a Finding."""
    check_id = mis.get("AVDID") or mis.get("ID") or "?"
    title = mis.get("Title") or check_id
    severity = _TRIVY_SEVERITY_MAP.get((mis.get("Severity") or "UNKNOWN").upper(), "info")
    message = mis.get("Message") or mis.get("Description") or "(no description)"
    resolution = mis.get("Resolution") or mis.get("PrimaryURL") or "See the Trivy/AVD advisory."

    start_line = (mis.get("CauseMetadata") or {}).get("StartLine")
    location = f"{target}:{start_line}" if start_line else target

    return Finding(
        title=f"[{check_id}] {title}",
        severity=severity,  # type: ignore[arg-type]
        framework="NIST SP 800-53 Rev. 5",
        control_id="CM-6",  # Configuration Settings — enables cross-framework mapping
        evidence=f"{location} — {message}",
        recommendation=resolution,
        source_artifact=scanned_path,
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

    return _trivy_findings_from_data(data, scanned_path)


def _trivy_findings_from_data(data: dict, scanned_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "?")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_vuln_to_finding(vuln, target, scanned_path))
        for mis in result.get("Misconfigurations") or []:
            findings.append(_misconfig_to_finding(mis, target, scanned_path))
    return findings


def audit_image(image_ref: str) -> list[Finding]:
    """Scan a container image with `trivy image` (CVEs + misconfigurations).

    Reuses the same Trivy JSON parsing + KEV/EPSS/CVSS enrichment as the
    filesystem scan, so a vulnerable base image is assessed exactly like a
    vulnerable dependency manifest.
    """
    ref = image_ref.strip()
    cmd = ["trivy", "image", "--scanners", "vuln,misconfig", "--format", "json",
           "--quiet", "--severity", "HIGH,CRITICAL", ref]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [_info("Trivy not installed", _TRIVY_INSTALL_HINT, _TRIVY_INSTALL_HINT, ref)]

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
        return [_info("Trivy image scan failed", "\n".join(stderr_tail) or f"exit {proc.returncode}",
                      f"Re-run `trivy image {ref}` manually to diagnose.", ref)]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        return [_info("Trivy returned non-JSON output", f"{type(e).__name__}: {e}",
                      "Check the installed Trivy version supports --format json.", ref)]
    return _trivy_findings_from_data(data, ref)


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
        framework="OWASP ASVS 5.0",
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


# ---- Semgrep ---------------------------------------------------------------


def _semgrep_cwe(metadata: dict) -> str | None:
    """Pull the first `CWE-<n>` token out of Semgrep's metadata.cwe field.

    Semgrep reports CWEs as e.g. ``["CWE-89: Improper Neutralization ..."]`` or
    occasionally a bare string. Return the canonical ``CWE-89`` token or None.
    """
    cwe = metadata.get("cwe")
    first = cwe[0] if isinstance(cwe, list) and cwe else cwe if isinstance(cwe, str) else None
    if not first:
        return None
    m = re.search(r"CWE-\d+", first)
    return m.group(0) if m else None


def _semgrep_result_to_finding(res: dict, scanned_path: str) -> Finding:
    check_id = res.get("check_id", "?")
    path = res.get("path", "?")
    line = (res.get("start") or {}).get("line", "?")
    extra = res.get("extra") or {}
    message = (extra.get("message") or "").strip()
    severity = _SEMGREP_SEVERITY_MAP.get((extra.get("severity") or "WARNING").upper(), "medium")
    metadata = extra.get("metadata") or {}

    # Last dotted segment is the human-readable rule name (full id is long & noisy).
    short_rule = check_id.rsplit(".", 1)[-1]
    code = (extra.get("lines") or "").strip()
    evidence = f"{path}:{line} — {message}"
    if code:
        evidence += f"\n```\n{code}\n```"

    references = metadata.get("references") or []
    ref = references[0] if references else f"https://semgrep.dev/r/{check_id}"

    return Finding(
        title=f"[semgrep] {short_rule}",
        severity=severity,  # type: ignore[arg-type]
        framework="OWASP ASVS 5.0",
        control_id=_semgrep_cwe(metadata) or check_id,
        evidence=evidence,
        recommendation=f"Review and remediate per the rule guidance: {ref}",
        source_artifact=scanned_path,
    )


def _run_semgrep(scanned_path: str) -> list[Finding]:
    cmd = [*_SEMGREP_CMD_PREFIX, scanned_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [_info("Semgrep not installed", _SEMGREP_INSTALL_HINT, _SEMGREP_INSTALL_HINT, scanned_path)]

    # Semgrep exits 0 even when it reports findings; a non-zero exit with no
    # parseable stdout is a real failure (bad rules, network fetch failed, etc.).
    if proc.returncode != 0 and not proc.stdout.strip():
        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
        return [
            _info(
                "Semgrep scan failed",
                "\n".join(stderr_tail) or f"exit code {proc.returncode}",
                "Re-run `semgrep scan --config auto <path>` manually to diagnose.",
                scanned_path,
            )
        ]

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        log.exception("Failed to parse Semgrep JSON")
        return [
            _info(
                "Semgrep returned non-JSON output",
                f"{type(e).__name__}: {e}",
                "Re-run Semgrep manually; check version compatibility.",
                scanned_path,
            )
        ]

    return [_semgrep_result_to_finding(r, scanned_path) for r in data.get("results") or []]


# ---- Secrets scanning ------------------------------------------------------

_GITLEAKS_INSTALL_HINT = (
    "gitleaks is not installed. Install: `brew install gitleaks` (macOS) "
    "or download from https://github.com/gitleaks/gitleaks/releases"
)

# Regex fallback patterns: (pattern, title, control_id)
# Used when gitleaks is not on PATH.
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID found in source", "IA-5"),
    (
        r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"']?(?!\$\{|{{)[^\s\"'\\]{8,}",
        "Hardcoded password in source",
        "IA-5",
    ),
    (
        r"(?i)(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}",
        "Hardcoded API key / token in source",
        "IA-5",
    ),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key embedded in source", "SC-28"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API key in source", "IA-5"),
    (r"gh[pousr]_[A-Za-z0-9]{36}", "GitHub token in source", "IA-5"),
]

# Directories / suffixes to skip in the regex fallback walk
_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".chromadb", "dist", "build", ".tox",
})
_SCAN_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".go", ".java", ".rb", ".php",
    ".env", ".cfg", ".conf", ".yaml", ".yml", ".json",
    ".toml", ".sh", ".tf", ".tfvars", ".ini", ".xml",
})


def _iter_text_files(root: Path, limit: int = 500):
    """Yield candidate text files for secret scanning, skipping noise dirs."""
    count = 0
    for fpath in root.rglob("*"):
        if count >= limit:
            break
        if not fpath.is_file():
            continue
        if any(part in _SKIP_DIRS for part in fpath.parts):
            continue
        if fpath.suffix.lower() in _SCAN_SUFFIXES or fpath.name.startswith(".env"):
            yield fpath
            count += 1


def _secrets_via_regex(scanned_path: str) -> list[Finding]:
    """Regex-based secret detection fallback (used when gitleaks is absent)."""
    findings: list[Finding] = []
    root = Path(scanned_path)
    seen: set[str] = set()  # deduplicate by (file, line, pattern)

    for fpath in _iter_text_files(root):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pattern, title, control_id in _SECRET_PATTERNS:
            for m in re.finditer(pattern, content, re.MULTILINE):
                lineno = content[: m.start()].count("\n") + 1
                try:
                    rel = str(fpath.relative_to(root))
                except ValueError:
                    rel = str(fpath)
                key = f"{rel}:{lineno}:{pattern}"
                if key in seen:
                    continue
                seen.add(key)
                snippet = m.group(0)[:80]
                findings.append(
                    Finding(
                        title=title,
                        severity="high",
                        framework="NIST SP 800-53 Rev. 5",
                        control_id=control_id,
                        evidence=f"{rel}:{lineno} — `{snippet}`",
                        recommendation=(
                            "Remove the secret from source. Store it in an environment variable "
                            "or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). "
                            "Rotate the credential immediately if it was ever committed."
                        ),
                        source_artifact=scanned_path,
                    )
                )
    return findings


def _try_gitleaks(scanned_path: str) -> list[Finding] | None:
    """Run gitleaks.  Returns:

    - ``list[Finding]`` (possibly empty) if gitleaks ran and produced parseable output.
    - ``None`` if gitleaks isn't installed or returned unusable output, so the
      caller should fall back to the regex scanner.
    """
    cmd = [
        "gitleaks", "detect",
        "--source", scanned_path,
        "--report-format", "json",
        "--no-git",          # scan the working tree, not git history
        "--exit-code", "0",  # always exit 0 so we parse stdout ourselves
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None  # gitleaks not on PATH

    if not proc.stdout.strip():
        return []  # gitleaks ran cleanly, found nothing

    try:
        leaks = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None  # malformed output — let regex fallback try

    if not isinstance(leaks, list):
        return None  # unexpected schema — let regex fallback try

    findings: list[Finding] = []
    for leak in leaks:
        if not isinstance(leak, dict):
            continue
        findings.append(
            Finding(
                title=f"Secret detected: {leak.get('Description', 'unknown')}",
                severity="high",
                framework="NIST SP 800-53 Rev. 5",
                control_id="IA-5",
                evidence=(
                    f"{leak.get('File', '?')}:{leak.get('StartLine', '?')}"
                    f" — rule `{leak.get('RuleID', '?')}`"
                ),
                recommendation=(
                    "Remove the secret from source code and rotate the credential. "
                    "Store secrets in environment variables or a secrets manager."
                ),
                source_artifact=scanned_path,
            )
        )
    return findings


def _run_secrets_scan(scanned_path: str) -> list[Finding]:
    """Scan for hardcoded secrets using gitleaks (preferred) or regex fallback."""
    gitleaks_findings = _try_gitleaks(scanned_path)
    if gitleaks_findings is not None:
        # gitleaks ran successfully — trust its result (even if empty)
        return gitleaks_findings

    # Gitleaks unavailable or broken — fall back to regex patterns
    regex_findings = _secrets_via_regex(scanned_path)
    if not regex_findings:
        return []

    info = _info(
        title="Secret scan used regex fallback (gitleaks not installed)",
        evidence="`gitleaks` binary not found on PATH; used built-in regex patterns instead.",
        recommendation=_GITLEAKS_INSTALL_HINT,
        source=scanned_path,
    )
    return [info, *regex_findings]


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

    # Each scanner is an independent, blocking subprocess (or filesystem walk),
    # so they run concurrently in threads — wall-clock collapses to the slowest
    # scanner instead of their sum. Subprocess waits release the GIL, so threads
    # (not processes) are the right primitive here. Order is preserved by reading
    # the futures in submission order; `normalize_findings` re-ranks downstream
    # regardless, so ordering is cosmetic.
    scanners = [_run_trivy, _run_semgrep, _run_secrets_scan]
    if _has_python_files(Path(scanned_path)):
        scanners.append(_run_bandit)

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=len(scanners)) as pool:
        futures = [pool.submit(scan, scanned_path) for scan in scanners]
        for scan, future in zip(scanners, futures, strict=True):
            try:
                findings.extend(future.result())
            except Exception as exc:  # one scanner crashing shouldn't sink the audit
                log.exception("Scanner %s failed", scan.__name__)
                findings.append(
                    _info(
                        title=f"{scan.__name__} crashed",
                        evidence=f"{type(exc).__name__}: {exc}",
                        recommendation="Check the server logs; re-run the scanner manually to diagnose.",
                        source=scanned_path,
                    )
                )

    return findings
