"""Dynamic application security testing (DAST) of a live web target via Nuclei.

Static analysis reads code; DAST probes a *running* application the way an
attacker would. We shell out to **Nuclei** (templated vulnerability scanner),
parse its JSONL output, and map each result to a NIST SP 800-53 control by the
template's tags (injection → SI-10, exposure → AC-3, TLS → SC-8, ...).

The `target_url` artifact's content is the URL to scan. Only scan systems you
are authorized to test.

Nuclei: https://github.com/projectdiscovery/nuclei
"""
from __future__ import annotations

import json
import logging
import subprocess

from auditor.models import Finding

log = logging.getLogger(__name__)

_NUCLEI_INSTALL_HINT = (
    "Nuclei is not installed. Install: `brew install nuclei` or "
    "see https://github.com/projectdiscovery/nuclei. Only scan targets you are "
    "authorized to test."
)

_NUCLEI_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}

# Template tag → NIST 800-53 anchor. First matching tag wins; default SI-10.
_TAG_CONTROL = [
    (("sqli", "injection", "rce", "xss", "ssti", "lfi", "xxe", "deserialization"), "SI-10"),
    (("ssrf",), "SC-7"),
    (("ssl", "tls", "cert"), "SC-8"),
    (("exposure", "disclosure", "files", "backup"), "AC-3"),
    (("default-login", "auth", "credential"), "IA-5"),
    (("cve", "tech", "version"), "SI-2"),
    (("misconfig", "config"), "CM-6"),
]


def _control_for_tags(tags: list[str]) -> str:
    flat = {t.lower() for t in tags}
    for keys, control in _TAG_CONTROL:
        if flat & set(keys):
            return control
    return "SI-10"


def _finding_from_nuclei(item: dict, url: str) -> Finding:
    info = item.get("info") or {}
    severity = _NUCLEI_SEVERITY_MAP.get((info.get("severity") or "info").lower(), "info")
    name = info.get("name") or item.get("template-id") or "Web finding"
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    matched = item.get("matched-at") or item.get("host") or url
    description = info.get("description") or ""
    remediation = info.get("remediation") or "Review the Nuclei template guidance and remediate the exposed issue."
    control = _control_for_tags(tags)

    evidence = f"{matched} — {name}"
    if description:
        evidence += f": {description.strip()}"

    return Finding(
        title=f"[nuclei] {name}",
        severity=severity,  # type: ignore[arg-type]
        framework="NIST SP 800-53 Rev. 5",
        control_id=control,
        evidence=evidence,
        recommendation=remediation,
        source_artifact=url,
        detection_source="scanner",
    )


def _parse_nuclei_output(text: str, url: str) -> list[Finding]:
    """Parse Nuclei JSONL (one JSON object per line)."""
    findings: list[Finding] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            findings.append(_finding_from_nuclei(item, url))
    return findings


def _info_finding(title: str, evidence: str, recommendation: str, url: str) -> Finding:
    return Finding(
        title=title, severity="info", evidence=evidence,
        recommendation=recommendation, source_artifact=url, detection_source="scanner",
    )


def audit_web(url: str) -> list[Finding]:
    """Run a Nuclei DAST scan against *url* and return findings."""
    target = url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-disable-update-check"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [_info_finding("Nuclei not installed", _NUCLEI_INSTALL_HINT, _NUCLEI_INSTALL_HINT, target)]

    findings = _parse_nuclei_output(proc.stdout, target)
    if not findings and proc.returncode != 0 and not proc.stdout.strip():
        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
        return [
            _info_finding(
                "Nuclei scan failed",
                "\n".join(stderr_tail) or f"exit code {proc.returncode}",
                f"Re-run `nuclei -u {target}` manually to diagnose.",
                target,
            )
        ]
    return findings
