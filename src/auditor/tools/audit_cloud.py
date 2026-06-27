"""Cloud security posture management (CSPM) via Prowler.

This is the closest the agent gets to what an auditor actually does against a
live environment: run hundreds of automated checks against a cloud account's
*current* configuration (IAM, logging, encryption, network exposure, ...) and
assess them against benchmarks. We shell out to **Prowler** (read-only) and map
its FAIL findings into our `Finding` shape, anchoring on the NIST SP 800-53
control Prowler reports in its compliance section when available.

The `cloud_account` artifact's content is a provider spec: ``aws``,
``aws:profile-name``, ``gcp``, or ``azure``. Credentials come from the host's
standard cloud SDK config (env vars / profiles) — the tool never handles them.

Prowler: https://github.com/prowler-cloud/prowler
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path

from auditor.models import Finding

log = logging.getLogger(__name__)

_PROWLER_INSTALL_HINT = (
    "Prowler is not installed. Install: `pip install prowler` "
    "(see https://docs.prowler.com). Cloud credentials use your standard "
    "AWS/GCP/Azure SDK configuration (read-only is sufficient)."
)

_PROWLER_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}

_SUPPORTED_PROVIDERS = {"aws", "gcp", "azure", "kubernetes"}

# A safe profile name (passed to prowler `-p`). No leading '-' (which prowler
# would parse as an option) and no shell metacharacters.
_SAFE_PROFILE = re.compile(r"^(?!-)[A-Za-z0-9._-]+$")

# Fallback service → NIST 800-53 anchor when a finding carries no NIST compliance
# mapping. Keeps cloud findings tied to a control so they flow into coverage.
_SERVICE_CONTROL = {
    "iam": "AC-6", "accessanalyzer": "AC-6", "s3": "SC-28", "kms": "SC-12",
    "cloudtrail": "AU-2", "cloudwatch": "SI-4", "config": "CA-7", "ec2": "SC-7",
    "vpc": "SC-7", "rds": "SC-28", "guardduty": "SI-4", "securityhub": "CA-7",
    "efs": "SC-28", "elb": "SC-8", "elbv2": "SC-8", "apigateway": "SC-8",
}


def _parse_provider(content: str) -> tuple[str, str | None]:
    """Return ``(provider, profile)`` from a 'provider[:profile]' spec."""
    spec = (content or "aws").strip().lower()
    provider, _, profile = spec.partition(":")
    return (provider or "aws"), (profile or None)


def _dig(d, *path):
    """Safe nested lookup across dicts and lists: _dig(item, 'resources', 0, 'uid')."""
    cur = d
    for key in path:
        if isinstance(key, int):
            if not isinstance(cur, list) or not (-len(cur) <= key < len(cur)):
                return None
            cur = cur[key]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
    return cur


def _first(*vals):
    for v in vals:
        if v:
            return v
    return None


def _nist_control(finding: dict) -> str | None:
    """Extract a NIST 800-53 control ID from Prowler's compliance block, if any.

    Handles both the legacy flat ``compliance`` dict and the OCSF location
    (``unmapped.compliance``).
    """
    for compliance in (finding.get("compliance"), finding.get("Compliance"), _dig(finding, "unmapped", "compliance")):
        if isinstance(compliance, dict):
            for key, vals in compliance.items():
                if "800-53" in key.replace("_", "-") and vals:
                    first = vals[0] if isinstance(vals, list) else vals
                    return str(first).strip().upper()
    service = (
        finding.get("service_name") or finding.get("ServiceName")
        or _dig(finding, "resources", 0, "group", "name") or ""
    )
    return _SERVICE_CONTROL.get(str(service).lower())


def _finding_from_prowler(item: dict, provider: str) -> Finding | None:
    """Map one Prowler FAIL result into a Finding (flat v3 or OCSF v4 shape)."""
    # OCSF uses status_code; legacy uses status/Status.
    status = str(_first(item.get("status_code"), item.get("status"), item.get("Status"), "")).upper()
    if status not in ("FAIL", "FAILED", "MANUAL", "NEW"):
        return None

    severity = _PROWLER_SEVERITY_MAP.get(
        str(_first(item.get("severity"), item.get("Severity"), "medium")).lower(), "medium"
    )
    check_id = _first(item.get("check_id"), item.get("CheckID"), _dig(item, "finding_info", "uid"),
                      _dig(item, "metadata", "event_code"), "?")
    title = _first(item.get("check_title"), item.get("CheckTitle"), _dig(item, "finding_info", "title"), check_id)
    region = _first(item.get("region"), item.get("Region"), _dig(item, "cloud", "region"),
                    _dig(item, "resources", 0, "region"), "")
    resource = _first(item.get("resource_uid"), item.get("resource_id"), item.get("ResourceId"),
                      _dig(item, "resources", 0, "uid"), "")
    description = _first(item.get("status_detail"), item.get("status_detail_message"),
                         item.get("description"), item.get("Description"),
                         _dig(item, "finding_info", "desc"), item.get("message"), "")
    remediation = _first(
        item.get("remediation_recommendation_text"),
        _dig(item, "remediation", "recommendation", "text"),
        _dig(item, "remediation", "desc"),
        "Review the Prowler check guidance and remediate the misconfiguration.",
    )
    control = _nist_control(item)
    location = " ".join(str(p) for p in (region, resource) if p) or provider

    return Finding(
        title=f"[{check_id}] {title}",
        severity=severity,  # type: ignore[arg-type]
        framework="NIST SP 800-53 Rev. 5" if control else None,
        control_id=control,
        evidence=f"{location} — {description}".strip(" —"),
        recommendation=remediation,
        source_artifact=f"cloud:{provider}",
        detection_source="scanner",
    )


def _parse_prowler_output(text: str, provider: str) -> list[Finding]:
    """Parse Prowler JSON output (a JSON array, or one JSON object per line)."""
    text = (text or "").strip()
    if not text:
        return []
    items: list = []
    try:
        parsed = json.loads(text)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    findings = [_finding_from_prowler(i, provider) for i in items if isinstance(i, dict)]
    return [f for f in findings if f is not None]


def audit_cloud(content: str) -> list[Finding]:
    """Run Prowler against a cloud account and return FAIL findings."""
    provider, profile = _parse_provider(content)
    if provider not in _SUPPORTED_PROVIDERS:
        return [
            Finding(
                title=f"Unsupported cloud provider: {provider}",
                severity="info",
                evidence=f"Provider '{provider}' is not one of {sorted(_SUPPORTED_PROVIDERS)}.",
                recommendation="Use a spec like 'aws', 'aws:profile-name', 'gcp', or 'azure'.",
                source_artifact=f"cloud:{provider}",
                detection_source="scanner",
            )
        ]

    if profile and not _SAFE_PROFILE.match(profile):
        return [
            Finding(
                title="Invalid cloud profile",
                severity="info",
                evidence=f"Profile '{profile}' contains unsupported characters.",
                recommendation="Use a profile name of letters, digits, dots, dashes, or underscores.",
                source_artifact=f"cloud:{provider}",
                detection_source="scanner",
            )
        ]

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        cmd = ["prowler", provider, "-M", "json-ocsf", "-o", str(out_dir), "--ignore-exit-code-3"]
        if profile:
            cmd += ["-p", profile]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return [
                Finding(
                    title="Prowler not installed",
                    severity="info",
                    evidence=_PROWLER_INSTALL_HINT,
                    recommendation=_PROWLER_INSTALL_HINT,
                    source_artifact=f"cloud:{provider}",
                    detection_source="scanner",
                )
            ]

        # Prefer the JSON file Prowler writes; fall back to stdout.
        json_files = sorted(out_dir.glob("*.json")) + sorted(out_dir.glob("*.ocsf.json"))
        text = ""
        for jf in json_files:
            try:
                text = jf.read_text(encoding="utf-8")
                break
            except OSError:
                continue
        if not text:
            text = proc.stdout or ""

    findings = _parse_prowler_output(text, provider)
    if not findings and proc.returncode not in (0, 3):
        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
        return [
            Finding(
                title="Prowler scan failed",
                severity="info",
                evidence="\n".join(stderr_tail) or f"exit code {proc.returncode}",
                recommendation=f"Re-run `prowler {provider}` manually to diagnose (check credentials).",
                source_artifact=f"cloud:{provider}",
                detection_source="scanner",
            )
        ]
    return findings
