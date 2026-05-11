"""Export Finding objects as OSCAL Assessment Results JSON (NIST schema 1.1.x).

OSCAL (Open Security Controls Assessment Language) is NIST's machine-readable
format for assessment plans, results, and POA&Ms. Outputs in this format can
be ingested by FedRAMP / RegScale / IBM Trestle and other GRC platforms.

We hand-roll the JSON rather than depend on `compliance-trestle` for two
reasons: (1) trestle pulls in a large dependency tree, and (2) hand-rolling
makes the field mapping from Finding → OSCAL transparent for resume review.

Schema reference: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from auditor.models import Finding

_OSCAL_VERSION = "1.1.2"
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 namespace (NameSpace_DNS)


def _stable_uuid(*parts: str) -> str:
    """Deterministic UUIDv5 from joined parts so the same finding produces the same UUID across runs."""
    seed = "|".join(p for p in parts if p)
    return str(uuid.uuid5(_NAMESPACE, seed or hashlib.sha1(b"empty").hexdigest()))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _observation(finding: Finding, run_id: str) -> dict:
    """An observation is the raw evidence collected during the assessment."""
    obs_id = _stable_uuid("observation", run_id, finding.title, finding.evidence)
    obs: dict = {
        "uuid": obs_id,
        "title": finding.title,
        "description": finding.evidence,
        "methods": ["AUTOMATED"],
        "types": ["finding"],
        "collected": _now_iso(),
    }
    if finding.source_artifact:
        obs["origins"] = [{"actors": [{"type": "tool", "actor-uuid": _stable_uuid("tool", "cybersecurity-auditor")}]}]
        obs["subjects"] = [{"subject-uuid": _stable_uuid("subject", finding.source_artifact), "type": "resource"}]
    return obs


def _finding_props(finding: Finding) -> list[dict]:
    """Emit OSCAL `prop` entries for our non-standard fields (CVSS, KEV, ATT&CK)."""
    props: list[dict] = [{"name": "severity", "value": finding.severity}]
    if finding.cvss_score is not None:
        props.append({"name": "cvss-v3-base-score", "value": f"{finding.cvss_score:.1f}"})
    if finding.cvss_vector:
        props.append({"name": "cvss-v3-vector", "value": finding.cvss_vector})
    if finding.kev:
        props.append({"name": "cisa-kev", "value": "true"})
    for technique in finding.attack_techniques:
        props.append({"name": "mitre-attack-technique", "value": technique})
    return props


def _finding(finding: Finding, observation_uuid: str, run_id: str) -> dict:
    finding_id = _stable_uuid("finding", run_id, finding.title)
    target_id = finding.control_id or "unspecified"
    return {
        "uuid": finding_id,
        "title": finding.title,
        "description": finding.recommendation,
        "props": _finding_props(finding),
        "target": {
            "type": "objective-id",
            "target-id": target_id,
            "status": {"state": "not-satisfied"},
        },
        "related-observations": [{"observation-uuid": observation_uuid}],
    }


def to_oscal_assessment_results(
    findings: list[Finding],
    *,
    title: str = "Cybersecurity Auditor — Automated Audit",
    description: str = "Findings produced by the Cybersecurity Auditor Agent.",
) -> dict:
    """Return an OSCAL Assessment Results document as a Python dict."""
    now = _now_iso()
    doc_id = str(uuid.uuid4())
    run_id = _stable_uuid("run", now, str(len(findings)))

    observations = [_observation(f, run_id) for f in findings]
    oscal_findings = [
        _finding(f, observations[i]["uuid"], run_id) for i, f in enumerate(findings)
    ]

    return {
        "assessment-results": {
            "uuid": doc_id,
            "metadata": {
                "title": title,
                "last-modified": now,
                "version": "1.0",
                "oscal-version": _OSCAL_VERSION,
            },
            "import-ap": {"href": "#system-security-plan"},
            "results": [
                {
                    "uuid": run_id,
                    "title": "Automated audit run",
                    "description": description,
                    "start": now,
                    "end": now,
                    "observations": observations,
                    "findings": oscal_findings,
                }
            ],
        }
    }
