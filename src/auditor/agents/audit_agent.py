"""Audit agent node: dispatches each uploaded artifact to its matching tool."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from auditor.agents.state import AuditorState
from auditor.assessment import assess_controls
from auditor.enrichment.mappings import enrich_with_mappings
from auditor.enrichment.mitre import enrich_findings
from auditor.enrichment.risk import normalize_findings
from auditor.models import Artifact, AuditScope, Finding
from auditor.tools.audit_cloud import audit_cloud
from auditor.tools.audit_codebase import audit_codebase, audit_image
from auditor.tools.audit_config import audit_config
from auditor.tools.audit_logs import audit_logs
from auditor.tools.audit_policy_pdf import audit_policy_text
from auditor.tools.audit_text import audit_system_description
from auditor.tools.audit_web import audit_web

log = logging.getLogger(__name__)


def _audit_one(artifact: Artifact, frameworks: list[str] | None) -> list[Finding]:
    if artifact.kind == "text":
        return audit_system_description(artifact.content, frameworks=frameworks, source_artifact=artifact.name)
    if artifact.kind == "policy_pdf":
        return audit_policy_text(artifact.content, frameworks=frameworks, source_artifact=artifact.name)
    if artifact.kind == "config":
        return audit_config(artifact.content, artifact.name, frameworks=frameworks)
    if artifact.kind == "log":
        return audit_logs(artifact.content, frameworks=frameworks, source_artifact=artifact.name)
    if artifact.kind == "codebase":
        return audit_codebase(artifact.content)  # content holds the directory path
    if artifact.kind == "cloud_account":
        return audit_cloud(artifact.content)  # content holds "provider[:profile]"
    if artifact.kind == "image_ref":
        return audit_image(artifact.content)  # content holds the image reference
    if artifact.kind == "target_url":
        return audit_web(artifact.content)  # content holds the URL
    log.warning("Unknown artifact kind: %s", artifact.kind)
    return []


def _audit_one_safe(artifact: Artifact, frameworks: list[str] | None) -> list[Finding]:
    """Audit a single artifact, converting any tool crash into an info finding so
    one bad artifact can't sink the whole run."""
    try:
        return _audit_one(artifact, frameworks)
    except Exception as e:
        log.exception("Audit failed for %s", artifact.name)
        return [
            Finding(
                title=f"Audit tool error while processing {artifact.name}",
                severity="info",
                evidence=f"{type(e).__name__}: {e}",
                recommendation="Re-upload the artifact or check the server logs.",
                source_artifact=artifact.name,
            )
        ]


def audit_node(state: AuditorState) -> dict:
    artifacts: list[Artifact] = state.get("artifacts") or []
    frameworks = state.get("target_frameworks") or None

    all_findings: list[Finding] = []
    if artifacts:
        # Artifacts are independent and each spends most of its time waiting on
        # LLM/subprocess I/O, so audit them concurrently. Order is preserved by
        # reading futures in submission order; results are re-ranked downstream.
        with ThreadPoolExecutor(max_workers=min(len(artifacts), 8)) as pool:
            futures = [pool.submit(_audit_one_safe, a, frameworks) for a in artifacts]
            for future in futures:
                all_findings.extend(future.result())

    enrich_findings(all_findings)
    enrich_with_mappings(all_findings)
    # Normalize: de-duplicate across scanners, score, and rank by risk.
    normalized = normalize_findings(all_findings)

    # Assess controls: turn findings into per-control verdicts + coverage so the
    # report reads like an audit (what passed / failed / went unassessed), not a
    # bare findings list.
    scope = state.get("scope") or AuditScope()
    kinds = [a.kind for a in artifacts]
    assessments, coverage = assess_controls(normalized, kinds, scope)

    return {"findings": normalized, "assessments": assessments, "coverage": coverage}
