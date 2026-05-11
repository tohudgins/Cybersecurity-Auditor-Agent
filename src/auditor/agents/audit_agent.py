"""Audit agent node: dispatches each uploaded artifact to its matching tool."""
from __future__ import annotations

import logging

from auditor.agents.state import AuditorState
from auditor.models import Artifact, Finding
from auditor.tools.audit_config import audit_config
from auditor.tools.audit_logs import audit_logs
from auditor.tools.audit_policy_pdf import audit_policy_text
from auditor.tools.audit_text import audit_system_description


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
    log.warning("Unknown artifact kind: %s", artifact.kind)
    return []


def audit_node(state: AuditorState) -> dict:
    artifacts: list[Artifact] = state.get("artifacts") or []
    frameworks = state.get("target_frameworks") or None

    all_findings: list[Finding] = []
    for artifact in artifacts:
        try:
            all_findings.extend(_audit_one(artifact, frameworks))
        except Exception as e:  # don't let one bad artifact kill the run
            log.exception("Audit failed for %s", artifact.name)
            all_findings.append(
                Finding(
                    title=f"Audit tool error while processing {artifact.name}",
                    severity="info",
                    evidence=f"{type(e).__name__}: {e}",
                    recommendation="Re-upload the artifact or check the server logs.",
                    source_artifact=artifact.name,
                )
            )

    return {"findings": all_findings}
