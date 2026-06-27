"""Shared LangGraph state for the auditor agent."""
from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from auditor.models import (
    Artifact,
    AuditScope,
    ControlAssessment,
    CoverageSummary,
    Finding,
)


class AuditorState(TypedDict, total=False):
    """State that flows through the supervisor → {compliance | audit} → reporting graph."""

    messages: Annotated[list[BaseMessage], add_messages]
    target_frameworks: list[str]
    artifacts: list[Artifact]
    scope: AuditScope
    findings: list[Finding]
    assessments: list[ControlAssessment]
    coverage: CoverageSummary
    final_report: str
    route: str  # "compliance" or "audit"; set by the supervisor
