"""LangGraph wiring: supervisor → {compliance | planning → audit} → reporting → END."""
from __future__ import annotations

import shutil

from langgraph.graph import END, START, StateGraph

from auditor.agents.audit_agent import audit_node
from auditor.agents.compliance_agent import compliance_node
from auditor.agents.reporting_agent import reporting_node
from auditor.agents.state import AuditorState
from auditor.config import settings
from auditor.planner import build_plan


def supervisor_node(state: AuditorState) -> dict:
    """Pick the route based on whether the user uploaded any artifacts."""
    artifacts = state.get("artifacts") or []
    route = "audit" if artifacts else "compliance"
    return {"route": route}


def planning_node(state: AuditorState) -> dict:
    """Adaptive scope planning: pull adjacent attack surface into the run.

    Runs before the audit dispatch so any artifacts it adds (e.g. a codebase's
    Dockerfile base image) join the *same* concurrent audit batch — broadening
    coverage at wall-clock ``max(scan, image-pull)``, not their sum.
    """
    artifacts = state.get("artifacts") or []
    if not settings.auto_expand_scope:
        return {}
    plan = build_plan(
        artifacts,
        allow_local=settings.allow_local_targets,
        trivy_available=shutil.which("trivy") is not None,
    )
    out: dict = {}
    if plan.notes:
        out["plan_notes"] = plan.notes
    if plan.recommendations:
        out["recommendations"] = plan.recommendations
    if len(plan.artifacts) != len(artifacts):
        out["artifacts"] = plan.artifacts
    return out


def _route(state: AuditorState) -> str:
    return state.get("route") or "compliance"


def build_graph():
    graph = StateGraph(AuditorState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("compliance", compliance_node)
    graph.add_node("planning", planning_node)
    graph.add_node("audit", audit_node)
    graph.add_node("reporting", reporting_node)

    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        _route,
        {"compliance": "compliance", "audit": "planning"},
    )
    graph.add_edge("planning", "audit")
    graph.add_edge("compliance", "reporting")
    graph.add_edge("audit", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile()


# Module-level singleton so repeated invocations don't pay graph-compile cost.
AUDITOR_GRAPH = build_graph()
