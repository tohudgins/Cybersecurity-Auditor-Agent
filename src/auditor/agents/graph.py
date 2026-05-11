"""LangGraph wiring: supervisor → {compliance | audit} → reporting → END."""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from auditor.agents.audit_agent import audit_node
from auditor.agents.compliance_agent import compliance_node
from auditor.agents.reporting_agent import reporting_node
from auditor.agents.state import AuditorState


def supervisor_node(state: AuditorState) -> dict:
    """Pick the route based on whether the user uploaded any artifacts."""
    artifacts = state.get("artifacts") or []
    route = "audit" if artifacts else "compliance"
    return {"route": route}


def _route(state: AuditorState) -> str:
    return state.get("route") or "compliance"


def build_graph():
    graph = StateGraph(AuditorState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("compliance", compliance_node)
    graph.add_node("audit", audit_node)
    graph.add_node("reporting", reporting_node)

    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        _route,
        {"compliance": "compliance", "audit": "audit"},
    )
    graph.add_edge("compliance", "reporting")
    graph.add_edge("audit", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile()


# Module-level singleton so repeated invocations don't pay graph-compile cost.
AUDITOR_GRAPH = build_graph()
