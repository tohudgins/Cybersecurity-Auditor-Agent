from langchain_core.messages import HumanMessage

from auditor.agents import graph as graph_mod
from auditor.models import Artifact


def test_supervisor_routes_no_artifacts_to_compliance(monkeypatch):
    captured = {}

    def fake_compliance(state):
        captured["called"] = "compliance"
        return {"final_report": "compliance answer"}

    def fake_audit(state):
        captured["called"] = "audit"
        return {"findings": []}

    monkeypatch.setattr(graph_mod, "compliance_node", fake_compliance)
    monkeypatch.setattr(graph_mod, "audit_node", fake_audit)

    graph = graph_mod.build_graph()
    out = graph.invoke({"messages": [HumanMessage(content="What is NIST CSF?")], "artifacts": []})
    assert captured["called"] == "compliance"
    assert out.get("final_report") == "compliance answer"


def test_supervisor_routes_with_artifacts_to_audit(monkeypatch):
    captured = {}

    def fake_compliance(state):
        captured["called"] = "compliance"
        return {}

    def fake_audit(state):
        captured["called"] = "audit"
        return {"findings": []}

    monkeypatch.setattr(graph_mod, "compliance_node", fake_compliance)
    monkeypatch.setattr(graph_mod, "audit_node", fake_audit)

    graph = graph_mod.build_graph()
    out = graph.invoke(
        {
            "messages": [HumanMessage(content="audit this")],
            "artifacts": [Artifact(kind="config", name="sshd_config", content="PermitRootLogin yes")],
        }
    )
    assert captured["called"] == "audit"
    assert "final_report" in out  # reporting node always emits
