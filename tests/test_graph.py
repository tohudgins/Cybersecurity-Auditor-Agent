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


def test_planning_node_expands_codebase_scope_before_audit(monkeypatch, tmp_path):
    """A codebase with a Dockerfile gets its base image pulled into scope, and the
    audit node receives the expanded artifact list."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim\nRUN pip install x")

    seen = {}

    def fake_audit(state):
        seen["kinds"] = [a.kind for a in state.get("artifacts", [])]
        return {"findings": []}

    # Pretend Trivy is on PATH so planning is active.
    monkeypatch.setattr(graph_mod.shutil, "which", lambda _name: "/usr/bin/trivy")
    monkeypatch.setattr(graph_mod.settings, "auto_expand_scope", True)
    monkeypatch.setattr(graph_mod.settings, "allow_local_targets", True)
    monkeypatch.setattr(graph_mod, "audit_node", fake_audit)

    graph = graph_mod.build_graph()
    out = graph.invoke(
        {
            "messages": [HumanMessage(content="audit my repo")],
            "artifacts": [Artifact(kind="codebase", name=str(tmp_path), content=str(tmp_path))],
        }
    )

    assert "image_ref" in seen["kinds"]  # base image was added to scope
    assert "## Audit Plan" in out["final_report"]
    assert "python:3.9-slim" in out["final_report"]


def test_planning_node_disabled_leaves_scope_untouched(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim")

    seen = {}

    def fake_audit(state):
        seen["kinds"] = [a.kind for a in state.get("artifacts", [])]
        return {"findings": []}

    monkeypatch.setattr(graph_mod.shutil, "which", lambda _name: "/usr/bin/trivy")
    monkeypatch.setattr(graph_mod.settings, "auto_expand_scope", False)
    monkeypatch.setattr(graph_mod, "audit_node", fake_audit)

    graph = graph_mod.build_graph()
    out = graph.invoke(
        {
            "messages": [HumanMessage(content="audit my repo")],
            "artifacts": [Artifact(kind="codebase", name=str(tmp_path), content=str(tmp_path))],
        }
    )
    assert seen["kinds"] == ["codebase"]  # no expansion
    assert "## Audit Plan" not in out["final_report"]
