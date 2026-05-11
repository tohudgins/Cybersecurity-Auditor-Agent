"""Test fixtures: stub out the LLM and retriever so tests never hit the network."""
from __future__ import annotations

import os

import pytest

# Make sure the package can import without a real key.
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-real")


@pytest.fixture(autouse=True)
def _stub_llm_and_retriever(monkeypatch):
    """Replace `run_findings_chain` and `retrieve` everywhere they're used."""
    from auditor.models import Finding
    from auditor.tools import _findings_llm, audit_config, audit_logs, audit_policy_pdf, audit_text
    from auditor.retrieval import retriever as retriever_mod

    def _fake_findings(prompt, inputs, model=None, source_artifact=None):
        return [
            Finding(
                title="LLM stub finding",
                severity="low",
                framework="STUB",
                control_id="X-0",
                evidence="stub evidence",
                recommendation="stub recommendation",
                source_artifact=source_artifact,
            )
        ]

    def _fake_retrieve(query, frameworks=None, k=None):
        return []

    for module in (_findings_llm, audit_config, audit_logs, audit_policy_pdf, audit_text):
        if hasattr(module, "run_findings_chain"):
            monkeypatch.setattr(module, "run_findings_chain", _fake_findings)

    for module in (audit_config, audit_logs, audit_policy_pdf, audit_text, retriever_mod):
        if hasattr(module, "retrieve"):
            monkeypatch.setattr(module, "retrieve", _fake_retrieve)
