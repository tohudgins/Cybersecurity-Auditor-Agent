"""Test fixtures: stub out the LLM, retriever, and enrichment network calls."""
from __future__ import annotations

import os

import pytest

# Make sure the package can import without a real key.
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-real")


@pytest.fixture(autouse=True)
def _stub_llm_and_retriever(monkeypatch):
    """Replace `run_findings_chain`, `retrieve`, KEV, EPSS, and ATT&CK STIX calls."""
    from auditor.enrichment import epss as epss_mod
    from auditor.enrichment import kev as kev_mod
    from auditor.enrichment import mitre as mitre_mod
    from auditor.models import Finding
    from auditor.retrieval import retriever as retriever_mod
    from auditor.tools import (
        _findings_llm,
        audit_config,
        audit_logs,
        audit_policy_pdf,
        audit_text,
        compliance_qa,
    )

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

    for module in (audit_config, audit_logs, audit_policy_pdf, audit_text, retriever_mod, compliance_qa):
        if hasattr(module, "retrieve"):
            monkeypatch.setattr(module, "retrieve", _fake_retrieve)

    # Default: KEV / EPSS lookups return safe defaults so tests don't hit the network.
    monkeypatch.setattr(kev_mod, "is_kev", lambda _cve: False)
    monkeypatch.setattr(epss_mod, "epss_score", lambda _cve: None)

    # Stub the STIX phrase index so ATT&CK tests use only the hand-curated keywords
    # and never hit the network.  Individual tests that want STIX coverage can
    # monkeypatch mitre_mod._stix_phrases to a custom dict.
    monkeypatch.setattr(mitre_mod, "_stix_phrases", {})
