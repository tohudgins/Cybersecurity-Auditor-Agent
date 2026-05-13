"""Tests for control-aware chunking in pdf_loader."""
from __future__ import annotations

from langchain_core.documents import Document

from auditor.ingest.pdf_loader import _CONTROL_PATTERNS, _split_by_controls, chunk_documents


def _page(text: str, page: int, framework: str = "NIST SP 800-53 Rev. 5") -> Document:
    return Document(
        page_content=text,
        metadata={"framework": framework, "source": "test.pdf", "page": page},
    )


def test_per_control_split_emits_one_chunk_per_id():
    text = (
        "AC-2 ACCOUNT MANAGEMENT\nDefine and document the types of accounts.\n\n"
        "AC-3 ACCESS ENFORCEMENT\nEnforce approved authorizations for logical access.\n\n"
        "AC-4 INFORMATION FLOW\nControl flows between systems.\n\n"
        "AC-5 SEPARATION OF DUTIES\nIdentify and document.\n\n"
        "AC-6 LEAST PRIVILEGE\nEmploy the principle of least privilege.\n\n"
        "AC-7 UNSUCCESSFUL LOGON\nEnforce a limit of consecutive invalid logon attempts.\n\n"
        "AC-8 SYSTEM USE NOTIFICATION\nDisplay the notification message.\n\n"
        "AC-11 SESSION LOCK\nPrevent further access after inactivity.\n"
    )
    chunks = _split_by_controls([_page(text, 1)])
    assert chunks is not None
    control_ids = sorted({c.metadata["control_id"] for c in chunks})
    assert {"AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-7", "AC-8", "AC-11"} <= set(control_ids)


def test_per_control_split_returns_none_below_threshold():
    """Narrative text that mentions only one control should fall back to generic chunking."""
    text = "This document discusses how AC-2 applies to cloud workloads in general."
    assert _split_by_controls([_page(text, 1)]) is None


def test_per_control_split_returns_none_for_non_catalog_framework():
    text = "NIST IR 7298 is the glossary. AC-2 means account management."
    pages = [_page(text * 3, 1, framework="NIST IR 7298 Rev. 3 (Glossary)")]
    assert _split_by_controls(pages) is None


def test_chunk_documents_mixes_per_control_and_generic():
    catalog_text = "\n".join(
        f"{cid} {name}\nDescription paragraph for {cid}. " + "Body text " * 25
        for cid, name in [
            ("AC-1", "POLICY"),
            ("AC-2", "ACCOUNT"),
            ("AC-3", "ACCESS"),
            ("AC-4", "FLOW"),
            ("AC-5", "DUTIES"),
            ("AC-6", "PRIV"),
            ("AC-7", "LOGON"),
            ("AC-8", "NOTICE"),
        ]
    )
    catalog = _page(catalog_text, 1)
    narrative_pages = [
        _page(
            "Incident response is a key capability. Build a team. Communicate with stakeholders. " * 30,
            i,
            framework="NIST SP 800-61 Rev. 3 (Incident Response)",
        )
        for i in range(1, 4)
    ]
    chunks = chunk_documents([catalog, *narrative_pages])
    has_control = [c for c in chunks if c.metadata.get("control_id")]
    no_control = [c for c in chunks if not c.metadata.get("control_id")]
    assert has_control, "expected per-control chunks for the 800-53 page"
    assert no_control, "expected generic chunks for the 800-61 narrative pages"


def test_control_patterns_match_expected_ids():
    """Smoke-test the regex patterns against realistic snippets."""
    cases = {
        "NIST SP 800-53 Rev. 5": ("AC-2 Account Management", "AC-2"),
        "NIST SP 800-171 Rev. 3": ("3.1.1 Limit system access", "3.1.1"),
        "NIST Cybersecurity Framework 2.1": ("PR.AA-05 Access permissions", "PR.AA-05"),
        "NIST SP 800-218 (SSDF)": ("PO.1.1 Document policies", "PO.1.1"),
        "CIS Controls v8.1": ("5.4 Restrict Administrator Privileges", "5.4"),
        "OWASP Top 10 2025": ("# A01:2025 – Broken Access Control", "A01:2025"),
    }
    for framework, (text, expected_id) in cases.items():
        pattern = _CONTROL_PATTERNS[framework]
        match = pattern.search(text)
        assert match, f"{framework} pattern failed on: {text}"
        assert match.group(1) == expected_id
