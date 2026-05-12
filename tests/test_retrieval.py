"""Tests for hybrid retrieval (BM25 + vector + exact control-ID lookup)."""
from __future__ import annotations

from langchain_core.documents import Document

from auditor.retrieval import retriever as retriever_mod

# Capture the real function at import time, before conftest's autouse fixture
# can stub it out.
_real_retrieve = retriever_mod.retrieve


def _doc(text: str, framework: str = "NIST SP 800-53 Rev. 5", control_id: str | None = None, page: int = 1) -> Document:
    meta = {"framework": framework, "source": "test.pdf", "page": page}
    if control_id:
        meta["control_id"] = control_id
    return Document(page_content=text, metadata=meta)


class _FakeStore:
    """Minimal stand-in for the Chroma vectorstore used by `retrieve`."""

    def __init__(self, docs: list[Document]):
        self._docs = docs

    def get(self, where=None, limit=None):
        docs = self._docs
        if where and "control_id" in where:
            cid = where["control_id"]
            docs = [d for d in docs if d.metadata.get("control_id") == cid]
        if where and "framework" in where:
            wf = where["framework"]
            if isinstance(wf, dict) and "$in" in wf:
                allowed = set(wf["$in"])
                docs = [d for d in docs if d.metadata.get("framework") in allowed]
            else:
                docs = [d for d in docs if d.metadata.get("framework") == wf]
        if limit:
            docs = docs[:limit]
        return {
            "documents": [d.page_content for d in docs],
            "metadatas": [d.metadata for d in docs],
        }

    def similarity_search(self, query, k=5, filter=None):
        docs = self._docs
        if filter:
            if "framework" in filter:
                wf = filter["framework"]
                if isinstance(wf, dict) and "$in" in wf:
                    allowed = set(wf["$in"])
                    docs = [d for d in docs if d.metadata.get("framework") in allowed]
                else:
                    docs = [d for d in docs if d.metadata.get("framework") == wf]
        return [d for d in docs if any(t in d.page_content.lower() for t in query.lower().split())][:k]


def _patch_store(monkeypatch, docs: list[Document]):
    fake = _FakeStore(docs)
    monkeypatch.setattr(retriever_mod, "get_vectorstore", lambda: fake)
    retriever_mod.reset_bm25_cache()


def test_exact_control_id_lookup_short_circuits(monkeypatch):
    docs = [
        _doc("AC-2 Account Management body text", control_id="AC-2"),
        _doc("AC-3 Access Enforcement body text", control_id="AC-3"),
        _doc("Filler chunk about logging", control_id="AU-2"),
    ]
    _patch_store(monkeypatch, docs)

    results = _real_retrieve("what does AC-2 require?", k=3)
    control_ids = [d.metadata.get("control_id") for d in results]
    assert "AC-2" in control_ids, "exact-ID lookup must surface AC-2"
    assert control_ids[0] == "AC-2", "AC-2 should be ranked first by RRF"


def test_bm25_finds_keyword_only_matches(monkeypatch):
    docs = [
        _doc("Multi-factor authentication is required for privileged accounts.", control_id="IA-2"),
        _doc("Generic boilerplate about controls", control_id="ZZ-1"),
        _doc("Discusses cryptography modules", control_id="SC-13"),
    ]
    _patch_store(monkeypatch, docs)

    results = _real_retrieve("multi-factor authentication", k=3)
    assert any("Multi-factor" in d.page_content for d in results)


def test_framework_filter_applies_to_both_retrievers(monkeypatch):
    docs = [
        _doc("MFA discussed here", framework="NIST SP 800-53 Rev. 5", control_id="IA-2"),
        _doc("MFA discussed here too", framework="CIS Controls v8.1", control_id="6.5"),
    ]
    _patch_store(monkeypatch, docs)

    results = _real_retrieve("MFA", frameworks=["CIS Controls v8.1"], k=5)
    frameworks = {d.metadata.get("framework") for d in results}
    assert frameworks == {"CIS Controls v8.1"}


def test_tokenizer_preserves_control_ids():
    tokens = retriever_mod._tokenize("Please cite AC-2 and PR.AA-05.")
    assert "ac-2" in tokens
    assert "pr.aa-05" in tokens


def test_rrf_merges_and_dedupes():
    a = _doc("alpha", control_id="A-1")
    b = _doc("beta", control_id="B-1")
    c = _doc("gamma", control_id="C-1")
    merged = retriever_mod._reciprocal_rank_fusion([[a, b], [b, c, a]], k=3)
    assert len(merged) == 3
    keys = {retriever_mod._doc_key(d) for d in merged}
    assert len(keys) == 3
