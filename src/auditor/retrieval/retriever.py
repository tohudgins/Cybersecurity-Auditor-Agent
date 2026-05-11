"""Retriever wrapper with optional framework metadata filtering."""
from __future__ import annotations

from collections.abc import Sequence

from langchain_core.documents import Document

from auditor.config import settings
from auditor.ingest.frameworks_index import get_vectorstore


def _framework_filter(frameworks: Sequence[str] | None) -> dict | None:
    if not frameworks:
        return None
    if len(frameworks) == 1:
        return {"framework": frameworks[0]}
    return {"framework": {"$in": list(frameworks)}}


def retrieve(
    query: str,
    frameworks: Sequence[str] | None = None,
    k: int | None = None,
) -> list[Document]:
    """Top-k similarity search, optionally restricted to a set of frameworks."""
    store = get_vectorstore()
    return store.similarity_search(
        query,
        k=k or settings.retrieval_k,
        filter=_framework_filter(frameworks),
    )


def format_docs(docs: Sequence[Document]) -> str:
    """Render retrieved chunks with citation headers the LLM can quote."""
    blocks = []
    for d in docs:
        framework = d.metadata.get("framework", "unknown")
        page = d.metadata.get("page", "?")
        blocks.append(f"[{framework}, p.{page}]\n{d.page_content}")
    return "\n\n---\n\n".join(blocks)
