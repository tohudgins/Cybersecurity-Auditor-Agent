"""Hybrid retrieval: BM25 (keyword) + Chroma vector search, fused with RRF.

Why hybrid: compliance Q&A often involves exact control IDs ("PR.AA-05",
"CC6.1") that vector search treats as generic tokens. BM25 nails those.
Vector search wins on semantic queries ("what controls prevent ransomware?").
Reciprocal Rank Fusion (RRF) combines the two ranked lists without either
retriever needing to know about the other's scoring.

We also support exact metadata lookups for `control_id` so a question that
parses out a control ID can short-circuit to the exact chunk.
"""
from __future__ import annotations

import logging
import pickle
import re
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

import numpy as np
from langchain_core.documents import Document
from rank_bm25 import BM25Okapi

from auditor.config import settings
from auditor.ingest.frameworks_index import get_vectorstore
from auditor.retrieval.framework_router import detect_frameworks

log = logging.getLogger(__name__)

# Cached BM25 index, built lazily from all Chroma docs on first query.
_bm25: BM25Okapi | None = None
_bm25_docs: list[Document] = []

# On-disk BM25 cache so the first query of a fresh process doesn't pay the cost
# of pulling every chunk out of Chroma and re-tokenizing the whole corpus.
# Keyed on the collection's chunk count, so a rebuild (which changes the count)
# transparently invalidates it. Delete the file to force a rebuild otherwise.
_BM25_CACHE_PATH = settings.chroma_dir / "bm25_cache.pkl"


def _collection_count(store) -> int | None:
    """Cheap doc count for cache invalidation; None if the store can't report it
    (e.g. the in-memory fake store used in tests)."""
    try:
        return store._collection.count()
    except Exception:
        return None


def _load_bm25_cache(count: int) -> tuple[BM25Okapi, list[Document]] | None:
    if not _BM25_CACHE_PATH.exists():
        return None
    try:
        with _BM25_CACHE_PATH.open("rb") as fh:
            data = pickle.load(fh)
        if data.get("count") != count:
            return None
        log.info("Loaded BM25 cache (%d chunks) from %s", count, _BM25_CACHE_PATH)
        return data["bm25"], data["docs"]
    except Exception as exc:  # corrupt/incompatible cache — rebuild
        log.warning("Ignoring unreadable BM25 cache: %s", exc)
        return None


def _save_bm25_cache(count: int, bm25: BM25Okapi, docs: list[Document]) -> None:
    try:
        _BM25_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _BM25_CACHE_PATH.open("wb") as fh:
            pickle.dump({"count": count, "bm25": bm25, "docs": docs}, fh)
    except Exception as exc:  # best-effort; a failed write just costs a rebuild
        log.warning("Could not write BM25 cache: %s", exc)

# Tokens that look like control IDs and should be preserved as-is by the
# tokenizer (so BM25 can match them exactly).
_CONTROL_ID_LIKE = re.compile(r"[A-Z]{2,3}-?\d+(?:\.\d+)*(?:\([0-9a-z]+\))?", re.IGNORECASE)
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9\-\.\:]+")


def _tokenize(text: str) -> list[str]:
    """Split on non-alphanum (preserving '-', '.', ':' inside tokens) and lowercase.
    Trailing/leading punctuation is stripped so 'AC-2.' tokenizes as 'ac-2'.
    """
    raw = _TOKEN_SPLIT.split(text.lower())
    cleaned: list[str] = []
    for t in raw:
        t = t.strip("-.:")
        if t:
            cleaned.append(t)
    return cleaned


def _framework_filter(frameworks: Sequence[str] | None) -> dict | None:
    if not frameworks:
        return None
    if len(frameworks) == 1:
        return {"framework": frameworks[0]}
    return {"framework": {"$in": list(frameworks)}}


def _get_all_documents(store, page: int = 2000) -> list[Document]:
    """Fetch every chunk's text + metadata, paged. A single unbounded
    ``store.get()`` blows chromadb's SQLite variable limit on a large corpus
    (40k+ chunks), so page through with limit/offset."""
    docs: list[Document] = []
    offset = 0
    while True:
        try:
            raw = store.get(include=["documents", "metadatas"], limit=page, offset=offset)
        except TypeError:
            # Fake/in-memory store used in tests may not support limit/offset.
            raw = store.get()
            return [
                Document(page_content=t or "", metadata=m or {})
                for t, m in zip(raw.get("documents") or [], raw.get("metadatas") or [], strict=False)
            ]
        batch = raw.get("documents") or []
        if not batch:
            break
        metas = raw.get("metadatas") or []
        docs.extend(
            Document(page_content=t or "", metadata=m or {})
            for t, m in zip(batch, metas, strict=False)
        )
        offset += len(batch)
    return docs


def _build_bm25_index() -> None:
    """Build (or load from disk) an in-memory BM25 index over all Chroma chunks."""
    global _bm25, _bm25_docs
    store = get_vectorstore()

    count = _collection_count(store)
    if count is not None:
        cached = _load_bm25_cache(count)
        if cached is not None:
            _bm25, _bm25_docs = cached
            return

    docs = _get_all_documents(store)
    log.info("Building BM25 over %d chunks", len(docs))
    _bm25_docs = docs
    tokenized = [_tokenize(d.page_content) for d in docs]
    # Guard against an empty corpus (e.g., before index is built)
    _bm25 = BM25Okapi(tokenized) if tokenized and any(tokenized) else None

    if count is not None and _bm25 is not None:
        _save_bm25_cache(count, _bm25, _bm25_docs)


def _bm25_search(query: str, k: int) -> list[Document]:
    global _bm25
    if _bm25 is None:
        _build_bm25_index()
    if _bm25 is None or not _bm25_docs:
        return []
    scores = np.asarray(_bm25.get_scores(_tokenize(query)))
    n = min(k * 3, len(scores))
    # argpartition finds the top-n in O(N) instead of a full O(N log N) Python
    # sort over all ~40k scores (the retrieval-latency hot spot), then we sort
    # just those n.
    part = np.argpartition(scores, -n)[-n:]
    top_idx = part[np.argsort(scores[part])[::-1]]
    return [_bm25_docs[i] for i in top_idx if scores[i] > 0]


def _vector_search(query: str, k: int, frameworks: Sequence[str] | None) -> list[Document]:
    store = get_vectorstore()
    return store.similarity_search(query, k=k, filter=_framework_filter(frameworks))


def _exact_control_lookup(query: str) -> list[Document]:
    """If the query mentions an exact control ID we know about, fetch chunks
    with that control_id directly from Chroma metadata. Bypasses ranking
    entirely for control-ID questions like 'what does AC-2 require?'.
    """
    candidates = _CONTROL_ID_LIKE.findall(query)
    if not candidates:
        return []
    # Normalize: uppercase the alpha prefix, keep numeric tail.
    normalized = []
    for c in candidates:
        m = re.match(r"([A-Za-z]{2,3})[\-\.]?(\d+.*)", c)
        if not m:
            continue
        normalized.append(f"{m.group(1).upper()}-{m.group(2)}")
    if not normalized:
        return []

    store = get_vectorstore()
    hits: list[Document] = []
    for control_id in normalized:
        raw = store.get(where={"control_id": control_id}, limit=5)
        for content, meta in zip(
            raw.get("documents") or [], raw.get("metadatas") or [], strict=False
        ):
            hits.append(Document(page_content=content or "", metadata=meta or {}))
    return hits


def _doc_key(d: Document) -> str:
    src = d.metadata.get("source", "?")
    page = d.metadata.get("page", "?")
    cid = d.metadata.get("control_id", "")
    return f"{src}::p{page}::{cid}::{d.page_content[:80]}"


def _reciprocal_rank_fusion(
    runs: Sequence[Sequence[Document]],
    k: int,
    rrf_k: int = 60,
) -> list[Document]:
    """Combine ranked lists. Higher rank → higher contribution (1 / (rrf_k + rank))."""
    scores: dict[str, float] = {}
    docs: dict[str, Document] = {}
    for run in runs:
        for rank, d in enumerate(run):
            key = _doc_key(d)
            scores[key] = scores.get(key, 0.0) + 1.0 / (rrf_k + rank + 1)
            docs.setdefault(key, d)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return [docs[key] for key, _ in ranked[:k]]


def _rerank(
    query: str,
    docs: list[Document],
    boost_frameworks: Sequence[str] | None,
    k: int,
) -> list[Document]:
    """Re-order the fused candidate pool with cheap, high-signal features, then
    trim to k. No model call — precision without latency:

    * base = the fusion rank (preserve BM25+vector agreement);
    * +exact control-ID match (a query naming AC-2 wants the AC-2 chunk on top);
    * +framework match (when the query named a framework);
    * +lexical overlap with the query.
    """
    q_tokens = set(_tokenize(query))
    q_ids = {c.upper() for c in _CONTROL_ID_LIKE.findall(query)}
    boost = set(boost_frameworks or [])

    scored: list[tuple[float, Document]] = []
    for rank, d in enumerate(docs):
        s = 1.0 / (rank + 1)
        meta = d.metadata
        if boost and meta.get("framework") in boost:
            s += 1.0  # a named-framework match is decisive over raw fusion rank
        cid = (meta.get("control_id") or "").upper()
        if cid and q_ids and any(cid == qi or cid in qi or qi in cid for qi in q_ids):
            s += 1.5
        if q_tokens:
            d_tokens = set(_tokenize(d.page_content[:500]))
            s += 0.4 * len(q_tokens & d_tokens) / len(q_tokens)
        scored.append((s, d))
    scored.sort(key=lambda sd: sd[0], reverse=True)
    return [d for _, d in scored[:k]]


def retrieve(
    query: str,
    frameworks: Sequence[str] | None = None,
    k: int | None = None,
) -> list[Document]:
    """Hybrid (vector + BM25) top-k retrieval, framework-scoped and re-ranked.

    Vector similarity and BM25 keyword search are fused via RRF; if the query
    names an exact control ID those chunks float up. When the caller doesn't pin
    ``frameworks``, we auto-scope to the framework(s) the query names (so a
    "SOC 2 CC6.1" question isn't drowned out by other standards). A cheap
    re-rank orders the fused pool before trimming to k.
    """
    k = k or settings.retrieval_k

    # Scope to the framework(s) the query explicitly names (unless caller pinned).
    if not frameworks:
        frameworks = detect_frameworks(query) or None

    # The three runs are independent — vector search waits on a network embed
    # while BM25 is CPU-bound — so run them concurrently (wall-clock ≈ the slowest,
    # not their sum).
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_exact = pool.submit(_exact_control_lookup, query)
        f_vec = pool.submit(_vector_search, query, k * 2, frameworks)
        f_bm25 = pool.submit(_bm25_search, query, k * 2)
        exact, vec, bm25 = f_exact.result(), f_vec.result(), f_bm25.result()

    # Apply framework filter to BM25 + exact results post-hoc (BM25 has no filter).
    if frameworks:
        fw_set = set(frameworks)
        bm25 = [d for d in bm25 if d.metadata.get("framework") in fw_set]
        exact = [d for d in exact if d.metadata.get("framework") in fw_set]

    # Fuse a larger pool, then re-rank down to k.
    pool = _reciprocal_rank_fusion([exact, vec, bm25], k=k * 3)
    return _rerank(query, pool, frameworks, k)


def format_docs(docs: Sequence[Document]) -> str:
    """Render retrieved chunks with citation headers the LLM can quote."""
    blocks = []
    for d in docs:
        framework = d.metadata.get("framework", "unknown")
        page = d.metadata.get("page", "?")
        control_id = d.metadata.get("control_id")
        header = f"[{framework}, p.{page}"
        if control_id:
            header += f", {control_id}"
        header += "]"
        blocks.append(f"{header}\n{d.page_content}")
    return "\n\n---\n\n".join(blocks)


def warm_cache() -> None:
    """Eagerly build/load the BM25 index (and instantiate the Chroma client) so
    the first user query doesn't pay the cold-start cost. Idempotent — backed by
    the in-memory and on-disk caches, so repeat calls are no-ops. Intended to be
    called once at app startup (e.g. behind Streamlit's ``st.cache_resource``).
    """
    if _bm25 is None:
        _build_bm25_index()


def reset_bm25_cache() -> None:
    """Test helper: drop the in-memory BM25 index."""
    global _bm25, _bm25_docs
    _bm25 = None
    _bm25_docs = []
