"""Topic summary across one or more frameworks via multi-query retrieval + map-reduce."""
from __future__ import annotations

from typing import Sequence

from langchain.chains.summarize import load_summarize_chain
from langchain.retrievers.multi_query import MultiQueryRetriever
from langchain_openai import ChatOpenAI

from auditor.config import settings
from auditor.ingest.frameworks_index import get_vectorstore
from auditor.prompts.compliance import (
    FRAMEWORK_SUMMARY_COMBINE_PROMPT,
    FRAMEWORK_SUMMARY_MAP_PROMPT,
)
from auditor.retrieval.retriever import _framework_filter


def summarize_topic(
    topic: str,
    frameworks: Sequence[str] | None = None,
) -> str:
    store = get_vectorstore()
    base = store.as_retriever(
        search_kwargs={"k": settings.retrieval_k, "filter": _framework_filter(frameworks)}
    )

    fast_llm = ChatOpenAI(model=settings.fast_model, api_key=settings.openai_api_key)
    multi_query = MultiQueryRetriever.from_llm(retriever=base, llm=fast_llm)

    docs = multi_query.invoke(topic)
    if not docs:
        return f"No relevant excerpts found for the topic '{topic}'."

    chain = load_summarize_chain(
        llm=fast_llm,
        chain_type="map_reduce",
        map_prompt=FRAMEWORK_SUMMARY_MAP_PROMPT,
        combine_prompt=FRAMEWORK_SUMMARY_COMBINE_PROMPT,
    )
    result = chain.invoke({"input_documents": docs, "topic": topic})
    return result["output_text"]
