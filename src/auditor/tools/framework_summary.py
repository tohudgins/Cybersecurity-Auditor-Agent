"""Topic summary across one or more frameworks via LLM-driven query expansion + map-reduce.

Pure LCEL — no `langchain.chains` / `langchain.retrievers` umbrella imports.
"""
from __future__ import annotations

from collections.abc import Sequence

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

from auditor.config import settings
from auditor.prompts.compliance import (
    FRAMEWORK_SUMMARY_COMBINE_PROMPT,
    FRAMEWORK_SUMMARY_MAP_PROMPT,
)
from auditor.retrieval.retriever import retrieve

_QUERY_EXPANSION_PROMPT = PromptTemplate(
    input_variables=["topic"],
    template=(
        "Generate 3 alternative phrasings of the following topic for a vector "
        "search over cybersecurity framework documents. One per line, no numbering, "
        "no commentary.\n\n"
        "Topic: {topic}\n\n"
        "Alternative phrasings:"
    ),
)


def _expand_queries(topic: str, llm: ChatOpenAI) -> list[str]:
    chain = _QUERY_EXPANSION_PROMPT | llm | StrOutputParser()
    raw = chain.invoke({"topic": topic})
    expansions = [line.strip() for line in raw.splitlines() if line.strip()]
    return [topic] + expansions[:3]


def summarize_topic(
    topic: str,
    frameworks: Sequence[str] | None = None,
) -> str:
    fast_llm = ChatOpenAI(model=settings.fast_model, api_key=settings.openai_api_key)

    queries = _expand_queries(topic, fast_llm)

    seen: set[str] = set()
    docs = []
    for q in queries:
        for d in retrieve(q, frameworks=frameworks, k=5):
            key = d.page_content[:200]
            if key not in seen:
                seen.add(key)
                docs.append(d)

    if not docs:
        return f"No relevant excerpts found for the topic '{topic}'."

    map_chain = FRAMEWORK_SUMMARY_MAP_PROMPT | fast_llm | StrOutputParser()
    point_blocks = [map_chain.invoke({"text": d.page_content}) for d in docs]

    combine_chain = FRAMEWORK_SUMMARY_COMBINE_PROMPT | fast_llm | StrOutputParser()
    return combine_chain.invoke({"text": "\n\n".join(point_blocks), "topic": topic})
