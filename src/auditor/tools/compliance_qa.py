"""Compliance Q&A: retrieve framework chunks, synthesize a cited answer."""
from __future__ import annotations

from collections.abc import Generator, Sequence

from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from auditor.config import settings
from auditor.prompts.compliance import COMPLIANCE_QA_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve

_NO_DOCS_MSG = "No relevant framework excerpts were found for this question."


def answer_compliance_question(
    question: str,
    frameworks: Sequence[str] | None = None,
) -> str:
    docs = retrieve(question, frameworks=frameworks)
    if not docs:
        return _NO_DOCS_MSG

    llm = ChatOpenAI(model=settings.synthesis_model, api_key=settings.openai_api_key)
    chain = COMPLIANCE_QA_PROMPT | llm | StrOutputParser()
    return chain.invoke({"context": format_docs(docs), "question": question})


def stream_compliance_answer(
    question: str,
    frameworks: Sequence[str] | None = None,
) -> Generator[str, None, None]:
    """Streaming variant — yields text chunks as the LLM produces them.

    Suitable for ``st.write_stream()`` in the Streamlit UI.
    """
    docs = retrieve(question, frameworks=frameworks)
    if not docs:
        yield _NO_DOCS_MSG
        return

    llm = ChatOpenAI(model=settings.synthesis_model, api_key=settings.openai_api_key)
    chain = COMPLIANCE_QA_PROMPT | llm | StrOutputParser()
    yield from chain.stream({"context": format_docs(docs), "question": question})
