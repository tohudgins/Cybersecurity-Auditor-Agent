"""Compliance Q&A: retrieve framework chunks, synthesize a cited answer."""
from __future__ import annotations

from collections.abc import Generator, Sequence

from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from auditor.config import settings
from auditor.enrichment.corpus_coverage import caveat_for
from auditor.prompts.compliance import COMPLIANCE_QA_PROMPT, FOLLOWUP_QA_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve

_NO_DOCS_MSG = "No relevant framework excerpts were found for this question."


def answer_compliance_question(
    question: str,
    frameworks: Sequence[str] | None = None,
) -> str:
    docs = retrieve(question, frameworks=frameworks)
    if not docs:
        return _NO_DOCS_MSG

    llm = ChatOpenAI(
        model=settings.synthesis_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.synthesis_reasoning_effort,
    )
    chain = COMPLIANCE_QA_PROMPT | llm | StrOutputParser()
    answer = chain.invoke({"context": format_docs(docs), "question": question})
    caveat = caveat_for(question)
    return f"{caveat}\n\n{answer}" if caveat else answer


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

    caveat = caveat_for(question)
    if caveat:
        yield caveat + "\n\n"

    llm = ChatOpenAI(
        model=settings.synthesis_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.synthesis_reasoning_effort,
    )
    chain = COMPLIANCE_QA_PROMPT | llm | StrOutputParser()
    yield from chain.stream({"context": format_docs(docs), "question": question})


def stream_followup_answer(
    question: str,
    report_md: str,
    frameworks: Sequence[str] | None = None,
) -> Generator[str, None, None]:
    """Answer a follow-up question about a just-produced audit report.

    Grounds the answer in the report itself, augmented with retrieved framework
    excerpts for control/remediation guidance. Yields text chunks for streaming.
    """
    docs = retrieve(question, frameworks=frameworks)
    context = format_docs(docs) if docs else "(no additional framework excerpts retrieved)"

    caveat = caveat_for(question)
    if caveat:
        yield caveat + "\n\n"

    llm = ChatOpenAI(
        model=settings.synthesis_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.synthesis_reasoning_effort,
    )
    chain = FOLLOWUP_QA_PROMPT | llm | StrOutputParser()
    yield from chain.stream(
        {"report": report_md, "context": context, "question": question}
    )
