"""Compliance Q&A: retrieve framework chunks, synthesize a cited answer.

Multi-turn: recent conversation is threaded in so follow-ups ("what about the
enhancement?") resolve against the thread. Mapping/comparison questions get the
authoritative cross-framework crosswalk injected alongside the retrieved text.
"""
from __future__ import annotations

from collections.abc import Generator, Sequence

from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from auditor.config import settings
from auditor.enrichment.corpus_coverage import caveat_for
from auditor.enrichment.mappings import crosswalk_context
from auditor.prompts.compliance import COMPLIANCE_QA_PROMPT, FOLLOWUP_QA_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve

_NO_DOCS_MSG = "No relevant framework excerpts were found for this question."

# A conversation turn: (role, content), role in {"user", "assistant"}.
Turn = tuple[str, str]


def _format_history(history: Sequence[Turn] | None, max_turns: int = 6, max_chars: int = 700) -> str:
    """Render the recent conversation for the prompt (bounded for speed)."""
    if not history:
        return ""
    recent = list(history)[-max_turns:]
    lines = []
    for role, content in recent:
        who = "User" if role == "user" else "Assistant"
        text = (content or "").strip().replace("\n", " ")
        if len(text) > max_chars:
            text = text[:max_chars] + "…"
        lines.append(f"{who}: {text}")
    return "Conversation so far:\n" + "\n".join(lines) + "\n\n"


def _retrieval_query(question: str, history: Sequence[Turn] | None) -> str:
    """Expand a terse follow-up with the prior user turn so retrieval has context
    (e.g. "what about the enhancement?" alone retrieves poorly)."""
    if history and len(question.split()) < 6:
        for role, content in reversed(list(history)):
            if role == "user" and content:
                return f"{content} {question}"
    return question


def _llm() -> ChatOpenAI:
    return ChatOpenAI(
        model=settings.synthesis_model,
        api_key=settings.openai_api_key,
        reasoning_effort=settings.synthesis_reasoning_effort,
    )


def _inputs(question: str, docs, history: Sequence[Turn] | None) -> dict:
    return {
        "context": format_docs(docs),
        "question": question,
        "history": _format_history(history),
        "crosswalk": crosswalk_context(question),
    }


def answer_compliance_question(
    question: str,
    frameworks: Sequence[str] | None = None,
    history: Sequence[Turn] | None = None,
) -> str:
    docs = retrieve(_retrieval_query(question, history), frameworks=frameworks)
    if not docs:
        return _NO_DOCS_MSG
    chain = COMPLIANCE_QA_PROMPT | _llm() | StrOutputParser()
    answer = chain.invoke(_inputs(question, docs, history))
    caveat = caveat_for(question)
    return f"{caveat}\n\n{answer}" if caveat else answer


def stream_compliance_answer(
    question: str,
    frameworks: Sequence[str] | None = None,
    history: Sequence[Turn] | None = None,
) -> Generator[str, None, None]:
    """Streaming variant — yields text chunks for ``st.write_stream()``."""
    docs = retrieve(_retrieval_query(question, history), frameworks=frameworks)
    if not docs:
        yield _NO_DOCS_MSG
        return

    caveat = caveat_for(question)
    if caveat:
        yield caveat + "\n\n"

    chain = COMPLIANCE_QA_PROMPT | _llm() | StrOutputParser()
    yield from chain.stream(_inputs(question, docs, history))


def stream_followup_answer(
    question: str,
    report_md: str,
    frameworks: Sequence[str] | None = None,
) -> Generator[str, None, None]:
    """Answer a follow-up about a just-produced audit report, grounded in the
    report + retrieved framework excerpts. Yields text chunks for streaming."""
    docs = retrieve(question, frameworks=frameworks)
    context = format_docs(docs) if docs else "(no additional framework excerpts retrieved)"

    caveat = caveat_for(question)
    if caveat:
        yield caveat + "\n\n"

    chain = FOLLOWUP_QA_PROMPT | _llm() | StrOutputParser()
    yield from chain.stream(
        {"report": report_md, "context": context, "question": question}
    )
