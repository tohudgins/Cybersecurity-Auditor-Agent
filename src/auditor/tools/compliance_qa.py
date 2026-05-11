"""Compliance Q&A: retrieve framework chunks, synthesize a cited answer."""
from __future__ import annotations

from typing import Sequence

from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from auditor.config import settings
from auditor.prompts.compliance import COMPLIANCE_QA_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve


def answer_compliance_question(
    question: str,
    frameworks: Sequence[str] | None = None,
) -> str:
    docs = retrieve(question, frameworks=frameworks)
    if not docs:
        return "No relevant framework excerpts were found for this question."

    llm = ChatOpenAI(model=settings.synthesis_model, api_key=settings.openai_api_key)
    chain = COMPLIANCE_QA_PROMPT | llm | StrOutputParser()
    return chain.invoke({"context": format_docs(docs), "question": question})
