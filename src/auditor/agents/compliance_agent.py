"""Compliance agent node: answers a user question against the framework corpus."""
from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from auditor.agents.state import AuditorState
from auditor.tools.compliance_qa import answer_compliance_question
from auditor.tools.framework_summary import summarize_topic


_SUMMARY_TRIGGERS = ("summarize", "summary", "overview", "high-level", "key points")


def _last_user_question(state: AuditorState) -> str:
    for msg in reversed(state.get("messages", [])):
        if isinstance(msg, HumanMessage):
            return msg.content if isinstance(msg.content, str) else str(msg.content)
    return ""


def compliance_node(state: AuditorState) -> dict:
    question = _last_user_question(state)
    frameworks = state.get("target_frameworks") or None

    use_summary = any(t in question.lower() for t in _SUMMARY_TRIGGERS)

    if use_summary:
        answer = summarize_topic(question, frameworks=frameworks)
    else:
        answer = answer_compliance_question(question, frameworks=frameworks)

    return {"messages": [AIMessage(content=answer)], "final_report": answer}
