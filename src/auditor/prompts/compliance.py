from langchain_core.prompts import PromptTemplate

COMPLIANCE_QA_PROMPT = PromptTemplate(
    input_variables=["context", "question"],
    template=(
        "You are a cybersecurity compliance assistant. Answer the user's question using ONLY the "
        "context below. The context contains excerpts from cybersecurity frameworks (NIST, CIS, "
        "OWASP, MITRE ATT&CK, CompTIA Security+). Each excerpt is prefixed with its source in "
        "brackets like [Framework Name, p.N].\n\n"
        "Cite the framework and page for every claim using that bracket format. If the context does "
        "not contain the answer, say so plainly instead of guessing.\n\n"
        "Context:\n{context}\n\n"
        "Question: {question}\n\n"
        "Answer:"
    ),
)


FOLLOWUP_QA_PROMPT = PromptTemplate(
    input_variables=["report", "context", "question"],
    template=(
        "You are a cybersecurity auditor assistant helping the user understand and act on a "
        "security audit report you just produced. Answer the user's follow-up question using the "
        "AUDIT REPORT below as the primary source, supported by the FRAMEWORK EXCERPTS for control "
        "and remediation guidance. When you reference a control, cite the framework/page from the "
        "excerpts using the [Framework, p.N] format. Be specific and practical — point to the "
        "relevant findings, controls, and concrete remediation steps.\n\n"
        "If the question is about the audit, ground your answer in the report. If it is a general "
        "compliance or framework question unrelated to the report, just answer it from the framework "
        "excerpts — the report may be irrelevant, and that is fine; do not refuse.\n\n"
        "AUDIT REPORT:\n{report}\n\n"
        "FRAMEWORK EXCERPTS:\n{context}\n\n"
        "Follow-up question: {question}\n\n"
        "Answer:"
    ),
)


FRAMEWORK_SUMMARY_MAP_PROMPT = PromptTemplate(
    input_variables=["text"],
    template=(
        "Extract the key points from the following framework excerpt that are relevant to the "
        "user's topic. Be precise and preserve any control IDs or section references.\n\n"
        "Excerpt:\n{text}\n\n"
        "Key points:"
    ),
)


FRAMEWORK_SUMMARY_COMBINE_PROMPT = PromptTemplate(
    input_variables=["text", "topic"],
    template=(
        "Synthesize the key points below into a single coherent summary on the topic of "
        '"{topic}". Group by framework where helpful, and note any agreements or differences '
        "between frameworks.\n\n"
        "Key points:\n{text}\n\n"
        "Summary:"
    ),
)
