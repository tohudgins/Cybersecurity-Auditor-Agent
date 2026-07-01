from langchain_core.prompts import PromptTemplate

# Turns the RAG corpus into an auditor's *worksheet* for organizational/process
# controls the technical scanners can't test (governance, personnel, training,
# incident-response process, vendor risk, physical security, ...). Grounded in
# retrieved framework text; cited.
CONTROL_ADVISORY_PROMPT = PromptTemplate(
    input_variables=["context", "topic"],
    template=(
        "You are a senior GRC auditor conducting an ADVISORY assessment of the organizational / "
        "process controls for the topic below. These are controls that are examined and interviewed "
        "(per NIST SP 800-53A), not scanned — so produce an auditor's worksheet, not prose.\n\n"
        "Use ONLY the framework excerpts as your source. Each is prefixed with its source in brackets "
        "like [Framework Name, p.N]. Cite the framework/page in that bracket format for the objective "
        "and where a question or evidence item derives from a specific control. If the excerpts don't "
        "cover the topic, say so in the objective rather than inventing controls.\n\n"
        "Produce:\n"
        "- applicable_controls: the specific controls this topic maps to (use the IDs/labels present "
        "in the excerpts, e.g. 'NIST 800-53 IR-8', 'CIS 17', 'SOC 2 CC7.4').\n"
        "- objective: what an assessor is trying to determine for this topic (1-3 sentences), cited.\n"
        "- interview_questions: 4-7 specific questions to ask the control owners.\n"
        "- evidence_to_request: the documents/records an assessor should collect (policies, tickets, "
        "logs, training records, meeting minutes, test results, ...).\n"
        "- common_gaps: typical deficiencies auditors find for this topic.\n"
        "- citations: the distinct [Framework, p.N] sources you relied on.\n\n"
        "Framework excerpts:\n{context}\n\n"
        "Topic to assess: {topic}\n"
    ),
)
