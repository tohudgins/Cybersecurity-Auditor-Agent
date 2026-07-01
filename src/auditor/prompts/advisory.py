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


# Closes the loop: given the auditee's RESPONSES to the worksheet, produce an
# interview/examine assessment (NIST SP 800-53A methods) — a verdict per control.
CONTROL_ASSESSMENT_PROMPT = PromptTemplate(
    input_variables=["context", "topic", "responses"],
    template=(
        "You are a senior GRC auditor performing an INTERVIEW + EXAMINE assessment (NIST SP "
        "800-53A methods) of the organizational / process controls for the topic below. You are "
        "given the control REQUIREMENTS (framework excerpts, each tagged [Framework, p.N]) and the "
        "auditee's RESPONSES describing their current practices.\n\n"
        "For each applicable control, return a verdict based ONLY on what the responses actually "
        "state against the requirement:\n"
        "- satisfied: responses demonstrate the control is fully met.\n"
        "- partial: partially met / met without evidence of testing or completeness.\n"
        "- not-satisfied: responses show the control is absent or inadequate.\n"
        "- not-assessed: the responses don't address this control (do NOT guess).\n\n"
        "For each: `control` (framework ID + short name), `title`, `status`, `rationale` "
        "(cite the requirement [Framework, p.N] and reference the response), and `evidence_gap` "
        "(what to provide/implement to reach satisfied). Then a 2-3 sentence `summary` of overall "
        "organizational-control posture for this topic. Be a skeptical auditor: absence of stated "
        "evidence is not satisfaction.\n\n"
        "Control requirements:\n{context}\n\n"
        "Topic: {topic}\n\n"
        "Auditee responses:\n{responses}\n"
    ),
)
