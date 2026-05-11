from langchain_core.prompts import PromptTemplate


SYSTEM_DESCRIPTION_AUDIT_PROMPT = PromptTemplate(
    input_variables=["description", "context", "frameworks"],
    template=(
        "You are a senior cybersecurity auditor. The user described their system below. "
        "Compare it against the framework excerpts and return a list of compliance findings.\n\n"
        "Target frameworks: {frameworks}\n\n"
        "User's system description:\n---\n{description}\n---\n\n"
        "Relevant framework excerpts (each prefixed with [Framework, p.N]):\n---\n{context}\n---\n\n"
        "Produce findings for: missing controls, weak claims, vague statements, and explicit "
        "violations. For each finding, cite the framework and a specific control ID where possible. "
        "Only report substantive issues — do not invent problems if the description is silent on a "
        "non-applicable area."
    ),
)


POLICY_PDF_AUDIT_PROMPT = PromptTemplate(
    input_variables=["policy_text", "context", "frameworks"],
    template=(
        "You are a cybersecurity auditor reviewing an internal policy document against external "
        "framework requirements. Identify topics the framework requires that the user's policy "
        "fails to address, addresses inadequately, or contradicts.\n\n"
        "Target frameworks: {frameworks}\n\n"
        "User's internal policy (verbatim):\n---\n{policy_text}\n---\n\n"
        "Framework excerpts that define the requirements:\n---\n{context}\n---\n\n"
        "Return concrete gap findings. For each, quote the framework requirement and explain "
        "what is missing or weak in the user's policy. Skip topics the user's policy already "
        "covers adequately."
    ),
)


CONFIG_AUDIT_PROMPT = PromptTemplate(
    input_variables=["config_kind", "config_text", "context", "frameworks", "heuristic_findings"],
    template=(
        "You are a cybersecurity auditor reviewing a {config_kind} configuration file. "
        "Identify security misconfigurations that violate the cited frameworks.\n\n"
        "Target frameworks: {frameworks}\n\n"
        "Heuristic checks already flagged the following (you may include, refine, or expand on these):\n"
        "{heuristic_findings}\n\n"
        "Configuration file contents:\n---\n{config_text}\n---\n\n"
        "Relevant framework excerpts:\n---\n{context}\n---\n\n"
        "Return concrete findings, each tied to a specific line or directive in the config and to "
        "a framework control where possible. Do not flag defaults that are already secure."
    ),
)


LOG_AUDIT_PROMPT = PromptTemplate(
    input_variables=["log_text", "context", "frameworks", "heuristic_findings"],
    template=(
        "You are a cybersecurity analyst reviewing a sample of system logs for compliance-relevant "
        "events.\n\n"
        "Target frameworks: {frameworks}\n\n"
        "Heuristic checks already flagged the following:\n{heuristic_findings}\n\n"
        "Log sample:\n---\n{log_text}\n---\n\n"
        "Relevant framework excerpts:\n---\n{context}\n---\n\n"
        "Return findings for: brute-force or credential-stuffing patterns, privileged account "
        "abuse, missing audit fields, log tampering signs, and any other compliance-relevant "
        "behavior. Quote the offending log line(s) as evidence and tie each finding to a control."
    ),
)
