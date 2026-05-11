from langchain_core.prompts import PromptTemplate


EXECUTIVE_SUMMARY_PROMPT = PromptTemplate(
    input_variables=["findings_text", "frameworks"],
    template=(
        "You are a senior cybersecurity auditor writing the executive summary of an audit report. "
        "The findings below were produced by automated tools against the target frameworks: "
        "{frameworks}.\n\n"
        "Findings:\n{findings_text}\n\n"
        "Write a 3-6 sentence executive summary that: (1) states the overall risk posture, "
        "(2) calls out the top 1-3 most critical issues by name, (3) notes if any framework area "
        "looks particularly weak. Be direct, no filler."
    ),
)
