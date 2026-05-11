"""Streamlit entrypoint for the Cybersecurity Auditor Agent.

Run with:
    streamlit run app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make `src/` importable when running via `streamlit run app.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import json  # noqa: E402
from datetime import UTC, datetime  # noqa: E402

import streamlit as st  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402

from auditor.agents.graph import AUDITOR_GRAPH  # noqa: E402
from auditor.ingest.pdf_loader import FRAMEWORK_NAMES  # noqa: E402
from auditor.models import Artifact  # noqa: E402
from auditor.oscal.exporter import to_oscal_assessment_results  # noqa: E402
from auditor.tools.audit_policy_pdf import extract_pdf_text  # noqa: E402

# ---- Page setup ------------------------------------------------------------

st.set_page_config(page_title="Cybersecurity Auditor", layout="wide")
st.title("Cybersecurity Auditor")
st.caption(
    "Ask compliance questions or upload artifacts (policy PDFs, configs, logs, system "
    "descriptions) for an automated audit against NIST, CIS, OWASP ASVS, MITRE ATT&CK, "
    "and CompTIA Security+."
)


# ---- Sidebar: framework selection + uploads -------------------------------

with st.sidebar:
    st.header("Frameworks")
    target_frameworks = st.multiselect(
        "Restrict to these frameworks (empty = all):",
        options=sorted(set(FRAMEWORK_NAMES.values())),
        default=[],
    )

    st.divider()
    st.header("Artifacts to audit")
    st.caption("Attach files for the next message; clears after each run.")

    uploaded_files = st.file_uploader(
        "Configs / logs / policy PDFs",
        type=["pdf", "tf", "tfvars", "yaml", "yml", "conf", "log", "txt", "json", "cfg"],
        accept_multiple_files=True,
        help="Dockerfiles: rename to `Dockerfile.txt` so the uploader accepts them.",
    )
    pasted_description = st.text_area(
        "...or paste a system description",
        height=120,
        placeholder="Describe your system, controls, environment...",
    )
    codebase_path = st.text_input(
        "...or a codebase path to scan with Trivy",
        placeholder=r"C:\path\to\project  or  /home/user/repo",
        help="Scans for known-vulnerable dependencies. Requires Trivy installed locally (see README).",
    )


# ---- Helpers ---------------------------------------------------------------

def _classify_upload(filename: str) -> str:
    name = filename.lower()
    if name.endswith(".pdf"):
        return "policy_pdf"
    if name.endswith(".log") or "log" in name:
        return "log"
    return "config"


def _build_artifacts() -> list[Artifact]:
    artifacts: list[Artifact] = []

    if pasted_description.strip():
        artifacts.append(
            Artifact(kind="text", name="pasted system description", content=pasted_description.strip())
        )

    for f in uploaded_files or []:
        kind = _classify_upload(f.name)
        raw = f.read()
        if kind == "policy_pdf":
            content = extract_pdf_text(raw)
        else:
            content = raw.decode("utf-8", errors="replace")
        artifacts.append(Artifact(kind=kind, name=f.name, content=content))  # type: ignore[arg-type]

    if codebase_path.strip():
        path = codebase_path.strip()
        artifacts.append(Artifact(kind="codebase", name=path, content=path))

    return artifacts


# ---- Chat history rendering -----------------------------------------------

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    role = "user" if isinstance(msg, HumanMessage) else "assistant"
    with st.chat_message(role):
        st.markdown(msg.content)


# ---- Input handling -------------------------------------------------------

prompt = st.chat_input("Ask a compliance question or describe what to audit...")
if prompt:
    artifacts = _build_artifacts()
    user_msg = HumanMessage(content=prompt)
    st.session_state.messages.append(user_msg)

    with st.chat_message("user"):
        st.markdown(prompt)
        if artifacts:
            st.caption("Attached: " + ", ".join(f"`{a.name}` ({a.kind})" for a in artifacts))

    with st.chat_message("assistant"):
        spinner_msg = "Running audit..." if artifacts else "Consulting frameworks..."
        with st.spinner(spinner_msg):
            result = AUDITOR_GRAPH.invoke(
                {
                    "messages": st.session_state.messages,
                    "target_frameworks": target_frameworks,
                    "artifacts": artifacts,
                }
            )
        answer = result.get("final_report") or (
            result["messages"][-1].content if result.get("messages") else "(no response)"
        )
        st.markdown(answer)
        st.session_state.messages.append(AIMessage(content=answer))

        findings = result.get("findings") or []
        if findings:
            oscal_doc = to_oscal_assessment_results(findings)
            timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            st.download_button(
                label="Export OSCAL Assessment Results",
                data=json.dumps(oscal_doc, indent=2),
                file_name=f"oscal-assessment-results-{timestamp}.json",
                mime="application/json",
                help="NIST OSCAL 1.1.2 Assessment Results JSON. Ingestible by FedRAMP / Trestle / RegScale.",
            )
