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
import re  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import streamlit as st  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402

from auditor.agents.graph import AUDITOR_GRAPH  # noqa: E402
from auditor.ingest.pdf_loader import FRAMEWORK_NAMES  # noqa: E402
from auditor.models import Artifact  # noqa: E402
from auditor.oscal.exporter import to_oscal_assessment_results  # noqa: E402
from auditor.tools.audit_policy_pdf import extract_pdf_text  # noqa: E402

# ---- Page setup ------------------------------------------------------------

st.set_page_config(
    page_title="Cybersecurity Auditor",
    page_icon="\U0001f6e1",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---- Theme / CSS -----------------------------------------------------------

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root {
  --bg:        #0a0b10;
  --surface:   #12141c;
  --surface-2: #181b25;
  --border:    #232735;
  --border-soft: #1a1d28;
  --text:      #f3f4f8;
  --text-mute: #8b8fa3;
  --text-dim:  #5c6075;
  --accent:    #7c5cff;
  --accent-soft: rgba(124, 92, 255, 0.12);

  --crit-fg: #f87171;  --crit-bg: rgba(248, 113, 113, 0.10);
  --high-fg: #fb923c;  --high-bg: rgba(251, 146, 60, 0.10);
  --med-fg:  #fbbf24;  --med-bg:  rgba(251, 191, 36, 0.10);
  --low-fg:  #34d399;  --low-bg:  rgba(52, 211, 153, 0.10);
  --info-fg: #60a5fa;  --info-bg: rgba(96, 165, 250, 0.10);
}

html, body, [class*="css"] {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  letter-spacing: -0.005em;
}

/* Hide Streamlit chrome */
#MainMenu, footer, header [data-testid="stToolbar"] { visibility: hidden; }
header[data-testid="stHeader"] { background: transparent; }

/* Block container */
.block-container {
  padding-top: 2.5rem;
  padding-bottom: 4rem;
  max-width: 1100px;
}

/* Page title */
.page-title {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 0.25rem;
}
.page-title .mark {
  width: 36px; height: 36px;
  border-radius: 10px;
  background: linear-gradient(135deg, #7c5cff 0%, #4f46e5 100%);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.05rem;
  box-shadow: 0 6px 20px -8px rgba(124, 92, 255, 0.5);
}
.page-title h1 {
  font-size: 1.6rem !important;
  font-weight: 600 !important;
  margin: 0 !important;
  letter-spacing: -0.02em;
  color: var(--text);
}
.page-subtitle {
  color: var(--text-mute);
  font-size: 0.94rem;
  margin-bottom: 2.25rem;
  font-weight: 400;
}

/* Welcome panel */
.welcome-card {
  background: linear-gradient(180deg, var(--surface) 0%, var(--bg) 100%);
  border: 1px solid var(--border-soft);
  border-radius: 14px;
  padding: 28px 32px;
  margin: 1rem 0 2rem 0;
}
.welcome-card h3 {
  font-size: 1.05rem !important;
  font-weight: 600 !important;
  color: var(--text) !important;
  margin: 0 0 1.25rem 0 !important;
}
.welcome-card .mode {
  padding: 14px 0;
  border-top: 1px solid var(--border-soft);
}
.welcome-card .mode:last-child { padding-bottom: 0; }
.welcome-card .mode-title {
  font-weight: 600;
  color: var(--text);
  font-size: 0.92rem;
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 4px;
}
.welcome-card .mode-title .bullet {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--accent);
}
.welcome-card .mode-body {
  color: var(--text-mute);
  font-size: 0.88rem;
  line-height: 1.6;
}

/* Stat tiles row */
.stats-row {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 0.5rem;
}
.stat-tile {
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  padding: 14px 18px;
}
.stat-tile .label {
  font-size: 0.72rem;
  color: var(--text-mute);
  font-weight: 500;
  margin-bottom: 4px;
}
.stat-tile .value {
  font-size: 1.05rem;
  color: var(--text);
  font-weight: 600;
  letter-spacing: -0.01em;
}

/* Sidebar */
section[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border-soft);
}
section[data-testid="stSidebar"] > div:first-child { padding-top: 2rem; }
.sidebar-label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--text);
  margin: 1.25rem 0 0.5rem 0;
}
.sidebar-help {
  font-size: 0.78rem;
  color: var(--text-dim);
  margin-bottom: 0.75rem;
  line-height: 1.5;
}

/* Chat messages */
[data-testid="stChatMessage"] {
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: 12px;
  padding: 16px 20px;
  margin-bottom: 12px;
}
[data-testid="stChatMessage"] p { line-height: 1.65; }
[data-testid="stChatMessage"] h2,
[data-testid="stChatMessage"] h3 {
  font-weight: 600 !important;
  letter-spacing: -0.01em;
  color: var(--text);
}

/* Severity pills */
.pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 9px;
  font-size: 0.72rem;
  font-weight: 600;
  letter-spacing: 0;
  border-radius: 999px;
  margin-right: 6px;
  border: 1px solid transparent;
}
.pill.crit { color: var(--crit-fg); background: var(--crit-bg); border-color: var(--crit-fg); }
.pill.high { color: var(--high-fg); background: var(--high-bg); border-color: var(--high-fg); }
.pill.med  { color: var(--med-fg);  background: var(--med-bg);  border-color: var(--med-fg); }
.pill.low  { color: var(--low-fg);  background: var(--low-bg);  border-color: var(--low-fg); }
.pill.info { color: var(--info-fg); background: var(--info-bg); border-color: var(--info-fg); }
.pill.kev {
  color: #fff;
  background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
  border-color: transparent;
}

/* Inputs — softer, rounded */
.stChatInput textarea, .stTextArea textarea, .stTextInput input {
  background: var(--surface-2) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 10px !important;
  font-family: inherit !important;
}
.stChatInput textarea:focus, .stTextArea textarea:focus, .stTextInput input:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px var(--accent-soft) !important;
}

/* Chat input dock */
[data-testid="stChatInput"] {
  background: transparent;
  border-top: 1px solid var(--border-soft);
}
[data-testid="stChatInput"] > div {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
}

/* Multiselect */
.stMultiSelect div[data-baseweb="select"] > div {
  background: var(--surface-2) !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
}
.stMultiSelect [data-baseweb="tag"] {
  background: var(--accent-soft) !important;
  color: var(--accent) !important;
  border-radius: 6px !important;
}

/* Buttons */
.stButton button, .stDownloadButton button {
  background: var(--accent);
  border: none;
  color: white;
  font-family: inherit;
  font-weight: 500;
  font-size: 0.86rem;
  border-radius: 10px;
  padding: 0.55rem 1rem;
  transition: all 0.15s ease;
  box-shadow: 0 4px 14px -6px rgba(124, 92, 255, 0.4);
}
.stButton button:hover, .stDownloadButton button:hover {
  background: #8a6cff;
  transform: translateY(-1px);
  box-shadow: 0 6px 18px -6px rgba(124, 92, 255, 0.55);
}
section[data-testid="stSidebar"] .stButton button {
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid var(--border);
  box-shadow: none;
}
section[data-testid="stSidebar"] .stButton button:hover {
  background: var(--surface);
  border-color: var(--accent);
  color: var(--accent);
  transform: none;
}

/* File uploader */
[data-testid="stFileUploader"] section {
  background: var(--surface-2);
  border: 1px dashed var(--border);
  border-radius: 10px;
}
[data-testid="stFileUploader"] button {
  background: transparent !important;
  color: var(--accent) !important;
  border: 1px solid var(--border) !important;
  box-shadow: none !important;
}

/* Attachments line */
.attached-line {
  color: var(--text-mute);
  font-size: 0.8rem;
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--border-soft);
}
.attached-line .chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 8px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.76rem;
  color: var(--text);
  margin-right: 6px;
}
.attached-line .chip .kind {
  color: var(--text-dim);
  font-size: 0.7rem;
}

/* Markdown body code */
[data-testid="stChatMessage"] code {
  background: var(--surface-2);
  color: var(--accent);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 0.85em;
}
[data-testid="stChatMessage"] pre {
  background: var(--surface-2) !important;
  border: 1px solid var(--border-soft);
  border-radius: 8px;
}

/* Scrollbars */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 5px; }
::-webkit-scrollbar-thumb:hover { background: #2d3142; }

/* Divider */
hr { border-color: var(--border-soft) !important; margin: 1.5rem 0 !important; }
</style>
"""
st.markdown(_CSS, unsafe_allow_html=True)


# ---- Title ----------------------------------------------------------------

st.markdown(
    """
<div class="page-title">
  <div class="mark">\U0001f6e1</div>
  <h1>Cybersecurity Auditor</h1>
</div>
<div class="page-subtitle">
  Compliance Q&A and automated audits across NIST, CIS, OWASP, CISA, and MITRE ATT&CK.
</div>
    """,
    unsafe_allow_html=True,
)


# ---- Sidebar --------------------------------------------------------------

with st.sidebar:
    st.markdown('<div class="sidebar-label">Frameworks</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sidebar-help">Restrict the corpus. Leave empty to use everything.</div>',
        unsafe_allow_html=True,
    )
    target_frameworks = st.multiselect(
        label="Frameworks",
        label_visibility="collapsed",
        options=sorted(set(FRAMEWORK_NAMES.values())),
        default=[],
        placeholder="All frameworks",
    )

    st.markdown('<div class="sidebar-label">Attach artifacts</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sidebar-help">Files, a pasted description, or a codebase path. Cleared after each run.</div>',
        unsafe_allow_html=True,
    )

    uploaded_files = st.file_uploader(
        "Files",
        type=["pdf", "tf", "tfvars", "yaml", "yml", "conf", "log", "txt", "json", "cfg"],
        accept_multiple_files=True,
        help="Dockerfiles: rename to Dockerfile.txt so the uploader accepts them.",
        label_visibility="collapsed",
    )
    pasted_description = st.text_area(
        "Description",
        height=100,
        placeholder="Paste a system description...",
        label_visibility="collapsed",
    )
    codebase_path = st.text_input(
        "Codebase path",
        placeholder="Codebase path to scan with Trivy",
        help="Requires Trivy installed locally (see README).",
        label_visibility="collapsed",
    )

    st.markdown('<div class="sidebar-label">Session</div>', unsafe_allow_html=True)
    if st.button("Clear chat history", use_container_width=True):
        st.session_state.messages = []
        st.rerun()


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


_SEVERITY_PILL = {
    "critical": '<span class="pill crit">Critical</span>',
    "high":     '<span class="pill high">High</span>',
    "medium":   '<span class="pill med">Medium</span>',
    "low":      '<span class="pill low">Low</span>',
    "info":     '<span class="pill info">Info</span>',
}


def _render_markdown_with_pills(md: str) -> str:
    out = md
    out = re.sub(
        r"\*\*\[KEV - actively exploited\]\*\*",
        '<span class="pill kev">KEV</span>',
        out,
    )
    for sev, pill in _SEVERITY_PILL.items():
        out = re.sub(rf"\*\*\[{sev.upper()}\]\*\*", pill, out)
    return out


# ---- Welcome panel (only when chat is empty) ------------------------------

if "messages" not in st.session_state:
    st.session_state.messages = []

if not st.session_state.messages:
    n_frameworks = len(set(FRAMEWORK_NAMES.values())) + 4  # +4 web sources
    st.markdown(
        f"""
<div class="stats-row">
  <div class="stat-tile">
    <div class="label">Frameworks indexed</div>
    <div class="value">{n_frameworks} sources</div>
  </div>
  <div class="stat-tile">
    <div class="label">Scanners wired</div>
    <div class="value">Trivy &middot; Bandit &middot; Checkov</div>
  </div>
  <div class="stat-tile">
    <div class="label">Enrichment</div>
    <div class="value">KEV &middot; EPSS &middot; ATT&amp;CK</div>
  </div>
</div>

<div class="welcome-card">
  <h3>Get started</h3>
  <div class="mode">
    <div class="mode-title"><span class="bullet"></span> Ask a compliance question</div>
    <div class="mode-body">
      Cite NIST SP 800-series, CSF 2.1, CIS Controls v8.1, OWASP Top 10 / ASVS 5.0 / API Top 10,
      OWASP Cheat Sheets, CISA Zero Trust, and MITRE ATT&amp;CK.
    </div>
  </div>
  <div class="mode">
    <div class="mode-title"><span class="bullet"></span> Run an audit</div>
    <div class="mode-body">
      Attach a config, log, policy PDF, or codebase path. Findings get enriched with CVSS, EPSS,
      CISA KEV, ATT&amp;CK techniques, and cross-framework mappings &mdash; then exportable as OSCAL 1.1.2.
    </div>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )


# ---- Chat history rendering -----------------------------------------------

for msg in st.session_state.messages:
    role = "user" if isinstance(msg, HumanMessage) else "assistant"
    with st.chat_message(role):
        st.markdown(_render_markdown_with_pills(msg.content), unsafe_allow_html=True)


# ---- Input handling -------------------------------------------------------

prompt = st.chat_input("Ask a compliance question or describe what to audit...")
if prompt:
    artifacts = _build_artifacts()
    user_msg = HumanMessage(content=prompt)
    st.session_state.messages.append(user_msg)

    with st.chat_message("user"):
        st.markdown(prompt)
        if artifacts:
            chips = "".join(
                f'<span class="chip">{a.name} <span class="kind">{a.kind}</span></span>'
                for a in artifacts
            )
            st.markdown(
                f'<div class="attached-line">Attached &middot; {chips}</div>',
                unsafe_allow_html=True,
            )

    with st.chat_message("assistant"):
        spinner_msg = "Running audit pipeline..." if artifacts else "Querying frameworks..."
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
        st.markdown(_render_markdown_with_pills(answer), unsafe_allow_html=True)
        st.session_state.messages.append(AIMessage(content=answer))

        findings = result.get("findings") or []
        if findings:
            oscal_doc = to_oscal_assessment_results(findings)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            st.download_button(
                label="Export OSCAL Assessment Results",
                data=json.dumps(oscal_doc, indent=2),
                file_name=f"oscal-assessment-results-{timestamp}.json",
                mime="application/json",
                help="NIST OSCAL 1.1.2 Assessment Results JSON. Ingestible by FedRAMP / Trestle / RegScale.",
            )
