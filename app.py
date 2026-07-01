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
from collections import Counter  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import streamlit as st  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402

from auditor import history as audit_history  # noqa: E402
from auditor import suppressions as audit_suppressions  # noqa: E402
from auditor.agents.graph import AUDITOR_GRAPH  # noqa: E402
from auditor.diff import serialize_findings, target_key  # noqa: E402
from auditor.ingest.pdf_loader import FRAMEWORK_NAMES  # noqa: E402
from auditor.intake import is_advisory_request, parse_targets  # noqa: E402
from auditor.models import Artifact, AuditScope  # noqa: E402
from auditor.oscal.exporter import to_oscal_assessment_results, to_oscal_poam  # noqa: E402
from auditor.retrieval.retriever import warm_cache  # noqa: E402
from auditor.tools.audit_policy_pdf import extract_pdf_text  # noqa: E402
from auditor.tools.compliance_qa import (  # noqa: E402
    stream_compliance_answer,
    stream_followup_answer,
)
from auditor.tools.control_advisor import (  # noqa: E402
    advise_controls,
    render_advisory_markdown,
)

# ---- Page setup ------------------------------------------------------------

st.set_page_config(
    page_title="Cybersecurity Auditor",
    page_icon="◉",  # ◉ — bullseye / scan reticle
    layout="wide",
    initial_sidebar_state="expanded",
)


# Build/load the BM25 index + Chroma client once per server process, at startup,
# so the cold-start cost lands here instead of on the first user question.
@st.cache_resource(show_spinner=False)
def _warm_retrieval() -> bool:
    warm_cache()
    return True


_warm_retrieval()


# ---- Theme / CSS -----------------------------------------------------------

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg:        #070a11;
  --surface:   #0e131c;
  --surface-2: #141a26;
  --surface-3: #1b2230;
  --border:    #1f2839;
  --border-soft: #161c28;
  --text:      #e9edf5;
  --text-mute: #7d8699;
  --text-dim:  #525c70;
  --accent:    #22d3ee;        /* cyan-400 — primary */
  --accent-2:  #0891b2;        /* cyan-700 — depth */
  --accent-3:  #164e63;        /* cyan-900 — base */
  --accent-warm: #ff5e7a;      /* coral — anomaly / alert */
  --accent-good: #34d399;      /* emerald — ready / healthy */
  --accent-soft: rgba(34, 211, 238, 0.10);
  --accent-glow: rgba(34, 211, 238, 0.35);

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

.stApp {
  background:
    radial-gradient(900px 400px at 12% -10%, rgba(34, 211, 238, 0.06), transparent 60%),
    radial-gradient(700px 350px at 95% 5%, rgba(8, 145, 178, 0.05), transparent 60%),
    linear-gradient(180deg, #080b13 0%, var(--bg) 50%, #060810 100%);
}

/* Faint scan-grid behind the content — reads as "console" without being loud */
.stApp::before {
  content: "";
  position: fixed; inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(to right, rgba(34, 211, 238, 0.035) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(34, 211, 238, 0.035) 1px, transparent 1px);
  background-size: 36px 36px;
  mask-image: radial-gradient(ellipse 80% 60% at 50% 0%, #000 0%, transparent 75%);
  -webkit-mask-image: radial-gradient(ellipse 80% 60% at 50% 0%, #000 0%, transparent 75%);
  z-index: 0;
}
.block-container, section[data-testid="stSidebar"] { position: relative; z-index: 1; }

/* Streamlit chrome: keep the header (it holds the sidebar collapse control).
   Only hide the main menu + footer. Leave the toolbar visible so the
   sidebar expand button remains clickable. */
#MainMenu, footer { visibility: hidden; }
header[data-testid="stHeader"] {
  background: transparent !important;
}

/* Make the collapse / expand controls subtle but always visible */
[data-testid="stSidebarCollapsedControl"] button,
[data-testid="stSidebarCollapseButton"] button {
  background: var(--surface-2) !important;
  border: 1px solid var(--border) !important;
  border-radius: 8px !important;
  color: var(--text) !important;
  transition: all 0.15s ease;
}
[data-testid="stSidebarCollapsedControl"] button:hover,
[data-testid="stSidebarCollapseButton"] button:hover {
  border-color: var(--accent) !important;
  background: var(--surface-3) !important;
}
[data-testid="stSidebarCollapsedControl"] svg,
[data-testid="stSidebarCollapseButton"] svg {
  color: var(--text) !important;
  fill: var(--text) !important;
}

/* Block container */
.block-container {
  padding-top: 3.25rem;
  padding-bottom: 4rem;
  max-width: 1120px;
}

/* Page title */
.page-title {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 0.4rem;
}
.page-title .mark {
  width: 44px; height: 44px;
  border-radius: 12px;
  background:
    radial-gradient(120% 120% at 0% 0%, rgba(255,255,255,0.20), transparent 55%),
    linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 55%, var(--accent-3) 100%);
  display: flex; align-items: center; justify-content: center;
  box-shadow:
    0 10px 28px -10px var(--accent-glow),
    inset 0 1px 0 rgba(255,255,255,0.22),
    inset 0 -10px 16px -10px rgba(0,0,0,0.45);
  position: relative;
}
.page-title .mark::after {
  content: ""; position: absolute; inset: 0;
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,0.12);
  pointer-events: none;
}
.page-title .mark::before {
  content: ""; position: absolute; inset: -1px;
  border-radius: 13px;
  background: linear-gradient(135deg, var(--accent), transparent 60%);
  filter: blur(8px);
  opacity: 0.35;
  z-index: -1;
}
.page-title .mark svg {
  width: 28px; height: 28px;
  display: block;
}
.page-title h1 {
  font-size: 1.75rem !important;
  font-weight: 600 !important;
  margin: 0 !important;
  letter-spacing: -0.025em;
  color: var(--text);
  background: linear-gradient(180deg, #ffffff 0%, #b6d7e0 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.page-subtitle {
  color: var(--text-mute);
  font-size: 0.94rem;
  margin-bottom: 0.9rem;
  font-weight: 400;
  max-width: 720px;
  line-height: 1.55;
}

/* HUD-style status line under the subtitle */
.status-line {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  font-family: 'JetBrains Mono', 'SF Mono', Menlo, monospace;
  font-size: 0.7rem;
  letter-spacing: 0.14em;
  color: var(--text-dim);
  text-transform: uppercase;
  margin-bottom: 2rem;
  padding: 5px 11px;
  border: 1px solid var(--border-soft);
  border-radius: 999px;
  background: rgba(15, 19, 28, 0.6);
  backdrop-filter: blur(4px);
}
.status-line .dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--accent-good);
  box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.6);
  animation: pulse-good 2.4s infinite;
}
.status-line .sep { color: var(--text-dim); opacity: 0.5; }
.status-line .accent { color: var(--accent); }
@keyframes pulse-good {
  0%   { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.55); }
  70%  { box-shadow: 0 0 0 8px rgba(52, 211, 153, 0); }
  100% { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); }
}

/* Welcome panel — HUD console card */
.welcome-card {
  position: relative;
  background:
    radial-gradient(1200px 200px at 0% 0%, rgba(34, 211, 238, 0.06), transparent 60%),
    linear-gradient(180deg, var(--surface) 0%, #0a0e16 100%);
  border: 1px solid var(--border-soft);
  border-radius: 16px;
  padding: 28px 32px;
  margin: 1rem 0 2rem 0;
  box-shadow:
    0 1px 0 rgba(255,255,255,0.025) inset,
    0 20px 40px -30px rgba(0,0,0,0.5),
    0 0 0 1px rgba(34, 211, 238, 0.04);
}
/* HUD corner brackets — top-left and bottom-right */
.welcome-card::before,
.welcome-card::after {
  content: "";
  position: absolute;
  width: 14px; height: 14px;
  border: 1px solid var(--accent);
  opacity: 0.55;
  pointer-events: none;
}
.welcome-card::before {
  top: 10px; left: 10px;
  border-right: 0; border-bottom: 0;
  border-top-left-radius: 6px;
}
.welcome-card::after {
  bottom: 10px; right: 10px;
  border-left: 0; border-top: 0;
  border-bottom-right-radius: 6px;
}
.welcome-card h3 {
  font-size: 0.78rem !important;
  font-weight: 600 !important;
  color: var(--text-mute) !important;
  margin: 0 0 1.1rem 0 !important;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}
.welcome-card .mode {
  padding: 16px 0;
  border-top: 1px solid var(--border-soft);
}
.welcome-card .mode:last-child { padding-bottom: 0; }
.welcome-card .mode-title {
  font-weight: 600;
  color: var(--text);
  font-size: 0.95rem;
  display: flex; align-items: center; gap: 10px;
  margin-bottom: 6px;
  letter-spacing: -0.01em;
}
.welcome-card .mode-title .bullet {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--accent);
  box-shadow:
    0 0 0 3px rgba(34, 211, 238, 0.10),
    0 0 14px var(--accent-glow);
}
.welcome-card .mode-body {
  color: var(--text-mute);
  font-size: 0.88rem;
  line-height: 1.65;
  padding-left: 16px;
}

/* Sidebar */
section[data-testid="stSidebar"] {
  background: #0d0f17 !important;
  border-right: 1px solid var(--border-soft);
}
section[data-testid="stSidebar"] > div:first-child { padding-top: 1.5rem; }
.sidebar-section {
  margin-top: 1.5rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--border-soft);
}
.sidebar-section:first-of-type {
  margin-top: 0.25rem;
  padding-top: 0;
  border-top: none;
}
.sidebar-label {
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--text);
  margin: 0 0 0.4rem 0;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.sidebar-help {
  font-size: 0.78rem;
  color: var(--text-dim);
  margin-bottom: 0.75rem;
  line-height: 1.55;
}

/* Chat messages */
[data-testid="stChatMessage"] {
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: 14px;
  padding: 18px 22px;
  margin-bottom: 14px;
  box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset;
  position: relative;
}
/* Slim accent stripe on assistant messages — uses :has() (modern browsers only) */
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"]) {
  border-left: 2px solid var(--accent);
  box-shadow:
    0 1px 0 rgba(255,255,255,0.02) inset,
    -2px 0 16px -8px var(--accent-glow);
}
[data-testid="stChatMessage"] p { line-height: 1.7; }
[data-testid="stChatMessage"] h1,
[data-testid="stChatMessage"] h2,
[data-testid="stChatMessage"] h3,
[data-testid="stChatMessage"] h4 {
  font-weight: 600 !important;
  letter-spacing: -0.015em;
  color: var(--text);
  margin-top: 1.25rem !important;
  margin-bottom: 0.6rem !important;
}
[data-testid="stChatMessage"] h2 { font-size: 1.15rem !important; }
[data-testid="stChatMessage"] h3 { font-size: 1rem !important; }
[data-testid="stChatMessage"] ul, [data-testid="stChatMessage"] ol {
  padding-left: 1.4rem;
}
[data-testid="stChatMessage"] li { margin: 0.25rem 0; }

/* Avatar — subtle accent ring */
[data-testid="stChatMessage"] [data-testid="stChatMessageAvatarUser"],
[data-testid="stChatMessage"] [data-testid="stChatMessageAvatarAssistant"] {
  border: 1px solid var(--border);
  background: var(--surface-2) !important;
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

/* Inputs — softer, rounded, with breathing room inside */
.stChatInput textarea, .stTextArea textarea, .stTextInput input {
  background: var(--surface-2) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 10px !important;
  font-family: inherit !important;
  padding: 0.7rem 0.95rem !important;
  line-height: 1.55 !important;
}
.stChatInput textarea::placeholder,
.stTextArea textarea::placeholder,
.stTextInput input::placeholder {
  color: var(--text-dim) !important;
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
  padding: 4px 6px;
}
[data-testid="stChatInput"] textarea {
  padding: 0.7rem 0.95rem !important;
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
  background: linear-gradient(180deg, #8a6cff 0%, var(--accent) 100%);
  border: 1px solid rgba(255,255,255,0.08);
  color: white;
  font-family: inherit;
  font-weight: 500;
  font-size: 0.86rem;
  border-radius: 10px;
  padding: 0.55rem 1rem;
  transition: all 0.15s ease;
  box-shadow: 0 4px 14px -6px var(--accent-glow), inset 0 1px 0 rgba(255,255,255,0.15);
}
.stButton button:hover, .stDownloadButton button:hover {
  background: linear-gradient(180deg, #9a7eff 0%, #8a6cff 100%);
  transform: translateY(-1px);
  box-shadow: 0 8px 22px -6px var(--accent-glow), inset 0 1px 0 rgba(255,255,255,0.2);
}
.stButton button:active, .stDownloadButton button:active {
  transform: translateY(0);
}
section[data-testid="stSidebar"] .stButton button {
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid var(--border);
  box-shadow: none;
}
section[data-testid="stSidebar"] .stButton button:hover {
  background: var(--surface-3);
  border-color: var(--accent);
  color: var(--text);
  transform: none;
  box-shadow: 0 0 0 3px var(--accent-soft);
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

_LOGO_SVG = """
<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <!-- Cyan glitch ghost (briefly shifts left every ~3s) -->
  <g opacity="0.55">
    <path d="M11 14 L19 20 L11 26" stroke="#22d3ee" stroke-width="2.2"
          stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    <rect x="22" y="24" width="6" height="2" fill="#22d3ee"/>
    <animateTransform attributeName="transform" type="translate"
                      values="0 0; -2 0; -1 0.5; 0.5 -0.5; 0 0"
                      keyTimes="0; 0.1; 0.15; 0.2; 1"
                      dur="2.8s" repeatCount="indefinite"/>
  </g>

  <!-- Coral glitch ghost (briefly shifts right) -->
  <g opacity="0.55">
    <path d="M11 14 L19 20 L11 26" stroke="#ff5e7a" stroke-width="2.2"
          stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    <rect x="22" y="24" width="6" height="2" fill="#ff5e7a"/>
    <animateTransform attributeName="transform" type="translate"
                      values="0 0; 2 0; 1 -0.5; -0.5 0.5; 0 0"
                      keyTimes="0; 0.1; 0.15; 0.2; 1"
                      dur="2.8s" repeatCount="indefinite"/>
  </g>

  <!-- Main prompt chevron `>` -->
  <path d="M11 14 L19 20 L11 26" stroke="white" stroke-width="2.4"
        stroke-linecap="round" stroke-linejoin="round" fill="none"/>

  <!-- Blinking cursor `_` -->
  <rect x="22" y="24" width="6" height="2" fill="white">
    <animate attributeName="opacity" values="1;0" dur="1s"
             repeatCount="indefinite" calcMode="discrete"/>
  </rect>
</svg>
"""

st.markdown(
    f"""
<div class="page-title">
  <div class="mark">{_LOGO_SVG}</div>
  <h1>Cybersecurity Auditor</h1>
</div>
<div class="page-subtitle">
  Compliance Q&A and automated audits across NIST, CIS, OWASP, CISA, and MITRE ATT&CK.
</div>
<div class="status-line">
  <span class="dot"></span>
  <span>System</span><span class="sep">/</span>
  <span class="accent">Online</span><span class="sep">/</span>
  <span>OSCAL 1.1.2</span><span class="sep">/</span>
  <span>BM25 + Vector</span>
</div>
    """,
    unsafe_allow_html=True,
)


# ---- Sidebar --------------------------------------------------------------

with st.sidebar:
    st.markdown(
        '<div class="sidebar-section">'
        '<div class="sidebar-label">Frameworks</div>'
        '<div class="sidebar-help">Restrict the corpus. Leave empty to use everything.</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    target_frameworks = st.multiselect(
        label="Frameworks",
        label_visibility="collapsed",
        options=sorted(set(FRAMEWORK_NAMES.values())),
        default=[],
        placeholder="All frameworks",
    )

    st.markdown(
        '<div class="sidebar-section">'
        '<div class="sidebar-label">Attach artifacts</div>'
        '<div class="sidebar-help">Files, a pasted description, or a codebase path. Cleared after each run.</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    uploaded_files = st.file_uploader(
        "Files",
        type=["pdf", "tf", "tfvars", "yaml", "yml", "conf", "log", "txt", "json", "cfg"],
        accept_multiple_files=True,
        help="Dockerfiles: rename to Dockerfile.txt so the uploader accepts them.",
        label_visibility="collapsed",
    )
    with st.expander("Other input methods"):
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
        st.markdown('<div class="sidebar-label" style="margin-top:0.75rem">Live scan targets</div>', unsafe_allow_html=True)
        cloud_target = st.text_input(
            "Cloud account",
            placeholder="Cloud posture, e.g. aws or aws:profile",
            help="Runs Prowler against the account using your local cloud SDK credentials (read-only).",
            label_visibility="collapsed",
        )
        image_ref = st.text_input(
            "Container image",
            placeholder="Container image, e.g. nginx:1.21",
            help="Scans the image with `trivy image` for CVEs + misconfigurations.",
            label_visibility="collapsed",
        )
        target_url = st.text_input(
            "Web target URL",
            placeholder="Web URL to DAST-scan, e.g. https://example.com",
            help="Runs a Nuclei DAST scan. Only scan targets you are authorized to test.",
            label_visibility="collapsed",
        )
        host_target = st.text_input(
            "Host / machine",
            placeholder="Machine to harden-audit, e.g. localhost or user@server",
            help="Runs a Lynis OS-hardening audit (local, or remote over SSH).",
            label_visibility="collapsed",
        )

    st.markdown(
        '<div class="sidebar-section">'
        '<div class="sidebar-label">Engagement scope</div>'
        '<div class="sidebar-help">Sets the control baseline (coverage denominator) and tunes risk to your environment.</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    _BASELINE_OPTIONS = {
        "NIST 800-53B Moderate": "moderate",
        "NIST 800-53B Low": "low",
        "NIST 800-53B High": "high",
        "CIS Controls v8.1": "cis",
        "PCI DSS v4.0.1": "pci",
        "NIST CSF 2.1": "csf",
        "SOC 2 (Trust Services Criteria)": "soc2",
        "Auditor-curated (technical)": "auditor-curated",
    }
    baseline_label_choice = st.selectbox(
        "Audit standard / baseline",
        options=list(_BASELINE_OPTIONS.keys()),
        index=0,
        help="The control set coverage is measured against. NIST 800-53B is assessed "
        "directly; CIS/PCI/CSF/SOC 2 are assessed by projecting findings through the "
        "NIST crosswalk (coverage is bounded by mapping completeness).",
    )
    selected_baseline = _BASELINE_OPTIONS[baseline_label_choice]
    internet_facing = st.checkbox(
        "Internet-facing system",
        value=False,
        help="Raises risk on exposure/boundary controls (e.g. SC-7, AC-17).",
    )
    data_classification = st.selectbox(
        "Data sensitivity",
        options=["Unspecified", "Public", "Internal", "PII", "PHI", "PCI/CHD", "CUI", "Confidential"],
        index=0,
        help="Sensitive classes raise risk on confidentiality controls (e.g. SC-28, IA-5).",
    )
    fast_mode = st.checkbox(
        "⚡ Fast mode (deterministic only)",
        value=False,
        help="Skip the AI narrative layer for a near-instant scanner/heuristic-only pass. "
        "Findings, risk scores, control mappings, coverage and OSCAL still render.",
    )

    st.markdown(
        '<div class="sidebar-section">'
        '<div class="sidebar-label">Session</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    if st.button("Clear chat history", use_container_width=True):
        st.session_state.messages = []
        st.session_state.pop("_viewed_run_id", None)
        st.rerun()

    # ── Audit history ────────────────────────────────────────────────────
    recent_runs = audit_history.list_runs(limit=3)
    total_run_count = audit_history.count_runs()
    if recent_runs:
        st.markdown(
            '<div class="sidebar-section">'
            '<div class="sidebar-label">Recent Audits</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        for run in recent_runs:
            severities = json.loads(run["severities"])
            badges = " · ".join(
                f"{severities[k]} {k}"
                for k in ("critical", "high", "medium")
                if severities.get(k)
            )
            ts = run["timestamp"][:16].replace("T", " ")
            label = f"{ts}" + (f" · {badges}" if badges else "")
            if st.button(label, key=f"hist_{run['id']}", use_container_width=True):
                st.session_state["_viewed_run_id"] = run["id"]
                st.rerun()

        if total_run_count > len(recent_runs):
            if st.button(
                f"View all ({total_run_count}) →",
                key="view_all_history",
                use_container_width=True,
            ):
                st.session_state["_viewed_run_id"] = "_all"
                st.rerun()

    # ── Accepted-risk / false-positive register ──────────────────────────
    all_suppressions = audit_suppressions.list_suppressions()
    if all_suppressions:
        st.markdown(
            '<div class="sidebar-section">'
            f'<div class="sidebar-label">Accepted Risks ({len(all_suppressions)})</div>'
            '<div class="sidebar-help">Dispositioned findings excluded from audits. Delete to re-surface.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        for s in all_suppressions[:8]:
            tag = "AR" if s["kind"] == "accepted-risk" else "FP"
            scope = "global" if not s.get("target_key") else "this target"
            col_a, col_b = st.columns([5, 1])
            with col_a:
                st.caption(f"[{tag}/{scope}] {s.get('title') or s['fingerprint']}")
            with col_b:
                if st.button("✕", key=f"unsup_{s['id']}", help="Remove suppression"):
                    audit_suppressions.delete_suppression(s["id"])
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

    if cloud_target.strip():
        spec = cloud_target.strip()
        artifacts.append(Artifact(kind="cloud_account", name=f"cloud:{spec}", content=spec))

    if image_ref.strip():
        ref = image_ref.strip()
        artifacts.append(Artifact(kind="image_ref", name=ref, content=ref))

    if target_url.strip():
        url = target_url.strip()
        artifacts.append(Artifact(kind="target_url", name=url, content=url))

    if host_target.strip():
        host = host_target.strip()
        artifacts.append(Artifact(kind="host", name=f"host:{host}", content=host))

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


# ── Node labels shown inside st.status during audit runs ────────────────────
_AUDIT_NODE_LABELS: dict[str, str] = {
    "supervisor":  "🔍 Routing request…",
    "planning":    "🗺️ Planning scope (adjacent targets)…",
    "audit":       "🔬 Running scanners and LLM analysis…",
    "compliance":  "📚 Searching frameworks…",
    "reporting":   "📝 Writing report…",
}


# ---- Session state init ----------------------------------------------------

if "messages" not in st.session_state:
    st.session_state.messages = []


# ---- History view (replaces chat when a run is selected) -------------------

_viewed = st.session_state.get("_viewed_run_id")

# Full history list (sentinel = "_all")
if _viewed == "_all":
    _HISTORY_PAGE_SIZE = 25
    total_runs = audit_history.count_runs()
    page = max(0, st.session_state.get("_history_page", 0))
    max_page = max(0, (total_runs - 1) // _HISTORY_PAGE_SIZE) if total_runs else 0
    page = min(page, max_page)  # clamp in case rows were deleted

    col_back, col_title, col_clear = st.columns([1, 4, 2])
    with col_back:
        if st.button("← Back"):
            for k in ("_viewed_run_id", "_history_page", "_confirming_clear"):
                st.session_state.pop(k, None)
            st.rerun()
    with col_title:
        st.caption(f"🗂 All audit history · {total_runs} runs")
    with col_clear:
        if total_runs > 0 and not st.session_state.get("_confirming_clear"):
            if st.button("🗑 Clear all", key="clear_all_btn", use_container_width=True):
                st.session_state["_confirming_clear"] = True
                st.rerun()

    # Confirmation banner — two-step destructive action
    if st.session_state.get("_confirming_clear"):
        with st.container(border=True):
            st.warning(f"Permanently delete all {total_runs} audit runs? This cannot be undone.")
            c1, c2, _ = st.columns([2, 1, 4])
            with c1:
                if st.button("Yes, delete all", type="primary", key="confirm_clear_yes"):
                    audit_history.clear_all()
                    for k in ("_confirming_clear", "_history_page"):
                        st.session_state.pop(k, None)
                    st.rerun()
            with c2:
                if st.button("Cancel", key="confirm_clear_no"):
                    st.session_state.pop("_confirming_clear", None)
                    st.rerun()

    runs_page = audit_history.list_runs(
        limit=_HISTORY_PAGE_SIZE,
        offset=page * _HISTORY_PAGE_SIZE,
    )
    if not runs_page:
        st.info("No audit runs yet.")
    for run in runs_page:
        with st.container(border=True):
            col_info, col_view, col_del = st.columns([6, 1, 1])
            ts = run["timestamp"][:16].replace("T", " ")
            severities = json.loads(run["severities"])
            sev_str = " · ".join(
                f"{severities[k]} {k}"
                for k in ("critical", "high", "medium", "low", "info")
                if severities.get(k)
            ) or "no findings"
            artifacts_list = json.loads(run["artifacts"])
            arts = ", ".join(artifacts_list[:3])
            if len(artifacts_list) > 3:
                arts += f" +{len(artifacts_list) - 3}"
            with col_info:
                st.markdown(f"**{ts} UTC** · {run['total']} findings · {sev_str}")
                if arts:
                    st.caption(f"📎 {arts}")
            with col_view:
                if st.button("View", key=f"all_view_{run['id']}", use_container_width=True):
                    st.session_state["_viewed_run_id"] = run["id"]
                    st.rerun()
            with col_del:
                if st.button("🗑", key=f"all_del_{run['id']}", help="Delete this run"):
                    audit_history.delete_run(run["id"])
                    st.rerun()

    # Page navigation
    if total_runs > _HISTORY_PAGE_SIZE:
        col_prev, col_info, col_next = st.columns([1, 3, 1])
        with col_prev:
            if st.button("← Previous", disabled=(page == 0), use_container_width=True):
                st.session_state["_history_page"] = page - 1
                st.rerun()
        with col_info:
            st.caption(f"Page {page + 1} of {max_page + 1}")
        with col_next:
            if st.button("Next →", disabled=(page >= max_page), use_container_width=True):
                st.session_state["_history_page"] = page + 1
                st.rerun()

    st.stop()

# Single run view (id is an int)
if _viewed:
    run = audit_history.get_run(_viewed)
    if run:
        col_back, col_ts = st.columns([1, 5])
        with col_back:
            if st.button("← Back"):
                del st.session_state["_viewed_run_id"]
                st.rerun()
        with col_ts:
            severities = json.loads(run["severities"])
            sev_str = " · ".join(
                f"{severities[k]} {k}"
                for k in ("critical", "high", "medium", "low", "info")
                if severities.get(k)
            )
            st.caption(f"🗂 Audit from **{run['timestamp'][:16].replace('T', ' ')} UTC** · {run['total']} findings · {sev_str}")

        st.markdown(_render_markdown_with_pills(run["report_md"]), unsafe_allow_html=True)

        if run.get("oscal_json"):
            st.download_button(
                label="⬇ Export OSCAL Assessment Results",
                data=run["oscal_json"],
                file_name=f"oscal-historical-{run['id']}.json",
                mime="application/json",
                help="NIST OSCAL 1.1.2 Assessment Results JSON from this historical run.",
            )
    else:
        st.warning("Run not found.")
        del st.session_state["_viewed_run_id"]
    st.stop()  # Don't render the chat below


# ---- Welcome panel (only when chat is empty) -------------------------------

if not st.session_state.messages:
    st.markdown(
        """
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
    <div class="mode-title"><span class="bullet"></span> Run an audit &mdash; just say what to scan</div>
    <div class="mode-body">
      Type a target in chat &mdash; <code>audit ~/myrepo</code>, <code>scan https://example.com</code>,
      <code>audit aws:prod</code>, <code>audit this machine</code>, <code>image:nginx:1.21</code> &mdash;
      or attach files / fill the sidebar. The agent runs the right scanners (Trivy, Semgrep, Bandit,
      gitleaks, Checkov, hadolint, Prowler, Nuclei, Lynis), produces a <b>control-coverage assessment</b>,
      and exports OSCAL Assessment Results + POA&amp;M.
    </div>
  </div>
  <div class="mode">
    <div class="mode-title"><span class="bullet"></span> Then dig in</div>
    <div class="mode-body">
      After an audit, ask follow-ups in plain language &mdash; &ldquo;explain finding 3&rdquo;,
      &ldquo;how do I fix the SQL injection?&rdquo;, &ldquo;which controls failed?&rdquo; &mdash;
      answered against the report and the framework corpus.
    </div>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )


# ---- Chat history rendering ------------------------------------------------

for msg in st.session_state.messages:
    role = "user" if isinstance(msg, HumanMessage) else "assistant"
    with st.chat_message(role):
        st.markdown(_render_markdown_with_pills(msg.content), unsafe_allow_html=True)


# ---- Input handling --------------------------------------------------------

prompt = st.chat_input("Ask a question, or say what to audit (e.g. 'audit ~/myrepo', 'scan https://site.com', 'audit this machine')…")
if prompt:
    # Targets come from the sidebar first; otherwise parse them out of the message
    # so the user can just *talk* to the agent ("audit /path", "scan https://x").
    artifacts = _build_artifacts()
    detected_from_chat = False
    if not artifacts:
        artifacts = parse_targets(prompt)
        detected_from_chat = bool(artifacts)

    user_msg = HumanMessage(content=prompt)
    st.session_state.messages.append(user_msg)

    with st.chat_message("user"):
        st.markdown(prompt)
        if artifacts:
            label = "Detected" if detected_from_chat else "Attached"
            chips = "".join(
                f'<span class="chip">{a.name} <span class="kind">{a.kind}</span></span>'
                for a in artifacts
            )
            st.markdown(
                f'<div class="attached-line">{label} &middot; {chips}</div>',
                unsafe_allow_html=True,
            )

    with st.chat_message("assistant"):
        # ── No target → advisory audit / follow-up / compliance Q&A ───────
        if not artifacts:
            last_audit = st.session_state.get("last_audit")
            try:
                if is_advisory_request(prompt):
                    # Organizational/process controls: examined + interviewed, not
                    # scanned. Produce a RAG-grounded auditor's worksheet.
                    with st.spinner("Assembling advisory assessment…"):
                        advisory = advise_controls(prompt, target_frameworks or None)
                    answer = render_advisory_markdown(advisory)
                    st.markdown(_render_markdown_with_pills(answer), unsafe_allow_html=True)
                elif last_audit and last_audit.get("report"):
                    answer = st.write_stream(
                        stream_followup_answer(prompt, last_audit["report"], target_frameworks or None)
                    )
                else:
                    answer = st.write_stream(
                        stream_compliance_answer(prompt, target_frameworks or None)
                    )
            except Exception as exc:
                answer = f"_(Error generating response: {exc})_"
                st.markdown(answer)
            st.session_state.messages.append(AIMessage(content=str(answer)))

        # ── Audit path — graph with step-by-step progress ─────────────────
        else:
            # Run-to-run lifecycle: find the previous audit of this same target set
            # so the report can show what was resolved / introduced / regressed.
            tkey = target_key(artifacts)
            prior_run = audit_history.latest_run_for_target(tkey)
            inputs = {
                "messages": st.session_state.messages,
                "target_frameworks": target_frameworks,
                "artifacts": artifacts,
                "scope": AuditScope(
                    baseline=selected_baseline,
                    internet_facing=internet_facing or None,
                    data_classification=(
                        None if data_classification == "Unspecified" else data_classification
                    ),
                ),
                "fast_mode": fast_mode,
            }
            if prior_run and prior_run.get("findings_json"):
                try:
                    inputs["previous_findings"] = json.loads(prior_run["findings_json"])
                    inputs["previous_run_at"] = prior_run.get("timestamp")
                except (ValueError, TypeError):
                    pass
            # Triage: apply any accepted-risk / false-positive dispositions the
            # user recorded for this target (or globally) on a previous run.
            inputs["suppressions"] = audit_suppressions.active_records(tkey)
            final_report: str | None = None
            findings = []
            assessments = []
            coverage = None

            with st.status("⚙️ Running audit pipeline…", expanded=True) as status:
                try:
                    for chunk in AUDITOR_GRAPH.stream(inputs, stream_mode="updates"):
                        for node_name, state_update in chunk.items():
                            label = _AUDIT_NODE_LABELS.get(node_name, f"Running {node_name}…")
                            status.write(label)
                            if isinstance(state_update, dict):
                                if state_update.get("final_report"):
                                    final_report = state_update["final_report"]
                                if state_update.get("findings"):
                                    findings = state_update["findings"]
                                if state_update.get("assessments"):
                                    assessments = state_update["assessments"]
                                if state_update.get("coverage"):
                                    coverage = state_update["coverage"]
                    status.update(label="✅ Audit complete", state="complete")
                except Exception as exc:
                    status.update(label="❌ Audit error", state="error")
                    final_report = f"_(Audit pipeline error: {exc})_"

            answer = final_report or "_(No report generated.)_"
            st.markdown(_render_markdown_with_pills(answer), unsafe_allow_html=True)
            st.session_state.messages.append(AIMessage(content=answer))
            # Remember this report so the next plain message is answered as a
            # follow-up ("explain finding 3", "how do I fix the SQLi?").
            st.session_state["last_audit"] = {"report": answer}

            if findings:
                oscal_doc = to_oscal_assessment_results(
                    findings, assessments=assessments or None, coverage=coverage
                )
                oscal_str = json.dumps(oscal_doc, indent=2)
                poam_str = json.dumps(to_oscal_poam(findings), indent=2)
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                col_ar, col_poam = st.columns(2)
                with col_ar:
                    st.download_button(
                        label="⬇ Export OSCAL Assessment Results",
                        data=oscal_str,
                        file_name=f"oscal-assessment-results-{timestamp}.json",
                        mime="application/json",
                        help="NIST OSCAL 1.1.2 Assessment Results JSON. Ingestible by FedRAMP / Trestle / RegScale.",
                    )
                with col_poam:
                    st.download_button(
                        label="⬇ Export OSCAL POA&M",
                        data=poam_str,
                        file_name=f"oscal-poam-{timestamp}.json",
                        mime="application/json",
                        help="NIST OSCAL 1.1.2 Plan of Action & Milestones — open findings as remediation items.",
                    )

                # Triage: let the analyst disposition a finding as accepted-risk /
                # false-positive. It's recorded against this target (or globally)
                # and excluded from the next audit, but stays in the register.
                with st.expander("🛑 Triage — accept risk / mark false positive"):
                    with st.form("suppress_form", clear_on_submit=True):
                        idx = st.selectbox(
                            "Finding",
                            options=list(range(len(findings))),
                            format_func=lambda i: f"[{findings[i].severity.upper()}] {findings[i].title}"[:90],
                        )
                        kind = st.radio(
                            "Disposition",
                            options=["accepted-risk", "false-positive"],
                            horizontal=True,
                            format_func=lambda k: "Accepted risk" if k == "accepted-risk" else "False positive",
                        )
                        reason = st.text_input("Rationale (required)", placeholder="e.g. compensating control X; not exploitable because …")
                        apply_global = st.checkbox("Apply to all targets (global)", value=False)
                        if st.form_submit_button("Suppress finding") :
                            if not reason.strip():
                                st.warning("A rationale is required to suppress a finding.")
                            else:
                                audit_suppressions.add_suppression(
                                    findings[idx], kind, reason.strip(),
                                    target_key=None if apply_global else tkey,
                                )
                                st.success("Recorded — excluded from the next audit of this target; visible in the register.")

                # Persist the run to history, including a finding snapshot keyed by
                # target so the *next* audit of this target can diff against it.
                sev_counts = dict(Counter(f.severity for f in findings))
                artifact_names = [a.name for a in artifacts]
                audit_history.save_run(
                    artifact_names=artifact_names,
                    total=len(findings),
                    severities=sev_counts,
                    report_md=answer,
                    oscal_json=oscal_str,
                    target_key=target_key(artifacts),
                    findings_json=json.dumps(serialize_findings(findings)),
                )
