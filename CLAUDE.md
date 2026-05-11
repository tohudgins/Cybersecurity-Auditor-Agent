# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

Multi-agent cybersecurity auditor: answers compliance questions and audits user-supplied artifacts (free-text system descriptions, internal policy PDFs, IaC/configs, logs) against NIST CSF/SP 800-30/37/53, CIS Controls v8.1, MITRE ATT&CK, OWASP ASVS, and CompTIA Security+.

The system was restarted from scratch in May 2026 — the prior `compliance_agent_tools.py` / `data_preprocessing.py` / `schema.json` / Neo4j layer were replaced by the `src/auditor/` package.

## Commands

```powershell
# 1. Install
pip install -e .[dev]

# 2. Build the framework index (one time, or after changing PDFs / chunking)
python -m auditor.ingest.frameworks_index --rebuild
python -m auditor.ingest.frameworks_index --probe "multi-factor authentication"   # sanity check

# 3. Launch the UI
streamlit run app.py

# 4. Tests (LLM and retriever are stubbed; no API calls)
pytest
pytest tests/test_audit_config.py::test_sshd_heuristics_flag_root_login_and_passwords
```

`.env` must define `OPENAI_API_KEY`. No other env vars are required (no Neo4j).

## Architecture

```
                ┌──────────────┐
   user input → │  supervisor  │ ──► route based on whether artifacts are attached
                └──────┬───────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
     compliance_node          audit_node
     (Q&A / summary)          (dispatches to per-kind audit tool)
            │                     │
            └──────────┬──────────┘
                       ▼
                reporting_node ──► Markdown report (or pass-through Q&A answer)
                       │
                      END
```

**LangGraph state** (`src/auditor/agents/state.py`): `messages`, `target_frameworks`, `artifacts`, `findings`, `final_report`, `route`. The `messages` channel uses `add_messages` reducer.

**Routing**: supervisor sets `route="audit"` if any artifacts are attached, else `"compliance"`. Reporting node short-circuits when route is `compliance` (the answer is already in `final_report`).

### Tool layout

- `tools/compliance_qa.py` — vector retrieval over the framework corpus + LLM synthesis with citations
- `tools/framework_summary.py` — `MultiQueryRetriever` + `load_summarize_chain(map_reduce)` for topic summaries
- `tools/audit_text.py` — audits a free-text system description; LLM with retrieval context
- `tools/audit_policy_pdf.py` — extracts PDF text, then audits as a policy-vs-framework gap analysis
- `tools/audit_config.py` — `detect_config_kind()` + per-kind regex heuristics (`_check_sshd`, `_check_dockerfile`, `_check_nginx`, `_check_terraform`, `_check_kubernetes`) merged with LLM analysis
- `tools/audit_logs.py` — regex heuristics for brute-force / root SSH / sudo-without-audit, then LLM
- `tools/_findings_llm.py` — shared helper that wires `ChatOpenAI.with_structured_output(_FindingList)` so every audit tool returns `list[Finding]` (defined in `models.py`)

### Conventions

- Single source of truth for paths/models/chunking: `src/auditor/config.py` (`Settings` via `pydantic-settings`). Don't hardcode model names or `.chromadb` paths elsewhere.
- Chroma collection name is `frameworks_v2` to keep new + old indexes from colliding in the same persist dir.
- Each ingested chunk carries `framework`, `source`, `page` metadata. Retrieval filtering uses `framework` (see `_framework_filter` in `retrieval/retriever.py`).
- Audit tools always return `list[Finding]`. Heuristic findings come first, then de-duplicated LLM findings. The reporting agent is responsible for ordering and rendering.
- New audit tool? Add it to `tools/`, surface it from `audit_agent._audit_one()`, and (if needed) extend `Artifact.kind` in `models.py`.
- New framework PDF? Drop it in `data/`, add an entry to `FRAMEWORK_NAMES` in `ingest/pdf_loader.py`, then `--rebuild` the index.

### Tests

`tests/conftest.py` autouse fixture monkeypatches `run_findings_chain` and `retrieve` across every audit module so tests run with no network and no API key. When adding a new audit tool, extend the `for module in (...)` loop in conftest if it imports `run_findings_chain` / `retrieve` directly.
