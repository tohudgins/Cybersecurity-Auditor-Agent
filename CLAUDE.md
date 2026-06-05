# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project Purpose

Multi-agent cybersecurity auditor. Two user-facing modes:

1. **Compliance Q&A** over an indexed corpus of cybersecurity frameworks.
2. **System auditing** — uploaded configs / logs / policy PDFs / codebase paths run through scanners + LLM analysis, producing a Markdown report and OSCAL JSON export.

Indexed corpus today:

- **PDFs** (in `data/`): NIST CSF 2.1, NIST SP 800-30 r1, 800-37 r2, 800-53 r5, 800-61 r3, 800-171 r3, 800-218 (SSDF), NIST IR 7298 r3 (glossary), CIS Controls v8.1, CISA Zero Trust Maturity Model v2, MITRE ATT&CK Enterprise.
- **GitHub markdown** (fetched into `data/web/`): OWASP Top 10 2025, OWASP ASVS 5.0, OWASP API Security Top 10 2023, OWASP Cheat Sheet Series.

The project was restarted from scratch in May 2026; the prior `compliance_agent_tools.py` / `data_preprocessing.py` / Neo4j layer was replaced by the `src/auditor/` package.

## Commands

```powershell
# 1. Install
pip install -e .[dev]

# 2. Fetch OWASP markdown sources (one time, idempotent)
python -m auditor.ingest.frameworks_index --fetch-web

# 3. Build / rebuild the framework index (after PDF or chunking changes)
python -m auditor.ingest.frameworks_index --rebuild
python -m auditor.ingest.frameworks_index --probe "AC-2 account management"

# Combined fetch + rebuild (cold start)
python -m auditor.ingest.frameworks_index --fetch-web --rebuild

# 4. Launch the UI
streamlit run app.py

# 5. Tests (LLM, retriever, KEV, EPSS all stubbed — no network, no API key)
pytest
pytest tests/test_audit_config.py::test_sshd_heuristics_flag_root_login_and_passwords
```

`.env` must define `OPENAI_API_KEY`. No other env vars required.

## Architecture

```
                ┌──────────────┐
   user input → │  supervisor  │ ──► routes on artifacts presence
                └──────┬───────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
     compliance_node          audit_node
     (hybrid BM25 +           (per-kind audit tool → findings →
      vector retrieval         enrichment: ATT&CK tagging + mapping
      + cited LLM)             lookup → risk normalization:
                               de-dup + 0-100 score + rank)
            │                     │
            └──────────┬──────────┘
                       ▼
                reporting_node ──► Markdown report (compliance path
                       │           short-circuits; answer is in final_report)
                      END
```

**LangGraph state** (`agents/state.py`): `messages` (uses `add_messages` reducer), `target_frameworks`, `artifacts`, `findings`, `final_report`, `route`.

**Routing**: supervisor sets `route="audit"` if any artifacts are attached, else `"compliance"`. The reporting node short-circuits when `route == "compliance"` because the cited answer is already in `final_report`.

## Module layout

### `ingest/`
- `pdf_loader.py` — loads PDFs page-by-page; `chunk_documents` dispatches per-framework: catalogs in `_CONTROL_PATTERNS` get per-control chunks with `control_id` metadata; everything else gets `RecursiveCharacterTextSplitter`. Also has `load_markdown_dir` for `data/web/<source>/*.md`.
- `web_fetcher.py` — `WEB_SOURCES` list of `WebSource(name, repo, branch, path, framework, license)`. Fetches via the GitHub Contents API + `raw.githubusercontent.com`, caches into `data/web/<name>/`. Idempotent unless `force=True`.
- `frameworks_index.py` — builds the Chroma collection (`frameworks_v2`). Flags: `--rebuild`, `--fetch-web`, `--force-fetch`, `--probe`.

### `retrieval/`
- `retriever.py` — hybrid retrieval. `retrieve(query, frameworks, k)` fuses three runs via Reciprocal Rank Fusion: (1) exact `control_id` metadata lookup if the query mentions one, (2) Chroma vector similarity, (3) BM25 keyword search (lazy-built from all chunks, cached in `_bm25`). Framework filter applies post-hoc to BM25 (since BM25 doesn't support metadata filters).
- `_tokenize` strips trailing `.:`-style punctuation so `AC-2.` tokenizes as `ac-2` and BM25 hits exact control IDs.

### `tools/`
- `compliance_qa.py` — vector retrieval + LLM synthesis with citations. Exposes both `answer_compliance_question()` (blocking) and `stream_compliance_answer()` (yields token chunks for `st.write_stream`).
- `framework_summary.py` — pure LCEL pipeline (no `MultiQueryRetriever` or `load_summarize_chain` — those legacy umbrella imports were removed)
- `audit_text.py` / `audit_policy_pdf.py` — LLM with retrieval context
- `audit_logs.py` — deterministic heuristics + LLM. Heuristics detect brute-force (≥5 failed logins/IP), successful login from a brute-forcing IP (critical, AC-7 compromise signal), direct root login, sudo without an audit trail (AU-2), web-attack signatures in access logs (SQLi/XSS/path-traversal/command-injection → SI-10 / AC-3), and log-tampering / anti-forensics (AU-9). LLM analysis layered on top, de-duped by title.
- `audit_config.py` — `detect_config_kind()` + per-kind heuristics: sshd / nginx regex, Dockerfile via **hadolint** (regex fallback when absent, findings cite `NIST SP 800-53 Rev. 5 / CM-6`), Terraform / K8s via **Checkov** (regex fallback). LLM analysis merged on top, de-duped against heuristic findings.
- `audit_codebase.py` — Trivy (dependency CVEs with CVSS + KEV + EPSS, **plus IaC/Dockerfile/Helm misconfigurations** via `--scanners vuln,misconfig`) + Semgrep (multi-language SAST, always runs) + Bandit (Python SAST, only when `*.py` present) + gitleaks secrets scanning with a regex fallback when gitleaks isn't on PATH. Semgrep runs `--config auto` (rules fetched from the registry + cached under `~/.semgrep`, `--metrics off`); findings cite `OWASP ASVS 5.0` with `control_id` set to the rule's CWE when present. Bandit findings cite `OWASP ASVS 5.0`. Trivy CVE findings cite `NIST SP 800-53 Rev. 5 / SI-2`; Trivy misconfig findings cite `CM-6`. Secret findings cite `NIST SP 800-53 Rev. 5 / IA-5` (passwords/keys) or `SC-28` (private keys at rest).
- `_findings_llm.py` — shared helper wiring `ChatOpenAI.with_structured_output(_FindingList)` so every audit tool returns `list[Finding]`.

### `enrichment/`
- `kev.py` — CISA KEV catalog, 24h cache at `~/.cache/auditor/kev.json`. `is_kev(cve)` returns bool.
- `epss.py` — FIRST.org EPSS daily CSV, 24h cache. `epss_score(cve)` returns `(score, percentile) | None`.
- `mitre.py` — two-layer ATT&CK tagging. Layer 1 is `_TECHNIQUE_KEYWORDS`, hand-curated substring rules. Layer 2 downloads the full ATT&CK Enterprise STIX bundle from `mitre/cti` on GitHub (7-day cache at `~/.cache/auditor/attack_techniques.json`) and matches multi-word technique names verbatim against finding text. `enrich_findings(findings)` annotates each finding's `attack_techniques` in place. Tests stub `_stix_phrases = {}` via conftest so the network is never touched.
- `mappings.py` — loads `data/mappings/control_mappings.json` (NIST 800-53 anchor → CSF 2.1 / CIS / ISO / PCI / SOC 2). `enrich_with_mappings(findings)` populates `Finding.mapped_controls` for any finding tagged `framework="NIST SP 800-53 Rev. 5"`. `_base_id()` strips enhancement suffixes so `AC-2(1)` resolves to `AC-2`.
- `risk.py` — the aggregation layer. `compute_risk_score(finding)` returns a deterministic 0-100 score (severity baseline, raised by CVSS×10, plus EPSS×10, floored at 95+3 for KEV). `deduplicate(findings)` collapses cross-tool duplicates by signature (same CVE; same `file:line` + CWE; or same normalized title within an artifact), keeping the highest-scoring member and noting corroboration. `normalize_findings(findings)` scores → de-dups → ranks (highest risk first) and is called last in `audit_node`, after ATT&CK + mapping enrichment. `Finding.risk_score` surfaces in the report (per-finding line), the report ordering, and the OSCAL `risk-score` prop.

### `history.py`
- SQLite-backed audit run history at `~/.cache/auditor/history.db`. Exposes `save_run()`, `list_runs(limit, offset)`, `count_runs()`, `get_run(id)`, `delete_run(id)`, `clear_all()`. Every audit run is persisted automatically after `reporting_node` produces a report; the Streamlit sidebar surfaces the 3 most recent + a "View all" page with pagination + bulk delete.

### `oscal/`
- `exporter.py` — `to_oscal_assessment_results(findings)` returns OSCAL 1.1.2 JSON. Deterministic UUIDv5 for stable observation/finding IDs across runs. All enrichment fields surface as OSCAL `props`: `severity`, `risk-score`, `cvss-v3-base-score`, `cvss-v3-vector`, `epss-score`, `epss-percentile`, `cisa-kev`, `mitre-attack-technique`, `mapped-control` (with `class=<framework>`).

### `agents/`
- `graph.py` — `AUDITOR_GRAPH` singleton, START → supervisor → conditional `{compliance | audit}` → reporting → END.
- `audit_agent.py` — dispatches each `Artifact` to its tool, then calls `enrich_findings()` (ATT&CK), `enrich_with_mappings()` (cross-framework), and finally `normalize_findings()` (de-dup + risk score + rank). Returns the normalized, ranked list.
- `reporting_agent.py` — renders findings as Markdown, ordered by `risk_score` (desc). Per-finding lines: KEV badge, severity badge, risk score, mapped control, CVSS line, EPSS line, MITRE ATT&CK line, cross-framework line, source artifact, evidence, recommendation. Executive summary uses `gpt-5-mini` (fast_model).

## Streamlit UI flow

`app.py` branches before invoking the graph based on whether artifacts are attached:
- **Compliance path** (no artifacts): bypasses the graph and calls `stream_compliance_answer()` directly through `st.write_stream()` for token-by-token output.
- **Audit path** (artifacts present): uses `AUDITOR_GRAPH.stream(stream_mode="updates")` inside an `st.status()` container that labels each node (`supervisor` / `audit_node` / `reporting_node`) as it completes. The final report is rendered, OSCAL is offered as a download, and the run is persisted via `history.save_run()`.

Sidebar shows the 3 most recent runs as buttons; a "View all (N) →" button opens a full pageable history view in the main area (replaces the chat via `st.stop()`), with per-row View / Delete and a confirmed Clear-All.

## Conventions

- **Single source of truth for config**: `src/auditor/config.py` (`Settings` via `pydantic-settings`). Don't hardcode model names, `.chromadb` path, or `data/` path elsewhere.
- **Chroma collection name**: `frameworks_v2`. Bumping the schema (e.g., adding new metadata fields) should bump this string.
- **Chunk metadata**: every chunk has `framework`, `source`, `page`. Control-catalog chunks additionally have `control_id`. Sub-chunks of long controls have `chunk_part`.
- **Audit tools always return `list[Finding]`**. Heuristic findings come first, then LLM findings (de-duplicated). The reporting agent handles ordering and rendering.
- **Adding an audit tool**: add to `tools/`, wire from `audit_agent._audit_one()`, extend `Artifact.kind` in `models.py` if a new kind is needed, and extend the conftest stub loop if it imports `run_findings_chain` / `retrieve` directly.
- **Adding a framework PDF**: drop in `data/`, add an entry to `FRAMEWORK_NAMES` in `ingest/pdf_loader.py`, optionally add a control-ID regex to `_CONTROL_PATTERNS`, then `--rebuild`.
- **Adding a web markdown source**: append a `WebSource(...)` to `WEB_SOURCES` in `ingest/web_fetcher.py`, optionally add a regex to `_CONTROL_PATTERNS` keyed on the framework label, then `--fetch-web --rebuild`.
- **Adding a cross-framework mapping**: edit `data/mappings/control_mappings.json` (anchored on NIST 800-53 IDs). No code change needed.

## Tests

- `tests/conftest.py` autouse fixture monkeypatches `run_findings_chain`, `retrieve` (across all tool modules including `compliance_qa`), `kev.is_kev`, `epss.epss_score`, and `mitre._stix_phrases = {}`. Suite runs offline with no real API key and no STIX download.
- Tests for `history.py` use a `tmp_db` fixture that monkeypatches `history._DB_PATH` to a temp file so the suite never touches `~/.cache/auditor/`.
- Tests that need the real (unstubbed) function — e.g., to test `retrieve` or `epss_score` directly — capture the function at module import time (`_real_retrieve = retriever_mod.retrieve`) before the conftest stub is applied per-test.
- When adding a new audit tool that imports `run_findings_chain` or `retrieve` directly, extend the `for module in (...)` loop in conftest.
- CI runs `pytest` + `ruff check` on Python 3.10/3.11/3.12. Gitleaks is a separate job. Use `examples/` for any intentionally-weak fixture content (the gitleaks allowlist exempts that directory).

## Known compatibility notes

- `datetime.UTC` is Python 3.11+. Both `oscal/exporter.py` and `app.py` use `datetime.now(timezone.utc)` for 3.10 compat.
- `langchain-community` and the `langchain` umbrella package are **not** dependencies. We use `langchain-core`, `langchain-openai`, `langchain-chroma`, `langchain-text-splitters`. EnsembleRetriever was replaced with a hand-rolled RRF in `retrieval/retriever.py` to avoid adding the umbrella.
- BM25 retrieval requires `rank-bm25`. It's in core dependencies (not an extra) because hybrid retrieval is on by default.
