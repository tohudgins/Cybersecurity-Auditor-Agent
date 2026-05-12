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
      vector retrieval         enrichment: ATT&CK keyword tagging,
      + cited LLM)             cross-framework mapping lookup)
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
- `compliance_qa.py` — vector retrieval + LLM synthesis with citations
- `framework_summary.py` — pure LCEL pipeline (no `MultiQueryRetriever` or `load_summarize_chain` — those legacy umbrella imports were removed)
- `audit_text.py` / `audit_policy_pdf.py` / `audit_logs.py` — LLM with retrieval context
- `audit_config.py` — `detect_config_kind()` + per-kind regex heuristics merged with Checkov (Terraform / K8s) or LLM analysis
- `audit_codebase.py` — Trivy (CVEs in deps, with CVSS + KEV + EPSS) + Bandit (Python SAST). Bandit findings cite `OWASP ASVS 5.0`. Trivy findings cite `NIST SP 800-53 Rev. 5 / SI-2`.
- `_findings_llm.py` — shared helper wiring `ChatOpenAI.with_structured_output(_FindingList)` so every audit tool returns `list[Finding]`.

### `enrichment/`
- `kev.py` — CISA KEV catalog, 24h cache at `~/.cache/auditor/kev.json`. `is_kev(cve)` returns bool.
- `epss.py` — FIRST.org EPSS daily CSV, 24h cache. `epss_score(cve)` returns `(score, percentile) | None`.
- `mitre.py` — `_TECHNIQUE_KEYWORDS` dict mapping ATT&CK technique IDs to substrings. `enrich_findings(findings)` annotates each finding's `attack_techniques` field in place.
- `mappings.py` — loads `data/mappings/control_mappings.json` (NIST 800-53 anchor → CSF 2.1 / CIS / ISO / PCI / SOC 2). `enrich_with_mappings(findings)` populates `Finding.mapped_controls` for any finding tagged `framework="NIST SP 800-53 Rev. 5"`. `_base_id()` strips enhancement suffixes so `AC-2(1)` resolves to `AC-2`.

### `oscal/`
- `exporter.py` — `to_oscal_assessment_results(findings)` returns OSCAL 1.1.2 JSON. Deterministic UUIDv5 for stable observation/finding IDs across runs. All enrichment fields surface as OSCAL `props`: `severity`, `cvss-v3-base-score`, `cvss-v3-vector`, `epss-score`, `epss-percentile`, `cisa-kev`, `mitre-attack-technique`, `mapped-control` (with `class=<framework>`).

### `agents/`
- `graph.py` — `AUDITOR_GRAPH` singleton, START → supervisor → conditional `{compliance | audit}` → reporting → END.
- `audit_agent.py` — dispatches each `Artifact` to its tool, then calls `enrich_findings()` (ATT&CK) and `enrich_with_mappings()` (cross-framework).
- `reporting_agent.py` — renders findings as Markdown. Per-finding lines: KEV badge, severity badge, mapped control, CVSS line, EPSS line, MITRE ATT&CK line, cross-framework line, source artifact, evidence, recommendation. Executive summary uses `gpt-5-mini` (fast_model).

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

- `tests/conftest.py` autouse fixture monkeypatches `run_findings_chain`, `retrieve`, `kev.is_kev`, and `epss.epss_score`. Suite runs offline with no real API key.
- Tests that need the real (unstubbed) function — e.g., to test `retrieve` or `epss_score` directly — capture the function at module import time (`_real_retrieve = retriever_mod.retrieve`) before the conftest stub is applied per-test.
- When adding a new audit tool that imports `run_findings_chain` or `retrieve` directly, extend the `for module in (...)` loop in conftest.
- CI runs `pytest` + `ruff check` on Python 3.10/3.11/3.12. Gitleaks is a separate job. Use `examples/` for any intentionally-weak fixture content (the gitleaks allowlist exempts that directory).

## Known compatibility notes

- `datetime.UTC` is Python 3.11+. Both `oscal/exporter.py` and `app.py` use `datetime.now(timezone.utc)` for 3.10 compat.
- `langchain-community` and the `langchain` umbrella package are **not** dependencies. We use `langchain-core`, `langchain-openai`, `langchain-chroma`, `langchain-text-splitters`. EnsembleRetriever was replaced with a hand-rolled RRF in `retrieval/retriever.py` to avoid adding the umbrella.
- BM25 retrieval requires `rank-bm25`. It's in core dependencies (not an extra) because hybrid retrieval is on by default.
