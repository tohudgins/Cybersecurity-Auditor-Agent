# Cybersecurity Auditor Agent

> Multi-agent cybersecurity auditor: ask compliance questions and audit your systems against NIST CSF 2.1, the NIST SP 800 series, CIS Controls v8.1, OWASP ASVS 5.0 / Top 10 2025 / API Top 10 2023, CISA Zero Trust, and MITRE ATT&CK.

![CI](https://github.com/tohudgins/Cybersecurity-Auditor-Agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Built with](https://img.shields.io/badge/built%20with-LangGraph%20%7C%20LangChain%20%7C%20Streamlit%20%7C%20OpenAI-orange)
<!-- After Streamlit Cloud deploy, replace YOUR-APP-URL with the real URL: -->
<!-- [![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://YOUR-APP-URL.streamlit.app) -->

A local Streamlit app that puts a cybersecurity GRC analyst behind a chat box. You **talk to it** — ask a compliance question, tell it what to audit, then dig into the results. Two modes:

- **Compliance Q&A** — cited answers grounded in the indexed framework corpus (PDFs + GitHub markdown). Hybrid BM25 + vector retrieval routes exact control-ID queries (`AC-2`, `A01:2025`, `API1:2023`) directly to the matching control.
- **System auditing** — just say what to scan: `audit ~/myrepo`, `scan https://example.com`, `audit aws:prod`, `image:nginx:1.21`, `audit this machine` (or attach files / use the sidebar). The agent detects the target, runs the right tools (regex heuristics + Trivy, Semgrep, Bandit, gitleaks, Checkov, hadolint, Prowler, Nuclei, Lynis) and LLM analysis, then returns a report that leads with a **control-coverage assessment** (per-control Satisfied / Not Satisfied / Not Assessed with the assessment method) — not just a findings list — ranked by risk and tied to framework controls. Afterward you can **ask follow-ups in plain language** ("explain finding 3", "how do I fix the SQL injection?", "which controls failed?"), answered against the report and the framework corpus.

Unlike a bare scanner, it assesses controls the way an assessor does: it reports what passed, what failed, and — honestly — what went **unassessed** because no artifact exercised it, with a coverage percentage. Findings are separated into **deterministic** (scanner/heuristic) vs **AI-assisted** evidence, and results export as both OSCAL Assessment Results and an OSCAL POA&M.

---

## What you can use it for

It orchestrates the standard open-source security toolchain, normalizes every result into one risk-ranked model, maps it to controls across six frameworks, and renders an assessment with coverage + exportable evidence. Concretely:

| If you are… | You can… | What you get back |
|---|---|---|
| **A GRC analyst prepping for an audit** (SOC 2 / ISO 27001 / FedRAMP / PCI) | Point it at the systems in scope and ask "audit X" | A control-coverage assessment (Satisfied / Not Satisfied / Not Assessed + method), cross-framework mappings, and **OSCAL Assessment Results + POA&M** you can hand to a GRC platform or use as evidence/work-paper starting points |
| **A developer / AppSec engineer** | `audit ~/service-repo` before a release | Dependency CVEs (with KEV/EPSS), SAST findings, IaC/Dockerfile misconfigs, and leaked secrets — each tied to a CWE → ASVS → NIST control, ranked by real exploit risk |
| **A DevOps / cloud engineer** | `audit aws:prod`, `image:myapp:1.4` | Live cloud-posture failures (Prowler) and image CVEs/misconfigs (Trivy), mapped to NIST controls and prioritized — a fast "where are we exposed?" pass |
| **A security engineer / pentester** | `scan https://staging.example.com` | A Nuclei DAST pass triaged into the same risk model, so web findings sit next to code and cloud findings in one report |
| **A sysadmin / blue-teamer** | `audit this machine` or `audit user@server` | A Lynis OS-hardening review (SSH, auth, firewall, logging, kernel, packages) mapped to controls — per host or across a fleet over SSH |
| **Anyone learning the standards** | Ask "what does AC-2 require?" or follow up on a finding | Cited answers from the indexed corpus (NIST, CIS, OWASP, CISA, MITRE), and report-grounded remediation guidance |

**A typical real-life flow:** scope the system → `audit` each target (repo, cloud account, host, URL) → read the coverage table to see what passed / failed / wasn't covered → ask follow-ups to understand and remediate the top risks → export OSCAL + POA&M as the evidence trail and remediation plan. It compresses the "run six tools, reconcile their output, map it to a framework, write it up" grind into one conversation — while being explicit that it's an **assistive** tool, not a replacement for a qualified assessor (see [Limitations & scope](#limitations--scope)).

### Finding enrichment

Every finding is enriched with industry-standard context before rendering:

| Enrichment | Source | What it adds |
|---|---|---|
| **CISA KEV** | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Bumps actively-exploited CVEs to `critical` with a `[KEV - actively exploited]` badge |
| **EPSS** | [FIRST.org Exploit Prediction](https://www.first.org/epss/) | Probability + percentile that the CVE will be exploited in the next 30 days |
| **CVSS v3** | NVD via Trivy | Numeric base score + vector + qualitative severity (e.g., `9.8 (Critical)`) |
| **MITRE ATT&CK** | Curated keyword map + full ATT&CK Enterprise STIX bundle from [mitre/cti](https://github.com/mitre/cti) (7-day cache) | Tags findings with technique IDs (e.g., brute-force log → `T1110.001`). Two layers: hand-curated high-precision rules, plus multi-word phrase matching across all ~600 ATT&CK techniques. |
| **Cross-framework mappings** | Curated crosswalk + NIST OLIR/CPRT importer | **Bidirectional** resolution across NIST 800-53, CSF 2.1, CIS v8.1, ISO 27001:2022, PCI DSS v4.0.1, SOC 2 TSC ([`data/mappings/control_mappings.json`](data/mappings/control_mappings.json)). A finding anchored on *any* of those frameworks resolves to all the others. SAST findings (Semgrep/Bandit) cross a **CWE → OWASP ASVS 5.0 → NIST** bridge ([`cwe_mappings.json`](data/mappings/cwe_mappings.json)) so a `CWE-89` SQLi finding inherits the full control crosswalk. |
| **Control assessment** | SP 800-53A model | Per-control verdict (Satisfied / Not Satisfied / Partial / Not Assessed) + method (Examine / Test) + a coverage % over the selected baseline. Converts findings into an assessment. |
| **OSCAL export** | NIST [OSCAL 1.1.2](https://pages.nist.gov/OSCAL/reference/latest/assessment-results/) | Every run downloadable as **Assessment Results** JSON (with `reviewed-controls` + coverage props) and an **OSCAL POA&M** (open findings as remediation items) — FedRAMP / Trestle / RegScale-ingestible. All enrichment fields surface as OSCAL `props`. |
| **Audit history** | Local SQLite at `~/.cache/auditor/history.db` | Every completed run is persisted with its report + OSCAL JSON. Sidebar shows the 3 most recent; "View all" opens a paged browser with per-row delete and confirmed bulk clear. |

---

## Demo

The `examples/` directory ships deliberately-weak artifacts so anyone can reproduce the demo:

| Artifact | What you'll see |
|---|---|
| `examples/sshd_config_weak.conf` | Root SSH login, password auth, empty passwords |
| `examples/Dockerfile_root.txt` | `:latest` tag, no `USER`, `ADD <url>` |
| `examples/auth_bruteforce.log` | Brute-force pattern + suspicious post-login activity |
| `examples/terraform_open_sg.tf` | `0.0.0.0/0` ingress, public S3 ACL, unencrypted RDS |
| `examples/policy_minimal.txt` | (paste into chat) Gap report against NIST/CIS policy requirements |

Sample audit finding (rendered Markdown):

```
### 1. [HIGH] Root SSH login is enabled
- Mapped control: NIST SP 800-53 Rev. 5 — AC-6
- Cross-framework: NIST CSF 2.1: PR.AA-05; CIS Controls v8.1: 5.4, 6.8; ISO 27001:2022: A.8.2
- MITRE ATT&CK: T1078.003
- Evidence: PermitRootLogin yes
- Recommendation: Set `PermitRootLogin no` and require named user accounts with sudo.
```

Sample CVE finding (Trivy + KEV + EPSS):

```
### 2. [KEV - actively exploited] [CRITICAL] log4j 2.14.1: CVE-2021-44228
- Mapped control: NIST SP 800-53 Rev. 5 — SI-2
- CVSS v3 base score: 10.0 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- EPSS: 0.9743 (top 0.0% most likely to be exploited)
- MITRE ATT&CK: T1190
```

---

## Architecture

```
                ┌──────────────┐
   user input → │  supervisor  │  routes on whether artifacts are attached
                └──────┬───────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
     compliance_node          audit_node
     (hybrid BM25+vector       (per-kind audit tool → findings →
      retrieval + cited LLM    enrich with KEV, EPSS, ATT&CK,
      synthesis)               cross-framework mappings)
            │                     │
            └──────────┬──────────┘
                       ▼
                reporting_node  ──►  Markdown report (+ OSCAL JSON export)
                       │
                      END
```

LangGraph wiring lives in `src/auditor/agents/graph.py`. Shared `AuditorState` carries `messages`, `target_frameworks`, `artifacts`, `findings`, `final_report`, and `route`.

Each audit tool pairs regex heuristics (instant, deterministic) with an LLM call (nuanced reasoning), and returns the same `Finding` shape so the reporting agent renders everything uniformly.

---

## Performance

The pipeline is tuned so neither mode makes the user wait on avoidable work:

- **Retrieval caches.** The Chroma client and OpenAI embeddings object are `lru_cache`d, so a single hybrid query builds them once instead of three times. The BM25 index is persisted to `.chromadb/bm25_cache.pkl` (keyed on chunk count, so a `--rebuild` auto-invalidates it) and loaded on startup via `st.cache_resource` — the cold-start corpus scan happens at app boot, not on the first question.
- **Right-sized reasoning.** Compliance synthesis and audit-path LLM calls (per-artifact finding extraction + the executive summary) run at `reasoning_effort="low"`. These are grounded, extractive tasks over context that's already assembled, so low effort sharply cuts time-to-first-token without measurable quality loss. Both knobs are configurable in `config.py`.
- **Concurrent scanning.** The four codebase scanners (Trivy, Semgrep, Bandit, secrets) run in a thread pool instead of sequentially — wall-clock collapses to the slowest scanner rather than their sum. Multiple uploaded artifacts are audited concurrently for the same reason. Subprocess and network waits release the GIL, so threads are the right primitive; each scanner is independently fault-isolated so one crash can't sink the run.
- **Enrichment built once.** KEV, EPSS, and ATT&CK STIX catalogs are parsed once into in-memory lookups (24h / 7-day on-disk caches), giving O(1) per-CVE checks across an entire audit.

---

## Supported frameworks

**Control catalogs** — per-control chunking, exact-ID retrieval:

| Framework | Filename | Download |
|---|---|---|
| NIST Cybersecurity Framework 2.1 | `NIST.CSWP.30.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.30.pdf) |
| NIST SP 800-53 Rev. 5 | `NIST.SP.800-53r5.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) |
| NIST SP 800-171 Rev. 3 (CUI) | `NIST.SP.800-171r3.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf) |
| NIST SP 800-218 (SSDF) | `NIST.SP.800-218.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) |
| CIS Controls v8.1 | `CIS_Controls__v8.1_Guide__2024_06.pdf` | [CIS](https://www.cisecurity.org/controls/v8-1) |

**Process / narrative / reference** — generic chunking:

| Framework | Filename | Download |
|---|---|---|
| NIST SP 800-37 Rev. 2 (RMF) | `NIST.SP.800-37r2.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf) |
| NIST SP 800-30 Rev. 1 (Risk Assessments) | `nistspecialpublication800-30r1.pdf` | [NIST Publications](https://www.nist.gov/publications/guide-conducting-risk-assessments) |
| NIST SP 800-61 Rev. 3 (Incident Response) | `NIST.SP.800-61r3.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf) |
| NIST IR 7298 Rev. 3 (Glossary) | `NIST.IR.7298r3.pdf` | [NIST CSRC](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.7298r3.pdf) |
| CISA Zero Trust Maturity Model v2 | `zero_trust_maturity_model_v2_508.pdf` | [CISA](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf) |
| MITRE ATT&CK Enterprise | `MITRE_ATTACK_Enterprise_11x17.pdf` | [MITRE ATT&CK](https://attack.mitre.org/) |

Drop the PDFs into `data/` then run `python -m auditor.ingest.frameworks_index --rebuild`. Missing PDFs are silently skipped — the agent only indexes what's actually present.

**Web-fetched markdown** — pulled from GitHub on `--fetch-web`, cached into `data/web/` (gitignored):

| Source | Repo | License |
|---|---|---|
| OWASP Top 10 2025 | [OWASP/Top10](https://github.com/OWASP/Top10/tree/master/2025/docs/en) | CC-BY-SA 4.0 |
| OWASP ASVS 5.0 | [OWASP/ASVS](https://github.com/OWASP/ASVS/tree/master/5.0/en) | CC-BY-SA 4.0 |
| OWASP API Security Top 10 2023 | [OWASP/API-Security](https://github.com/OWASP/API-Security/tree/master/editions/2023/en) | CC-BY-SA 4.0 |
| OWASP Cheat Sheet Series | [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) | CC-BY-SA 4.0 |

```bash
python -m auditor.ingest.frameworks_index --fetch-web --rebuild
```

Idempotent — files already on disk are skipped. Use `--force-fetch` to refresh.

To add a new framework: drop the PDF in `data/` (or add a `WebSource` in `ingest/web_fetcher.py`), add an entry to `FRAMEWORK_NAMES` in `ingest/pdf_loader.py`, optionally extend `_CONTROL_PATTERNS` with a control-ID regex, then `--rebuild`.

### Cross-framework mappings

The crosswalk is anchored on NIST SP 800-53 Rev. 5 and resolves bidirectionally to NIST CSF 2.1, CIS Controls v8.1, ISO/IEC 27001:2022, PCI DSS v4.0.1, and SOC 2 TSC. A CWE → OWASP ASVS 5.0 → NIST bridge gives SAST findings the same cross-framework context. To add a mapping, edit [`data/mappings/control_mappings.json`](data/mappings/control_mappings.json) (or [`cwe_mappings.json`](data/mappings/cwe_mappings.json)) — no code change required. A test (`tests/test_mappings.py::test_every_scanner_control_id_is_mapped`) fails the build if a scanner emits a control with no mapping.

To **augment the curated crosswalk from NIST's official machine-readable exports** (OLIR via the Cybersecurity & Privacy Reference Tool):

```bash
python -m auditor.ingest.olir_import --fetch          # dry run: parsed reference counts
python -m auditor.ingest.olir_import --fetch --merge  # union OLIR references into the curated file
```

The importer is orientation-agnostic (detects the 800-53 side by ID shape) and only augments controls already present in the curated file, so it never invents an un-vetted entry. The curated file remains the source of truth used in CI and the demo.

---

## Supported audit inputs

| Artifact kind | Examples | Tool |
|---|---|---|
| `text` | Pasted system / architecture description | `tools/audit_text.py` |
| `policy_pdf` | Internal security policy PDF | `tools/audit_policy_pdf.py` |
| `config` | `sshd_config`, `nginx.conf`, `Dockerfile` (hadolint), `*.tf` / Kubernetes YAML (Checkov) | `tools/audit_config.py` |
| `log` | `auth.log`, syslog, access logs, JSON event logs — heuristics for brute force, post-brute-force compromise, web attacks (SQLi/XSS/traversal/cmd-injection), and log tampering | `tools/audit_logs.py` |
| `codebase` | Local directory path; Trivy scans dependency CVEs + IaC/Dockerfile misconfigurations + Semgrep multi-language SAST + Bandit Python SAST + gitleaks secrets (regex fallback if gitleaks isn't installed) | `tools/audit_codebase.py` |
| `cloud_account` | **Live cloud posture (CSPM).** A provider spec (`aws`, `aws:profile`, `gcp`, `azure`); runs Prowler against the account using your local read-only SDK credentials and maps FAIL findings to NIST controls | `tools/audit_cloud.py` |
| `image_ref` | **Container image.** An image reference (`nginx:1.21`); `trivy image` for CVEs + misconfigurations, with the same KEV/EPSS/CVSS enrichment as a codebase scan | `tools/audit_codebase.py` |
| `target_url` | **Live web target (DAST).** A URL; runs a Nuclei templated scan and maps results to NIST controls by tag. Only scan targets you are authorized to test | `tools/audit_web.py` |
| `host` | **Machine / OS hardening.** `localhost` or `user@server`; runs a Lynis audit (local, or remote over SSH) and maps each warning/suggestion to a NIST control by test category | `tools/audit_host.py` |

Targets can be supplied through the sidebar **or stated in chat** — `auditor.intake.parse_targets()` detects paths, URLs, cloud accounts, images, and hosts from a message (with explicit `path:`/`url:`/`image:`/`cloud:`/`host:` prefixes always honored).

---

## Quickstart

```bash
git clone <your-repo-url>
cd Cybersecurity-Auditor-Agent

# Recommended: isolate dependencies in a virtual env
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

cp .env.example .env
# edit .env and set OPENAI_API_KEY

pip install -e .[dev]
pre-commit install     # one-time: enables ruff + gitleaks on every commit

# One-time: fetch OWASP markdown + embed all sources into Chroma
python -m auditor.ingest.frameworks_index --fetch-web --rebuild

# Sanity check (hybrid retrieval routes the exact control ID directly)
python -m auditor.ingest.frameworks_index --probe "AC-2 account management"

# Launch the UI
streamlit run app.py
```

Open `http://localhost:8501`.

---

## Run with Docker

Full feature set including all bundled scanners (Trivy, Semgrep, Bandit, gitleaks, Checkov, hadolint):

```powershell
# Windows PowerShell
$env:OPENAI_API_KEY="sk-..."
docker compose up --build
```
```bash
# macOS / Linux
export OPENAI_API_KEY=sk-...
docker compose up --build
```

First boot fetches markdown sources, embeds everything (~2-3 min, ~$0.20 of OpenAI credits), and pre-warms the MITRE ATT&CK STIX cache. Named volumes are mounted:

- `chromadb` → `/app/.chromadb` — framework embeddings
- `auditor_cache` → `/root/.cache/auditor` — KEV / EPSS / ATT&CK STIX caches and the SQLite audit history
- `semgrep_cache` → `/root/.semgrep` — Semgrep `--config auto` rule cache (avoids re-download on restart)

All persist across container restarts.

**Scanning a local codebase:** the compose file mirrors your host `$HOME` into the container read-only at the same path (`${HOME}:${HOME}:ro`), so you can paste a real local path (e.g. `/Users/you/code/repo`) straight into the UI's *Codebase path* field. Narrow this mount to a single directory in `docker-compose.yml` if you don't want the container to see all of `$HOME`.

The image: `python:3.12-slim` + Trivy (from Aqua's Debian repo) + gitleaks & hadolint (multi-arch release binaries) + Semgrep/Checkov/Bandit via pip. Entrypoint is `docker/entrypoint.sh`.

Without docker-compose:
```bash
docker build -t cybersecurity-auditor .
docker run -p 8501:8501 -e OPENAI_API_KEY=sk-... -v auditor-chromadb:/app/.chromadb cybersecurity-auditor
```

---

## Live demo (Streamlit Community Cloud)

> Live URL will be added here after the first deploy.

The hosted version runs **compliance Q&A** (with streaming output), **policy PDF audit**, **config / IaC audits via Checkov**, **Python SAST via Bandit / Semgrep** (pip-installable), **OSCAL export**, and **audit history**. Scanners that ship as system binaries — Trivy (CVEs + IaC misconfig), gitleaks (secrets), and hadolint (Dockerfile linting) — aren't available on Streamlit Cloud, so the agent gracefully surfaces info findings and falls back to regex heuristics. For full functionality, use the local Docker setup.

> **Shared deployments:** set `AUDITOR_ALLOW_LOCAL_TARGETS=false` so users can't read or scan the server's filesystem/OS through the chat (codebase, host, and chat-referenced file targets are refused). It defaults to `true` for normal local use.

---

## Security posture

The agent shells out to real scanners, so it treats its own inputs as untrusted:

- **No shell** — every external tool is invoked via `subprocess.run([...])` argument lists (never `shell=True`), so messages can't inject shell commands.
- **Argument-injection hardening** — SSH host specs, container image references, and cloud profile names are validated and may not begin with `-`, so a value like `-oProxyCommand=…` can't be reinterpreted as a tool flag (a classic RCE vector); image refs are also passed after a `--` separator.
- **Filesystem/OS gating** — `AUDITOR_ALLOW_LOCAL_TARGETS=false` disables codebase/host/chat-file targets for shared hosting; chat-referenced files are size-capped before being read.
- **Read-only by design** — scanners are pointed at targets in read-only modes; cloud auditing uses your existing read-only SDK credentials, which the app never handles or stores.
- **Graceful degradation** — a missing scanner becomes an info finding, never a crash.

Only audit systems you are authorized to assess.

---

## Project structure

```
.
├── app.py                          # Streamlit entrypoint
├── pyproject.toml
├── data/
│   ├── *.pdf                       # Framework PDFs
│   ├── mappings/                   # Cross-framework control mapping JSON
│   └── web/                        # Markdown fetched from GitHub (gitignored)
├── examples/                       # Weak artifacts for reproducible demos
├── docker/                         # Dockerfile entrypoint
├── .github/workflows/ci.yml        # pytest + ruff + gitleaks (Py 3.10/3.11/3.12)
├── .pre-commit-config.yaml         # ruff + end-of-file + gitleaks
├── src/auditor/
│   ├── config.py                   # Settings (paths, model names, k)
│   ├── models.py                   # Finding, Artifact
│   ├── history.py                  # SQLite audit run history
│   ├── ingest/                     # PDF + markdown loader + GitHub fetcher
│   ├── retrieval/                  # Hybrid BM25 + vector retrieval (RRF fusion)
│   ├── tools/                      # compliance_qa (sync + streaming), framework_summary, audit_*
│   ├── enrichment/                 # CISA KEV, EPSS, MITRE ATT&CK (curated + STIX), control mappings
│   ├── oscal/                      # NIST OSCAL Assessment Results exporter
│   ├── prompts/                    # PromptTemplates kept separate from logic
│   └── agents/                     # supervisor, compliance, audit, reporting + graph
└── tests/                          # pytest (LLM + retriever + KEV/EPSS/STIX all stubbed)
```

---

## Tests

```bash
pytest                              # full suite, no network calls
pytest tests/test_audit_config.py   # single file
```

`tests/conftest.py` autouse fixture stubs the LLM call helper (`run_findings_chain`), the retriever, KEV lookups, and EPSS lookups — so the suite runs offline with no API key. CI (`.github/workflows/ci.yml`) runs `pytest` + `ruff` on the matrix Py 3.10/3.11/3.12, plus a separate gitleaks job on every push and PR.

---

## Tech stack

- **[LangGraph](https://github.com/langchain-ai/langgraph)** — multi-node agent state machine
- **[LangChain](https://github.com/langchain-ai/langchain)** — retrieval, prompts, structured output
- **[ChromaDB](https://github.com/chroma-core/chroma)** — local vector store
- **[rank-bm25](https://github.com/dorianbrown/rank_bm25)** — BM25 keyword retrieval (fused with Chroma via RRF)
- **[OpenAI](https://platform.openai.com/)** — `gpt-5` / `gpt-5-mini` synthesis, `text-embedding-3-small` embeddings
- **[Streamlit](https://streamlit.io/)** — chat UI + file uploader
- **[Pydantic](https://docs.pydantic.dev/)** — typed `Finding` / `Artifact` models, structured LLM output
- **[pypdf](https://github.com/py-pdf/pypdf)** — PDF text extraction

### External scanners (auto-degraded if missing)

| Scanner | Audit kind | Install |
|---|---|---|
| **[Trivy](https://aquasecurity.github.io/trivy/)** | `codebase` (dependency CVEs + IaC/Dockerfile misconfig) | `scoop install trivy` / `brew install trivy` / [releases](https://github.com/aquasecurity/trivy/releases) |
| **[Semgrep](https://semgrep.dev/)** | `codebase` (multi-language SAST) | `pip install semgrep` / `brew install semgrep` |
| **[Bandit](https://bandit.readthedocs.io/)** | `codebase` (Python SAST) | `pip install bandit` |
| **[gitleaks](https://github.com/gitleaks/gitleaks)** | `codebase` (secrets) | `brew install gitleaks` / [releases](https://github.com/gitleaks/gitleaks/releases) — if missing, a built-in regex fallback covers AWS keys, OpenAI keys, GitHub tokens, hardcoded passwords, and embedded private keys. |
| **[Checkov](https://www.checkov.io/)** | `config` (Terraform / K8s IaC) | `pip install checkov` |
| **[hadolint](https://github.com/hadolint/hadolint)** | `config` (Dockerfile linting) | `brew install hadolint` / [releases](https://github.com/hadolint/hadolint/releases) — regex fallback if missing |
| **[Prowler](https://github.com/prowler-cloud/prowler)** | `cloud_account` (live CSPM: AWS / GCP / Azure) | `pip install prowler` — uses your read-only cloud SDK credentials |
| **[Nuclei](https://github.com/projectdiscovery/nuclei)** | `target_url` (live web DAST) | `brew install nuclei` / [releases](https://github.com/projectdiscovery/nuclei/releases) |
| **[Lynis](https://github.com/CISOfy/lynis)** | `host` (OS hardening, local or remote-over-SSH) | `brew install lynis` / `apt install lynis` — for remote audits, Lynis must be on the target host |

If a scanner isn't on PATH, the corresponding tool emits an info-level finding with the install hint and falls back to either regex heuristics or a degraded mode — the demo still runs.

---

## Limitations & scope

Stated plainly, because a GRC tool that overstates its rigor is worse than one that doesn't:

- **Mappings are informative, not authoritative.** The crosswalk is curated from the public OLIR/CIS/ISO/PCI/SOC 2 references and covers the control families this agent exercises (~40 anchor controls, ~35 CWEs) — not the full ~1,000-control 800-53 catalog. The OLIR importer can augment it from NIST's machine-readable exports, but a compliance decision should still be confirmed against the official source. ASVS references are at chapter/domain granularity so they survive ASVS minor revisions.
- **LLM findings are assistive, not a substitute for a human assessor.** The deterministic scanners (Trivy, Semgrep, Bandit, gitleaks, Checkov, hadolint) and regex heuristics are the evidentiary backbone; the LLM layer adds narrative analysis and can produce false positives/negatives. Findings are meant to be triaged, not auto-accepted.
- **Point-in-time, on-demand.** The agent assesses what you point it at — uploaded artifacts *or* live targets (cloud account, container image, web URL) — at the moment you run it. It doesn't do continuous control monitoring, evidence collection, or ticketing; the OSCAL export exists so results can feed a system that does.
- **Live scanning needs the prerequisites and your authorization.** Cloud posture (Prowler) requires read-only credentials in your local SDK config; web DAST (Nuclei) must only be pointed at systems you are permitted to test; remote host audits (Lynis) need SSH access and Lynis installed on the target. Missing scanners degrade gracefully to an info finding rather than failing the run.
- **Chat target detection is heuristic.** Plain-language targeting (`audit aws:prod`) is best-effort and gated on an audit verb to avoid hijacking compliance questions; the explicit `path:`/`url:`/`image:`/`cloud:`/`host:` prefixes are the deterministic path.
- **Single-user, local-first.** Audit history is a local SQLite DB — no multi-tenant RBAC or shareable report links yet.

## Roadmap

Deliberate v1 cuts; happy to revisit:

- **Expand the OLIR import** — broaden `OLIR_SOURCES` to the full CSF / ISO / SP 800-171 reference set and grow the anchor catalog toward complete 800-53 coverage.
- **CIS Foundations Benchmarks** — ingest the AWS / Azure / GCP benchmarks and route Terraform findings to the cloud-specific catalog.
- **Custom Checkov policies** tagging NIST 800-53 control IDs (stock rules tag CIS only).
- **Live cloud-API scanning** — AWS Config / Azure Policy ingestion instead of file uploads.
- **Multi-user persistence** — RBAC and shareable report links on top of the existing per-user SQLite history.

---

## License

MIT — see [LICENSE](LICENSE).
