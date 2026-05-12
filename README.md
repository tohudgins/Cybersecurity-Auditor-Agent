# Cybersecurity Auditor Agent

> Multi-agent cybersecurity auditor: ask compliance questions and audit your systems against NIST CSF 2.1, the NIST SP 800 series, CIS Controls v8.1, OWASP ASVS 5.0 / Top 10 2025 / API Top 10 2023, CISA Zero Trust, and MITRE ATT&CK.

![CI](https://github.com/tohudgins/Cybersecurity-Auditor-Agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Built with](https://img.shields.io/badge/built%20with-LangGraph%20%7C%20LangChain%20%7C%20Streamlit%20%7C%20OpenAI-orange)
<!-- After Streamlit Cloud deploy, replace YOUR-APP-URL with the real URL: -->
<!-- [![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://YOUR-APP-URL.streamlit.app) -->

A local Streamlit app that puts a cybersecurity GRC analyst behind a chat box. Two modes:

- **Compliance Q&A** — cited answers grounded in the indexed framework corpus (PDFs + GitHub markdown). Hybrid BM25 + vector retrieval routes exact control-ID queries (`AC-2`, `A01:2025`, `API1:2023`) directly to the matching control.
- **System auditing** — upload a config, log, internal policy PDF, codebase path, or paste a free-text description. The agent runs regex heuristics, Trivy / Checkov / Bandit scanners, and LLM analysis, then returns a Markdown audit report ranked by severity and tied to specific framework controls.

### Finding enrichment

Every finding is enriched with industry-standard context before rendering:

| Enrichment | Source | What it adds |
|---|---|---|
| **CISA KEV** | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Bumps actively-exploited CVEs to `critical` with a `[KEV - actively exploited]` badge |
| **EPSS** | [FIRST.org Exploit Prediction](https://www.first.org/epss/) | Probability + percentile that the CVE will be exploited in the next 30 days |
| **CVSS v3** | NVD via Trivy | Numeric base score + vector + qualitative severity (e.g., `9.8 (Critical)`) |
| **MITRE ATT&CK** | Curated keyword map → [ATT&CK Enterprise](https://attack.mitre.org/) | Tags findings with technique IDs (e.g., brute-force log → `T1110.001`) |
| **Cross-framework mappings** | NIST OLIR + curated | Resolves every NIST 800-53 control to CSF 2.1, CIS v8.1, ISO 27001:2022, PCI DSS v4, SOC 2 TSC ([`data/mappings/control_mappings.json`](data/mappings/control_mappings.json)) |
| **OSCAL export** | NIST [OSCAL 1.1.2](https://pages.nist.gov/OSCAL/reference/latest/assessment-results/) | Every audit run downloadable as Assessment Results JSON (FedRAMP / Trestle / RegScale-ingestible). All enrichment fields above surface as OSCAL `props`. |

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

---

## Supported audit inputs

| Artifact kind | Examples | Tool |
|---|---|---|
| `text` | Pasted system / architecture description | `tools/audit_text.py` |
| `policy_pdf` | Internal security policy PDF | `tools/audit_policy_pdf.py` |
| `config` | `sshd_config`, `nginx.conf`, `Dockerfile`, `*.tf`, Kubernetes YAML | `tools/audit_config.py` |
| `log` | `auth.log`, syslog, JSON event logs | `tools/audit_logs.py` |
| `codebase` | Local directory path; Trivy scans CVEs in deps + Bandit for Python SAST | `tools/audit_codebase.py` |

---

## Quickstart

```bash
git clone <your-repo-url>
cd "Cybersecurity Auditor Agent"

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

Full feature set including Trivy / Checkov / Bandit:

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

First boot fetches markdown sources and embeds everything (~2-3 min, ~$0.20 of OpenAI credits). The named `chromadb` volume persists embeddings so subsequent starts skip the build.

The image: `python:3.12-slim` + Trivy from Aqua's Debian repo + Checkov/Bandit via pip. Entrypoint is `docker/entrypoint.sh`.

Without docker-compose:
```bash
docker build -t cybersecurity-auditor .
docker run -p 8501:8501 -e OPENAI_API_KEY=sk-... -v auditor-chromadb:/app/.chromadb cybersecurity-auditor
```

---

## Live demo (Streamlit Community Cloud)

> Live URL will be added here after the first deploy.

The hosted version runs **compliance Q&A**, **policy PDF audit**, **config / IaC audits via Checkov**, and **OSCAL export**. Codebase scanning (Trivy) is not available because Streamlit Cloud doesn't ship Trivy on its PATH — the agent surfaces a graceful "Trivy not installed" info finding. For full functionality, use the local Docker setup.

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
│   ├── ingest/                     # PDF + markdown loader + GitHub fetcher
│   ├── retrieval/                  # Hybrid BM25 + vector retrieval (RRF fusion)
│   ├── tools/                      # compliance_qa, framework_summary, audit_*
│   ├── enrichment/                 # CISA KEV, EPSS, MITRE ATT&CK, control mappings
│   ├── oscal/                      # NIST OSCAL Assessment Results exporter
│   ├── prompts/                    # PromptTemplates kept separate from logic
│   └── agents/                     # supervisor, compliance, audit, reporting + graph
└── tests/                          # pytest (LLM + retriever + network stubbed)
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
| **[Trivy](https://aquasecurity.github.io/trivy/)** | `codebase` (CVE scanning) | `scoop install trivy` / `brew install trivy` / [releases](https://github.com/aquasecurity/trivy/releases) |
| **[Checkov](https://www.checkov.io/)** | `config` (Terraform / K8s IaC) | `pip install checkov` |
| **[Bandit](https://bandit.readthedocs.io/)** | `codebase` (Python SAST) | `pip install bandit` |

If a scanner isn't on PATH, the corresponding tool emits an info-level finding with the install hint and falls back to the regex heuristics — the demo still runs.

---

## Roadmap

Deliberate v1 cuts; happy to revisit:

- **Full NIST OLIR import** — replace the curated `control_mappings.json` with the complete OLIR set (~3,000 entries).
- **CIS Foundations Benchmarks** — ingest the AWS / Azure / GCP benchmarks and route Terraform findings to the cloud-specific catalog.
- **Custom Checkov policies** tagging NIST 800-53 control IDs (stock rules tag CIS only).
- **Live cloud-API scanning** — AWS Config / Azure Policy ingestion instead of file uploads.
- **Multi-user persistence** — audit history, RBAC, shareable report links.

---

## License

MIT — see [LICENSE](LICENSE).
