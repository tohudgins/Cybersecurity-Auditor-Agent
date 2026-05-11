# Cybersecurity Auditor Agent

> Multi-agent cybersecurity auditor: ask compliance questions and audit your systems against NIST, CIS, OWASP, MITRE ATT&CK, and CompTIA Security+.

![CI](https://github.com/tohudgins/Cybersecurity-Auditor-Agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Built with](https://img.shields.io/badge/built%20with-LangGraph%20%7C%20LangChain%20%7C%20Streamlit%20%7C%20OpenAI-orange)


A local Streamlit app that puts a cybersecurity GRC analyst behind a chat box. Two modes:

- **Compliance Q&A** — ask any question about NIST CSF, NIST SP 800-53/37/30, CIS Controls v8.1, OWASP ASVS, MITRE ATT&CK, or CompTIA Security+ and get a cited answer pulling directly from the framework PDFs.
- **System auditing** — upload a config file, log sample, internal policy PDF, codebase path, or paste a free-text system description; the agent runs heuristic + LLM checks, scans dependencies with **Trivy** for CVEs, runs **Bandit** for Python SAST, runs **Checkov** for Terraform / Kubernetes IaC scanning, and returns a Markdown audit report with severity-ranked findings tied to specific framework controls.

Every finding is enriched with industry-standard context:

- **CISA KEV** — CVEs in CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog get bumped to `critical` severity with a `[KEV - actively exploited]` badge.
- **MITRE ATT&CK** — each finding is tagged with the relevant [ATT&CK techniques](https://attack.mitre.org/techniques/enterprise/) (e.g., a brute-force log finding → `T1110.001`, an open security group → `T1190`).
- **CVSS v3** — CVE findings carry the NVD base score and vector string, rendered alongside qualitative severity (e.g., `9.8 (Critical)`).
- **OSCAL export** — every audit run is downloadable as [OSCAL Assessment Results JSON](https://pages.nist.gov/OSCAL/reference/latest/assessment-results/), the NIST format that FedRAMP / Trestle / RegScale consume.

---

## Demo

The `examples/` directory ships five deliberately-weak artifacts so anyone can reproduce the demo without writing their own. After running the [Quickstart](#quickstart):

| Upload | What you'll see |
|---|---|
| `examples/sshd_config_weak.conf` | Findings for root SSH login, password auth, empty passwords |
| `examples/Dockerfile_root.txt` | Findings for `:latest` tag, no `USER`, `ADD <url>` |
| `examples/auth_bruteforce.log` | Findings for brute-force pattern + suspicious post-login activity |
| `examples/terraform_open_sg.tf` | Findings for `0.0.0.0/0` ingress, public S3 ACL, unencrypted RDS |
| `examples/policy_minimal.txt` | Pasted into chat: gap report against NIST/CIS policy requirements |

Sample compliance Q&A:

```
You: What does NIST SP 800-53 require for password complexity?
Auditor: NIST SP 800-53 Rev. 5 control IA-5(1) [NIST SP 800-53 Rev. 5, p.214]
         requires that authenticators meet defined composition and complexity
         rules. The companion guidance in SP 800-63B...
```

```
You: [uploads sshd_config with PermitRootLogin yes]
Auditor: # Cybersecurity Audit Report
         Findings count: 1 high, 1 medium

         ## Findings
         ### 1. [HIGH] Root SSH login is enabled
         - Mapped control: CIS Controls v8.1 — 5.4
         - Evidence: PermitRootLogin yes
         - Recommendation: Set `PermitRootLogin no` and require named user
           accounts with sudo.
         ...
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
     (Q&A / summary)          (dispatches to per-kind audit tool;
                              enriches every finding with KEV + ATT&CK)
            │                     │
            └──────────┬──────────┘
                       ▼
                reporting_node  ──►  Markdown report
                       │
                      END
```

The graph is wired in `src/auditor/agents/graph.py`. State (`AuditorState` in `agents/state.py`) carries `messages`, `target_frameworks`, `artifacts`, `findings`, `final_report`, and `route` between nodes.

Each audit tool combines cheap regex heuristics with an LLM call so the obvious issues are caught instantly and the model handles the nuanced reasoning. All tools return the same `Finding` shape (`models.py`), so the reporting agent renders them uniformly.

---

## Supported frameworks

| Framework | Source PDF |
|---|---|
| NIST Cybersecurity Framework 2.0 | `NIST.CSWP.29.pdf` |
| NIST SP 800-53 Rev. 5 (Security & Privacy Controls) | `NIST.SP.800-53r5.pdf` |
| NIST SP 800-37 Rev. 2 (Risk Management Framework) | `NIST.SP.800-37r2.pdf` |
| NIST SP 800-30 Rev. 1 (Risk Assessments) | `nistspecialpublication800-30r1.pdf` |
| CIS Controls v8.1 | `CIS_Controls__v8.1_Guide__2024_06.pdf` |
| OWASP ASVS 4.0.3 | `OWASP Application Security Verification Standard 4.0.3-en.pdf` |
| MITRE ATT&CK Enterprise | `MITRE_ATTACK_Enterprise_11x17.pdf` |
| CompTIA Security+ (SY0-701) | `CompTIA_Security+.pdf` (commercial — see note below) |

> **Note on the CompTIA PDF**: the CompTIA Security+ study guide is commercial copyrighted material and is **not** included in the public repo. To enable that framework locally, place a legally-obtained copy at `data/CompTIA_Security+.pdf` before running `--rebuild`. The other seven framework PDFs are public-domain or open-license and ship in the repo. If you skip the CompTIA PDF, the loader silently omits it.

To add a framework: drop the PDF in `data/`, add an entry to `FRAMEWORK_NAMES` in `src/auditor/ingest/pdf_loader.py`, and re-run `--rebuild`.

---

## Supported audit inputs

| Artifact kind | Examples | Tool |
|---|---|---|
| `text` | Pasted system / architecture description | `tools/audit_text.py` |
| `policy_pdf` | Internal security policy PDF | `tools/audit_policy_pdf.py` |
| `config` | `sshd_config`, `nginx.conf`, `Dockerfile`, `*.tf`, Kubernetes YAML | `tools/audit_config.py` |
| `log` | `auth.log`, syslog, JSON event logs | `tools/audit_logs.py` |
| `codebase` | Local directory path; Trivy scans for known-vulnerable dependencies (CVEs) | `tools/audit_codebase.py` |

---

## Quickstart

```bash
git clone <your-repo-url>
cd "Cybersecurity Auditor Agent"

cp .env.example .env
# edit .env and set OPENAI_API_KEY

pip install -e .[dev]
pre-commit install     # one-time: enables ruff + gitleaks on every commit

# One-time: embed the framework PDFs into the local Chroma vector store
python -m auditor.ingest.frameworks_index --rebuild

# Sanity check
python -m auditor.ingest.frameworks_index --probe "multi-factor authentication"

# Launch the UI
streamlit run app.py
```

Open the printed URL (defaults to `http://localhost:8501`).

---

## Project structure

```
.
├── app.py                          # Streamlit entrypoint
├── pyproject.toml
├── data/                           # Framework PDFs (input)
├── examples/                       # 5 weak artifacts for reproducible demos
├── .github/workflows/ci.yml        # pytest + ruff + gitleaks
├── .pre-commit-config.yaml         # ruff + end-of-file + gitleaks
├── src/auditor/
│   ├── config.py                   # pydantic-settings: model names, paths, k
│   ├── models.py                   # Finding, Artifact
│   ├── ingest/                     # PDF -> chunks -> Chroma
│   ├── retrieval/                  # vector retrieval with framework filtering
│   ├── tools/                      # compliance_qa, framework_summary, audit_*
│   ├── enrichment/                 # CISA KEV lookup + MITRE ATT&CK technique tagging
│   ├── oscal/                      # NIST OSCAL Assessment Results exporter
│   ├── prompts/                    # PromptTemplates kept separate from logic
│   └── agents/                     # supervisor, compliance, audit, reporting + graph wiring
└── tests/                          # pytest smoke tests (LLM + retriever stubbed)
```

---

## Tests

```bash
pytest                              # all smoke tests, no network calls
pytest tests/test_audit_config.py   # one file
```

`tests/conftest.py` monkeypatches the LLM-call helper (`run_findings_chain`) and the retriever globally, so the suite runs without an OpenAI key and never touches the vector store.

The same `pytest` and `ruff check` commands run automatically on every push and pull request via `.github/workflows/ci.yml`. A separate gitleaks job scans the diff for accidentally-committed secrets.

---

## Tech stack

- [LangGraph](https://github.com/langchain-ai/langgraph) — multi-node agent state machine
- [LangChain](https://github.com/langchain-ai/langchain) — retrieval, prompts, structured output
- [ChromaDB](https://github.com/chroma-core/chroma) — local vector store
- [OpenAI](https://platform.openai.com/) — `gpt-5` / `gpt-5-mini` for synthesis, `text-embedding-3-small` for embeddings
- [Streamlit](https://streamlit.io/) — chat UI + file uploader
- [Pydantic](https://docs.pydantic.dev/) — typed `Finding` / `Artifact` models, structured LLM output
- [pypdf](https://github.com/py-pdf/pypdf) — PDF text extraction

---

## External tools

Some audit paths shell out to industry-standard scanners. Install these locally to enable the corresponding audit kind:

- **[Trivy](https://aquasecurity.github.io/trivy/)** — SBOM + CVE scanning for the `codebase` artifact kind. Install:
  - Windows (scoop): `scoop install trivy`
  - Windows (manual): download from https://github.com/aquasecurity/trivy/releases
  - macOS: `brew install trivy`
  - Linux: see https://aquasecurity.github.io/trivy/latest/getting-started/installation/
- **[Checkov](https://www.checkov.io/)** — IaC scanning for Terraform / Kubernetes configs. Replaces the regex heuristics in `audit_config.py` with 1000+ real rules.
  - All platforms: `pip install checkov`
  - Fallback: if Checkov isn't installed, `audit_config` emits an info-level "Checkov not installed" finding and falls back to the regex heuristics, so the demo still works.
- **[Bandit](https://bandit.readthedocs.io/)** — Python static security analysis. Runs as part of `audit_codebase` whenever the scanned path contains `*.py` files.
  - All platforms: `pip install bandit`

The auditor degrades gracefully if any scanner is missing — it surfaces an info-level finding telling you to install the tool, rather than crashing.

---

## Roadmap

Deliberate v1 cuts; happy to revisit:

- **Cross-framework knowledge graph** — Neo4j with `MAPS_TO` / `SIMILAR` relationships between controls in different frameworks.
- **Live cloud-API scanning** — AWS Config / Azure Policy ingestion instead of file uploads.
- **Multi-user persistence** — audit history, RBAC, shareable report links.

---

## License

MIT — see [LICENSE](LICENSE).
