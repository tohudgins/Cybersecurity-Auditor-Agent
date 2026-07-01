# Cybersecurity Auditor Agent

> A local, chat-driven GRC auditor. Scan systems, assess organizational controls, and answer compliance questions — grounded in **56 indexed frameworks**, mapped to real controls, and exported as **OSCAL**. An *accelerator* for security work, not a replacement for a qualified assessor.

![CI](https://github.com/tohudgins/Cybersecurity-Auditor-Agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Built with](https://img.shields.io/badge/built%20with-LangGraph%20%7C%20LangChain%20%7C%20Streamlit%20%7C%20OpenAI-orange)

It turns *"run nine scanners, reconcile the output, map it to a framework, and write it up"* into one conversation. A Streamlit app with **three ways to audit**:

- 🔍 **Technical audit** — point it at a repo, config, container image, cloud account, web URL, or host (`audit ~/myrepo`, `scan https://x`, `audit aws:prod`, or attach files with 📎). It runs the right scanners and returns a **control-coverage assessment** — what passed, what failed, and honestly what went *unassessed* — ranked by risk and tied to controls.
- 🗣️ **Advisory audit** — assess the *organizational / process* controls scanners can't (`assess our incident response process`). Get an auditor's worksheet (objective, interview questions, evidence, common gaps); reply with your answers and it produces an **interview-method assessment** (satisfied / partial / not-satisfied per control) that folds into the coverage.
- 💬 **Compliance Q&A** — cited, multi-turn answers grounded in the corpus. Framework-scoped retrieval routes "SOC 2 CC6.1" to SOC 2 and "AC-2" to the exact control.

**More than a scanner.** It assesses controls the way an assessor does — against a real **NIST SP 800-53B baseline** (or CIS / PCI / CSF / SOC 2 / CMMC) with an honest coverage %, plus a **scope-completeness** check against your declared asset inventory (SSP-lite). Findings are risk-scored 0–100 (tuned to internet exposure + data sensitivity), split into **deterministic vs AI-assisted** evidence, mapped across frameworks (NIST ↔ CSF / CIS / ISO / PCI / SOC 2, and CWE → ASVS → NIST for code), and exported as **OSCAL Assessment Results + POA&M** with remediation SLAs. Accepted risks go to an auditable register; re-audits show a remediation diff.

---

## Who it's for

| If you are… | Ask… | You get back |
|---|---|---|
| **GRC analyst** (SOC 2 / PCI / HIPAA / CMMC / FedRAMP) | `audit <systems in scope>` | Coverage against a real baseline + cross-framework mappings + **OSCAL AR & POA&M** for your GRC platform |
| **Developer / AppSec** | `audit ~/service-repo` | Dependency CVEs (KEV/EPSS), SAST, IaC/Dockerfile misconfigs, leaked secrets — each tied to CWE → ASVS → NIST, ranked by exploit risk |
| **DevOps / cloud** | `audit aws:prod`, `image:myapp:1.4` | Live cloud-posture failures (Prowler) + image CVEs (Trivy), mapped to controls — a fast "where are we exposed?" pass |
| **Security eng / pentester** | `scan https://staging.example.com` | A Nuclei DAST pass triaged into the same risk model as code and cloud findings |
| **Sysadmin / blue-teamer** | `audit this machine` / `audit user@server` | A Lynis OS-hardening review (SSH, auth, firewall, logging, kernel, packages) |
| **Learning the standards** | `what does AC-2 require?` | Cited answers across NIST / CIS / OWASP / PCI / HIPAA / SOC 2 / CMMC / MITRE |

**Typical flow:** pick the audit standard → attach or name targets → read the coverage table → ask follow-ups or run an advisory assessment → export OSCAL. ⚡ **Fast mode** skips the AI layer for a near-instant scanner-only pass (~3s).

Example finding (rendered Markdown) — the enrichment a raw scanner doesn't give you:

```
### 2. [KEV - actively exploited] [CRITICAL] log4j 2.14.1: CVE-2021-44228
- Risk score: 100 / 100
- Mapped control: NIST SP 800-53 Rev. 5 — SI-2
- Cross-framework: NIST CSF 2.1: ID.RA-01; CIS Controls v8.1: 7.1, 7.4
- CVSS v3 base score: 10.0 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- EPSS: 0.9743 (top 0.0% most likely to be exploited)
- MITRE ATT&CK: T1190
- Detection: scanner (deterministic)
```

The `examples/` directory ships deliberately-weak artifacts (`sshd_config_weak.conf`, `terraform_open_sg.tf`, …) so the demo is reproducible.

---

## Quickstart

```bash
git clone https://github.com/tohudgins/Cybersecurity-Auditor-Agent && cd Cybersecurity-Auditor-Agent
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
cp .env.example .env                                 # add your OPENAI_API_KEY
pip install -e ".[dev,scanners]"                     # core + tests + Bandit (quote for zsh)

# One-time: fetch OWASP sources + embed the corpus into Chroma (~2–3 min)
python -m auditor.ingest.frameworks_index --fetch-web --rebuild

streamlit run app.py                                 # http://localhost:8501
```

Then install any [external scanners](#external-scanners) you want — Trivy / Nuclei / gitleaks / hadolint / Lynis via `brew`, and **Semgrep / Checkov / Prowler via `pipx`** (they're heavy apps whose pins conflict with the venv). Each **auto-degrades** to a regex fallback or an info finding if absent, so the app runs without them.

In the app: attach files with **📎** in the chat, pick the **audit standard**, and optionally fill the **System profile (SSP)** under *Audit settings* for the scope-completeness check.

### Docker (bundles Trivy, Semgrep, Checkov, gitleaks, hadolint, Bandit)

```bash
export OPENAI_API_KEY=sk-...        # Windows: $env:OPENAI_API_KEY="sk-..."
docker compose up --build
```

Named volumes persist the Chroma embeddings, KEV/EPSS/ATT&CK caches, SQLite history, and Semgrep rule cache. `$HOME` is mounted read-only so you can scan real local paths (narrow it in `docker-compose.yml` if you prefer).

> **Shared/hosted deployments:** set `AUDITOR_ALLOW_LOCAL_TARGETS=false` so users can't read or scan the host filesystem/OS through the chat.

---

## How it works

```
   your message → supervisor ──► routes on whether a target is present
                     │
        ┌────────────┼─────────────────────────┐
        ▼            ▼                           ▼
  Compliance Q&A   Advisory audit        planning → audit → report
  (framework-scoped (RAG worksheet /     (per-kind scanners, concurrent →
   hybrid retrieval  interview-method     enrich: ATT&CK + KEV/EPSS + risk +
   + reranker,        assessment)          cross-framework mappings →
   multi-turn, cited)                      per-control coverage + scope check →
                                           Markdown report + OSCAL AR & POA&M)
```

- **Hybrid, scoped retrieval.** Chroma vector search + BM25, fused via RRF, re-ranked, and **auto-scoped** to the framework a query names — so at 56 frameworks a "PCI" question gets a PCI answer. Runs concurrently (~240 ms).
- **Deterministic + AI layers.** Every tool pairs regex/scanner heuristics (the evidentiary backbone) with an LLM pass (narrative), returning one `Finding` shape. The report labels each as scanner/heuristic vs AI-assisted.
- **Adaptive scope planning.** Safe, local, read-only adjacencies are pulled into the run (a Dockerfile's base image → an image scan); live/credentialed targets are *recommended, never auto-run*.
- **Tuned for speed.** Concurrent scanners + retrieval, cached indices warmed at boot, `reasoning_effort="low"`, and tiered models (`gpt-5.5` for Q&A, `gpt-5.4-mini` for structured audit/advisory tasks).

LangGraph wiring lives in [`agents/graph.py`](src/auditor/agents/graph.py); architecture and module layout are in [CLAUDE.md](CLAUDE.md).

---

## Audit inputs & enrichment

| Input | Tooling |
|---|---|
| `config` — sshd/nginx, Dockerfile (hadolint), Terraform/K8s (Checkov) | regex heuristics + linters |
| `log` — auth/syslog/access (brute force, post-compromise, web attacks, tampering) | deterministic heuristics + LLM |
| `codebase` — a local dir | Trivy (CVEs + IaC) + Semgrep + Bandit + gitleaks, concurrent |
| `image_ref` — `nginx:1.21` | `trivy image` (CVEs + misconfig) |
| `cloud_account` — `aws[:profile]` / `gcp` / `azure` | Prowler (your read-only creds) |
| `target_url` — a URL *(authorized only)* | Nuclei DAST |
| `host` — `localhost` / `user@server` | Lynis OS hardening |
| `policy_pdf` / `text` — a policy or system description | LLM + retrieval |

Each finding is enriched with **CISA KEV**, **EPSS**, **CVSS v3**, **MITRE ATT&CK**, a **0–100 risk score** (scope-tuned), **cross-framework mappings**, and a **per-control assessment** (Satisfied / Not Satisfied / Partial / Not Assessed × Test / Examine / Interview). Every run exports **OSCAL 1.1.2** Assessment Results + POA&M (owners, severity-based SLAs, milestones).

---

## Frameworks & corpus (~40k chunks, 56 frameworks)

- **Control catalogs / assessment procedures:** NIST CSF 2.1, SP 800-53 r5 **+ 800-53A** (assessment), 800-171 r3 **+ 800-171A**, 800-172 / 172A, 800-218 (SSDF), CIS Controls v8.1.
- **Regulatory / audit criteria:** HIPAA Security Rule (45 CFR 164), PCI DSS v4.0.1, SOC 2 Trust Services Criteria, CMMC 2.0 L1/L2/L3.
- **17 CIS Benchmarks:** AWS/Azure/GCP/M365/Google Workspace, Windows 10/11/Server, Ubuntu, macOS, iPadOS, Docker, Kubernetes, PostgreSQL, VMware ESXi, Chrome.
- **Guidance:** NIST SP 800-30/34/37/40/61/63A-B-C/82/92/115/128/137/161/190/207, AI 100-1 (AI RMF), CISA ZTMM, MITRE ATT&CK.
- **OWASP** (web markdown): Top 10 2025, ASVS 5.0, API Top 10 2023, Cheat Sheets.

**Selectable audit standard:** NIST 800-53B is assessed directly; CIS / PCI / CSF / SOC 2 are assessed by projecting findings through the NIST crosswalk (coverage bounded by mapping completeness, stated in the report). Refresh the authoritative baselines anytime: `python -m auditor.ingest.baseline_import --fetch --write`.

> **Licensing:** NIST/US-gov, HIPAA/CFR, and CMMC are public-domain and included. **CIS Benchmarks, PCI DSS, and SOC 2 TSC are licensed** — drop your own copies in `data/` (they're `.gitignore`d, indexed locally, never redistributed). ISO 27001/27002 is copyrighted and can't be indexed — findings still map to it via the crosswalk, and the tool says so when a framework's text isn't indexed.

---

## Security posture

The agent shells out to real scanners, so it treats its own inputs as untrusted:

- **No shell** — tools run via `subprocess.run([...])` argument lists, never `shell=True`.
- **Argument-injection hardening** — SSH host specs, image refs, and cloud profiles are validated and may not begin with `-`; image refs pass after `--`.
- **Filesystem/OS gating** — `AUDITOR_ALLOW_LOCAL_TARGETS=false` disables codebase/host/chat-file targets for shared hosting; chat files are size-capped.
- **Read-only by design** — scanners run read-only; cloud auditing uses your existing read-only credentials, which the app never stores.
- **Only safe local scans auto-run** — anything touching a live account/host/service is recommended, never auto-launched.

Only audit systems you are authorized to assess.

---

## Limitations

Stated plainly — a GRC tool that overstates its rigor is worse than one that doesn't:

- **An accelerator, not an audit of record.** It gets *some* of the work done fast; a qualified assessor validates and signs.
- **Technical + interview, not full evidence sampling.** Scanners test config/code; the advisory path examines/interviews from your stated practices. It doesn't collect evidence over a period or sample populations.
- **LLM findings are assistive** — deterministic scanners are the backbone; triage AI-assisted findings (there's an accepted-risk/false-positive register), don't auto-accept.
- **Point-in-time, not continuous** — a deliberate choice. The run-to-run diff tracks posture; OSCAL export feeds a system that does continuous monitoring.
- **Cross-framework mappings are informative** (curated crosswalk, ~40 anchor controls); confirm cross-standard decisions against the source.
- **Single-user, local-first** — history is a local SQLite DB, no multi-tenant RBAC.

---

## Tech stack

**[LangGraph](https://github.com/langchain-ai/langgraph)** (agent state machine) · **[LangChain](https://github.com/langchain-ai/langchain)** · **[ChromaDB](https://github.com/chroma-core/chroma)** + **[rank-bm25](https://github.com/dorianbrown/rank_bm25)** (hybrid retrieval via RRF) · **[OpenAI](https://platform.openai.com/)** (`gpt-5.5` / `gpt-5.4-mini`, `text-embedding-3-small`; all `.env`-overridable) · **[Streamlit](https://streamlit.io/)** · **[Pydantic](https://docs.pydantic.dev/)**.

### External scanners

| Scanner | Kind | Install |
|---|---|---|
| [Trivy](https://aquasecurity.github.io/trivy/) | `codebase` / `image_ref` | `brew install trivy` |
| [Semgrep](https://semgrep.dev/) | `codebase` (SAST) | `pipx install semgrep` |
| [Bandit](https://bandit.readthedocs.io/) | `codebase` (Python SAST) | bundled in `.[scanners]` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | `codebase` (secrets) | `brew install gitleaks` |
| [Checkov](https://www.checkov.io/) | `config` (Terraform/K8s) | `pipx install checkov` |
| [hadolint](https://github.com/hadolint/hadolint) | `config` (Dockerfile) | `brew install hadolint` |
| [Prowler](https://github.com/prowler-cloud/prowler) | `cloud_account` (CSPM) | `pipx install prowler --python python3.12` |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | `target_url` (DAST) | `brew install nuclei` |
| [Lynis](https://github.com/CISOfy/lynis) | `host` (hardening) | `brew install lynis` / `apt install lynis` |

Semgrep, Checkov, and Prowler are **pipx-isolated** (their dependency pins conflict with the app's stack); each is only ever called as a CLI. Any missing scanner emits an info finding and falls back to regex heuristics.

---

## Tests

```bash
pytest          # ~290 tests, fully offline (LLM, retrieval, KEV, EPSS, STIX stubbed — no API key)
```

CI runs `pytest` + `ruff` on Python 3.10 / 3.11 / 3.12 plus a gitleaks job on every push and PR. See [CLAUDE.md](CLAUDE.md) for architecture, module layout, and how to add a framework, mapping, or audit tool.

## License

MIT — see [LICENSE](LICENSE).
