# Cybersecurity Auditor Agent

> A multi-agent GRC analyst behind a chat box: ask compliance questions, audit your systems, and get a control-coverage assessment mapped across NIST, CIS, OWASP, CISA, and MITRE ATT&CK — with OSCAL evidence export.

![CI](https://github.com/tohudgins/Cybersecurity-Auditor-Agent/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Built with](https://img.shields.io/badge/built%20with-LangGraph%20%7C%20LangChain%20%7C%20Streamlit%20%7C%20OpenAI-orange)
<!-- After Streamlit Cloud deploy: [![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://YOUR-APP-URL.streamlit.app) -->

A local Streamlit app with two modes you drive by talking to it:

- **Compliance Q&A** — cited answers grounded in an indexed framework corpus. Hybrid BM25 + vector retrieval routes exact control-ID queries (`AC-2`, `A01:2025`, `API1:2023`) straight to the matching control.
- **System auditing** — say what to scan (`audit ~/myrepo`, `scan https://example.com`, `audit aws:prod`, `image:nginx:1.21`, `audit this machine`) or attach files. The agent plans the scope, runs the right tools, and returns a **control-coverage assessment** — not just a findings list — ranked by risk and tied to framework controls.

Unlike a bare scanner, it assesses controls the way an assessor does: against a full **NIST SP 800-53B baseline** (Low / Moderate / High — the authoritative 149 / 287 / 370-control sets imported from NIST OSCAL), it reports what passed, what failed, and — honestly — what went **unassessed** because no artifact exercised it, with a coverage percentage. Risk is tuned to your system's internet exposure and data sensitivity; findings split into **deterministic** (scanner/heuristic) vs **AI-assisted** evidence; dispositioned findings (accepted-risk / false-positive) move to an auditable **register**; and every run exports as OSCAL Assessment Results + POA&M with severity-based remediation SLAs.

---

## What you can use it for

| If you are… | Run… | You get back |
|---|---|---|
| **GRC analyst** (SOC 2 / ISO 27001 / FedRAMP / PCI) | `audit <systems in scope>` | Coverage against a full **NIST 800-53B baseline** + cross-framework mappings + **OSCAL AR & POA&M** (with remediation SLAs) for your GRC platform |
| **Developer / AppSec** | `audit ~/service-repo` | Dependency CVEs (KEV/EPSS), SAST, IaC/Dockerfile misconfigs, leaked secrets — each tied to CWE → ASVS → NIST, ranked by exploit risk |
| **DevOps / cloud** | `audit aws:prod`, `image:myapp:1.4` | Live cloud-posture failures (Prowler) and image CVEs (Trivy), mapped to NIST controls — a fast "where are we exposed?" pass |
| **Security eng / pentester** | `scan https://staging.example.com` | A Nuclei DAST pass triaged into the same risk model as code and cloud findings |
| **Sysadmin / blue-teamer** | `audit this machine` / `audit user@server` | A Lynis OS-hardening review (SSH, auth, firewall, logging, kernel, packages), per host or over SSH |
| **Learning the standards** | "what does AC-2 require?" | Cited answers from NIST / CIS / OWASP / CISA / MITRE + report-grounded remediation guidance |

**Typical flow:** scope → `audit` each target → read the coverage table → ask follow-ups to remediate the top risks → export OSCAL. It compresses the "run six tools, reconcile output, map to a framework, write it up" grind into one conversation. It's an **assistive** tool, not a replacement for a qualified assessor (see [Limitations](#limitations--scope)).

Example finding (rendered Markdown), showing the enrichment a raw scanner doesn't give you:

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

The `examples/` directory ships deliberately-weak artifacts (`sshd_config_weak.conf`, `auth_bruteforce.log`, `terraform_open_sg.tf`, …) so the demo is reproducible.

---

## Architecture

```
   user input → supervisor ──► routes on whether artifacts are attached
                   │
        ┌──────────┴───────────────┐
        ▼                          ▼
  compliance_node          planning_node → audit_node
  (hybrid BM25+vector       (adaptive scope:  per-kind tool, run concurrently →
   retrieval + cited LLM)    pull adjacent     enrich (ATT&CK + KEV/EPSS + mappings)
        │                    targets in)       → normalize (de-dup + 0–100 risk + rank)
        │                          │           → assess (per-control verdict + coverage)
        └───────────┬──────────────┘
                    ▼
              reporting_node ──► Markdown report: audit plan + remediation diff +
                    │            coverage + control assessment + scope & limitations
                   END           + accepted risks + ranked findings (+ OSCAL AR & POA&M)
```

LangGraph wiring lives in [`agents/graph.py`](src/auditor/agents/graph.py). Key design points:

- **Adaptive scope planning.** Before scanning, the planning node pulls *safe, local, read-only* adjacent targets into the same run (a codebase's Dockerfile/compose images → container-image scans). *Live, credentialed* targets (e.g. a cloud audit inferred from Terraform) are **recommended, never auto-run**. Planning is deterministic (a parser, not an LLM guess) and a no-op when its scanner is absent.
- **Deterministic + AI layers.** Each tool pairs regex/scanner heuristics (the evidentiary backbone) with an LLM call (narrative analysis), returning the same `Finding` shape so the report renders uniformly.
- **Conversational follow-ups.** After an audit, a no-target message (`"explain finding 3"`, `"which controls failed?"`) is answered against the prior report + retrieved framework excerpts, no re-scan needed.
- **Tuned for speed.** Retrieval caches (Chroma + embeddings `lru_cache`d, BM25 index persisted and warmed at boot); LLM calls right-sized to `reasoning_effort="low"`; scanners and artifacts run concurrently in fault-isolated thread pools; KEV/EPSS/ATT&CK catalogs parsed once into in-memory lookups.

---

## Finding enrichment

Every finding is enriched with industry-standard context before rendering:

| Enrichment | Source | What it adds |
|---|---|---|
| **CISA KEV** | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Bumps actively-exploited CVEs to `critical` with a `[KEV]` badge |
| **EPSS** | [FIRST.org EPSS](https://www.first.org/epss/) | Probability + percentile of exploitation in the next 30 days |
| **CVSS v3** | NVD via Trivy | Base score + vector + qualitative severity |
| **MITRE ATT&CK** | Curated rules + [mitre/cti](https://github.com/mitre/cti) STIX bundle | Technique IDs (e.g. brute-force → `T1110.001`) via high-precision rules + phrase matching across ~600 techniques |
| **Cross-framework mappings** | Curated crosswalk + NIST OLIR importer | **Bidirectional** across NIST 800-53, CSF 2.1, CIS v8.1, ISO 27001:2022, PCI DSS v4.0.1, SOC 2 TSC; SAST findings cross a **CWE → ASVS 5.0 → NIST** bridge |
| **Risk score (0–100)** | Severity + CVSS + EPSS + KEV, tuned by scope | Deterministic, explainable priority; internet-facing systems lift exposure controls, sensitive data lifts confidentiality controls |
| **Control assessment** | SP 800-53A model vs **800-53B baseline** | Per-control verdict (Satisfied / Not Satisfied / Partial / Not Assessed) + method (Examine / Test) + honest coverage % against the selected Low/Moderate/High baseline |
| **OSCAL export** | [OSCAL 1.1.2](https://pages.nist.gov/OSCAL/reference/latest/assessment-results/) | **Assessment Results** + **POA&M** JSON, FedRAMP / Trestle / RegScale-ingestible; POA&M items carry owner + severity-based remediation SLA + milestone; all enrichment surfaces as `props` |
| **Accepted-risk register** | Local triage store | Disposition a finding (accepted-risk / false-positive + rationale); it drops from the active assessment but stays in an auditable section |
| **Remediation tracking** | Run-to-run diff over local history | Re-audit a target → **Remediation Progress** section: resolved / new / regressed / persisting + an open-issue delta (`7 → 4 ⬇`) |

---

## Supported audit inputs

| Kind | Examples | Tooling |
|---|---|---|
| `text` | Pasted system / architecture description | LLM + retrieval |
| `policy_pdf` | Internal security policy PDF | LLM + retrieval, gap report |
| `config` | `sshd_config`, `nginx.conf`, `Dockerfile` (hadolint), `*.tf` / K8s YAML (Checkov) | regex heuristics + linters |
| `log` | `auth.log`, syslog, access logs — brute force, post-compromise login, web attacks, log tampering | deterministic heuristics + LLM |
| `codebase` | Local dir — Trivy (CVEs + IaC misconfig) + Semgrep + Bandit + gitleaks (regex fallback) | concurrent scanners |
| `cloud_account` | `aws[:profile]`, `gcp`, `azure` — live CSPM via Prowler (your read-only creds) | Prowler |
| `image_ref` | `nginx:1.21` — `trivy image` for CVEs + misconfigs | Trivy |
| `target_url` | A URL — live web DAST via Nuclei *(authorized targets only)* | Nuclei |
| `host` | `localhost` / `user@server` — OS hardening via Lynis (local or over SSH) | Lynis |

Targets come from the sidebar **or** the chat message — `intake.parse_targets()` detects paths, URLs, cloud accounts, images, and hosts (explicit `path:`/`url:`/`image:`/`cloud:`/`host:` prefixes always honored).

---

## Quickstart

```bash
git clone <your-repo-url> && cd Cybersecurity-Auditor-Agent
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
cp .env.example .env                                 # set OPENAI_API_KEY
pip install -e ".[dev,scanners]"                     # quotes required on zsh; bundles Semgrep/Bandit/Checkov

# One-time: fetch OWASP markdown + embed all sources into Chroma (~2-3 min)
python -m auditor.ingest.frameworks_index --fetch-web --rebuild

streamlit run app.py                                 # opens http://localhost:8501
```

Pick the **control baseline** (NIST 800-53B Low/Moderate/High) and declare **scope** (internet-facing, data sensitivity) in the sidebar's *Engagement scope* panel — these set the coverage denominator and tune risk. Refresh the baselines from authoritative NIST OSCAL anytime with `python -m auditor.ingest.baseline_import --fetch --write`.

### Docker (full scanner set: Trivy, Semgrep, Bandit, gitleaks, Checkov, hadolint)

```bash
export OPENAI_API_KEY=sk-...        # Windows: $env:OPENAI_API_KEY="sk-..."
docker compose up --build
```

Named volumes persist the Chroma embeddings, the KEV/EPSS/ATT&CK caches + SQLite history, and the Semgrep rule cache across restarts. The compose file mounts your `$HOME` read-only so you can scan real local paths; narrow that mount in `docker-compose.yml` if you prefer. See [`docker/`](docker/) for the image build.

> **Shared deployments:** set `AUDITOR_ALLOW_LOCAL_TARGETS=false` so users can't read or scan the host filesystem/OS through the chat.

---

## Supported frameworks

**Control catalogs** (per-control chunking, exact-ID retrieval): NIST CSF 2.1, NIST SP 800-53 Rev. 5, SP 800-171 Rev. 3, SP 800-218 (SSDF), CIS Controls v8.1.

**Process / reference** (generic chunking): NIST SP 800-37 r2 (RMF), 800-30 r1, 800-61 r3, IR 7298 r3 (glossary), CISA Zero Trust Maturity Model v2, MITRE ATT&CK Enterprise.

**Web-fetched markdown** (cached into `data/web/` on `--fetch-web`): OWASP Top 10 2025, ASVS 5.0, API Security Top 10 2023, Cheat Sheet Series — all CC-BY-SA 4.0.

PDFs go in `data/` (free from NIST CSRC, CIS, and CISA); missing ones are skipped. See [CLAUDE.md](CLAUDE.md) for the per-file list and how to add a framework or mapping. The crosswalk ([`control_mappings.json`](data/mappings/control_mappings.json)) is data-driven — no code change to extend — and can be augmented from NIST's official OLIR exports via `python -m auditor.ingest.olir_import --fetch --merge`.

---

## Security posture

The agent shells out to real scanners, so it treats its own inputs as untrusted:

- **No shell** — external tools run via `subprocess.run([...])` argument lists, never `shell=True`.
- **Argument-injection hardening** — SSH host specs, image refs, and cloud profiles are validated and may not begin with `-` (blocks `-oProxyCommand=…`-style RCE); image refs pass after a `--` separator.
- **Filesystem/OS gating** — `AUDITOR_ALLOW_LOCAL_TARGETS=false` disables codebase/host/chat-file targets for shared hosting; chat-referenced files are size-capped.
- **Read-only by design** — scanners run in read-only modes; cloud auditing uses your existing read-only SDK credentials, which the app never handles or stores.
- **Auto-runs only safe local scans** — scope planning auto-expands *only* into local, read-only assessments. Anything touching a live account, host, or external service is **recommended, never auto-launched** — it needs your explicit authorization.
- **Graceful degradation** — a missing scanner becomes an info finding, never a crash.

Only audit systems you are authorized to assess.

---

## Limitations & scope

Stated plainly, because a GRC tool that overstates its rigor is worse than one that doesn't:

- **Baselines are complete; cross-framework mappings are informative.** Coverage is measured against the authoritative 800-53B baselines (imported from NIST OSCAL). The *cross-framework crosswalk* (CSF/CIS/ISO/PCI/SOC 2), however, covers only the ~40 anchor controls + ~35 CWEs this agent exercises — confirm cross-standard compliance decisions against the official source.
- **Technical controls only.** Automated scanning tests configuration and code; it cannot examine governance evidence or interview personnel, so management/operational control families (PM, PS, PE, AT, …) are reported *not-assessed* and flagged in the report's **Scope & Limitations** section. This is a technical-control assessment, not a full audit.
- **LLM findings are assistive.** The deterministic scanners + heuristics are the evidentiary backbone; the LLM layer adds narrative and can produce false positives/negatives. Triage them (accepted-risk / false-positive register), don't auto-accept.
- **On-demand, not continuous.** A deliberate design choice: it assesses what you point it at, when you run it. The run-to-run diff tracks posture over time, but there's no scheduling or unattended evidence collection — the OSCAL export exists to feed a GRC system that does.
- **Live scanning needs prerequisites + authorization.** Prowler needs read-only cloud creds; Nuclei must target only systems you may test; Lynis needs SSH + Lynis on the host.
- **Single-user, local-first.** Audit history is a local SQLite DB — no multi-tenant RBAC yet.

---

## Tech stack

**[LangGraph](https://github.com/langchain-ai/langgraph)** (agent state machine) · **[LangChain](https://github.com/langchain-ai/langchain)** (retrieval/prompts/structured output) · **[ChromaDB](https://github.com/chroma-core/chroma)** + **[rank-bm25](https://github.com/dorianbrown/rank_bm25)** (hybrid retrieval via RRF) · **[OpenAI](https://platform.openai.com/)** (`gpt-5` / `gpt-5-mini`, `text-embedding-3-small`) · **[Streamlit](https://streamlit.io/)** (UI) · **[Pydantic](https://docs.pydantic.dev/)** (typed models) · **[pypdf](https://github.com/py-pdf/pypdf)**.

### External scanners (auto-degraded if missing)

| Scanner | Audit kind | Install |
|---|---|---|
| [Trivy](https://aquasecurity.github.io/trivy/) | `codebase` / `image_ref` (CVEs + IaC misconfig) | `brew install trivy` |
| [Semgrep](https://semgrep.dev/) | `codebase` (multi-language SAST) | `pip install semgrep` |
| [Bandit](https://bandit.readthedocs.io/) | `codebase` (Python SAST) | `pip install bandit` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | `codebase` (secrets) | `brew install gitleaks` — regex fallback if missing |
| [Checkov](https://www.checkov.io/) | `config` (Terraform / K8s) | `pip install checkov` |
| [hadolint](https://github.com/hadolint/hadolint) | `config` (Dockerfile) | `brew install hadolint` — regex fallback if missing |
| [Prowler](https://github.com/prowler-cloud/prowler) | `cloud_account` (live CSPM) | `pipx install prowler --python python3.12` (isolate it — a plain `pip install` into the venv pins pydantic v1 and breaks the stack) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | `target_url` (live DAST) | `brew install nuclei` |
| [Lynis](https://github.com/CISOfy/lynis) | `host` (OS hardening) | `brew install lynis` / `apt install lynis` |

A missing scanner emits an info finding with the install hint and falls back to regex heuristics — the demo still runs.

---

## Tests

```bash
pytest          # full suite, fully offline (LLM, retriever, KEV, EPSS, STIX all stubbed — no API key)
```

250+ tests. CI runs `pytest` + `ruff` on Python 3.10/3.11/3.12 plus a gitleaks job on every push and PR. Architecture, module layout, and contribution conventions are documented in [CLAUDE.md](CLAUDE.md).

---

## License

MIT — see [LICENSE](LICENSE).
