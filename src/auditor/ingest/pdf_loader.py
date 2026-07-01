"""PDF loading + control-aware chunking.

For control catalogs (NIST 800-53, CIS Controls, OWASP ASVS, NIST 800-171,
NIST CSF, NIST 800-218 SSDF, OWASP Top 10), we split text on control-ID
boundaries and stamp each chunk with `control_id` metadata. That metadata
unlocks two retrieval modes:

  1. Exact-ID lookup ("what does NIST AC-2 say?") via metadata filter.
  2. Sharper BM25 / vector hits — a chunk titled "AC-2 ACCOUNT MANAGEMENT"
     has a much stronger token signal than a half-page that mentions AC-2
     in passing.

Narrative documents (800-30, 800-37, 800-61, CISA ZTM, NIST IR 7298 glossary)
fall back to the generic recursive splitter.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from auditor.config import settings

FRAMEWORK_NAMES: dict[str, str] = {
    # ── Control catalogs / frameworks (per-control chunking where an ID regex exists) ──
    "CIS_Controls_v8.1_Guide.pdf": "CIS Controls v8.1",
    "NIST.SP.800-53r5.pdf": "NIST SP 800-53 Rev. 5",
    "NIST.SP.800-53Ar5.pdf": "NIST SP 800-53A Rev. 5 (Assessment Procedures)",
    "NIST.SP.800-171r3.pdf": "NIST SP 800-171 Rev. 3",
    "NIST.SP.800-171Ar3.pdf": "NIST SP 800-171A Rev. 3 (Assessment Procedures)",
    "NIST.SP.800-172.pdf": "NIST SP 800-172 (Enhanced Security Requirements for CUI)",
    "NIST.SP.800-172A.pdf": "NIST SP 800-172A (Enhanced Requirements Assessment)",
    "NIST.CSWP.30.pdf": "NIST Cybersecurity Framework 2.1",
    "NIST.SP.800-218.pdf": "NIST SP 800-218 (SSDF)",
    # OWASP ASVS 5.0 is sourced from GitHub markdown (see web_fetcher.py).
    # ── Regulatory / audit criteria (per-section chunking) ──
    "HIPAA-45-CFR-164.pdf": "HIPAA Security Rule (45 CFR Part 164)",
    # PCI DSS + SOC 2 TSC are licensed — user-supplied, gitignored (not redistributed).
    "PCI-DSS-v4_0_1.pdf": "PCI DSS v4.0.1",
    "AICPA_Trust_Services_Criteria_2017-2022.pdf": "SOC 2 Trust Services Criteria",
    "GDPR-Regulation-2016-679.pdf": "GDPR (Regulation (EU) 2016/679)",
    # ── CMMC assessment guides (DoD, public domain) ──
    "CMMC_Assessment_Guide_L1.pdf": "CMMC 2.0 Level 1 (Assessment Guide)",
    "CMMC_Assessment_Guide_L2.pdf": "CMMC 2.0 Level 2 (Assessment Guide)",
    "CMMC_Assessment_Guide_L3.pdf": "CMMC 2.0 Level 3 (Assessment Guide)",
    # ── Process / narrative documents (generic chunking) ──
    "NIST.SP.800-30r1.pdf": "NIST SP 800-30 Rev. 1",
    "NIST.SP.800-37r2.pdf": "NIST SP 800-37 Rev. 2 (RMF)",
    "NIST.SP.800-61r3.pdf": "NIST SP 800-61 Rev. 3 (Incident Response)",
    "NIST.SP.800-63a.pdf": "NIST SP 800-63A (Identity Proofing and Enrollment)",
    "NIST.SP.800-63b.pdf": "NIST SP 800-63B (Digital Identity / Authentication)",
    "NIST.SP.800-63c.pdf": "NIST SP 800-63C (Federation and Assertions)",
    "NIST.SP.800-207.pdf": "NIST SP 800-207 (Zero Trust Architecture)",
    "NIST.SP.800-115.pdf": "NIST SP 800-115 (Security Testing and Assessment)",
    "NIST.SP.800-128.pdf": "NIST SP 800-128 (Security-Focused Configuration Management)",
    "NIST.SP.800-190.pdf": "NIST SP 800-190 (Application Container Security)",
    "NIST.SP.800-82r3.pdf": "NIST SP 800-82 Rev. 3 (OT / ICS Security)",
    "NIST.SP.800-40r4.pdf": "NIST SP 800-40 Rev. 4 (Enterprise Patch Management)",
    "NIST.SP.800-161r1.pdf": "NIST SP 800-161 Rev. 1 (Supply Chain Risk Management)",
    "NIST.SP.800-137.pdf": "NIST SP 800-137 (Information Security Continuous Monitoring)",
    "NIST.SP.800-92.pdf": "NIST SP 800-92 (Log Management)",
    "NIST.SP.800-34r1.pdf": "NIST SP 800-34 Rev. 1 (Contingency Planning)",
    "NIST.AI.100-1-RMF.pdf": "NIST AI 100-1 (AI Risk Management Framework)",
    "CISA_Zero_Trust_Maturity_Model_v2.pdf": "CISA Zero Trust Maturity Model v2",
    "NIST.IR.7298r3.pdf": "NIST IR 7298 Rev. 3 (Glossary)",
    # Adversary reference
    "MITRE_ATTACK_Enterprise.pdf": "MITRE ATT&CK Enterprise",
}

# Regex that detects a control-ID header (matched against the start of a line
# via re.MULTILINE). Only frameworks listed here get per-control chunking.
_CONTROL_PATTERNS: dict[str, re.Pattern[str]] = {
    "NIST SP 800-53 Rev. 5": re.compile(r"^\s*([A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?)\s", re.MULTILINE),
    # 800-53A assessment procedures are headed by the same control IDs, so
    # per-control chunking lets a query hit the exact assessment objective.
    "NIST SP 800-53A Rev. 5 (Assessment Procedures)": re.compile(
        r"^\s*([A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?)\s", re.MULTILINE
    ),
    # 800-171 r3 / 171A r3 use the zero-padded "03.01.04" form (assessment
    # objectives are "A.03.01.04"); older text used "3.1.1". Match both.
    "NIST SP 800-171 Rev. 3": re.compile(r"^\s*((?:A\.)?0?3\.\d{1,2}\.\d{1,2})\b", re.MULTILINE),
    "NIST SP 800-171A Rev. 3 (Assessment Procedures)": re.compile(
        r"^\s*((?:A\.)?0?3\.\d{1,2}\.\d{1,2})\b", re.MULTILINE
    ),
    "NIST Cybersecurity Framework 2.1": re.compile(r"^\s*([A-Z]{2}\.[A-Z]{2}-\d{2})\b", re.MULTILINE),
    "NIST SP 800-218 (SSDF)": re.compile(r"^\s*((?:PO|PS|PW|RV)\.\d+\.\d+)\b", re.MULTILINE),
    "CIS Controls v8.1": re.compile(r"^\s*(\d{1,2}\.\d{1,2})\s+[A-Z]", re.MULTILINE),
    # HIPAA Security/Privacy Rule sections, e.g. "§ 164.308" / "164.312".
    "HIPAA Security Rule (45 CFR Part 164)": re.compile(
        r"^\s*§?\s*(164\.\d{3})\b", re.MULTILINE
    ),
    # PCI DSS requirements, e.g. "8.3.1" (sub-requirement) or "8.3".
    "PCI DSS v4.0.1": re.compile(r"^\s*(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b", re.MULTILINE),
    # SOC 2 Trust Services Criteria, e.g. "CC6.1", "A1.2", "PI1.4", "P3.1".
    "SOC 2 Trust Services Criteria": re.compile(
        r"^\s*((?:CC|PI|[ACP])\d\.\d+)\b", re.MULTILINE
    ),
    # 800-172 / 172A enhanced CUI requirements share the 800-171 zero-padded form
    # (e.g. "03.01.01e" / "A.03.01.01e").
    "NIST SP 800-172 (Enhanced Security Requirements for CUI)": re.compile(
        r"^\s*((?:A\.)?0?3\.\d{1,2}\.\d{1,2}e?)\b", re.MULTILINE
    ),
    "NIST SP 800-172A (Enhanced Requirements Assessment)": re.compile(
        r"^\s*((?:A\.)?0?3\.\d{1,2}\.\d{1,2}e?)\b", re.MULTILINE
    ),
    # ASVS 5.0 markdown uses table rows with bold IDs like **1.2.1** and
    # gets generic chapter-level chunking instead, so no per-control regex.
    # OWASP Top 10 markdowns lead each risk with a level-1 heading like
    # "# A01:2025 – Broken Access Control". Anchor on the heading to avoid
    # false matches when a body paragraph cross-references another risk.
    "OWASP Top 10 2025": re.compile(r"^#\s+(A\d{2}:2025)\b", re.MULTILINE),
    # OWASP API Security Top 10 uses "API1:2023" through "API10:2023".
    "OWASP API Security Top 10 2023": re.compile(r"^#\s+(API\d{1,2}:2023)\b", re.MULTILINE),
}

# Min number of control-ID hits before we trust the pattern (avoid splitting
# narrative docs that happen to mention "AC-2" once).
_MIN_CONTROL_HITS = 8

# Page-marker sentinels we inject before chunking so we can recover the page
# number a control falls on. Both code points are Unicode separators that will
# never appear in real PDF text.
_PAGE_OPEN = "␟"
_PAGE_CLOSE = "␞"
_PAGE_RE = re.compile(re.escape(_PAGE_OPEN) + r"(\d+)" + re.escape(_PAGE_CLOSE))


def framework_for(filename: str) -> str:
    if filename in FRAMEWORK_NAMES:
        return FRAMEWORK_NAMES[filename]
    # CIS Benchmarks are numerous and versioned; derive a clean label from the
    # filename instead of hardcoding each (new benchmarks then "just work").
    # "CIS_Amazon_Web_Services_Foundations_Benchmark_v7.0.0.pdf"
    #   -> "CIS Amazon Web Services Foundations Benchmark v7.0.0"
    if filename.startswith("CIS_") and "Benchmark" in filename:
        return Path(filename).stem.replace("_", " ")
    return Path(filename).stem


def load_pdf_pages(pdf_path: Path) -> list[Document]:
    """One Document per page so chunking preserves accurate page numbers."""
    reader = PdfReader(str(pdf_path))
    framework = framework_for(pdf_path.name)
    pages: list[Document] = []
    for page_idx, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        if not text.strip():
            continue
        pages.append(
            Document(
                page_content=text,
                metadata={
                    "framework": framework,
                    "source": pdf_path.name,
                    "page": page_idx,
                },
            )
        )
    return pages


def load_all_pdfs(directory: Path | None = None) -> list[Document]:
    """Recursively load every PDF under *directory* (data/ is organized into
    nist/ · standards/ · regulatory/ · benchmarks/ subfolders). The framework
    label is resolved by *basename* (see ``framework_for``), so the folder a PDF
    lives in doesn't affect its label. The ``web/`` subtree holds markdown only."""
    directory = directory or settings.data_dir
    pdfs = sorted(
        p for p in directory.rglob("*.pdf")
        if p.suffix.lower() == ".pdf" and "web" not in p.relative_to(directory).parts
    )
    pages: list[Document] = []
    for pdf in pdfs:
        pages.extend(load_pdf_pages(pdf))
    return pages


def load_markdown_dir(web_dir: Path) -> list[Document]:
    """Load every .md file under data/web/<source>/. Framework label is taken
    from the source-directory name via web_fetcher.framework_for_dir().
    """
    # Local import to keep web_fetcher optional at import time.
    from auditor.ingest.web_fetcher import framework_for_dir

    docs: list[Document] = []
    if not web_dir.exists():
        return docs
    for md in sorted(web_dir.rglob("*.md")):
        rel_parts = md.relative_to(web_dir).parts
        if len(rel_parts) < 2:
            # File sitting at the top of data/web/ — no source directory.
            continue
        framework = framework_for_dir(rel_parts[0])
        if framework is None:
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            continue
        docs.append(
            Document(
                page_content=text,
                metadata={
                    "framework": framework,
                    "source": md.name,
                    "page": 1,  # markdown has no pages; metadata kept stable
                },
            )
        )
    return docs


def load_all_documents(directory: Path | None = None) -> list[Document]:
    """Load PDFs from `data/` and markdown from `data/web/<source>/`."""
    directory = directory or settings.data_dir
    docs = load_all_pdfs(directory)
    docs.extend(load_markdown_dir(directory / "web"))
    return docs


def _build_blob_with_page_markers(pages: list[Document]) -> str:
    """Concatenate page text, prefixing each page with a recoverable marker."""
    parts: list[str] = []
    for p in pages:
        parts.append(f"{_PAGE_OPEN}{p.metadata['page']}{_PAGE_CLOSE}")
        parts.append(p.page_content)
    return "\n".join(parts)


def _page_at(blob: str, offset: int, fallback: int) -> int:
    """Find the page number of the marker most recently preceding `offset`."""
    page = None
    for pm in _PAGE_RE.finditer(blob, 0, offset + 50):
        page = int(pm.group(1))
    return page if page is not None else fallback


def _strip_page_markers(text: str) -> str:
    return _PAGE_RE.sub("", text)


def _split_by_controls(pages: list[Document]) -> list[Document] | None:
    """If the first page's framework is a known catalog AND the pattern matches
    enough control headers, return per-control chunks. Otherwise return None
    so the caller falls back to generic chunking.
    """
    if not pages:
        return None
    framework = pages[0].metadata.get("framework")
    pattern = _CONTROL_PATTERNS.get(framework)
    if pattern is None:
        return None

    source = pages[0].metadata.get("source")
    blob = _build_blob_with_page_markers(pages)
    matches = list(pattern.finditer(blob))
    if len(matches) < _MIN_CONTROL_HITS:
        return None

    fallback_page = pages[0].metadata.get("page", 1)
    sub_splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
    )

    chunks: list[Document] = []
    for i, m in enumerate(matches):
        control_id = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(blob)
        page = _page_at(blob, start, fallback_page)
        clean = _strip_page_markers(blob[start:end]).strip()
        if not clean:
            continue

        # Long control descriptions (common in 800-53) get sub-chunked but
        # every piece keeps the control_id tag so retrieval still pinpoints them.
        if len(clean) > settings.chunk_size * 1.5:
            for j, sub in enumerate(sub_splitter.split_text(clean)):
                chunks.append(
                    Document(
                        page_content=sub,
                        metadata={
                            "framework": framework,
                            "source": source,
                            "page": page,
                            "control_id": control_id,
                            "chunk_part": j,
                        },
                    )
                )
        else:
            chunks.append(
                Document(
                    page_content=clean,
                    metadata={
                        "framework": framework,
                        "source": source,
                        "page": page,
                        "control_id": control_id,
                    },
                )
            )
    return chunks


def chunk_documents(
    docs: Iterable[Document],
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
) -> list[Document]:
    """Chunk per-framework: control-catalogs get per-control splits, the rest
    use the generic recursive splitter.
    """
    by_framework: dict[str, list[Document]] = {}
    for d in docs:
        by_framework.setdefault(d.metadata.get("framework", "?"), []).append(d)

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size or settings.chunk_size,
        chunk_overlap=chunk_overlap or settings.chunk_overlap,
    )

    out: list[Document] = []
    for framework_pages in by_framework.values():
        per_control = _split_by_controls(framework_pages)
        if per_control is not None:
            out.extend(per_control)
        else:
            out.extend(splitter.split_documents(framework_pages))
    return out
