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
    # Control catalogs (per-control chunking applies)
    "CIS_Controls__v8.1_Guide__2024_06.pdf": "CIS Controls v8.1",
    "NIST.SP.800-53r5.pdf": "NIST SP 800-53 Rev. 5",
    "NIST.SP.800-171r3.pdf": "NIST SP 800-171 Rev. 3",
    "NIST.CSWP.30.pdf": "NIST Cybersecurity Framework 2.1",
    "NIST.CSWP.29.pdf": "NIST Cybersecurity Framework 2.0",  # superseded by 2.1; kept for back-compat
    "NIST.SP.800-218.pdf": "NIST SP 800-218 (SSDF)",
    # OWASP ASVS is now sourced from GitHub markdown (see web_fetcher.py).
    # Legacy ASVS 4.0.3 PDF is still recognized if a user keeps it locally:
    "OWASP Application Security Verification Standard 4.0.3-en.pdf": "OWASP ASVS 4.0.3",
    # Process / narrative documents (generic chunking)
    "nistspecialpublication800-30r1.pdf": "NIST SP 800-30 Rev. 1",
    "NIST.SP.800-37r2.pdf": "NIST SP 800-37 Rev. 2 (RMF)",
    "NIST.SP.800-61r3.pdf": "NIST SP 800-61 Rev. 3 (Incident Response)",
    "NIST.SP.800-61r2.pdf": "NIST SP 800-61 Rev. 2 (Incident Response)",  # superseded by r3
    "zero_trust_maturity_model_v2_508.pdf": "CISA Zero Trust Maturity Model v2",
    "NIST.IR.7298r3.pdf": "NIST IR 7298 Rev. 3 (Glossary)",
    # Adversary reference
    "MITRE_ATTACK_Enterprise_11x17.pdf": "MITRE ATT&CK Enterprise",
}

# Regex that detects a control-ID header (matched against the start of a line
# via re.MULTILINE). Only frameworks listed here get per-control chunking.
_CONTROL_PATTERNS: dict[str, re.Pattern[str]] = {
    "NIST SP 800-53 Rev. 5": re.compile(r"^\s*([A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?)\s", re.MULTILINE),
    "NIST SP 800-171 Rev. 3": re.compile(r"^\s*(3\.\d{1,2}\.\d{1,2})\b", re.MULTILINE),
    "NIST Cybersecurity Framework 2.0": re.compile(r"^\s*([A-Z]{2}\.[A-Z]{2}-\d{2})\b", re.MULTILINE),
    "NIST SP 800-218 (SSDF)": re.compile(r"^\s*((?:PO|PS|PW|RV)\.\d+\.\d+)\b", re.MULTILINE),
    "CIS Controls v8.1": re.compile(r"^\s*(\d{1,2}\.\d{1,2})\s+[A-Z]", re.MULTILINE),
    # ASVS 4.0.3 PDF (legacy) uses V-prefixed control IDs like V1.1.1.
    # ASVS 5.0 markdown uses table rows with bold IDs like **1.2.1** and
    # gets generic chapter-level chunking instead.
    "OWASP ASVS 4.0.3": re.compile(r"^\s*(V\d+\.\d+\.\d+)\b", re.MULTILINE),
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
    return FRAMEWORK_NAMES.get(filename, Path(filename).stem)


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
    directory = directory or settings.data_dir
    pdfs = sorted(p for p in directory.iterdir() if p.suffix.lower() == ".pdf")
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
