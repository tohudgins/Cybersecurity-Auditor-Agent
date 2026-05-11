from collections.abc import Iterable
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from auditor.config import settings

FRAMEWORK_NAMES: dict[str, str] = {
    "CIS_Controls__v8.1_Guide__2024_06.pdf": "CIS Controls v8.1",
    "CompTIA_Security+.pdf": "CompTIA Security+ (SY0-701)",
    "MITRE_ATTACK_Enterprise_11x17.pdf": "MITRE ATT&CK Enterprise",
    "NIST.CSWP.29.pdf": "NIST Cybersecurity Framework 2.0",
    "NIST.SP.800-37r2.pdf": "NIST SP 800-37 Rev. 2 (RMF)",
    "NIST.SP.800-53r5.pdf": "NIST SP 800-53 Rev. 5",
    "nistspecialpublication800-30r1.pdf": "NIST SP 800-30 Rev. 1",
    "OWASP Application Security Verification Standard 4.0.3-en.pdf": "OWASP ASVS 4.0.3",
}


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


def chunk_documents(
    docs: Iterable[Document],
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
) -> list[Document]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size or settings.chunk_size,
        chunk_overlap=chunk_overlap or settings.chunk_overlap,
    )
    return splitter.split_documents(list(docs))
