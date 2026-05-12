"""Tests for markdown loading and integration with chunk_documents."""
from __future__ import annotations

from auditor.ingest.pdf_loader import _split_by_controls, chunk_documents, load_markdown_dir


def _write_owasp_top10(web_dir):
    src = web_dir / "owasp_top10_2025"
    src.mkdir(parents=True)
    for i, name in enumerate(
        [
            "Broken_Access_Control",
            "Cryptographic_Failures",
            "Injection",
            "Insecure_Design",
            "Security_Misconfiguration",
            "Vulnerable_and_Outdated_Components",
            "Identification_and_Authentication_Failures",
            "Software_and_Data_Integrity_Failures",
            "Security_Logging_and_Monitoring_Failures",
            "Server_Side_Request_Forgery_SSRF",
        ],
        start=1,
    ):
        (src / f"A{i:02d}_2025-{name}.md").write_text(
            f"# A{i:02d}:2025 – {name.replace('_', ' ')}\n\nThis risk concerns {name}.\n"
            + ("Discussion paragraph. " * 10),
            encoding="utf-8",
        )


def test_load_markdown_dir_stamps_framework(tmp_path):
    _write_owasp_top10(tmp_path)
    docs = load_markdown_dir(tmp_path)
    assert len(docs) == 10
    assert {d.metadata["framework"] for d in docs} == {"OWASP Top 10 2025"}
    assert all(d.metadata["page"] == 1 for d in docs)


def test_load_markdown_dir_ignores_unknown_source(tmp_path):
    other = tmp_path / "random_corpus"
    other.mkdir()
    (other / "doc.md").write_text("# Heading\nbody", encoding="utf-8")
    assert load_markdown_dir(tmp_path) == []


def test_per_control_split_on_owasp_top10_markdown(tmp_path):
    _write_owasp_top10(tmp_path)
    docs = load_markdown_dir(tmp_path)
    chunks = _split_by_controls(docs)
    assert chunks is not None
    control_ids = {c.metadata["control_id"] for c in chunks}
    assert control_ids == {f"A{i:02d}:2025" for i in range(1, 11)}


def test_chunk_documents_handles_mixed_markdown_and_other(tmp_path):
    _write_owasp_top10(tmp_path)
    md_docs = load_markdown_dir(tmp_path)
    # Plus a non-catalog framework markdown to confirm fall-through.
    cheat_src = tmp_path / "owasp_cheatsheets"
    cheat_src.mkdir()
    (cheat_src / "Authentication.md").write_text(
        "# Authentication Cheat Sheet\n\n" + ("Practical guidance. " * 50),
        encoding="utf-8",
    )
    md_docs = load_markdown_dir(tmp_path)

    chunks = chunk_documents(md_docs)
    by_framework = {}
    for c in chunks:
        by_framework.setdefault(c.metadata.get("framework"), []).append(c)

    assert "OWASP Top 10 2025" in by_framework
    assert "OWASP Cheat Sheet Series" in by_framework
    # Top 10 chunks carry control_id; cheat sheets don't.
    assert all(c.metadata.get("control_id") for c in by_framework["OWASP Top 10 2025"])
    assert all(not c.metadata.get("control_id") for c in by_framework["OWASP Cheat Sheet Series"])
