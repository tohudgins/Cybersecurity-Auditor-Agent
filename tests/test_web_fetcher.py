"""Tests for the GitHub markdown fetcher."""
from __future__ import annotations

import json

from auditor.ingest import web_fetcher


def test_framework_for_dir_resolves_known_sources():
    assert web_fetcher.framework_for_dir("owasp_top10_2025") == "OWASP Top 10 2025"
    assert web_fetcher.framework_for_dir("owasp_cheatsheets") == "OWASP Cheat Sheet Series"
    assert web_fetcher.framework_for_dir("unknown") is None


def test_fetch_source_writes_files_and_skips_existing(monkeypatch, tmp_path):
    source = web_fetcher.WebSource(
        name="test_source",
        repo="example/repo",
        branch="main",
        path="docs",
        framework="Example Framework",
        license="CC0",
    )

    listing = json.dumps(
        [
            {"name": "A01.md", "type": "file"},
            {"name": "A02.md", "type": "file"},
            {"name": ".hidden.md", "type": "file"},
            {"name": "subdir", "type": "dir"},
            {"name": "README.txt", "type": "file"},
        ]
    ).encode()

    def fake_http_get(url, accept=None):
        if "/contents/" in url:
            return listing
        # Raw file fetch: filename is the tail of the path.
        return f"# {url.rsplit('/', 1)[-1]}\nbody text".encode()

    monkeypatch.setattr(web_fetcher, "_http_get", fake_http_get)

    written, skipped = web_fetcher.fetch_source(source, tmp_path)
    assert written == 2  # A01 + A02 (the hidden + subdir + .txt are filtered)
    assert skipped == 0
    assert (tmp_path / "test_source" / "A01.md").exists()
    assert (tmp_path / "test_source" / "A02.md").exists()
    assert not (tmp_path / "test_source" / ".hidden.md").exists()

    # Second run: nothing new to write, both files skipped.
    written2, skipped2 = web_fetcher.fetch_source(source, tmp_path)
    assert written2 == 0
    assert skipped2 == 2


def test_fetch_source_force_redownloads(monkeypatch, tmp_path):
    source = web_fetcher.WEB_SOURCES[0]
    monkeypatch.setattr(
        web_fetcher,
        "_http_get",
        lambda url, accept=None: (
            json.dumps([{"name": "A01_2025.md", "type": "file"}]).encode()
            if "/contents/" in url
            else b"fresh content"
        ),
    )

    # Pre-populate cache with stale content.
    target = tmp_path / source.name
    target.mkdir(parents=True)
    (target / "A01_2025.md").write_text("stale", encoding="utf-8")

    written, skipped = web_fetcher.fetch_source(source, tmp_path, force=True)
    assert written == 1
    assert (target / "A01_2025.md").read_text(encoding="utf-8") == "fresh content"


def test_fetch_source_handles_listing_failure(monkeypatch, tmp_path):
    def _explode(url, accept=None):
        raise OSError("network down")

    monkeypatch.setattr(web_fetcher, "_http_get", _explode)
    source = web_fetcher.WEB_SOURCES[0]
    written, skipped = web_fetcher.fetch_source(source, tmp_path)
    assert (written, skipped) == (0, 0)


def test_fetch_all_iterates_all_sources(monkeypatch, tmp_path):
    monkeypatch.setattr(web_fetcher, "fetch_source", lambda src, out, force=False: (1, 0))
    results = web_fetcher.fetch_all(tmp_path)
    assert set(results.keys()) == {s.name for s in web_fetcher.WEB_SOURCES}
