"""Fetch CC-BY-SA / openly-licensed markdown corpora from GitHub.

Adds public knowledge sources the agent can cite alongside the bundled PDFs:

- OWASP Top 10 2021 — only released as a static site (no PDF), but the
  authoritative source is the markdown in OWASP/Top10.
- OWASP Cheat Sheet Series — ~100 cheat sheets covering everything from
  authentication to TLS to file upload security; the best library of
  recommendation language an auditor can cite.

Files land in `data/web/<source-name>/*.md` and are picked up by the same
indexing pipeline as the PDFs. Re-runs are idempotent: an existing file is
left in place unless `force=True`.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com/repos"
_GITHUB_RAW = "https://raw.githubusercontent.com"
_USER_AGENT = "cybersecurity-auditor"
_TIMEOUT = 30


@dataclass(frozen=True)
class WebSource:
    name: str          # short slug — becomes the subdir under data/web/
    repo: str          # GitHub "owner/repo"
    branch: str        # branch or tag
    path: str          # path within the repo
    framework: str     # framework label stamped on every chunk
    license: str       # for documentation / README


WEB_SOURCES: tuple[WebSource, ...] = (
    WebSource(
        name="owasp_top10_2025",
        repo="OWASP/Top10",
        branch="master",
        # English markdown for the 2025 release. Peer dirs under docs/
        # (ar/, de/, es/, …) are translations we don't ingest.
        path="2025/docs/en",
        framework="OWASP Top 10 2025",
        license="CC-BY-SA 4.0",
    ),
    WebSource(
        name="owasp_cheatsheets",
        repo="OWASP/CheatSheetSeries",
        branch="master",
        path="cheatsheets",
        framework="OWASP Cheat Sheet Series",
        license="CC-BY-SA 4.0",
    ),
    WebSource(
        name="owasp_asvs_5_0",
        repo="OWASP/ASVS",
        branch="master",
        path="5.0/en",
        framework="OWASP ASVS 5.0",
        license="CC-BY-SA 4.0",
    ),
    WebSource(
        name="owasp_api_top10_2023",
        repo="OWASP/API-Security",
        branch="master",
        path="editions/2023/en",
        framework="OWASP API Security Top 10 2023",
        license="CC-BY-SA 4.0",
    ),
)


def framework_for_dir(dirname: str) -> str | None:
    for s in WEB_SOURCES:
        if s.name == dirname:
            return s.framework
    return None


def _http_get(url: str, accept: str | None = None) -> bytes:
    headers = {"User-Agent": _USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read()


def _list_markdown_files(source: WebSource) -> list[str]:
    """Use the GitHub Contents API to list .md files in the source path."""
    url = f"{_GITHUB_API}/{source.repo}/contents/{source.path}?ref={source.branch}"
    payload = json.loads(_http_get(url, accept="application/vnd.github+json"))
    return sorted(
        item["name"]
        for item in payload
        if item.get("type") == "file"
        and item.get("name", "").endswith(".md")
        and not item["name"].startswith(".")
    )


def _fetch_raw(source: WebSource, filename: str) -> str:
    url = f"{_GITHUB_RAW}/{source.repo}/{source.branch}/{source.path}/{filename}"
    return _http_get(url).decode("utf-8", errors="replace")


def fetch_source(source: WebSource, out_dir: Path, force: bool = False) -> tuple[int, int]:
    """Fetch all markdown for one source. Returns (written, skipped)."""
    target = out_dir / source.name
    target.mkdir(parents=True, exist_ok=True)

    try:
        files = _list_markdown_files(source)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("Failed to list %s contents: %s", source.repo, e)
        return (0, 0)

    written = 0
    skipped = 0
    for fname in files:
        dest = target / fname
        if dest.exists() and not force:
            skipped += 1
            continue
        try:
            content = _fetch_raw(source, fname)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("Failed to fetch %s: %s", fname, e)
            continue
        dest.write_text(content, encoding="utf-8")
        written += 1
    return (written, skipped)


def fetch_all(out_dir: Path, force: bool = False) -> dict[str, tuple[int, int]]:
    """Fetch every configured web source. Returns {source_name: (written, skipped)}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return {s.name: fetch_source(s, out_dir, force=force) for s in WEB_SOURCES}
