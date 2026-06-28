"""Adaptive scope planning — the agent decides what *else* is worth assessing.

A scanner audits exactly what you point it at. An auditor *scopes the engagement*:
it looks at the target, notices adjacent attack surface the user didn't name, and
pulls it into scope. This module is that step. Today it expands a codebase audit
to the container **base image(s)** the repo builds on — a `FROM python:3.9` line
means the running system inherits that image's OS-package CVEs, which a scan of
the source tree never sees.

Design choices that keep it strong rather than partial:

* **Deterministic, not LLM-driven.** For a security tool a rule that parses
  Dockerfiles is faster and more trustworthy than asking a model to guess scan
  targets — no added latency, no hallucinated hosts. The "agent decides" is a
  deterministic decision with an auditable reason attached.
* **No dead work.** Discovery only runs when the prerequisite scanner (Trivy) is
  installed and local targets are permitted; otherwise it is a clean no-op.
* **Bounded and concurrent.** The filesystem walk is depth/size-capped, and the
  artifacts it adds join the *same* concurrent audit batch — so expansion costs
  wall-clock `max(scan, image-pull)`, never their sum.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from auditor.models import Artifact

# Directories that never contain a project Dockerfile worth scanning and would
# otherwise blow up the walk on a real repo.
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
    "vendor", "site-packages", ".terraform", ".next", "target",
})

_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE | re.MULTILINE)


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _iter_dockerfiles(root: str | Path, *, max_files: int = 25, max_depth: int = 6) -> list[Path]:
    """Bounded walk for Dockerfiles under ``root`` (or ``root`` itself)."""
    root = Path(root)
    found: list[Path] = []
    if not root.exists():
        return found
    if root.is_file():
        return [root] if _is_dockerfile(root.name) else []

    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if _is_dockerfile(fn):
                found.append(Path(dirpath) / fn)
                if len(found) >= max_files:
                    return found
    return found


def _base_images(dockerfile_text: str) -> list[str]:
    """Extract concrete base images from a Dockerfile, in order, de-duplicated.

    Skips ``scratch``, ARG/variable-templated refs (``${BASE}``), and references
    to earlier build stages (multi-stage ``AS builder`` aliases) — those are not
    independently pullable images.
    """
    stage_aliases = {
        m.group(2).lower() for m in _FROM_RE.finditer(dockerfile_text) if m.group(2)
    }
    images: list[str] = []
    seen: set[str] = set()
    for m in _FROM_RE.finditer(dockerfile_text):
        img = m.group(1).strip()
        low = img.lower()
        if low == "scratch" or low in stage_aliases or "$" in img or img.startswith("-"):
            continue
        if img in seen:
            continue
        seen.add(img)
        images.append(img)
    return images


def plan_expansion(
    artifacts: list[Artifact],
    *,
    allow_local: bool,
    trivy_available: bool,
    max_images: int = 3,
) -> tuple[list[Artifact], list[str]]:
    """Return ``(expanded_artifacts, plan_notes)``.

    For every codebase target, discover container base images and add an
    ``image_ref`` artifact for each (bounded by ``max_images``). A clean no-op
    when local targets are disabled or Trivy isn't installed.
    """
    notes: list[str] = []
    if not (allow_local and trivy_available):
        return list(artifacts), notes

    in_scope_images = {a.content.strip() for a in artifacts if a.kind == "image_ref"}
    added: list[Artifact] = []

    for a in artifacts:
        if a.kind != "codebase":
            continue
        discovered: list[str] = []
        for df in _iter_dockerfiles(a.content):
            try:
                text = df.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for img in _base_images(text):
                if img not in in_scope_images and img not in discovered:
                    discovered.append(img)

        for img in discovered[:max_images]:
            added.append(Artifact(kind="image_ref", name=img, content=img))
            in_scope_images.add(img)
            notes.append(
                f"Codebase `{a.name}`: detected base image `{img}` in a Dockerfile "
                "→ added a container-image scan (catches inherited OS-package CVEs a "
                "source-tree scan can't see)."
            )
        if len(discovered) > max_images:
            extra = len(discovered) - max_images
            notes.append(
                f"Codebase `{a.name}`: {extra} further base image(s) found; scanned the "
                f"first {max_images} to keep the run fast."
            )

    return list(artifacts) + added, notes
