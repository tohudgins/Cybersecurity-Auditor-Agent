"""Turn a natural-language chat message into audit targets (Artifacts).

Lets the user *talk* to the agent instead of filling sidebar fields, e.g.:

    "audit the repo at /Users/me/project"
    "scan https://example.com"
    "audit aws:prod"
    "audit this machine"
    "scan image nginx:1.21"            (or  image:nginx:1.21)

Detection is conservative to avoid hijacking ordinary compliance questions:
* Explicit ``kind:`` prefixes (path:/url:/image:/cloud:/host:) always win.
* ``http(s)://`` URLs and existing filesystem paths are always detected.
* Weaker cues — bare cloud providers ("aws"), "this machine" — only fire when
  the message also contains an audit verb (audit/scan/assess/check/review).

`describe_targets()` renders a short human summary so the UI can show what it
detected before running.
"""
from __future__ import annotations

import os
import re

from auditor.models import Artifact

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_CLOUD_RE = re.compile(r"^(aws|gcp|azure)(:[\w-]+)?$", re.IGNORECASE)
_AUDIT_INTENT_RE = re.compile(r"\b(audit|scan|assess|review|check|harden|pentest)\b", re.IGNORECASE)
_LOCAL_HOST_RE = re.compile(
    r"\b(this|my|the\s+local|local)\s+(machine|host|system|server|box|laptop|computer)\b",
    re.IGNORECASE,
)
_SSH_HOST_RE = re.compile(r"^[\w.-]+@[\w.-]+$")


def _classify_path(path: str) -> Artifact | None:
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return None
    if os.path.isdir(expanded):
        return Artifact(kind="codebase", name=path, content=expanded)
    name = os.path.basename(expanded).lower()
    try:
        if name.endswith(".pdf"):
            from auditor.tools.audit_policy_pdf import extract_pdf_text

            with open(expanded, "rb") as fh:
                content = extract_pdf_text(fh.read())
            return Artifact(kind="policy_pdf", name=path, content=content)
        content = open(expanded, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    if name.endswith(".log") or "log" in name:
        return Artifact(kind="log", name=path, content=content)
    return Artifact(kind="config", name=path, content=content)


def _prefixed_artifact(token: str) -> Artifact | None:
    low = token.lower()
    if low.startswith("path:"):
        return _classify_path(token[5:])
    if low.startswith("url:"):
        val = token[4:]
        return Artifact(kind="target_url", name=val, content=val)
    if low.startswith("image:"):
        val = token[6:]
        return Artifact(kind="image_ref", name=val, content=val)
    if low.startswith("cloud:"):
        val = token[6:]
        return Artifact(kind="cloud_account", name=f"cloud:{val}", content=val)
    if low.startswith("host:"):
        val = token[5:]
        return Artifact(kind="host", name=f"host:{val}", content=val)
    return None


def parse_targets(text: str) -> list[Artifact]:
    """Detect audit targets in *text*. Returns an empty list when none are found."""
    if not text:
        return []
    has_intent = bool(_AUDIT_INTENT_RE.search(text))
    tokens = text.split()
    artifacts: list[Artifact] = []
    seen: set[tuple[str, str]] = set()

    def _add(art: Artifact | None) -> None:
        if art and (art.kind, art.content) not in seen:
            seen.add((art.kind, art.content))
            artifacts.append(art)

    for tok in tokens:
        tok = tok.strip().strip(",;")
        if not tok:
            continue
        # 1. Explicit prefixes — always honored.
        if (art := _prefixed_artifact(tok)) is not None:
            _add(art)
            continue
        # 2. http(s) URLs — always.
        if _URL_RE.match(tok):
            _add(Artifact(kind="target_url", name=tok, content=tok))
            continue
        # 3. Existing filesystem paths — always (path-like tokens only).
        if ("/" in tok or tok.startswith("~") or tok in (".", "..")) and (art := _classify_path(tok)):
            _add(art)
            continue
        # 4. Weaker cues — only with an audit verb present.
        if has_intent and _CLOUD_RE.match(tok):
            _add(Artifact(kind="cloud_account", name=f"cloud:{tok}", content=tok))
            continue
        if has_intent and _SSH_HOST_RE.match(tok):
            _add(Artifact(kind="host", name=f"host:{tok}", content=tok))
            continue

    # 5. "audit this machine" style phrases → local host.
    if has_intent and (_LOCAL_HOST_RE.search(text) or re.search(r"\blocalhost\b", text, re.IGNORECASE)):
        _add(Artifact(kind="host", name="host:localhost", content="localhost"))

    return artifacts


_KIND_LABEL = {
    "codebase": "codebase", "config": "config file", "log": "log file",
    "policy_pdf": "policy PDF", "text": "description",
    "cloud_account": "cloud account", "image_ref": "container image",
    "target_url": "web target", "host": "host/machine",
}


def describe_targets(artifacts: list[Artifact]) -> str:
    """Short human summary of detected targets, e.g. 'codebase `~/proj`, web target `https://x`'."""
    return ", ".join(f"{_KIND_LABEL.get(a.kind, a.kind)} `{a.name}`" for a in artifacts)
