"""MITRE ATT&CK technique tagging for Findings.

Two-layer approach:
1. Hand-curated ``_TECHNIQUE_KEYWORDS`` — high-precision substring rules tuned to
   the exact finding types this auditor produces.
2. STIX technique-name phrase matching — downloads the full ATT&CK Enterprise
   STIX bundle once (7-day cache at ``~/.cache/auditor/attack_techniques.json``)
   and checks whether any technique *name* appears verbatim in the finding text.
   This adds ~600 technique names on top of the curated rules without false positives
   from description-level keyword soup.

References:
- https://attack.mitre.org/techniques/enterprise/
- https://github.com/mitre/cti  (STIX source)
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from pathlib import Path

from auditor.models import Finding

log = logging.getLogger(__name__)

# ── 1. Hand-curated keyword map ─────────────────────────────────────────────
# technique_id → substrings that, if present in a finding's haystack, indicate
# the technique applies.  Kept intentionally precise to avoid noise.

_TECHNIQUE_KEYWORDS: dict[str, tuple[str, ...]] = {
    # Initial Access / Public-facing exploitation
    "T1190": (
        "0.0.0.0/0",
        "public-facing",
        "exposed service",
        "open ingress",
        "ingress from anywhere",
        "cve-",
    ),
    # Valid Accounts (and sub-techniques)
    "T1078":     ("valid account", "shared credential", "default credential"),
    "T1078.003": ("permitrootlogin", "root ssh", "root login", "local account"),
    # Brute Force (and sub-techniques)
    "T1110":     ("brute force", "brute-force"),
    "T1110.001": ("password guess", "failed password", "failed login"),
    "T1110.004": ("credential stuffing", "empty password", "permitemptypasswords"),
    # Supply chain / image integrity
    "T1195.002": (
        ":latest tag",
        "mutable tag",
        "no integrity check",
        "supply chain",
        "unverified download",
        "add http",
    ),
    # Cloud-storage data exfil
    "T1530": ("public-read", "publicly accessible bucket", "public bucket", "cloud storage exposure"),
    # Escape to host / container privilege
    "T1611": (
        "privileged",
        "host network",
        "hostnetwork",
        "runasuser: 0",
        "container escape",
        "runs as root",
        "no user directive",
    ),
    # Impair Defenses (logging tampering)
    "T1562.012": ("disable audit", "without audit trail", "no logging", "log tampering"),
    # Input Capture
    "T1056.002": ("x11 forwarding",),
    # Hardcoded credentials / secrets in source
    "T1552.001": (
        "hardcoded secret",
        "hardcoded password",
        "hardcoded api key",
        "private key in source",
        "aws access key",
        "openai api key",
    ),
}

# ── 2. STIX bundle — lazy-loaded technique-name phrase index ────────────────

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_STIX_CACHE = Path.home() / ".cache" / "auditor" / "attack_techniques.json"
_STIX_TTL_SECONDS = 7 * 24 * 3600  # 7 days

# Maps lowercase technique name → technique_id.  None = not yet loaded.
# Tests can monkeypatch this to {} to skip STIX matching.
_stix_phrases: dict[str, str] | None = None


def _load_stix_techniques() -> dict[str, str]:
    """Return ``{tid: name}`` for all non-revoked ATT&CK Enterprise techniques.

    Uses a 7-day on-disk cache.  Returns ``{}`` on any network/parse failure.
    """
    if _STIX_CACHE.exists():
        age = time.time() - _STIX_CACHE.stat().st_mtime
        if age < _STIX_TTL_SECONDS:
            try:
                return json.loads(_STIX_CACHE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass  # corrupted cache — re-download below

    try:
        log.info("Downloading ATT&CK STIX bundle from MITRE GitHub…")
        with urllib.request.urlopen(_STIX_URL, timeout=20) as resp:  # noqa: S310
            bundle = json.loads(resp.read())
    except Exception as exc:
        log.warning("ATT&CK STIX download failed (%s); falling back to curated keywords.", exc)
        return {}

    techniques: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                if re.match(r"T\d{4}(\.\d{3})?$", tid):
                    techniques[tid] = obj.get("name", "")
                    break

    try:
        _STIX_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _STIX_CACHE.write_text(json.dumps(techniques), encoding="utf-8")
    except OSError as exc:
        log.warning("Could not write ATT&CK cache: %s", exc)

    return techniques


def _get_stix_phrases() -> dict[str, str]:
    """Return lazily-built ``{lowercase_name: tid}`` from the STIX cache.

    Only includes multi-word technique names (≥2 words).  Single-word names like
    "Phishing" or "Email" are common-enough English to cause too many substring
    false positives — those still get coverage via the curated layer-1 keywords.

    Returns ``{}`` silently on any failure so enrichment degrades gracefully.
    """
    global _stix_phrases
    if _stix_phrases is not None:
        return _stix_phrases
    try:
        techniques = _load_stix_techniques()
        _stix_phrases = {
            name.lower(): tid
            for tid, name in techniques.items()
            if name and " " in name  # multi-word only — precision filter
        }
    except Exception as exc:
        log.warning("Failed to build STIX phrase index: %s", exc)
        _stix_phrases = {}
    return _stix_phrases


# ── Core tagging logic ───────────────────────────────────────────────────────


def _haystack(finding: Finding) -> str:
    parts = [finding.title, finding.evidence, finding.recommendation]
    return " ".join(p for p in parts if p).lower()


def tag_finding(finding: Finding) -> list[str]:
    """Return MITRE ATT&CK technique IDs that apply to *finding*.

    Combines the curated keyword rules (layer 1) with STIX technique-name
    phrase matching (layer 2).  Deduplicates; order: curated first, STIX second.
    """
    hay = _haystack(finding)
    matched: list[str] = []
    matched_set: set[str] = set()

    # Layer 1 — hand-curated (high precision)
    for tid, keywords in _TECHNIQUE_KEYWORDS.items():
        if any(k in hay for k in keywords):
            matched.append(tid)
            matched_set.add(tid)

    # Layer 2 — STIX technique-name phrases (broader coverage, still precise)
    for phrase, tid in _get_stix_phrases().items():
        if tid not in matched_set and phrase in hay:
            matched.append(tid)
            matched_set.add(tid)

    return matched


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Annotate each finding in-place with its matching ATT&CK technique IDs."""
    for f in findings:
        techniques = tag_finding(f)
        if techniques:
            f.attack_techniques = techniques
    return findings
