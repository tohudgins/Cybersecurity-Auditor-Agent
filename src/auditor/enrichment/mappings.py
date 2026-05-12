"""Cross-framework control mappings (NIST 800-53 ↔ CSF, CIS, ISO 27001, PCI, SOC 2).

Real GRC tools (RegScale, Drata, Trestle) ship mapping tables — usually derived
from NIST's OLIR (Open Security Controls Assessment Language Informative
References) program. We ship a hand-curated JSON subset focused on the controls
this agent commonly cites. Replace `data/mappings/control_mappings.json` with a
fuller OLIR-derived file for production use.

Usage:
    from auditor.enrichment.mappings import lookup_control
    lookup_control("AC-2")
    # → {"title": "Account Management",
    #    "NIST CSF 2.0": ["PR.AA-01", ...],
    #    "CIS Controls v8.1": [...], "ISO 27001:2022": [...], ...}
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache

from auditor.config import settings
from auditor.models import Finding

log = logging.getLogger(__name__)

_MAPPING_FILE = settings.data_dir / "mappings" / "control_mappings.json"

# Anchor framework for the mapping table. Findings tagged with this framework
# are looked up directly; findings tagged with other frameworks (CIS, ASVS, etc.)
# don't currently reverse-resolve — that's a follow-up.
_ANCHOR_FRAMEWORK = "NIST SP 800-53 Rev. 5"

# Some Trivy/Bandit findings emit decorated control IDs ("AC-2(1)", "CWE-78").
# Normalize to the base ID for lookup.
_BASE_ID_RE = re.compile(r"^([A-Z]{2}-\d{1,2})")


@lru_cache(maxsize=1)
def _load_mappings() -> dict[str, dict]:
    if not _MAPPING_FILE.exists():
        log.warning("Control mappings file not found at %s", _MAPPING_FILE)
        return {}
    try:
        data = json.loads(_MAPPING_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        log.exception("Failed to load control mappings")
        return {}
    return data.get("mappings", {})


def _base_id(control_id: str) -> str:
    m = _BASE_ID_RE.match(control_id.strip())
    return m.group(1) if m else control_id.strip()


def lookup_control(control_id: str) -> dict[str, list[str]] | None:
    """Return cross-framework mappings for a NIST 800-53 control, or None."""
    if not control_id:
        return None
    base = _base_id(control_id)
    entry = _load_mappings().get(base)
    if not entry:
        return None
    return {k: v for k, v in entry.items() if k != "title" and isinstance(v, list)}


def control_title(control_id: str) -> str | None:
    base = _base_id(control_id)
    entry = _load_mappings().get(base)
    return entry.get("title") if entry else None


def enrich_with_mappings(findings: list[Finding]) -> list[Finding]:
    """Populate `finding.mapped_controls` for any finding anchored on NIST 800-53."""
    for f in findings:
        if not f.control_id or f.framework != _ANCHOR_FRAMEWORK:
            continue
        mapped = lookup_control(f.control_id)
        if mapped:
            f.mapped_controls = mapped
    return findings


def reset_cache() -> None:
    """Test helper: drop the cached mapping table."""
    _load_mappings.cache_clear()
