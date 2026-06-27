"""Cross-framework control mappings (NIST 800-53 ↔ CSF, CIS, ISO 27001, PCI, SOC 2).

Real GRC tools (RegScale, Drata, Trestle) ship mapping tables — usually derived
from NIST's OLIR (Open Security Controls Assessment Language Informative
References) program. We ship a curated JSON crosswalk anchored on NIST SP 800-53
Rev. 5 (`data/mappings/control_mappings.json`) plus a CWE → ASVS → NIST bridge
for SAST findings (`data/mappings/cwe_mappings.json`). The
`auditor.ingest.olir_import` module can regenerate/augment the anchor table from
NIST's official machine-readable exports.

Resolution is **bidirectional**. A finding can be anchored on:

- NIST SP 800-53 (e.g. ``AC-2``) → direct lookup of the crosswalk.
- A CWE (e.g. ``CWE-89`` from Semgrep/Bandit) → resolved via the CWE bridge to
  an ASVS domain + a NIST anchor, then expanded through the anchor's crosswalk.
- Any *other* crosswalk framework (CSF/CIS/ISO/PCI/SOC 2 — e.g. an LLM finding
  citing ``PR.AA-05``) → reverse-resolved to its NIST anchor(s), then expanded.

Usage:
    from auditor.enrichment.mappings import lookup_control, resolve_finding
    lookup_control("AC-2")
    # → {"NIST CSF 2.1": ["PR.AA-01", ...], "CIS Controls v8.1": [...], ...}
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
_CWE_FILE = settings.data_dir / "mappings" / "cwe_mappings.json"

# Anchor framework for the mapping table.
_ANCHOR_FRAMEWORK = "NIST SP 800-53 Rev. 5"

# The non-anchor frameworks carried in each crosswalk entry. Used to build the
# reverse index that powers bidirectional resolution.
_CROSSWALK_FRAMEWORKS = (
    "NIST CSF 2.1",
    "CIS Controls v8.1",
    "ISO 27001:2022",
    "PCI DSS v4.0.1",
    "SOC 2 TSC",
)

# Some Trivy/Bandit findings emit decorated control IDs ("AC-2(1)"). Normalize
# to the base ID for the anchor lookup.
_BASE_ID_RE = re.compile(r"^([A-Z]{2}-\d{1,2})")
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


@lru_cache(maxsize=1)
def _load_mappings() -> dict[str, dict]:
    return _load_json_mappings(_MAPPING_FILE)


@lru_cache(maxsize=1)
def _load_cwe_mappings() -> dict[str, dict]:
    return _load_json_mappings(_CWE_FILE)


def _load_json_mappings(path) -> dict[str, dict]:
    if not path.exists():
        log.warning("Mappings file not found at %s", path)
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        log.exception("Failed to load mappings from %s", path)
        return {}
    return data.get("mappings", {})


@lru_cache(maxsize=1)
def _reverse_index() -> dict[str, dict[str, list[str]]]:
    """Build ``{framework: {their_id(upper): [nist_anchors]}}`` for reverse lookup."""
    rev: dict[str, dict[str, list[str]]] = {fw: {} for fw in _CROSSWALK_FRAMEWORKS}
    for nist_id, entry in _load_mappings().items():
        for fw in _CROSSWALK_FRAMEWORKS:
            for cid in entry.get(fw, []) or []:
                anchors = rev[fw].setdefault(cid.upper(), [])
                if nist_id not in anchors:
                    anchors.append(nist_id)
    return rev


def _base_id(control_id: str) -> str:
    m = _BASE_ID_RE.match(control_id.strip())
    return m.group(1) if m else control_id.strip()


def lookup_control(control_id: str) -> dict[str, list[str]] | None:
    """Return the cross-framework crosswalk for a NIST 800-53 control, or None."""
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


def catalog_control_ids() -> list[str]:
    """All NIST 800-53 anchor controls in the curated crosswalk (the default
    assessment baseline). Sorted by family then number."""

    def _key(cid: str) -> tuple[str, int]:
        fam, _, num = cid.partition("-")
        return (fam, int(num) if num.isdigit() else 0)

    return sorted(_load_mappings().keys(), key=_key)


def _merge(into: dict[str, list[str]], extra: dict[str, list[str]]) -> None:
    """Union framework→ids lists, preserving order and de-duplicating."""
    for fw, ids in extra.items():
        if not isinstance(ids, list):
            continue
        dst = into.setdefault(fw, [])
        for cid in ids:
            if cid not in dst:
                dst.append(cid)


def _resolve_cwe(control_id: str) -> dict[str, list[str]] | None:
    """Resolve a CWE finding to ASVS + NIST anchor + the anchor's full crosswalk."""
    m = _CWE_RE.search(control_id or "")
    if not m:
        return None
    entry = _load_cwe_mappings().get(m.group(0).upper())
    if not entry:
        return None

    result: dict[str, list[str]] = {}
    anchor = entry.get("nist")
    if anchor:
        result[_ANCHOR_FRAMEWORK] = [anchor]
        crosswalk = lookup_control(anchor)
        if crosswalk:
            _merge(result, crosswalk)
    # Carry through any framework lists on the CWE entry itself (e.g. ASVS).
    _merge(result, {k: v for k, v in entry.items() if k not in ("title", "nist")})
    return result or None


def _resolve_reverse(framework: str, control_id: str) -> dict[str, list[str]] | None:
    """Reverse-resolve a non-anchor framework ID to its NIST anchor(s) + crosswalk."""
    rev = _reverse_index().get(framework)
    if not rev:
        return None
    anchors = rev.get((control_id or "").upper())
    if not anchors:
        return None

    result: dict[str, list[str]] = {_ANCHOR_FRAMEWORK: list(anchors)}
    for anchor in anchors:
        crosswalk = lookup_control(anchor)
        if crosswalk:
            _merge(result, crosswalk)
    # Don't echo the finding's own framework back at it.
    result.pop(framework, None)
    return result or None


def resolve_finding(finding: Finding) -> dict[str, list[str]]:
    """Return the cross-framework crosswalk for a finding, anchored on whatever
    framework/control it carries. Empty dict when nothing resolves."""
    cid = finding.control_id
    if not cid:
        return {}

    # 1. CWE bridge — applies regardless of the framework label, since SAST tools
    #    tag CWE in `control_id` while labelling the framework "OWASP ASVS 5.0".
    cwe = _resolve_cwe(cid)
    if cwe:
        return cwe

    # 2. Direct NIST 800-53 anchor.
    if finding.framework == _ANCHOR_FRAMEWORK:
        return lookup_control(cid) or {}

    # 3. Reverse lookup from another crosswalk framework.
    if finding.framework in _CROSSWALK_FRAMEWORKS:
        return _resolve_reverse(finding.framework, cid) or {}

    return {}


def enrich_with_mappings(findings: list[Finding]) -> list[Finding]:
    """Populate ``finding.mapped_controls`` with the cross-framework crosswalk,
    resolving NIST-, CWE-, and other-framework-anchored findings alike."""
    for f in findings:
        mapped = resolve_finding(f)
        if mapped:
            f.mapped_controls = mapped
    return findings


def reset_cache() -> None:
    """Test helper: drop all cached mapping tables and the reverse index."""
    _load_mappings.cache_clear()
    _load_cwe_mappings.cache_clear()
    _reverse_index.cache_clear()
