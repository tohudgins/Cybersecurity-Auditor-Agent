"""CISA Known Exploited Vulnerabilities (KEV) catalog lookup.

The KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
is the authoritative list of CVEs confirmed to be actively exploited in the wild.
Federal agencies are required by BOD 22-01 to remediate KEV vulnerabilities on
a deadline, so security teams rely on it to prioritize patching.

We cache the JSON feed locally for 24 hours.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_PATH = Path.home() / ".cache" / "auditor" / "kev.json"
_CACHE_TTL_SECONDS = 24 * 60 * 60

# Lazily populated on first lookup.
_cve_set: set[str] | None = None


def _cache_is_fresh() -> bool:
    if not _CACHE_PATH.exists():
        return False
    age = time.time() - _CACHE_PATH.stat().st_mtime
    return age < _CACHE_TTL_SECONDS


def _download_kev() -> bytes:
    log.info("Downloading CISA KEV catalog from %s", _KEV_URL)
    req = urllib.request.Request(_KEV_URL, headers={"User-Agent": "cybersecurity-auditor"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _load_catalog() -> dict:
    """Return the parsed KEV catalog, refreshing the cache if stale."""
    if _cache_is_fresh():
        try:
            return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            log.warning("KEV cache file unreadable; will re-download")

    try:
        payload = _download_kev()
    except (urllib.error.URLError, TimeoutError) as e:
        log.warning("KEV download failed (%s); falling back to stale cache if present", e)
        if _CACHE_PATH.exists():
            return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        return {"vulnerabilities": []}

    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_bytes(payload)
    return json.loads(payload)


def _build_cve_set() -> set[str]:
    catalog = _load_catalog()
    return {entry["cveID"].upper() for entry in catalog.get("vulnerabilities", []) if entry.get("cveID")}


def is_kev(cve_id: str) -> bool:
    """Return True if the given CVE is in the CISA KEV catalog."""
    global _cve_set
    if _cve_set is None:
        _cve_set = _build_cve_set()
    return (cve_id or "").upper().strip() in _cve_set


def reset_cache() -> None:
    """Test helper: forget the in-memory CVE set."""
    global _cve_set
    _cve_set = None
