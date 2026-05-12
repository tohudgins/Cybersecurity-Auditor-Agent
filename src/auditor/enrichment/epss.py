"""EPSS (Exploit Prediction Scoring System) lookup.

EPSS is FIRST.org's daily-refreshed estimate of the probability (0-1) that a
given CVE will be exploited in the wild within the next 30 days, plus its
percentile against all CVEs that day. Combined with CISA KEV:

  KEV  = "is being exploited" (binary, lagging)
  EPSS = "likely to be exploited" (probabilistic, forward-looking)

Together they give defenders a much sharper prioritization than CVSS alone.

We cache the daily CSV at ~/.cache/auditor/epss.csv for 24 hours. The full
catalog is ~25 MB uncompressed and contains ~250k CVEs.
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

_EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_CACHE_PATH = Path.home() / ".cache" / "auditor" / "epss.csv"
_CACHE_TTL_SECONDS = 24 * 60 * 60

# Lazily populated on first lookup: cve_id (upper) → (score, percentile).
_scores: dict[str, tuple[float, float]] | None = None


def _cache_is_fresh() -> bool:
    if not _CACHE_PATH.exists():
        return False
    age = time.time() - _CACHE_PATH.stat().st_mtime
    return age < _CACHE_TTL_SECONDS


def _download_epss() -> str:
    log.info("Downloading EPSS catalog from %s", _EPSS_URL)
    req = urllib.request.Request(_EPSS_URL, headers={"User-Agent": "cybersecurity-auditor"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    return gzip.decompress(raw).decode("utf-8", errors="replace")


def _load_csv_text() -> str:
    if _cache_is_fresh():
        try:
            return _CACHE_PATH.read_text(encoding="utf-8")
        except OSError:
            log.warning("EPSS cache file unreadable; will re-download")

    try:
        text = _download_epss()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("EPSS download failed (%s); falling back to stale cache if present", e)
        if _CACHE_PATH.exists():
            return _CACHE_PATH.read_text(encoding="utf-8")
        return ""

    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(text, encoding="utf-8")
    return text


def _build_score_map() -> dict[str, tuple[float, float]]:
    """Parse the EPSS CSV. The file format is:

        #model_version:vX,score_date:YYYY-MM-DDTHH:MM:SS+00:00
        cve,epss,percentile
        CVE-2024-1234,0.97432,0.99800
        ...
    """
    text = _load_csv_text()
    if not text:
        return {}

    out: dict[str, tuple[float, float]] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#") or row[0].lower() == "cve":
            continue
        if len(row) < 3:
            continue
        cve, score, pct = row[0], row[1], row[2]
        try:
            out[cve.upper().strip()] = (float(score), float(pct))
        except ValueError:
            continue
    return out


def epss_score(cve_id: str) -> tuple[float, float] | None:
    """Return (score, percentile) for a CVE, or None if not in the catalog."""
    global _scores
    if _scores is None:
        _scores = _build_score_map()
    return _scores.get((cve_id or "").upper().strip())


def reset_cache() -> None:
    """Test helper: forget the in-memory score map."""
    global _scores
    _scores = None
