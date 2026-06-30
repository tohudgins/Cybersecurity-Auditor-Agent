"""NIST SP 800-53 Rev. 5 control catalog + named assessment baselines.

Two jobs:

1. **Titles** — ``catalog_title(control_id)`` resolves *any* 800-53 control (base
   or enhancement) to its title, so an assessment row never renders blank when a
   finding anchors to a control outside the curated crosswalk (e.g. ``IR-2``,
   ``PE-6``, ``AC-16(4)``).

2. **Baselines** — ``baseline_control_ids(name)`` returns the control set a real
   engagement assesses against (NIST SP 800-53B Low / Moderate / High), the
   honest denominator for coverage. Baselines compose additively (moderate = low
   + adds; high = moderate + adds) and every member is validated against the
   catalog at load time, so there are no dangling/untitled controls.

Data lives in ``data/baselines/``; no code change is needed to extend a baseline.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache

from auditor.config import settings

log = logging.getLogger(__name__)

_BASE_DIR = settings.data_dir / "baselines"
_CATALOG_FILE = _BASE_DIR / "control_catalog.json"
_BASELINES_FILE = _BASE_DIR / "baselines.json"

# The curated-crosswalk baseline keeps its historical name; anything else is a
# named impact baseline resolved from baselines.json.
CURATED_BASELINE = "auditor-curated"


def _base_id(control_id: str) -> str:
    """Strip an enhancement suffix: ``AC-2(1)`` -> ``AC-2``."""
    cid = (control_id or "").strip()
    paren = cid.find("(")
    return cid[:paren].strip() if paren != -1 else cid


@lru_cache(maxsize=1)
def _catalog() -> dict[str, str]:
    try:
        data = json.loads(_CATALOG_FILE.read_text(encoding="utf-8"))
        return data.get("controls", {})
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Could not load control catalog: %s", exc)
        return {}


def catalog_title(control_id: str) -> str | None:
    """Title for any 800-53 control (enhancements fall back to their base)."""
    if not control_id:
        return None
    cat = _catalog()
    cid = control_id.strip()
    return cat.get(cid) or cat.get(_base_id(cid))


def catalog_control_ids() -> list[str]:
    """All base controls in the catalog (the control universe)."""
    return list(_catalog().keys())


@lru_cache(maxsize=1)
def _baselines_raw() -> dict:
    try:
        return json.loads(_BASELINES_FILE.read_text(encoding="utf-8")).get("baselines", {})
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Could not load baselines: %s", exc)
        return {}


@lru_cache(maxsize=16)
def baseline_control_ids(name: str) -> list[str]:
    """Resolve a named baseline to its full, catalog-validated control-ID list.

    Composes the ``extends`` chain (high → moderate → low), de-duplicates, drops
    any id absent from the catalog (so every returned control has a title), and
    sorts by family then number. Unknown baseline → empty list.
    """
    raw = _baselines_raw()
    seen: set[str] = set()
    chain: list[str] = []
    cur: str | None = name
    # Walk the extends chain, guarding against cycles.
    while cur and cur in raw and cur not in chain:
        chain.append(cur)
        cur = raw[cur].get("extends")

    catalog = _catalog()
    ids: list[str] = []
    for level in chain:
        for cid in raw[level].get("controls", []):
            if cid in seen:
                continue
            seen.add(cid)
            if cid in catalog:
                ids.append(cid)
            else:  # dangling id — keep the baseline honest by not inventing it
                log.warning("Baseline %r references uncatalogued control %s; skipping", name, cid)
    return sorted(ids, key=_sort_key)


def baseline_label(name: str) -> str:
    """Human label for a named baseline, falling back to the name itself."""
    return _baselines_raw().get(name, {}).get("label", name)


def list_baselines() -> list[str]:
    """Named baselines available (excludes the curated-crosswalk default)."""
    return list(_baselines_raw().keys())


def _sort_key(cid: str) -> tuple[str, int]:
    fam, _, num = cid.partition("-")
    digits = "".join(c for c in num if c.isdigit())
    return (fam, int(digits) if digits else 0)


def reset_cache() -> None:
    """Test helper: drop the catalog/baseline caches."""
    _catalog.cache_clear()
    _baselines_raw.cache_clear()
    baseline_control_ids.cache_clear()
