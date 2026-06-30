"""Import the authoritative NIST SP 800-53 Rev. 5 catalog + 800-53B baselines.

NIST publishes the control catalog and the Low/Moderate/High baselines as
machine-readable OSCAL content. This module fetches those, parses them into the
two data files the auditor reads — ``data/baselines/control_catalog.json``
(id→title) and ``data/baselines/baselines.json`` (named baseline membership) —
and (with ``--write``) replaces the curated files with the authoritative set so
the baselines are *provably complete* at NIST's own granularity (enhancements
included).

Design — mirrors ``olir_import.py``:
* The **curated files remain the source of truth** for CI / the demo (no
  network). This importer is the refresh path; ``--write`` overwrites them.
* The fetcher is **injectable** so the parser is unit-tested offline against a
  small OSCAL fixture (``tests/test_baseline_import.py``).

OSCAL ids are lowercase dotted (``ac-2``, ``ac-2.1``); we canonicalize to the
project's shape (``AC-2``, ``AC-2(1)``).

Run:
    python -m auditor.ingest.baseline_import --fetch          # preview counts
    python -m auditor.ingest.baseline_import --fetch --write  # refresh data files
"""
from __future__ import annotations

import argparse
import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator

from auditor.config import settings

log = logging.getLogger(__name__)

_BASE_DIR = settings.data_dir / "baselines"
_CATALOG_FILE = _BASE_DIR / "control_catalog.json"
_BASELINES_FILE = _BASE_DIR / "baselines.json"

_OSCAL_ROOT = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json"
)
CATALOG_URL = f"{_OSCAL_ROOT}/NIST_SP-800-53_rev5_catalog.json"
# Resolved-profile catalogs enumerate exactly the controls each baseline includes.
BASELINE_URLS: dict[str, str] = {
    "low": f"{_OSCAL_ROOT}/NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json",
    "moderate": f"{_OSCAL_ROOT}/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json",
    "high": f"{_OSCAL_ROOT}/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json",
}
_BASELINE_LABELS = {
    "low": "NIST SP 800-53B — Low Impact",
    "moderate": "NIST SP 800-53B — Moderate Impact",
    "high": "NIST SP 800-53B — High Impact",
}


def fetch_json(url: str, timeout: int = 60) -> dict:
    """Download and parse an OSCAL JSON document. Raises on network/parse error."""
    log.info("Fetching OSCAL content from %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "cybersecurity-auditor"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read())


def _canonical_id(oscal_id: str) -> str:
    """``ac-2`` → ``AC-2``; ``ac-2.1`` → ``AC-2(1)``."""
    fam, _, rest = oscal_id.partition("-")
    if not rest:
        return oscal_id.upper()
    base, dot, enh = rest.partition(".")
    head = f"{fam.upper()}-{base}"
    return f"{head}({enh})" if dot else head


def _walk_controls(node: dict) -> Iterator[dict]:
    """Yield every control object in an OSCAL catalog (groups + nested enhancements)."""
    for group in node.get("groups", []) or []:
        yield from _walk_controls(group)
    for control in node.get("controls", []) or []:
        yield control
        yield from _walk_controls(control)  # enhancements nest under their base


def parse_catalog(payload: dict) -> dict[str, str]:
    """Parse the OSCAL catalog into ``{canonical_control_id: title}``."""
    catalog = payload.get("catalog", payload)
    out: dict[str, str] = {}
    for control in _walk_controls(catalog):
        cid = control.get("id")
        title = control.get("title")
        if cid and title:
            out[_canonical_id(cid)] = title.strip()
    return out


def parse_baseline(payload: dict) -> list[str]:
    """Parse a resolved-profile catalog into its sorted canonical control-ID list."""
    catalog = payload.get("catalog", payload)
    ids = {_canonical_id(c["id"]) for c in _walk_controls(catalog) if c.get("id")}
    return sorted(ids, key=_sort_key)


def _sort_key(cid: str) -> tuple[str, int, int]:
    fam, _, rest = cid.partition("-")
    base, _, enh = rest.partition("(")
    base_n = int("".join(ch for ch in base if ch.isdigit()) or 0)
    enh_n = int("".join(ch for ch in enh if ch.isdigit()) or 0)
    return (fam, base_n, enh_n)


def import_baselines(
    fetcher: Callable[[str], dict] = fetch_json,
    write: bool = False,
) -> dict[str, int]:
    """Fetch + parse the catalog and all baselines; optionally rewrite the data files.

    Returns ``{"catalog": n_controls, "low": n, "moderate": n, "high": n}``.
    Network failure on any document aborts the write (the curated files are only
    replaced when the full authoritative set was fetched).
    """
    catalog = parse_catalog(fetcher(CATALOG_URL))
    baselines = {name: parse_baseline(fetcher(url)) for name, url in BASELINE_URLS.items()}

    counts = {"catalog": len(catalog)}
    counts.update({name: len(ids) for name, ids in baselines.items()})

    if write:
        _write_catalog(catalog)
        _write_baselines(baselines)
        log.info("Wrote authoritative catalog + baselines into %s", _BASE_DIR)
    return counts


def _write_catalog(catalog: dict[str, str]) -> None:
    doc = {
        "_meta": {
            "description": (
                "NIST SP 800-53 Rev. 5 control catalog (id -> title), imported from "
                "the authoritative NIST OSCAL content. Includes enhancements."
            ),
            "source": CATALOG_URL,
            "granularity": "control-and-enhancement",
        },
        "controls": dict(sorted(catalog.items(), key=lambda kv: _sort_key(kv[0]))),
    }
    _CATALOG_FILE.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_baselines(baselines: dict[str, list[str]]) -> None:
    doc = {
        "_meta": {
            "description": (
                "NIST SP 800-53B baselines, imported from the authoritative NIST OSCAL "
                "resolved-profile catalogs. Each list is complete and explicit "
                "(extends=null); membership matches NIST exactly at control + enhancement "
                "granularity."
            ),
            "source": {name: BASELINE_URLS[name] for name in baselines},
            "granularity": "control-and-enhancement",
            "compose": "explicit",
        },
        "baselines": {
            name: {"label": _BASELINE_LABELS.get(name, name), "extends": None, "controls": ids}
            for name, ids in baselines.items()
        },
    }
    _BASELINES_FILE.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Fetch + parse the OSCAL content.")
    parser.add_argument("--write", action="store_true", help="Overwrite the curated data files.")
    args = parser.parse_args()

    if not args.fetch:
        parser.print_help()
        return

    try:
        counts = import_baselines(write=args.write)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
        print(f"Import failed: {exc}")
        return
    print(f"  catalog: {counts['catalog']} controls (incl. enhancements)")
    for name in ("low", "moderate", "high"):
        print(f"  {name}: {counts.get(name, 0)} controls")
    if not args.write:
        print("\nDry run (no --write): data files unchanged.")


if __name__ == "__main__":
    main()
