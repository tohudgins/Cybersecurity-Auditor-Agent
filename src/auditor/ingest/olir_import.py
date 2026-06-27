"""Import cross-framework mappings from NIST's official OLIR / CPRT exports.

NIST's OLIR program (Open Security Controls Assessment Language Informative
References) publishes machine-readable crosswalks between frameworks, served
through the Cybersecurity & Privacy Reference Tool (CPRT). This module fetches
those relationship exports and normalizes them into the same NIST SP 800-53
Rev. 5-anchored structure used by ``data/mappings/control_mappings.json``, then
merges them into the curated file.

Design notes
------------
* The **curated file remains the source of truth** for CI and the demo (no
  network). This importer is an *augmentation* path: ``--merge`` unions the
  fetched references into the curated entries; curated titles are preserved.
* The parser is **orientation-agnostic**. OLIR relationship records name a
  "focal" and a "reference" element; rather than assume which side is 800-53,
  we detect the 800-53 control by its ID shape and treat the other element as
  the reference-framework ID. This keeps the parser robust to per-export
  differences and is exercised by ``tests/test_olir_import.py``.
* Each :class:`OlirSource` declares which framework label its reference IDs map
  to, plus a regex that recognizes those IDs (so we don't mistake, say, a PCI
  requirement number for a CIS safeguard).

Run:
    python -m auditor.ingest.olir_import --fetch            # preview parsed counts
    python -m auditor.ingest.olir_import --fetch --merge    # merge into curated file
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from auditor.config import settings

log = logging.getLogger(__name__)

_MAPPING_FILE = settings.data_dir / "mappings" / "control_mappings.json"

# A NIST SP 800-53 control ID, e.g. "AC-2", "AC-2(1)", "si-7". Base captured.
# The negative lookbehind stops "AA-09" inside a CSF subcategory like "PR.AA-09"
# from being mistaken for a 800-53 control.
_NIST_RE = re.compile(r"(?<![A-Za-z0-9.])([A-Z]{2}-\d{1,3})(?:\(\d+\))?", re.IGNORECASE)


@dataclass(frozen=True)
class OlirSource:
    """One OLIR/CPRT crosswalk export to import."""

    name: str
    url: str
    framework: str  # the framework label its reference IDs belong to
    id_pattern: str  # regex recognizing that framework's element IDs


# CPRT JSON export endpoints. URLs are the documented CPRT download shape; verify
# the current query params at https://csrc.nist.gov/projects/cprt before a
# production import — the curated file is what ships and is tested.
OLIR_SOURCES: tuple[OlirSource, ...] = (
    OlirSource(
        name="csf-2.0-to-800-53r5",
        url="https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/element/mapping/sp_800_53_5_1_1",
        framework="NIST CSF 2.1",
        id_pattern=r"[A-Z]{2}\.[A-Z]{2}-\d{2}",
    ),
    OlirSource(
        name="iso-27001-2022-to-800-53r5",
        url="https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/iso_iec_27001_2022/element/mapping/sp_800_53_5_1_1",
        framework="ISO 27001:2022",
        id_pattern=r"A\.\d{1,2}\.\d{1,2}",
    ),
)


def fetch_json(url: str, timeout: int = 60) -> dict:
    """Download and parse a CPRT JSON export. Raises on network/parse failure."""
    log.info("Fetching OLIR export from %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "cybersecurity-auditor"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read())


def _iter_strings(obj) -> list[str]:
    """Recursively collect every string value in a nested JSON structure."""
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_iter_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_iter_strings(v))
    return out


def _records(payload: dict) -> list:
    """Pull the list of relationship records out of common CPRT container keys."""
    for container in ("relationships", "relationship_mappings", "mappings"):
        node = payload.get(container)
        if isinstance(node, list):
            return node
    response = payload.get("response")
    if isinstance(response, dict):
        return _records(response)
    return []


def _extract_pair(record: dict, id_re: re.Pattern) -> tuple[str, str] | None:
    """From one relationship record, return ``(nist_base_id, reference_id)``.

    Orientation-agnostic: finds the 800-53 control by ID shape and the reference
    framework ID by the source's pattern, wherever they sit in the record.
    """
    strings = _iter_strings(record)

    nist_base: str | None = None
    for s in strings:
        m = _NIST_RE.search(s)
        if m:
            nist_base = m.group(1).upper()
            break

    reference: str | None = None
    for s in strings:
        m = id_re.search(s)
        if m:
            reference = m.group(0)
            break

    if nist_base and reference:
        return nist_base, reference
    return None


def parse_relationships(payload: dict, source: OlirSource) -> dict[str, list[str]]:
    """Parse a CPRT export into ``{nist_base_id: [reference_ids]}`` for one source."""
    id_re = re.compile(source.id_pattern)
    out: dict[str, list[str]] = {}
    for record in _records(payload):
        if not isinstance(record, dict):
            continue
        pair = _extract_pair(record, id_re)
        if not pair:
            continue
        nist_base, reference = pair
        ids = out.setdefault(nist_base, [])
        if reference not in ids:
            ids.append(reference)
    return out


def merge_into_curated(
    curated: dict,
    parsed: dict[str, list[str]],
    framework: str,
) -> tuple[int, int]:
    """Union *parsed* reference IDs into *curated* under *framework*.

    Only augments controls already present in the curated table (so the importer
    never invents a control without a vetted title/crosswalk). Returns
    ``(controls_touched, ids_added)``.
    """
    mappings = curated.setdefault("mappings", {})
    touched = added = 0
    for nist_id, refs in parsed.items():
        entry = mappings.get(nist_id)
        if entry is None:
            continue
        dst = entry.setdefault(framework, [])
        before = len(dst)
        for ref in refs:
            if ref not in dst:
                dst.append(ref)
        if len(dst) != before:
            touched += 1
            added += len(dst) - before
    return touched, added


def import_olir(
    sources: tuple[OlirSource, ...] = OLIR_SOURCES,
    fetcher: Callable[[str], dict] = fetch_json,
    merge: bool = False,
    mapping_file: Path = _MAPPING_FILE,
) -> dict[str, tuple[int, int]]:
    """Fetch + parse every source; optionally merge into the curated file.

    Returns ``{source_name: (controls_touched, ids_added)}``. Network failures
    on one source are logged and skipped, not fatal.
    """
    curated = json.loads(mapping_file.read_text(encoding="utf-8")) if mapping_file.exists() else {"mappings": {}}
    results: dict[str, tuple[int, int]] = {}

    for source in sources:
        try:
            payload = fetcher(source.url)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            log.warning("Skipping %s — fetch/parse failed: %s", source.name, exc)
            results[source.name] = (0, 0)
            continue
        parsed = parse_relationships(payload, source)
        results[source.name] = merge_into_curated(curated, parsed, source.framework)

    if merge:
        mapping_file.write_text(json.dumps(curated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        log.info("Merged OLIR references into %s", mapping_file)

    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Fetch + parse the OLIR exports.")
    parser.add_argument("--merge", action="store_true", help="Write merged references into the curated file.")
    args = parser.parse_args()

    if not args.fetch:
        parser.print_help()
        return

    results = import_olir(merge=args.merge)
    for name, (touched, added) in results.items():
        print(f"  {name}: {added} reference IDs added across {touched} controls")
    if not args.merge:
        print("\nDry run (no --merge): curated file unchanged.")


if __name__ == "__main__":
    main()
