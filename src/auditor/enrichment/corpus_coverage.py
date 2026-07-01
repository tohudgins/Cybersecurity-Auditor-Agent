"""Honesty guard for frameworks not in the indexed corpus.

Compliance Q&A and the advisory auditor are RAG-grounded, so they can only cite
what's indexed (NIST family, CIS Controls, OWASP, MITRE ATT&CK, CISA ZTMM). When
a user asks about a framework whose *text* isn't indexed (PCI DSS, SOC 2, ISO
27001, HIPAA, GDPR, CMMC, ...), retrieval silently substitutes NIST/CIS proxies.
That's fine as a *mapping*, but the answer must say so rather than imply it quoted
the standard. This module detects that case and renders the caveat.

(Note: baseline *selection* still supports CIS/PCI/CSF/SOC 2 — that projects
findings through the crosswalk. This is about the *text corpus* for Q&A/advice.)
"""
from __future__ import annotations

import re

# Framework whose own text is NOT indexed → display label. Detection is
# deliberately conservative (word-boundaried acronyms/names).
_UNCOVERED: dict[str, re.Pattern[str]] = {
    "PCI DSS": re.compile(r"\bPCI(?:[-\s]?DSS)?\b", re.IGNORECASE),
    "SOC 2": re.compile(r"\bSOC[-\s]?2\b", re.IGNORECASE),
    "ISO/IEC 27001/27002": re.compile(r"\bISO(?:/IEC)?[-\s]?2700[12]\b", re.IGNORECASE),
    "HIPAA": re.compile(r"\bHIPAA\b", re.IGNORECASE),
    "GDPR": re.compile(r"\bGDPR\b", re.IGNORECASE),
    "CMMC": re.compile(r"\bCMMC\b", re.IGNORECASE),
    "FedRAMP": re.compile(r"\bFedRAMP\b", re.IGNORECASE),
    "CCPA": re.compile(r"\bCCPA\b", re.IGNORECASE),
    "SOX (Sarbanes-Oxley)": re.compile(r"\b(SOX|Sarbanes[-\s]?Oxley)\b", re.IGNORECASE),
    "NYDFS": re.compile(r"\bNYDFS\b", re.IGNORECASE),
    "NERC CIP": re.compile(r"\bNERC[-\s]?CIP\b", re.IGNORECASE),
}


def uncovered_frameworks(text: str) -> list[str]:
    """Framework labels the text references whose own text isn't indexed."""
    if not text:
        return []
    return [name for name, rx in _UNCOVERED.items() if rx.search(text)]


def coverage_caveat(names: list[str]) -> str:
    """Render the Markdown honesty caveat for un-indexed frameworks (or '')."""
    if not names:
        return ""
    joined = ", ".join(names)
    is_are = "is" if len(names) == 1 else "are"
    src = names[0] if len(names) == 1 else "each standard's"
    return (
        f"> ⚠️ **Coverage note:** {joined} {is_are} not in the indexed framework "
        "corpus. The guidance below is derived from the **mapped NIST 800-53 / CIS / "
        "OWASP** controls, not the standard's own text — verify against the "
        f"authoritative {src} source before relying on it for a compliance decision."
    )


def caveat_for(text: str) -> str:
    """Convenience: caveat string for whatever un-indexed frameworks *text* names."""
    return coverage_caveat(uncovered_frameworks(text))
