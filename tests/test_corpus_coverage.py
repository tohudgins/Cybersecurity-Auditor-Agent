"""Tests for the un-indexed-framework honesty guard."""
from __future__ import annotations

from auditor.enrichment.corpus_coverage import (
    caveat_for,
    coverage_caveat,
    uncovered_frameworks,
)


def test_detects_uncovered_frameworks():
    assert uncovered_frameworks("map this to ISO 27001") == ["ISO/IEC 27001/27002"]
    assert "GDPR" in uncovered_frameworks("GDPR data protection obligations")
    assert "FedRAMP" in uncovered_frameworks("FedRAMP Moderate authorization")


def test_indexed_frameworks_are_not_flagged():
    # These ARE in the corpus → no caveat.
    assert uncovered_frameworks("What does NIST 800-53 AC-2 require?") == []
    assert uncovered_frameworks("CIS Control 5 account management") == []
    assert uncovered_frameworks("OWASP Top 10 injection") == []
    # Now indexed → no longer flagged: HIPAA, PCI, SOC 2 TSC, CMMC.
    assert uncovered_frameworks("HIPAA Security Rule access control") == []
    assert uncovered_frameworks("PCI DSS Requirement 8 authentication") == []
    assert uncovered_frameworks("assess our SOC 2 CC6.1 controls") == []
    assert uncovered_frameworks("what CMMC level 2 practices apply") == []
    assert uncovered_frameworks("") == []


def test_caveat_text():
    assert coverage_caveat([]) == ""
    single = coverage_caveat(["ISO/IEC 27001/27002"])
    assert "Coverage note" in single and "ISO" in single and "not in the indexed" in single
    multi = coverage_caveat(["ISO/IEC 27001/27002", "GDPR"])
    assert "GDPR" in multi and "are not" in multi


def test_caveat_for_convenience():
    assert caveat_for("what is AC-2") == ""
    assert caveat_for("PCI DSS requirement 8") == ""  # PCI now indexed → no caveat
    assert caveat_for("SOC 2 CC6 controls") == ""  # SOC 2 TSC now indexed → no caveat
    assert "ISO" in caveat_for("ISO 27001 Annex A")  # still un-indexed (copyright)
