"""Tests for the un-indexed-framework honesty guard."""
from __future__ import annotations

from auditor.enrichment.corpus_coverage import (
    caveat_for,
    coverage_caveat,
    uncovered_frameworks,
)


def test_detects_uncovered_frameworks():
    assert uncovered_frameworks("assess our SOC 2 CC6.1 controls") == ["SOC 2"]
    assert "CMMC" in uncovered_frameworks("what CMMC level 2 practices apply")
    assert "ISO/IEC 27001/27002" in uncovered_frameworks("map this to ISO 27001")
    assert "GDPR" in uncovered_frameworks("GDPR data protection obligations")


def test_indexed_frameworks_are_not_flagged():
    # These ARE in the corpus → no caveat.
    assert uncovered_frameworks("What does NIST 800-53 AC-2 require?") == []
    assert uncovered_frameworks("CIS Control 5 account management") == []
    assert uncovered_frameworks("OWASP Top 10 injection") == []
    # HIPAA (45 CFR 164) and PCI DSS v4 are now indexed → no longer flagged.
    assert uncovered_frameworks("HIPAA Security Rule access control") == []
    assert uncovered_frameworks("PCI DSS Requirement 8 authentication") == []
    assert uncovered_frameworks("") == []


def test_caveat_text():
    assert coverage_caveat([]) == ""
    single = coverage_caveat(["SOC 2"])
    assert "Coverage note" in single and "SOC 2" in single and "not in the indexed" in single
    multi = coverage_caveat(["SOC 2", "CMMC"])
    assert "SOC 2, CMMC" in multi and "are not" in multi


def test_caveat_for_convenience():
    assert caveat_for("what is AC-2") == ""
    assert caveat_for("PCI DSS requirement 8") == ""  # PCI now indexed → no caveat
    assert "SOC 2" in caveat_for("SOC 2 CC6 controls")
