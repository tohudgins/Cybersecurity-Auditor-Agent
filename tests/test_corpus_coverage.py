"""Tests for the un-indexed-framework honesty guard."""
from __future__ import annotations

from auditor.enrichment.corpus_coverage import (
    caveat_for,
    coverage_caveat,
    uncovered_frameworks,
)


def test_detects_uncovered_frameworks():
    assert uncovered_frameworks("How do I meet PCI DSS Requirement 8?") == ["PCI DSS"]
    assert "SOC 2" in uncovered_frameworks("assess our SOC 2 CC6.1 controls")
    assert "HIPAA" in uncovered_frameworks("HIPAA Security Rule access control")
    assert "ISO/IEC 27001/27002" in uncovered_frameworks("map this to ISO 27001")


def test_indexed_frameworks_are_not_flagged():
    # These ARE in the corpus → no caveat.
    assert uncovered_frameworks("What does NIST 800-53 AC-2 require?") == []
    assert uncovered_frameworks("CIS Control 5 account management") == []
    assert uncovered_frameworks("OWASP Top 10 injection") == []
    assert uncovered_frameworks("") == []


def test_caveat_text():
    assert coverage_caveat([]) == ""
    single = coverage_caveat(["PCI DSS"])
    assert "Coverage note" in single and "PCI DSS" in single and "not in the indexed" in single
    multi = coverage_caveat(["PCI DSS", "HIPAA"])
    assert "PCI DSS, HIPAA" in multi and "are not" in multi


def test_caveat_for_convenience():
    assert caveat_for("what is AC-2") == ""
    assert "PCI DSS" in caveat_for("PCI DSS requirement 8")
