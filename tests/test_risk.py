"""Tests for the finding normalization / de-dup / risk-scoring layer."""
from __future__ import annotations

from auditor.enrichment.risk import (
    compute_risk_score,
    deduplicate,
    normalize_findings,
)
from auditor.models import AuditScope, Finding


def _f(title: str, severity: str = "medium", **kw) -> Finding:
    return Finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        evidence=kw.pop("evidence", "evidence"),
        recommendation="fix it",
        **kw,
    )


# ---- Risk scoring -----------------------------------------------------------


def test_risk_score_severity_baseline():
    assert compute_risk_score(_f("x", "critical")) == 90.0
    assert compute_risk_score(_f("x", "high")) == 70.0
    assert compute_risk_score(_f("x", "medium")) == 45.0
    assert compute_risk_score(_f("x", "low")) == 20.0
    assert compute_risk_score(_f("x", "info")) == 5.0


# ---- Contextual risk uplift (engagement scope) ------------------------------


def _nist(control_id: str, severity: str = "high") -> Finding:
    return _f("ctx", severity, framework="NIST SP 800-53 Rev. 5", control_id=control_id)


def test_internet_facing_uplifts_exposure_controls():
    f = _nist("SC-7")  # boundary protection
    base = compute_risk_score(f)
    ctx = compute_risk_score(f, AuditScope(internet_facing=True))
    assert ctx > base
    # A non-exposure control is unaffected by internet exposure.
    assert compute_risk_score(_nist("AT-2"), AuditScope(internet_facing=True)) == compute_risk_score(_nist("AT-2"))


def test_sensitive_data_uplifts_confidentiality_controls():
    f = _nist("SC-28")  # protection of information at rest
    base = compute_risk_score(f)
    ctx = compute_risk_score(f, AuditScope(data_classification="PII"))
    assert ctx > base


def test_context_uplift_is_bounded_and_skips_info():
    # Both dimensions on a control in both sets → bounded uplift, never over 100.
    f = _nist("SC-8", "critical")  # in exposure AND confidentiality sets
    ctx = compute_risk_score(f, AuditScope(internet_facing=True, data_classification="PHI"))
    assert ctx <= 100.0
    # Info findings get no uplift.
    info = _nist("SC-7", "info")
    assert compute_risk_score(info, AuditScope(internet_facing=True)) == compute_risk_score(info)


def test_no_scope_preserves_legacy_score():
    assert compute_risk_score(_nist("SC-7")) == 70.0  # unchanged when scope omitted


def test_risk_score_cvss_dominates_when_higher():
    # A "high" finding with a 9.8 CVSS should score from CVSS (98), not the 70 baseline.
    f = _f("cve", "high", cvss_score=9.8)
    assert compute_risk_score(f) == 98.0


def test_risk_score_epss_adds_likelihood_weight():
    base = compute_risk_score(_f("x", "medium"))
    f = _f("x", "medium", epss_score=0.5)  # +5
    assert compute_risk_score(f) == base + 5.0


def test_risk_score_kev_floors_and_caps_at_100():
    f = _f("x", "low", kev=True)  # KEV floors at 95, +3 = 98
    assert compute_risk_score(f) == 98.0
    # Never exceeds 100 even with everything stacked.
    maxed = _f("x", "critical", cvss_score=10.0, epss_score=1.0, kev=True)
    assert compute_risk_score(maxed) == 100.0


# ---- De-duplication ---------------------------------------------------------


def test_dedup_same_cve_collapses_keeping_highest_score():
    a = _f("requests 2.0: CVE-2023-9999", "medium")
    b = _f("[KEV] requests 2.0: CVE-2023-9999", "critical", kev=True)
    for x in (a, b):
        x.risk_score = compute_risk_score(x)
    out = deduplicate([a, b])
    assert len(out) == 1
    assert out[0].kev is True  # the higher-scoring KEV finding survived


def test_dedup_same_file_line_and_cwe_merges_across_tools():
    bandit = _f("[B602] subprocess shell", "high", control_id="CWE-78",
                evidence="app/x.py:42 — subprocess with shell=True")
    semgrep = _f("[semgrep] dangerous-subprocess", "high", control_id="CWE-78",
                 evidence="app/x.py:42 — Detected subprocess with non-static input")
    for x in (bandit, semgrep):
        x.risk_score = compute_risk_score(x)
    out = deduplicate([bandit, semgrep])
    assert len(out) == 1
    assert "Corroborated by 1 other scanner finding" in out[0].evidence


def test_dedup_keeps_distinct_findings_apart():
    a = _f("[B602] shell", "high", control_id="CWE-78", evidence="app/x.py:42 — shell")
    b = _f("[B105] hardcoded", "high", control_id="CWE-259", evidence="app/x.py:99 — pw")
    for x in (a, b):
        x.risk_score = compute_risk_score(x)
    out = deduplicate([a, b])
    assert len(out) == 2


def test_dedup_does_not_annotate_info_notices():
    a = _f("Trivy not installed", "info", evidence="no trivy")
    b = _f("Trivy not installed", "info", evidence="no trivy")
    for x in (a, b):
        x.risk_score = compute_risk_score(x)
    out = deduplicate([a, b])
    assert len(out) == 1
    assert "Corroborated" not in out[0].evidence


# ---- End-to-end normalization ----------------------------------------------


def test_normalize_scores_dedups_and_ranks():
    findings = [
        _f("low thing", "low"),
        _f("[KEV] pkg: CVE-2021-44228", "critical", kev=True, cvss_score=10.0),
        _f("medium thing", "medium"),
    ]
    out = normalize_findings(findings)
    # All scored
    assert all(f.risk_score is not None for f in out)
    # Ranked highest-risk first → the KEV/CVSS critical leads.
    assert "CVE-2021-44228" in out[0].title
    assert out[0].risk_score == 100.0
    # Ascending severity afterwards
    assert [f.severity for f in out] == ["critical", "medium", "low"]
