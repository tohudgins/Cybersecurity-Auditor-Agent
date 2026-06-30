"""Finding normalization: cross-tool de-duplication + risk scoring + ranking.

Multiple scanners (Trivy, Semgrep, Bandit, gitleaks, Checkov, hadolint) plus the
LLM can independently report the same underlying issue. This module is the
"aggregation" layer real vulnerability-management platforms (DefectDojo, etc.)
provide: it collapses duplicates, assigns each surviving finding a single
0-100 risk score, and orders the list so the report leads with what matters.

The risk score is deterministic and explainable:

    base   = severity baseline (critical 90 / high 70 / medium 45 / low 20 / info 5)
    +CVSS  = max(base, cvss_base * 10)          # CVE findings dominated by CVSS
    +EPSS  = + epss_probability * 10            # likelihood of exploitation (≤ +10)
    +KEV   = floor at 95, then +3              # actively exploited in the wild

De-duplication groups findings by a signature (same CVE; or same file:line + CWE;
or same normalized title within one artifact), keeps the highest-scoring member,
and notes how many other scanners corroborated it (agreement is itself a signal).
"""
from __future__ import annotations

import re

from auditor.models import AuditScope, Finding

_SEVERITY_BASE: dict[str, float] = {
    "critical": 90.0,
    "high": 70.0,
    "medium": 45.0,
    "low": 20.0,
    "info": 5.0,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_LOCATION_RE = re.compile(r"^\s*([^\s:]+):(\d+)")
_TITLE_TAG_RE = re.compile(r"^\s*\[[^\]]+\]\s*")  # leading "[B602] " / "[semgrep] " / "[KEV] "

# Controls whose findings get *more likely* to be exploited when the system is
# internet-facing (exposure / boundary / remote-access / transport).
_EXPOSURE_CONTROLS = frozenset({
    "AC-17", "AC-3", "AC-4", "SC-5", "SC-7", "SC-8", "SC-23", "SI-10", "CA-3",
})
# Controls whose findings carry *more impact* when the system handles sensitive
# data (confidentiality / crypto / at-rest / authenticator / least-privilege).
_CONFIDENTIALITY_CONTROLS = frozenset({
    "SC-28", "SC-13", "SC-12", "SC-8", "IA-5", "AC-3", "AC-6", "MP-6", "AU-9",
})
# Data classifications that signal elevated impact.
_SENSITIVE_DATA = frozenset({
    "pii", "phi", "pci", "chd", "cui", "confidential", "secret", "restricted",
    "regulated", "sensitive",
})

# Max contextual uplift from each dimension (kept bounded + explainable).
_EXPOSURE_UPLIFT = 8.0
_DATA_UPLIFT = 8.0


def _anchor_controls(f: Finding) -> set[str]:
    """The 800-53 anchor control(s) a finding touches, base-id form."""
    ids: set[str] = set()
    if f.control_id:
        ids.add(_base_control(f.control_id))
    mapped = (f.mapped_controls or {}).get("NIST SP 800-53 Rev. 5") or []
    ids.update(_base_control(c) for c in mapped)
    return ids


def _base_control(cid: str) -> str:
    cid = (cid or "").strip()
    paren = cid.find("(")
    return cid[:paren].strip() if paren != -1 else cid


def _context_uplift(f: Finding, scope: AuditScope) -> float:
    """Deterministic risk uplift from engagement context (likelihood × impact).

    Only non-info findings on relevant control families are adjusted, and the
    uplift is bounded so context tunes priority without overwhelming the
    severity/CVSS/EPSS signal.
    """
    if f.severity == "info":
        return 0.0
    controls = _anchor_controls(f)
    uplift = 0.0
    if scope.internet_facing and (controls & _EXPOSURE_CONTROLS):
        uplift += _EXPOSURE_UPLIFT
    data = (scope.data_classification or "").strip().lower()
    if data and any(tok in data for tok in _SENSITIVE_DATA) and (controls & _CONFIDENTIALITY_CONTROLS):
        uplift += _DATA_UPLIFT
    return uplift


def compute_risk_score(f: Finding, scope: AuditScope | None = None) -> float:
    """Return a deterministic 0-100 risk score blending severity, CVSS, EPSS, KEV,
    plus a bounded contextual uplift from engagement scope (internet exposure +
    data sensitivity) when *scope* is supplied."""
    score = _SEVERITY_BASE.get(f.severity, 45.0)

    if f.cvss_score is not None:
        score = max(score, f.cvss_score * 10.0)
    if f.epss_score is not None:
        score += f.epss_score * 10.0
    if f.kev:
        score = max(score, 95.0) + 3.0

    if scope is not None:
        score += _context_uplift(f, scope)

    return round(min(score, 100.0), 1)


def _normalize_title(title: str) -> str:
    return _TITLE_TAG_RE.sub("", title).strip().lower().rstrip(".:")


def _signature(f: Finding) -> tuple:
    """A hashable identity for de-duplication, most-specific first.

    1. Same CVE → one finding regardless of which scanner reported it.
    2. Same file:line + CWE → cross-tool SAST overlap (e.g. Bandit + Semgrep).
    3. Same normalized title within the same artifact → near-identical reports.
    """
    cve = _CVE_RE.search(f.title) or _CVE_RE.search(f.evidence)
    if cve:
        return ("cve", cve.group(0).upper())

    loc = _LOCATION_RE.match(f.evidence)
    cls = (f.control_id or "").upper()
    if loc and cls.startswith("CWE-"):
        return ("loc-cwe", loc.group(1), loc.group(2), cls)

    return ("title", _normalize_title(f.title), f.source_artifact)


def finding_signature(f: Finding) -> tuple:
    """Public, stable identity for a finding.

    Shared with the run-to-run diff layer (:mod:`auditor.diff`) so a finding is
    matched across audits exactly the way de-duplication matches it within one.
    """
    return _signature(f)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a signature, keeping the highest-scoring one.

    Assumes ``risk_score`` is already populated. The survivor gets a corroboration
    note when other scanners independently flagged the same issue.
    """
    groups: dict[tuple, list[Finding]] = {}
    order: list[tuple] = []
    for f in findings:
        sig = _signature(f)
        if sig not in groups:
            groups[sig] = []
            order.append(sig)
        groups[sig].append(f)

    survivors: list[Finding] = []
    for sig in order:
        members = groups[sig]
        winner = max(members, key=lambda f: f.risk_score or 0.0)
        extra = len(members) - 1
        # Only annotate corroboration for genuine cross-source agreement, not the
        # always-on "scanner not installed" info notices.
        if extra > 0 and winner.severity != "info":
            winner.evidence = (
                f"{winner.evidence}\n\n_Corroborated by {extra} other scanner "
                f"finding{'s' if extra != 1 else ''}._"
            )
        survivors.append(winner)
    return survivors


def normalize_findings(findings: list[Finding], scope: AuditScope | None = None) -> list[Finding]:
    """Score, de-duplicate, and rank findings (highest risk first).

    Returns a new ordered list; ``risk_score`` is set on each surviving finding.
    When *scope* is supplied, scoring applies the engagement's contextual uplift
    (internet exposure + data sensitivity).
    """
    for f in findings:
        f.risk_score = compute_risk_score(f, scope)

    deduped = deduplicate(findings)
    deduped.sort(
        key=lambda f: (-(f.risk_score or 0.0), _severity_rank(f.severity), f.title.lower())
    )
    return deduped


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 99)
