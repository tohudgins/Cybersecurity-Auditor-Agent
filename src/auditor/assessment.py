"""Control-coverage assessment — turn findings into a per-control verdict.

A scanner produces *findings* (problems). An auditor produces an *assessment*:
for every control in the selected baseline, a verdict (satisfied / not-satisfied
/ partial / not-assessed) plus the method used and the evidence. This module is
that layer. It runs after enrichment + normalization, so every finding already
carries its NIST 800-53 anchor (directly or via `mapped_controls`).

Coverage model
--------------
Each artifact *kind* declares which control aspects its checks exercise
(`_KIND_COVERAGE`). For a given run:

* a control with one or more findings   → ``not-satisfied`` (``partial`` if the
  worst finding is only low/info severity);
* a control a scanner exercised cleanly → ``satisfied``;
* anything else in the baseline          → ``not-assessed``.

The honest denominator — how many baseline controls went unassessed because no
artifact covered them — is what distinguishes an audit from a scan dump.
"""
from __future__ import annotations

import re
from collections import defaultdict

from auditor.enrichment.catalog import (
    CURATED_BASELINE,
    baseline_control_ids,
    baseline_label,
    framework_control_ids,
    framework_crosswalk_name,
    framework_label,
    framework_title,
    is_framework_baseline,
    project_framework_id,
)
from auditor.enrichment.mappings import (
    catalog_control_ids,
    control_title,
    lookup_control,
    project_to_framework,
)
from auditor.models import (
    AuditScope,
    ControlAssessment,
    CoverageSummary,
    Finding,
)

_ANCHOR_FRAMEWORK = "NIST SP 800-53 Rev. 5"

# Control aspects each artifact kind exercises. Curated to mirror what the tools
# actually check; see README "Limitations & scope". A control listed here that
# yields no finding on a run is reported 'satisfied' for the aspect tested.
_KIND_COVERAGE: dict[str, tuple[str, ...]] = {
    "config": (
        "AC-3", "AC-6", "AC-17", "CM-2", "CM-6", "CM-7",
        "IA-2", "IA-5", "SC-5", "SC-7", "SC-8", "SC-23", "SC-28",
    ),
    "log": (
        "AC-7", "AU-2", "AU-3", "AU-6", "AU-9", "AU-12",
        "SI-4", "SI-10", "IR-4", "IR-5",
    ),
    "codebase": (
        "RA-5", "SI-2", "SI-7", "SI-10", "SA-3", "SA-11",
        "IA-5", "SC-8", "SC-12", "SC-13", "SC-28", "CM-6", "AC-3", "AC-6",
    ),
    "policy_pdf": (
        "AT-2", "PL-2", "RA-3", "IR-4", "IR-6", "IR-8",
        "CP-9", "CP-10", "AC-2", "AU-11",
    ),
    "text": ("AC-2", "AC-3", "IA-2", "SC-7", "RA-3", "PL-2"),
    # Live-scanning targets (Phase 2).
    "cloud_account": (
        "AC-3", "AC-6", "IA-2", "IA-5", "AU-2", "AU-6", "CA-7",
        "SC-7", "SC-8", "SC-12", "SC-13", "SC-28", "CM-6", "RA-5", "SI-4", "CP-9",
    ),
    "image_ref": ("RA-5", "SI-2", "SI-7", "CM-6"),
    "target_url": ("SI-10", "SC-7", "SC-8", "SC-23", "AC-3", "IA-5"),
    "host": (
        "AC-6", "AC-17", "AU-2", "AU-8", "CM-6", "CM-7", "IA-2",
        "SC-7", "SC-8", "SC-13", "SC-28", "SI-2", "SI-3", "SI-7",
    ),
}

# Kinds whose checks actively execute (per SP 800-53A, "Test") vs inspect ("Examine").
_TEST_KINDS = frozenset(
    {"config", "log", "codebase", "cloud_account", "image_ref", "target_url", "host"}
)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def baseline_controls(scope: AuditScope) -> list[str]:
    """Return the control IDs in scope for the engagement's baseline.

    ``scope.baseline`` selects the assessment denominator:

    * ``"auditor-curated"`` (default) → the curated cross-framework catalog —
      the controls the tool's checks and mappings actually exercise;
    * a named NIST SP 800-53B baseline (``"low"`` / ``"moderate"`` / ``"high"``)
      → that baseline's full control set, the honest denominator a real
      engagement assesses against (most will be ``not-assessed`` unless an
      artifact exercises them — which is the point).
    """
    name = (scope.baseline or CURATED_BASELINE).strip()
    if name and name != CURATED_BASELINE:
        ids = baseline_control_ids(name)
        if ids:
            return ids
        # Unknown baseline name → fall back to the curated catalog rather than
        # assess against an empty set.
    return catalog_control_ids()


def _finding_controls(f: Finding) -> set[str]:
    """The NIST 800-53 anchor control(s) a finding maps to."""
    cid = (f.control_id or "").strip()
    if cid and f.framework == _ANCHOR_FRAMEWORK:
        return {cid}
    mapped = f.mapped_controls.get(_ANCHOR_FRAMEWORK) if f.mapped_controls else None
    return set(mapped) if mapped else set()


def _coverage_for(kinds: set[str]) -> dict[str, set[str]]:
    """Return ``{control_id: {covering_kinds}}`` for the artifact kinds in a run."""
    cov: dict[str, set[str]] = defaultdict(set)
    for kind in kinds:
        for cid in _KIND_COVERAGE.get(kind, ()):
            cov[cid].add(kind)
    return cov


def _method_for(kinds: set[str]) -> str:
    return "test" if kinds & _TEST_KINDS else "examine"


def _nist_assessment_maps(baseline: str, findings, kinds):
    """Assessment maps in NIST 800-53 space (the internal anchor framework)."""
    findings_by_control: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for cid in _finding_controls(f):
            findings_by_control[cid].append(f)
    coverage = _coverage_for(kinds)
    # Assess the baseline plus any control a finding implicated (so out-of-baseline
    # findings are still surfaced rather than silently dropped).
    denom = baseline_control_ids(baseline) if baseline not in (CURATED_BASELINE, "") else catalog_control_ids()
    ordered = sorted(set(denom) | set(findings_by_control))
    return ordered, findings_by_control, coverage, control_title, _ANCHOR_FRAMEWORK, _baseline_label(baseline)


def _framework_assessment_maps(key: str, findings, kinds):
    """Assessment maps in an alternative framework's space (CIS/PCI/CSF/SOC2).

    Findings and per-kind coverage are projected from their NIST anchors onto the
    framework's controls via the crosswalk, then reduced to the framework's
    natural granularity (e.g. CIS safeguard ``5.4`` -> Control ``5``).
    """
    cw_name = framework_crosswalk_name(key) or ""
    catalog = framework_control_ids(key)
    catalog_set = set(catalog)

    findings_by_control: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for sub in project_to_framework(_finding_controls(f), cw_name):
            fc = project_framework_id(key, sub)
            if fc in catalog_set:
                findings_by_control[fc].append(f)

    coverage: dict[str, set[str]] = defaultdict(set)
    for kind in kinds:
        for nist in _KIND_COVERAGE.get(kind, ()):
            for sub in project_to_framework({nist}, cw_name):
                fc = project_framework_id(key, sub)
                if fc in catalog_set:
                    coverage[fc].add(kind)

    title_fn = lambda cid: framework_title(key, cid)  # noqa: E731
    return catalog, findings_by_control, coverage, title_fn, framework_label(key), framework_label(key)


def assess_controls(
    findings: list[Finding],
    artifact_kinds: list[str],
    scope: AuditScope | None = None,
) -> tuple[list[ControlAssessment], CoverageSummary]:
    """Produce a per-control assessment + a coverage roll-up for the run.

    ``scope.baseline`` selects the audit standard: a NIST 800-53B baseline
    (``low``/``moderate``/``high``/``auditor-curated``) assessed directly, or an
    alternative framework (``cis``/``pci``/``csf``/``soc2``) assessed by
    projecting findings through the NIST crosswalk.
    """
    scope = scope or AuditScope()
    baseline = (scope.baseline or CURATED_BASELINE).strip()
    kinds = set(artifact_kinds)

    if is_framework_baseline(baseline):
        ordered, findings_by_control, coverage, title_fn, framework, label = (
            _framework_assessment_maps(baseline, findings, kinds)
        )
    else:
        ordered, findings_by_control, coverage, title_fn, framework, label = (
            _nist_assessment_maps(baseline, findings, kinds)
        )

    assessments: list[ControlAssessment] = []
    for cid in ordered:
        fs = findings_by_control.get(cid, [])
        covering = coverage.get(cid, set())

        if fs:
            worst = max((_SEVERITY_RANK.get(f.severity, 2) for f in fs), default=2)
            status = "partial" if worst <= 1 else "not-satisfied"
            method = _method_for(covering) if covering else "examine"
            rationale = (
                f"{len(fs)} finding(s) implicate this control "
                f"(worst severity: {_severity_name(worst)})."
            )
            related = [f.title for f in fs[:5]]
        elif covering:
            status = "satisfied"
            method = _method_for(covering)
            rationale = (
                f"Exercised by {', '.join(sorted(covering))} artifact check(s) "
                "with no findings."
            )
            related = []
        else:
            status = "not-assessed"
            method = None
            rationale = "No in-scope artifact exercised this control."
            related = []

        assessments.append(
            ControlAssessment(
                control_id=cid,
                title=title_fn(cid),
                framework=framework,
                status=status,
                method=method,  # type: ignore[arg-type]
                rationale=rationale,
                related_findings=related,
            )
        )

    summary = _summarize(label, assessments)
    return assessments, summary


_VERDICT_ID_RE = re.compile(r"\b([A-Z]{2}-\d{1,3}(?:\(\d+\))?)\b")
_VERDICT_STATUS = {"satisfied", "not-satisfied", "partial", "not-assessed"}


def merge_interview_verdicts(
    assessments: list[ControlAssessment],
    coverage: CoverageSummary,
    verdicts,
) -> tuple[list[ControlAssessment], CoverageSummary]:
    """Fold advisory **interview** verdicts into a technical assessment, unifying
    the two ways to audit into one control-coverage picture.

    For each verdict (from :class:`OrganizationalAssessment`) that resolves to a
    NIST 800-53 control ID: if that control was ``not-assessed`` by the scanners,
    it takes the interview verdict (method ``interview``); if the scanners already
    assessed it (``test``/``examine``), the technical verdict stands (it exercised
    the control directly). Controls the interview raises that weren't in scope are
    surfaced too. Coverage is recomputed. Non-NIST verdicts (e.g. SOC 2 CC6.1) are
    left for a NIST-anchored coverage to ignore.
    """
    by_id: dict[str, ControlAssessment] = {a.control_id: a for a in assessments}
    for v in verdicts or []:
        status = getattr(v, "status", None)
        if status not in _VERDICT_STATUS or status == "not-assessed":
            continue
        m = _VERDICT_ID_RE.search(getattr(v, "control", "") or "")
        if not m:
            continue
        cid = m.group(1)
        rationale = f"Interview/examine: {getattr(v, 'rationale', '')}".strip()
        existing = by_id.get(cid)
        if existing is None:
            by_id[cid] = ControlAssessment(
                control_id=cid,
                title=getattr(v, "title", "") or control_title(cid),
                status=status,  # type: ignore[arg-type]
                method="interview",
                rationale=rationale,
            )
        elif existing.status == "not-assessed":
            existing.status = status  # type: ignore[assignment]
            existing.method = "interview"
            existing.rationale = rationale
        # else: scanner already assessed this control — its verdict stands.

    merged = sorted(by_id.values(), key=lambda a: a.control_id)
    return merged, _summarize(coverage.baseline, merged)


def _summarize(baseline: str, assessments: list[ControlAssessment]) -> CoverageSummary:
    counts: dict[str, int] = defaultdict(int)
    for a in assessments:
        counts[a.status] += 1
    not_assessed = counts.get("not-assessed", 0)
    total = len(assessments)
    return CoverageSummary(
        baseline=baseline,
        total_controls=total,
        assessed=total - not_assessed,
        satisfied=counts.get("satisfied", 0),
        not_satisfied=counts.get("not-satisfied", 0),
        partial=counts.get("partial", 0),
        not_applicable=counts.get("not-applicable", 0),
        not_assessed=not_assessed,
    )


def _baseline_label(baseline: str | None) -> str:
    """Friendly label for the coverage summary: the curated default keeps its
    name; named 800-53B baselines render their human label."""
    name = (baseline or CURATED_BASELINE).strip()
    if name and name != CURATED_BASELINE:
        return baseline_label(name)
    return name or CURATED_BASELINE


def _severity_name(rank: int) -> str:
    for name, r in _SEVERITY_RANK.items():
        if r == rank:
            return name
    return "medium"


def control_is_assessable(control_id: str) -> bool:
    """True if the control exists in the crosswalk catalog (has a title/mappings)."""
    return lookup_control(control_id) is not None
