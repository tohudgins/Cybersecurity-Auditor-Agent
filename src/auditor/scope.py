"""Scope completeness — did the audit cover the declared system?

A control-coverage table answers "which controls did we assess." Scope coverage
answers the prior question a real engagement asks: "did we assess every asset in
the authorization boundary?" Given the SSP asset inventory (`AuditScope.assets`)
and the artifacts actually audited, this flags in-scope assets that went
unassessed — an honesty check that turns "scanned some files" into "assessed a
defined system (with these gaps)."
"""
from __future__ import annotations

from pydantic import BaseModel

from auditor.models import Artifact, Asset, AuditScope

# Asset-kind aliases → the audit artifact kind that assesses them.
_KIND_ALIASES: dict[str, str] = {
    "web": "target_url", "web_app": "target_url", "website": "target_url", "url": "target_url",
    "container": "image_ref", "image": "image_ref", "container_image": "image_ref",
    "repo": "codebase", "repository": "codebase", "code": "codebase", "application": "codebase",
    "server": "host", "machine": "host", "vm": "host", "instance": "host", "os": "host",
    "cloud": "cloud_account", "account": "cloud_account", "aws": "cloud_account",
    "gcp": "cloud_account", "azure": "cloud_account",
    "policy": "policy_pdf", "document": "policy_pdf",
}


class AssetCoverage(BaseModel):
    """Whether one in-scope asset was assessed, and by which artifact."""

    asset: Asset
    assessed: bool = False
    covered_by: str = ""  # artifact name


class ScopeCoverage(BaseModel):
    """Roll-up of asset-level scope coverage for the run."""

    assets: list[AssetCoverage] = []

    @property
    def total(self) -> int:
        return len(self.assets)

    @property
    def assessed(self) -> int:
        return sum(1 for a in self.assets if a.assessed)

    @property
    def coverage_pct(self) -> float:
        return round(100.0 * self.assessed / self.total, 1) if self.total else 0.0


def _canonical_kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    return _KIND_ALIASES.get(k, k)


def _match_asset(asset: Asset, artifacts: list[Artifact]) -> Artifact | None:
    """Find the artifact that assessed *asset* — by name reference first (specific),
    then by matching kind."""
    name = (asset.name or "").strip().lower()
    if name:
        for a in artifacts:
            an = a.name.lower()
            if name in an or an in name or name in (a.content or "").lower()[:300]:
                return a
    kind = _canonical_kind(asset.kind)
    if kind:
        for a in artifacts:
            if kind == a.kind.lower():
                return a
    return None


def assess_scope_coverage(scope: AuditScope | None, artifacts: list[Artifact]) -> ScopeCoverage:
    """Map each declared in-scope asset to whether an artifact assessed it."""
    if not scope or not scope.assets:
        return ScopeCoverage(assets=[])
    out: list[AssetCoverage] = []
    for asset in scope.assets:
        match = _match_asset(asset, artifacts)
        out.append(
            AssetCoverage(asset=asset, assessed=match is not None, covered_by=match.name if match else "")
        )
    return ScopeCoverage(assets=out)
