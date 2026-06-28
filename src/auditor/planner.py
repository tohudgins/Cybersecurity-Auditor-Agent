"""Adaptive scope planning — the agent decides what *else* is worth assessing.

A scanner audits exactly what you point it at. An auditor *scopes the engagement*:
it looks at the target, notices adjacent attack surface the user didn't name, and
either pulls it into scope or flags it as a recommended next step. This module is
that step, and it splits cleanly into two kinds of action:

* **Auto-expansions** (safe, local, read-only) — pulled into the *same* run. Today:
  the container images a codebase references (Dockerfile `FROM` bases and
  docker-compose `services.*.image`) become container-image scans, surfacing the
  inherited OS-package CVEs a source-tree scan never sees.
* **Recommendations** (live / credentialed / personal) — *surfaced, never run*.
  Today: a repo containing Terraform provisions live cloud infrastructure whose
  posture isn't visible from source; the agent recommends a read-only cloud audit
  rather than launching a billable, credentialed account-wide scan on its own.

The split is the point: only assessments that are safe, local, and read-only run
without being asked. Anything that touches a live account, host, or external
service is the user's call.

Design choices that keep it strong rather than partial:

* **Deterministic, not LLM-driven.** For a security tool a rule that parses
  Dockerfiles is faster and more trustworthy than asking a model to guess scan
  targets — no added latency, no hallucinated hosts. The "agent decides" is a
  deterministic decision with an auditable reason attached.
* **No dead work.** Image expansion only runs when its scanner (Trivy) is
  installed and local targets are permitted; otherwise it is a clean no-op.
* **Bounded and concurrent.** A single depth/size-capped filesystem walk feeds
  every discoverer, and the artifacts expansion adds join the *same* concurrent
  audit batch — so expansion costs wall-clock `max(scan, image-pull)`, never their
  sum.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import yaml

from auditor.models import Artifact

# Directories that never contain a project Dockerfile worth scanning and would
# otherwise blow up the walk on a real repo.
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
    "vendor", "site-packages", ".terraform", ".next", "target",
})

_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE | re.MULTILINE)
_COMPOSE_NAME_RE = re.compile(r"^(docker-compose|compose)(\.[\w.-]+)?\.ya?ml$", re.IGNORECASE)


class _RepoSurface(NamedTuple):
    """The plan-relevant files a single repo walk turned up."""

    dockerfiles: list[Path]
    compose_files: list[Path]
    terraform_files: list[Path]


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _is_compose_file(name: str) -> bool:
    return bool(_COMPOSE_NAME_RE.match(name))


def _is_terraform(name: str) -> bool:
    return name.endswith(".tf")


def _scan_repo(root: str | Path, *, max_files: int = 40, max_depth: int = 6) -> _RepoSurface:
    """One bounded, heavy-dir-pruned walk collecting every plan-relevant file."""
    root = Path(root)
    surface = _RepoSurface([], [], [])
    if not root.exists():
        return surface
    if root.is_file():
        if _is_dockerfile(root.name):
            surface.dockerfiles.append(root)
        elif _is_compose_file(root.name):
            surface.compose_files.append(root)
        elif _is_terraform(root.name):
            surface.terraform_files.append(root)
        return surface

    root_depth = len(root.parts)
    collected = 0
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if _is_dockerfile(fn):
                surface.dockerfiles.append(Path(dirpath) / fn)
            elif _is_compose_file(fn):
                surface.compose_files.append(Path(dirpath) / fn)
            elif _is_terraform(fn):
                surface.terraform_files.append(Path(dirpath) / fn)
            else:
                continue
            collected += 1
            if collected >= max_files:
                return surface
    return surface


def _iter_dockerfiles(root: str | Path, *, max_files: int = 25, max_depth: int = 6) -> list[Path]:
    """Bounded walk for Dockerfiles under ``root`` (or ``root`` itself)."""
    return _scan_repo(root, max_files=max_files, max_depth=max_depth).dockerfiles


def _base_images(dockerfile_text: str) -> list[str]:
    """Extract concrete base images from a Dockerfile, in order, de-duplicated.

    Skips ``scratch``, ARG/variable-templated refs (``${BASE}``), and references
    to earlier build stages (multi-stage ``AS builder`` aliases) — those are not
    independently pullable images.
    """
    stage_aliases = {
        m.group(2).lower() for m in _FROM_RE.finditer(dockerfile_text) if m.group(2)
    }
    images: list[str] = []
    seen: set[str] = set()
    for m in _FROM_RE.finditer(dockerfile_text):
        img = m.group(1).strip()
        low = img.lower()
        if low == "scratch" or low in stage_aliases or "$" in img or img.startswith("-"):
            continue
        if img in seen:
            continue
        seen.add(img)
        images.append(img)
    return images


def _images_from_compose(compose_text: str) -> list[str]:
    """Extract ``services.*.image`` refs from a docker-compose file, in order.

    Uses ``yaml.safe_load`` (never ``load`` — no arbitrary object construction).
    Skips variable-interpolated refs (``${TAG}``) and build-only services (those
    have no ``image:`` and are covered by Dockerfile discovery). Malformed YAML
    degrades to an empty list rather than raising.
    """
    try:
        docs = list(yaml.safe_load_all(compose_text))
    except yaml.YAMLError:
        return []
    images: list[str] = []
    seen: set[str] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        services = doc.get("services")
        if not isinstance(services, dict):
            continue
        for svc in services.values():
            if not isinstance(svc, dict):
                continue
            img = svc.get("image")
            if not isinstance(img, str):
                continue
            img = img.strip()
            if not img or "$" in img or img.startswith("-") or img in seen:
                continue
            seen.add(img)
            images.append(img)
    return images


# Per-source phrasing for the audit-plan note, so the rationale is explainable.
_SOURCE_NOTE = {
    "dockerfile": (
        "detected base image `{img}` in a Dockerfile → added a container-image scan "
        "(catches inherited OS-package CVEs a source-tree scan can't see)"
    ),
    "compose": (
        "detected image `{img}` referenced in docker-compose → added a container-image "
        "scan (assesses the deployed image's CVEs + misconfigurations)"
    ),
}


def _image_targets_from_surface(surface: _RepoSurface) -> list[tuple[str, str]]:
    """Ordered, de-duplicated ``(image_ref, source)`` pairs from a repo surface.

    Source is ``"dockerfile"`` or ``"compose"``; Dockerfile bases come first.
    """
    targets: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(image: str, source: str) -> None:
        if image not in seen:
            seen.add(image)
            targets.append((image, source))

    for df in surface.dockerfiles:
        try:
            text = df.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for img in _base_images(text):
            _add(img, "dockerfile")
    for cf in surface.compose_files:
        try:
            text = cf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for img in _images_from_compose(text):
            _add(img, "compose")
    return targets


# Terraform provider / resource-prefix → cloud + the `audit <provider>:…` spec.
_TF_PROVIDER_RE = re.compile(r'provider\s+"([a-z0-9_-]+)"', re.IGNORECASE)
_TF_RESOURCE_RE = re.compile(r'(?:resource|data)\s+"([a-z0-9]+)_', re.IGNORECASE)
_TF_CLOUD = {
    "aws": ("AWS", "aws"),
    "google": ("GCP", "gcp"),
    "google-beta": ("GCP", "gcp"),
    "azurerm": ("Azure", "azure"),
    "azuread": ("Azure", "azure"),
}


def _terraform_clouds(surface: _RepoSurface, *, max_read: int = 20) -> list[tuple[str, str]]:
    """Detect which clouds a repo's Terraform provisions → ordered ``(label, provider)``.

    Reads provider blocks first, falling back to resource/data prefixes, over a
    bounded number of ``.tf`` files. Returns only recognized cloud providers.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for tf in surface.terraform_files[:max_read]:
        try:
            text = tf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        keys = _TF_PROVIDER_RE.findall(text) + _TF_RESOURCE_RE.findall(text)
        for key in keys:
            cloud = _TF_CLOUD.get(key.lower())
            if cloud and cloud[1] not in seen:
                seen.add(cloud[1])
                found.append(cloud)
    return found


def _terraform_recommendation(codebase_name: str, surface: _RepoSurface) -> str:
    """Advisory next step for a Terraform-bearing repo — surfaced, never run."""
    clouds = _terraform_clouds(surface)
    if clouds:
        labels = ", ".join(label for label, _ in clouds)
        specs = " or ".join(f"`audit {provider}:<profile>`" for _, provider in clouds)
        provisions = f"provisions live {labels} infrastructure"
    else:
        specs = "`audit <provider>:<profile>`"
        provisions = "provisions live cloud infrastructure"
    return (
        f"Codebase `{codebase_name}`: Terraform detected — {provisions}, whose runtime "
        f"security posture isn't visible from source alone. Consider a read-only "
        f"cloud-posture audit of the deployed account ({specs}, via Prowler). "
        f"_Not run automatically — live cloud scans require your explicit "
        f"authorization and credentials._"
    )


@dataclass
class Plan:
    """The output of scope planning.

    ``artifacts`` is the (possibly expanded) set to audit this run; ``notes``
    explain auto-expansions that were made; ``recommendations`` are advisory next
    steps the agent deliberately did **not** run (live/credentialed targets).
    """

    artifacts: list[Artifact]
    notes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


def build_plan(
    artifacts: list[Artifact],
    *,
    allow_local: bool,
    trivy_available: bool,
    max_images: int = 3,
) -> Plan:
    """Plan the engagement: safe local expansions run; live targets are recommended.

    For each codebase target (only when local targets are permitted), a single
    bounded walk feeds both: container images are pulled into scope as
    ``image_ref`` artifacts (when Trivy is present, bounded by ``max_images``),
    while detected Terraform yields a *recommendation* to run a live cloud audit —
    never an auto-launched, credentialed scan.
    """
    notes: list[str] = []
    recommendations: list[str] = []
    in_scope_images = {a.content.strip() for a in artifacts if a.kind == "image_ref"}
    has_cloud_target = any(a.kind == "cloud_account" for a in artifacts)
    added: list[Artifact] = []

    for a in artifacts:
        if a.kind != "codebase" or not allow_local:
            continue
        surface = _scan_repo(a.content)

        if trivy_available:
            discovered = [
                (img, src) for img, src in _image_targets_from_surface(surface)
                if img not in in_scope_images
            ]
            for img, src in discovered[:max_images]:
                added.append(Artifact(kind="image_ref", name=img, content=img))
                in_scope_images.add(img)
                notes.append(f"Codebase `{a.name}`: " + _SOURCE_NOTE[src].format(img=img) + ".")
            if len(discovered) > max_images:
                extra = len(discovered) - max_images
                notes.append(
                    f"Codebase `{a.name}`: {extra} further referenced image(s) found; "
                    f"scanned the first {max_images} to keep the run fast."
                )

        # Live cloud posture is recommended, never auto-run. Skip if the user
        # already put a cloud account in scope.
        if surface.terraform_files and not has_cloud_target:
            recommendations.append(_terraform_recommendation(a.name, surface))

    return Plan(list(artifacts) + added, notes, recommendations)


def plan_expansion(
    artifacts: list[Artifact],
    *,
    allow_local: bool,
    trivy_available: bool,
    max_images: int = 3,
) -> tuple[list[Artifact], list[str]]:
    """Back-compat shim: the auto-expansion half of :func:`build_plan`."""
    plan = build_plan(
        artifacts,
        allow_local=allow_local,
        trivy_available=trivy_available,
        max_images=max_images,
    )
    return plan.artifacts, plan.notes
