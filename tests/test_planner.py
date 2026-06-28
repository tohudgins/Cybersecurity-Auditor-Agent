"""Tests for the adaptive scope-planning layer."""
from __future__ import annotations

from auditor.models import Artifact
from auditor.planner import _base_images, _iter_dockerfiles, plan_expansion

# ── Dockerfile parsing ───────────────────────────────────────────────────────


def test_base_images_simple():
    assert _base_images("FROM python:3.9-slim\nRUN echo hi") == ["python:3.9-slim"]


def test_base_images_multistage_skips_stage_aliases():
    df = (
        "FROM golang:1.22 AS builder\n"
        "RUN go build\n"
        "FROM gcr.io/distroless/base AS final\n"
        "COPY --from=builder /app /app\n"
        "FROM final\n"  # reference to a stage alias — not a real image
    )
    imgs = _base_images(df)
    assert "golang:1.22" in imgs
    assert "gcr.io/distroless/base" in imgs
    assert "final" not in imgs  # stage alias excluded


def test_base_images_skips_scratch_and_templated():
    df = "FROM scratch\nFROM ${BASE_IMAGE}\nFROM alpine:3.20"
    assert _base_images(df) == ["alpine:3.20"]


def test_base_images_dedupes():
    df = "FROM node:20 AS a\nFROM node:20 AS b"
    assert _base_images(df) == ["node:20"]


# ── Filesystem discovery ─────────────────────────────────────────────────────


def test_iter_dockerfiles_finds_variants_and_skips_heavy_dirs(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9")
    (tmp_path / "Dockerfile.prod").write_text("FROM nginx:1.27")
    sub = tmp_path / "service"
    sub.mkdir()
    (sub / "Dockerfile").write_text("FROM redis:7")
    noise = tmp_path / "node_modules" / "pkg"
    noise.mkdir(parents=True)
    (noise / "Dockerfile").write_text("FROM evil:latest")

    found = {p.name for p in _iter_dockerfiles(tmp_path)}
    assert "Dockerfile" in found
    assert "Dockerfile.prod" in found
    # node_modules is pruned
    assert all("node_modules" not in str(p) for p in _iter_dockerfiles(tmp_path))


# ── Expansion planning ───────────────────────────────────────────────────────


def _codebase(path):
    return Artifact(kind="codebase", name=str(path), content=str(path))


def test_plan_expansion_adds_image_targets(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim\nFROM nginx:1.27")
    artifacts = [_codebase(tmp_path)]
    expanded, notes = plan_expansion(artifacts, allow_local=True, trivy_available=True)

    added = [a for a in expanded if a.kind == "image_ref"]
    refs = {a.content for a in added}
    assert refs == {"python:3.9-slim", "nginx:1.27"}
    assert len(notes) == 2
    assert all("container-image scan" in n for n in notes)


def test_plan_expansion_noop_without_trivy(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9")
    artifacts = [_codebase(tmp_path)]
    expanded, notes = plan_expansion(artifacts, allow_local=True, trivy_available=False)
    assert expanded == artifacts
    assert notes == []


def test_plan_expansion_noop_when_local_disabled(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9")
    artifacts = [_codebase(tmp_path)]
    expanded, notes = plan_expansion(artifacts, allow_local=False, trivy_available=True)
    assert expanded == artifacts
    assert notes == []


def test_plan_expansion_dedupes_against_existing_image(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim")
    artifacts = [
        _codebase(tmp_path),
        Artifact(kind="image_ref", name="python:3.9-slim", content="python:3.9-slim"),
    ]
    expanded, notes = plan_expansion(artifacts, allow_local=True, trivy_available=True)
    # Already in scope → not added again.
    assert len(expanded) == len(artifacts)
    assert notes == []


def test_plan_expansion_bounded(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM a:1\nFROM b:1\nFROM c:1\nFROM d:1\nFROM e:1"
    )
    artifacts = [_codebase(tmp_path)]
    expanded, notes = plan_expansion(artifacts, allow_local=True, trivy_available=True, max_images=3)
    added = [a for a in expanded if a.kind == "image_ref"]
    assert len(added) == 3
    assert any("further base image" in n for n in notes)


def test_plan_expansion_ignores_non_codebase(tmp_path):
    artifacts = [Artifact(kind="config", name="sshd_config", content="PermitRootLogin yes")]
    expanded, notes = plan_expansion(artifacts, allow_local=True, trivy_available=True)
    assert expanded == artifacts
    assert notes == []
