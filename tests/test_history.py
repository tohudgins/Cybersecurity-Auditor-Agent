"""Tests for the SQLite audit history module."""
from __future__ import annotations

import json

import pytest

import auditor.history as history_mod


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """Redirect the history DB to a temp file so tests don't touch ~/.cache."""
    db_path = tmp_path / "history.db"
    monkeypatch.setattr(history_mod, "_DB_PATH", db_path)
    return db_path


def test_save_and_list(tmp_db):
    run_id = history_mod.save_run(
        artifact_names=["sshd_config"],
        total=3,
        severities={"high": 2, "medium": 1},
        report_md="# Report\n\nSome findings.",
        oscal_json='{"assessment-results": {}}',
    )
    assert isinstance(run_id, int)

    runs = history_mod.list_runs()
    assert len(runs) == 1
    r = runs[0]
    assert r["id"] == run_id
    assert json.loads(r["artifacts"]) == ["sshd_config"]
    assert r["total"] == 3
    assert json.loads(r["severities"])["high"] == 2
    # Full text not returned by list_runs
    assert "report_md" not in r


def test_get_run_returns_full_record(tmp_db):
    run_id = history_mod.save_run(
        artifact_names=["Dockerfile"],
        total=1,
        severities={"critical": 1},
        report_md="# Audit\n\nCritical finding.",
        oscal_json='{}',
    )
    rec = history_mod.get_run(run_id)
    assert rec is not None
    assert rec["report_md"] == "# Audit\n\nCritical finding."
    assert rec["oscal_json"] == '{}'


def test_get_run_missing_returns_none(tmp_db):
    assert history_mod.get_run(9999) is None


def test_delete_run(tmp_db):
    run_id = history_mod.save_run(
        artifact_names=["nginx.conf"],
        total=0,
        severities={},
        report_md="No findings.",
    )
    history_mod.delete_run(run_id)
    assert history_mod.get_run(run_id) is None
    assert history_mod.list_runs() == []


def test_list_runs_ordered_newest_first(tmp_db):
    for i in range(3):
        history_mod.save_run(
            artifact_names=[f"file_{i}.tf"],
            total=i,
            severities={},
            report_md=f"Report {i}",
        )
    runs = history_mod.list_runs()
    ids = [r["id"] for r in runs]
    assert ids == sorted(ids, reverse=True)


def test_list_runs_respects_limit(tmp_db):
    for i in range(5):
        history_mod.save_run([], 0, {}, f"Report {i}")
    assert len(history_mod.list_runs(limit=3)) == 3


def test_oscal_json_optional(tmp_db):
    run_id = history_mod.save_run(
        artifact_names=[],
        total=0,
        severities={},
        report_md="Nothing.",
        oscal_json=None,
    )
    rec = history_mod.get_run(run_id)
    assert rec["oscal_json"] is None


def test_list_runs_offset_pagination(tmp_db):
    for i in range(7):
        history_mod.save_run([f"file_{i}.tf"], i, {}, f"Report {i}")

    page1 = history_mod.list_runs(limit=3, offset=0)
    page2 = history_mod.list_runs(limit=3, offset=3)
    page3 = history_mod.list_runs(limit=3, offset=6)

    assert len(page1) == 3
    assert len(page2) == 3
    assert len(page3) == 1
    # No overlap between pages
    all_ids = [r["id"] for page in (page1, page2, page3) for r in page]
    assert len(all_ids) == len(set(all_ids)) == 7


def test_count_runs(tmp_db):
    assert history_mod.count_runs() == 0
    for _ in range(4):
        history_mod.save_run([], 0, {}, "x")
    assert history_mod.count_runs() == 4


def test_clear_all(tmp_db):
    for _ in range(3):
        history_mod.save_run([], 0, {}, "x")
    assert history_mod.count_runs() == 3

    deleted = history_mod.clear_all()
    assert deleted == 3
    assert history_mod.count_runs() == 0
    assert history_mod.list_runs() == []


def test_clear_all_when_empty(tmp_db):
    """Clearing an already-empty table is a no-op that returns 0."""
    assert history_mod.clear_all() == 0


def test_latest_run_for_target_matches_same_target(tmp_db):
    history_mod.save_run(
        ["/repo"], 2, {"high": 2}, "old report",
        target_key="abc123", findings_json='[{"fp":"x"}]',
    )
    history_mod.save_run(
        ["/repo"], 1, {"high": 1}, "new report",
        target_key="abc123", findings_json='[{"fp":"y"}]',
    )
    # An unrelated target shouldn't be returned.
    history_mod.save_run(
        ["/other"], 5, {"critical": 5}, "other report",
        target_key="zzz999", findings_json='[{"fp":"z"}]',
    )
    latest = history_mod.latest_run_for_target("abc123")
    assert latest is not None
    assert latest["findings_json"] == '[{"fp":"y"}]'  # newest of the matching target


def test_latest_run_for_target_none_when_no_prior(tmp_db):
    assert history_mod.latest_run_for_target("never-seen") is None
    assert history_mod.latest_run_for_target("") is None


def test_latest_run_ignores_runs_without_snapshot(tmp_db):
    history_mod.save_run(
        ["/repo"], 0, {}, "no snapshot", target_key="t1", findings_json=None,
    )
    assert history_mod.latest_run_for_target("t1") is None
