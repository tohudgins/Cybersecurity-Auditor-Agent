"""Tests for the finding suppression / accepted-risk register."""
from __future__ import annotations

import pytest

from auditor import suppressions as supp
from auditor.diff import fingerprint
from auditor.models import Finding


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Point the suppressions DB at a temp file so tests never touch ~/.cache."""
    monkeypatch.setattr(supp, "_DB_PATH", tmp_path / "suppressions.db")


def _f(title="finding", severity="high", **kw) -> Finding:
    return Finding(
        title=title, severity=severity, evidence=kw.pop("evidence", "ev"),
        recommendation="fix", control_id=kw.pop("control_id", "SI-2"), **kw,
    )


def test_add_and_apply_removes_matching_finding():
    f = _f(risk_score=70.0)
    supp.add_suppression(f, "accepted-risk", "compensating control X in place", target_key="t1")
    records = supp.active_records("t1")
    active, suppressed = supp.apply_suppressions([f, _f(title="other")], records)
    assert [a.title for a in active] == ["other"]
    assert len(suppressed) == 1
    assert suppressed[0]["kind"] == "accepted-risk"
    assert suppressed[0]["reason"] == "compensating control X in place"


def test_global_suppression_applies_to_any_target():
    f = _f()
    supp.add_suppression(f, "false-positive", "test fixture, not real", target_key=None)
    # A different target still sees the global suppression.
    active, suppressed = supp.apply_suppressions([f], supp.active_records("other-target"))
    assert active == [] and len(suppressed) == 1


def test_target_scoped_suppression_does_not_leak():
    f = _f()
    supp.add_suppression(f, "accepted-risk", "scoped", target_key="t1")
    # t2 should NOT pick up t1's scoped suppression.
    active, suppressed = supp.apply_suppressions([f], supp.active_records("t2"))
    assert len(active) == 1 and suppressed == []


def test_expired_suppression_is_inactive():
    f = _f()
    supp.add_suppression(f, "accepted-risk", "temporary", target_key="t1", expires_at="2000-01-01T00:00:00Z")
    assert supp.active_records("t1") == []
    active, _ = supp.apply_suppressions([f], supp.active_records("t1"))
    assert len(active) == 1


def test_delete_and_list():
    sid = supp.add_suppression(_f(), "accepted-risk", "r", target_key="t1")
    assert len(supp.list_suppressions("t1")) == 1
    supp.delete_suppression(sid)
    assert supp.list_suppressions("t1") == []


def test_add_validates_kind_and_reason():
    with pytest.raises(ValueError):
        supp.add_suppression(_f(), "bogus-kind", "r")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        supp.add_suppression(_f(), "accepted-risk", "   ")  # empty reason


def test_apply_with_no_records_is_identity():
    fs = [_f(title="a"), _f(title="b")]
    active, suppressed = supp.apply_suppressions(fs, [])
    assert active == fs and suppressed == []


def test_fingerprint_matching_is_consistent_with_diff():
    # The register keys on diff.fingerprint, so suppression matches a finding the
    # same way the run-to-run diff matches it across runs.
    f = _f()
    supp.add_suppression(f, "accepted-risk", "r", target_key="t1")
    rec = supp.active_records("t1")[0]
    assert rec["fingerprint"] == fingerprint(f)


def test_audit_node_excludes_suppressed_findings():
    # End-to-end through the audit node: a suppressed finding leaves the active
    # set + assessment and lands in suppressed_findings instead. (LLM findings are
    # stubbed by conftest; sshd heuristics provide the deterministic finding.)
    from auditor.agents.audit_agent import audit_node
    from auditor.models import Artifact

    art = Artifact(
        kind="config", name="sshd_config",
        content="PermitRootLogin yes\nPermitEmptyPasswords yes",
    )
    baseline = audit_node({"artifacts": [art]})
    assert baseline["findings"]
    victim = baseline["findings"][0]

    rec = {"fingerprint": fingerprint(victim), "kind": "accepted-risk", "reason": "accepted for test"}
    out = audit_node({"artifacts": [art], "suppressions": [rec]})
    assert victim.title not in {f.title for f in out["findings"]}
    assert any(s["reason"] == "accepted for test" for s in out["suppressed_findings"])
