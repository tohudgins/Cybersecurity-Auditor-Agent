"""Tests for natural-language target detection (auditor.intake)."""
from __future__ import annotations

from auditor.intake import describe_targets, parse_targets


def _kinds(text):
    return [a.kind for a in parse_targets(text)]


def test_detects_http_url_without_intent_word():
    arts = parse_targets("https://example.com/login")
    assert [a.kind for a in arts] == ["target_url"]
    assert arts[0].content == "https://example.com/login"


def test_explicit_prefixes():
    assert _kinds("url:example.com") == ["target_url"]
    assert _kinds("image:nginx:1.21") == ["image_ref"]
    assert _kinds("cloud:aws:prod") == ["cloud_account"]
    assert _kinds("host:user@box") == ["host"]


def test_image_prefix_keeps_tag_in_content():
    art = parse_targets("image:nginx:1.21")[0]
    assert art.content == "nginx:1.21"


def test_cloud_keyword_requires_audit_intent():
    assert _kinds("what does aws recommend for s3") == []      # no verb → no target
    assert _kinds("audit aws:prod") == ["cloud_account"]


def test_bare_provider_word_is_not_a_target():
    # "aws" without a profile must never trigger a live scan, even with a verb.
    assert _kinds("audit aws") == []
    assert _kinds("scan our gcp environment") == []


def test_local_targets_can_be_disabled(monkeypatch, tmp_path):
    from auditor.config import settings as cfg

    d = tmp_path / "repo"
    d.mkdir()
    monkeypatch.setattr(cfg, "allow_local_targets", False)
    assert parse_targets(f"audit {d}") == []          # filesystem path gated
    assert parse_targets("audit this machine") == []  # host gated
    # Non-local targets still work when local is disabled.
    assert _kinds("scan https://x.test") == ["target_url"]


def test_dispatch_blocks_local_kinds_when_disabled(monkeypatch):
    from auditor.agents import audit_agent
    from auditor.config import settings as cfg
    from auditor.models import Artifact

    monkeypatch.setattr(cfg, "allow_local_targets", False)
    out = audit_agent._audit_one(Artifact(kind="host", name="host:localhost", content="localhost"), None)
    assert out[0].severity == "info" and "disabled" in out[0].title.lower()


def test_this_machine_phrase_with_intent():
    arts = parse_targets("audit this machine please")
    assert arts and arts[0].kind == "host"
    assert arts[0].content == "localhost"


def test_existing_path_is_detected(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    arts = parse_targets(f"audit {d}")
    assert arts and arts[0].kind == "codebase"
    assert arts[0].content == str(d)


def test_existing_file_classified_by_extension(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Jan 1 sshd failed password\n")
    arts = parse_targets(f"scan {log}")
    assert arts and arts[0].kind == "log"


def test_plain_question_yields_no_targets():
    assert parse_targets("what does AC-2 require?") == []
    assert parse_targets("how do I fix the SQL injection finding?") == []


def test_ssh_host_requires_intent():
    assert _kinds("user@server") == []          # could be an email-ish token in prose
    assert _kinds("audit user@server") == ["host"]


def test_describe_targets_is_human_readable():
    arts = parse_targets("scan https://x.test")
    assert "web target" in describe_targets(arts)
