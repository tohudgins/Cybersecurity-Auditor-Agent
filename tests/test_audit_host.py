"""Tests for the Lynis host/machine audit (subprocess mocked)."""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from auditor.tools import audit_host

_REPORT = """# Lynis report
warning[]=SSH-7408|Consider hardening SSH configuration|root login allowed|
suggestion[]=AUTH-9262|Install a PAM module for password strength|libpam-passwdqc|
suggestion[]=PKGS-7370|Check for available package updates|run apt upgrade|
vulnerable_package[]=openssl|||
"""


def _fake_run(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def test_parse_maps_categories_to_controls():
    findings = audit_host._parse_lynis_report(_REPORT, "localhost")
    by_control = {f.control_id for f in findings}
    assert "AC-17" in by_control   # SSH-* → AC-17
    assert "IA-2" in by_control    # AUTH-* → IA-2
    assert "SI-2" in by_control    # PKGS-* and vulnerable_package → SI-2
    assert all(f.detection_source == "scanner" for f in findings)
    assert all(f.framework == "NIST SP 800-53 Rev. 5" for f in findings)


def test_warning_outranks_suggestion_severity():
    findings = audit_host._parse_lynis_report(_REPORT, "localhost")
    ssh = next(f for f in findings if "SSH-7408" in f.title)
    auth = next(f for f in findings if "AUTH-9262" in f.title)
    assert ssh.severity == "medium"   # warning
    assert auth.severity == "low"     # suggestion


def test_vulnerable_package_is_high():
    findings = audit_host._parse_lynis_report(_REPORT, "localhost")
    pkg = next(f for f in findings if "openssl" in f.title.lower())
    assert pkg.severity == "high"
    assert pkg.control_id == "SI-2"


def test_unknown_category_defaults_to_cm6():
    findings = audit_host._parse_lynis_report("warning[]=ZZZZ-1|Mystery check||", "localhost")
    assert findings[0].control_id == "CM-6"


def test_missing_lynis_is_info(monkeypatch):
    def _raise(*_a, **_k):
        raise FileNotFoundError
    monkeypatch.setattr(subprocess, "run", _raise)
    findings = audit_host.audit_host("localhost")
    assert len(findings) == 1 and findings[0].severity == "info"
    assert "lynis" in findings[0].title.lower()


def test_remote_rejects_ssh_arg_injection(monkeypatch):
    """A target that looks like an ssh option (-oProxyCommand=…) must be refused
    BEFORE ssh is ever invoked."""
    called = {"ran": False}

    def _spy(*_a, **_k):
        called["ran"] = True
        return _fake_run(stdout="")
    monkeypatch.setattr(subprocess, "run", _spy)

    findings = audit_host.audit_host("-oProxyCommand=touch /tmp/pwned")
    assert findings[0].severity == "info"
    assert "invalid host" in findings[0].title.lower()
    assert called["ran"] is False  # ssh never ran


def test_remote_uses_ssh(monkeypatch):
    captured = {}

    def _capture(cmd, **_k):
        captured["cmd"] = cmd
        return _fake_run(stdout=_REPORT)
    monkeypatch.setattr(subprocess, "run", _capture)
    findings = audit_host.audit_host("user@server")
    assert captured["cmd"][0] == "ssh"
    assert "user@server" in captured["cmd"]
    assert any(f.control_id == "AC-17" for f in findings)
