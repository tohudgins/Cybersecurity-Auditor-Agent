"""Tests for audit_codebase. Subprocess is mocked so Trivy doesn't need to be installed."""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from auditor.tools import audit_codebase as ac

_FAKE_TRIVY_OUTPUT = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-11111",
                    "PkgName": "cryptography",
                    "InstalledVersion": "3.0",
                    "FixedVersion": "41.0.6",
                    "Severity": "HIGH",
                    "Title": "OpenSSL bundled with cryptography contains a heap buffer overflow",
                },
                {
                    "VulnerabilityID": "CVE-2023-22222",
                    "PkgName": "obscurepkg",
                    "InstalledVersion": "0.1.0",
                    "Severity": "CRITICAL",
                    "Title": "Remote code execution in obscurepkg",
                },
            ],
        }
    ],
}


def _fake_run(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def test_audit_codebase_parses_two_vulns(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_, **__: _fake_run(stdout=json.dumps(_FAKE_TRIVY_OUTPUT)),
    )

    findings = ac.audit_codebase(tmp_path)
    assert len(findings) == 2

    fixed = next(f for f in findings if "CVE-2023-11111" in f.title)
    unfixed = next(f for f in findings if "CVE-2023-22222" in f.title)

    assert fixed.severity == "high"
    assert fixed.framework == "NIST SP 800-53 Rev. 5"
    assert fixed.control_id == "SI-2"
    assert "Upgrade cryptography to 41.0.6" in fixed.recommendation
    assert "requirements.txt" in fixed.evidence

    assert unfixed.severity == "critical"
    assert "No fix available" in unfixed.recommendation


def test_audit_codebase_handles_missing_trivy(monkeypatch, tmp_path):
    def _raise(*_args, **_kwargs):
        raise FileNotFoundError("trivy not found")

    monkeypatch.setattr(subprocess, "run", _raise)

    findings = ac.audit_codebase(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "Trivy" in findings[0].title


def test_audit_codebase_handles_nonexistent_path(monkeypatch):
    # No subprocess call should happen for a bad path; assert by making it explode if invoked.
    monkeypatch.setattr(subprocess, "run", lambda *_, **__: (_ for _ in ()).throw(AssertionError))

    findings = ac.audit_codebase(r"C:\definitely\does\not\exist\anywhere")
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "not found" in findings[0].title.lower()


def test_audit_codebase_empty_results(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_, **__: _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []})),
    )
    assert ac.audit_codebase(tmp_path) == []
