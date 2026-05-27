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


# ---- Bandit -----------------------------------------------------------------

_FAKE_BANDIT_OUTPUT = {
    "errors": [],
    "results": [
        {
            "code": "subprocess.run(cmd, shell=True)",
            "filename": "/scan/app/handlers.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
            "issue_severity": "HIGH",
            "issue_text": "subprocess call with shell=True identified, security issue.",
            "line_number": 42,
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
        },
    ],
}


def test_audit_codebase_runs_bandit_when_python_present(monkeypatch, tmp_path):
    # Create a .py file so _has_python_files returns True.
    (tmp_path / "app.py").write_text("import subprocess\nsubprocess.run('x', shell=True)\n")

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "bandit":
            return _fake_run(stdout=json.dumps(_FAKE_BANDIT_OUTPUT))
        # default to trivy with no findings
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)

    findings = ac.audit_codebase(tmp_path)
    bandit_findings = [f for f in findings if (f.control_id or "").startswith(("CWE-", "B"))]
    assert len(bandit_findings) == 1
    f = bandit_findings[0]
    assert "B602" in f.title
    assert f.severity == "high"
    assert f.framework == "OWASP ASVS 5.0"
    assert f.control_id == "CWE-78"
    assert "shell=True" in f.evidence


def test_audit_codebase_skips_bandit_when_no_python(monkeypatch, tmp_path):
    # tmp_path has no .py files. Bandit should NOT be invoked.
    called: dict[str, bool] = {"bandit": False}

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "bandit":
            called["bandit"] = True
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)

    ac.audit_codebase(tmp_path)
    assert called["bandit"] is False


def test_audit_codebase_extracts_cvss_score_from_trivy(monkeypatch, tmp_path):
    payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgName": "log4j",
                        "InstalledVersion": "2.14.0",
                        "FixedVersion": "2.17.1",
                        "Severity": "CRITICAL",
                        "Title": "Log4Shell",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 10.0,
                                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            },
                            "redhat": {"V3Score": 9.8},
                        },
                    },
                ],
            }
        ],
    }
    monkeypatch.setattr(subprocess, "run", lambda *_, **__: _fake_run(stdout=json.dumps(payload)))

    findings = ac.audit_codebase(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.cvss_score == 10.0  # NVD chosen over Red Hat
    assert f.cvss_vector is not None
    assert f.cvss_vector.startswith("CVSS:3.1/")


def test_audit_codebase_missing_cvss_is_none(monkeypatch, tmp_path):
    payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-00001",
                        "PkgName": "obscure",
                        "InstalledVersion": "0.0.1",
                        "Severity": "HIGH",
                        "Title": "Some vuln",
                    },
                ],
            }
        ],
    }
    monkeypatch.setattr(subprocess, "run", lambda *_, **__: _fake_run(stdout=json.dumps(payload)))

    f = ac.audit_codebase(tmp_path)[0]
    assert f.cvss_score is None
    assert f.cvss_vector is None


def test_audit_codebase_handles_missing_bandit(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("pass\n")

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "bandit":
            raise FileNotFoundError("bandit not found")
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)
    findings = ac.audit_codebase(tmp_path)
    bandit_msg = [f for f in findings if "Bandit not installed" in f.title]
    assert len(bandit_msg) == 1


# ---- Secrets scanning -------------------------------------------------------

_FAKE_GITLEAKS_OUTPUT = [
    {
        "Description": "Generic API Key",
        "File": "config/settings.py",
        "StartLine": 12,
        "RuleID": "generic-api-key",
        "Secret": "REDACTED",
    }
]


def test_secrets_scan_gitleaks_found(monkeypatch, tmp_path):
    """When gitleaks is installed and finds a leak, it surfaces as a finding."""

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "gitleaks":
            return _fake_run(stdout=json.dumps(_FAKE_GITLEAKS_OUTPUT))
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)
    findings = ac.audit_codebase(tmp_path)
    secret_findings = [f for f in findings if "Secret detected" in f.title]
    assert len(secret_findings) == 1
    f = secret_findings[0]
    assert f.severity == "high"
    assert f.control_id == "IA-5"
    assert "generic-api-key" in f.evidence


def test_secrets_scan_gitleaks_no_leaks(monkeypatch, tmp_path):
    """When gitleaks finds nothing it returns an empty list; no extra findings."""

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "gitleaks":
            return _fake_run(stdout="[]")
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)
    findings = ac.audit_codebase(tmp_path)
    assert not any("Secret" in f.title for f in findings)


def test_secrets_scan_regex_fallback_finds_password(monkeypatch, tmp_path):
    """Without gitleaks, the regex fallback catches a hardcoded password."""
    (tmp_path / "config.py").write_text('DB_PASSWORD = "SuperSecret123!"\n')

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "gitleaks":
            raise FileNotFoundError("gitleaks not found")
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)
    findings = ac.audit_codebase(tmp_path)
    secret_findings = [f for f in findings if "password" in f.title.lower() or "Secret" in f.title]
    assert len(secret_findings) >= 1
    assert all(f.control_id == "IA-5" for f in secret_findings if f.severity == "high")


def test_secrets_scan_regex_fallback_finds_private_key(monkeypatch, tmp_path):
    """Regex fallback detects an embedded RSA private key."""
    (tmp_path / "deploy.sh").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "gitleaks":
            raise FileNotFoundError
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)
    findings = ac.audit_codebase(tmp_path)
    key_findings = [f for f in findings if "private key" in f.title.lower()]
    assert len(key_findings) >= 1
    assert key_findings[0].control_id == "SC-28"


def test_secrets_scan_regex_no_secrets_in_clean_file(monkeypatch, tmp_path):
    """A clean Python file produces no secret findings via regex."""
    (tmp_path / "clean.py").write_text("x = 1 + 1\nprint(x)\n")

    def _route(cmd, *_a, **_kw):
        if cmd and cmd[0] == "gitleaks":
            raise FileNotFoundError
        return _fake_run(stdout=json.dumps({"SchemaVersion": 2, "Results": []}))

    monkeypatch.setattr(subprocess, "run", _route)
    findings = ac.audit_codebase(tmp_path)
    # The info "gitleaks not installed" finding may appear but no secret findings
    secret_high = [f for f in findings if f.severity == "high" and f.control_id in ("IA-5", "SC-28")]
    assert secret_high == []
