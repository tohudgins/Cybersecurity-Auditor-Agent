import json
import subprocess
from types import SimpleNamespace

from auditor.tools import audit_config as ac
from auditor.tools.audit_config import (
    _check_dockerfile,
    _check_kubernetes_regex,
    _check_sshd,
    _check_terraform_regex,
    audit_config,
    detect_config_kind,
)


def test_detect_config_kind_handles_common_files():
    assert detect_config_kind("main.tf") == "Terraform"
    assert detect_config_kind("Dockerfile") == "Dockerfile"
    assert detect_config_kind("sshd_config") == "sshd_config"
    assert detect_config_kind("nginx.conf") == "nginx"
    assert detect_config_kind("deployment.yaml", "apiVersion: v1\nkind: Pod") == "Kubernetes"


def test_sshd_heuristics_flag_root_login_and_passwords():
    cfg = "PermitRootLogin yes\nPasswordAuthentication yes\n"
    findings = _check_sshd(cfg)
    titles = {f.title for f in findings}
    assert any("Root SSH login" in t for t in titles)
    assert any("Password-based" in t for t in titles)


def test_dockerfile_heuristics_flag_root_and_latest_tag():
    df = "FROM python:latest\nRUN apt-get update\n"
    findings = _check_dockerfile(df)
    titles = {f.title for f in findings}
    assert any("runs as root" in t for t in titles)
    assert any(":latest" in t for t in titles)


def test_audit_config_returns_combined_heuristic_and_llm_findings():
    cfg = "PermitRootLogin yes\n"
    out = audit_config(cfg, "sshd_config")
    assert any(f.title.startswith("Root SSH login") for f in out)
    assert any(f.title == "LLM stub finding" for f in out)
    assert all(f.source_artifact == "sshd_config" for f in out)


# ---- Checkov path ---------------------------------------------------------

_FAKE_CHECKOV_OUTPUT = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                "check_result": {"result": "FAILED"},
                "file_path": "/tmp/abc.tf",
                "file_line_range": [10, 20],
                "resource": "aws_security_group.web",
                "guideline": "https://docs.bridgecrew.io/CKV_AWS_24",
                "severity": "MEDIUM",
            },
        ]
    },
}


def _fake_run(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def test_terraform_uses_checkov_when_available(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_kw: _fake_run(stdout=json.dumps(_FAKE_CHECKOV_OUTPUT)),
    )
    out = audit_config("resource \"aws_security_group\" \"web\" {}", "main.tf")
    titles = [f.title for f in out]
    assert any("CKV_AWS_24" in t for t in titles)
    # Should NOT include the regex fallback finding when Checkov ran.
    assert not any("falling back to regex" in t for t in titles)


def test_terraform_falls_back_to_regex_when_checkov_missing(monkeypatch):
    def _raise(*_a, **_kw):
        raise FileNotFoundError("checkov not found")

    monkeypatch.setattr(subprocess, "run", _raise)
    out = audit_config(
        'resource "aws_security_group" "web" { cidr_blocks = ["0.0.0.0/0"] }',
        "main.tf",
    )
    titles = [f.title for f in out]
    assert any("Checkov not installed" in t for t in titles)
    assert any("0.0.0.0/0" in t for t in titles)


def test_kubernetes_regex_still_works_standalone():
    yaml = "spec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n"
    findings = _check_kubernetes_regex(yaml)
    assert any("privileged" in f.title.lower() for f in findings)


def test_terraform_regex_still_works_standalone():
    tf = 'resource "aws_security_group" "x" { ingress { cidr_blocks = ["0.0.0.0/0"] } }'
    findings = _check_terraform_regex(tf)
    assert any("0.0.0.0/0" in f.title for f in findings)


def test_checkov_finding_severity_mapping(monkeypatch):
    payload = {
        "results": {
            "failed_checks": [
                {"check_id": "CKV_HIGH", "check_name": "Critical thing", "severity": "CRITICAL"},
                {"check_id": "CKV_LOW", "check_name": "Low thing", "severity": "LOW"},
                {"check_id": "CKV_NONE", "check_name": "Missing severity"},
            ]
        }
    }
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: _fake_run(stdout=json.dumps(payload)))
    out = audit_config("foo", "main.tf")
    sev_by_id = {f.control_id: f.severity for f in out if (f.control_id or "").startswith("CKV_")}
    assert sev_by_id["CKV_HIGH"] == "critical"
    assert sev_by_id["CKV_LOW"] == "low"
    assert sev_by_id["CKV_NONE"] == "medium"  # default when severity field absent


def test_checkov_handles_list_shaped_output(monkeypatch):
    """Some Checkov versions emit a list of framework dicts instead of one dict."""
    payload = [_FAKE_CHECKOV_OUTPUT]
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: _fake_run(stdout=json.dumps(payload)))
    out = audit_config("foo", "main.tf")
    assert any("CKV_AWS_24" in f.title for f in out)


def test_run_checkov_silent_on_clean_input(monkeypatch):
    """Empty failed_checks → no Checkov findings (only LLM stub from audit_config)."""
    payload = {"results": {"failed_checks": []}}
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: _fake_run(stdout=json.dumps(payload)))
    out = audit_config("foo", "main.tf")
    # Only the LLM stub finding should remain
    titles = [f.title for f in out]
    assert "LLM stub finding" in titles
    assert not any(t.startswith("[CKV_") for t in titles)


def test_module_exports_ac_for_completeness():
    """Defensive: confirm the public function is still accessible via module import."""
    assert callable(ac.audit_config)
