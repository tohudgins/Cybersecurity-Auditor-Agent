"""Tests for live-scanning tools: Prowler (cloud), Nuclei (web), Trivy (image).

Subprocess is mocked so none of the binaries need to be installed.
"""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from auditor.tools import audit_cloud, audit_web
from auditor.tools import audit_codebase as ac


def _fake_run(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


# ── Prowler / cloud ──────────────────────────────────────────────────────────

def test_cloud_parses_fail_finding_with_nist_mapping():
    items = [
        {
            "status": "FAIL", "severity": "high", "check_id": "s3_bucket_public",
            "check_title": "S3 bucket is public", "region": "us-east-1",
            "resource_id": "my-bucket", "status_detail": "Bucket allows public read",
            "service_name": "s3",
            "compliance": {"NIST-800-53-r5": ["SC-28"]},
        },
        {"status": "PASS", "severity": "low", "check_id": "x", "service_name": "iam"},
    ]
    # Directly exercise the parser (no subprocess needed).
    findings = audit_cloud._parse_prowler_output(json.dumps(items), "aws")
    assert len(findings) == 1  # PASS excluded
    f = findings[0]
    assert f.severity == "high"
    assert f.control_id == "SC-28"
    assert f.framework == "NIST SP 800-53 Rev. 5"
    assert f.detection_source == "scanner"


def test_cloud_service_fallback_control():
    items = [{"status": "FAIL", "severity": "medium", "check_id": "iam_root_mfa",
              "check_title": "Root MFA", "service_name": "iam"}]
    findings = audit_cloud._parse_prowler_output(json.dumps(items), "aws")
    assert findings[0].control_id == "AC-6"  # iam → AC-6 fallback


def test_cloud_missing_prowler_is_info(monkeypatch):
    def _raise(*_a, **_k):
        raise FileNotFoundError
    monkeypatch.setattr(subprocess, "run", _raise)
    findings = audit_cloud.audit_cloud("aws")
    assert len(findings) == 1 and findings[0].severity == "info"
    assert "not installed" in findings[0].title.lower()


def test_cloud_unsupported_provider():
    findings = audit_cloud.audit_cloud("digitalocean")
    assert findings[0].severity == "info"
    assert "unsupported" in findings[0].title.lower()


def test_cloud_handles_jsonl_output():
    lines = "\n".join(json.dumps(x) for x in [
        {"status": "FAIL", "severity": "critical", "check_id": "a", "service_name": "kms"},
        {"status": "FAIL", "severity": "low", "check_id": "b", "service_name": "cloudtrail"},
    ])
    findings = audit_cloud._parse_prowler_output(lines, "aws")
    assert {f.control_id for f in findings} == {"SC-12", "AU-2"}


# ── Nuclei / web DAST ────────────────────────────────────────────────────────

def test_web_parses_jsonl_and_maps_control():
    line = json.dumps({
        "template-id": "sqli-detect",
        "info": {"name": "SQL Injection", "severity": "high", "tags": ["sqli", "injection"]},
        "matched-at": "https://x.test/q?id=1",
    })
    findings = audit_web._parse_nuclei_output(line, "https://x.test")
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].control_id == "SI-10"  # injection → SI-10
    assert findings[0].detection_source == "scanner"


def test_web_tls_tag_maps_to_sc8():
    line = json.dumps({"info": {"name": "Weak TLS", "severity": "medium", "tags": ["ssl", "tls"]}})
    findings = audit_web._parse_nuclei_output(line, "https://x.test")
    assert findings[0].control_id == "SC-8"


def test_web_missing_nuclei_is_info(monkeypatch):
    def _raise(*_a, **_k):
        raise FileNotFoundError
    monkeypatch.setattr(subprocess, "run", _raise)
    findings = audit_web.audit_web("example.com")
    assert findings[0].severity == "info" and "not installed" in findings[0].title.lower()


def test_web_normalizes_scheme(monkeypatch):
    captured = {}

    def _capture(cmd, **_k):
        captured["cmd"] = cmd
        return _fake_run(stdout="")
    monkeypatch.setattr(subprocess, "run", _capture)
    audit_web.audit_web("example.com")
    assert "https://example.com" in captured["cmd"]


# ── Trivy image ──────────────────────────────────────────────────────────────

_IMG_TRIVY = {
    "Results": [{
        "Target": "nginx:1.21 (debian)",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-99999", "PkgName": "openssl",
            "InstalledVersion": "1.1", "FixedVersion": "1.1.1", "Severity": "CRITICAL",
            "Title": "openssl flaw",
        }],
    }]
}


def test_image_scan_parses_cve(monkeypatch):
    monkeypatch.setattr(subprocess, "run",
                        lambda *_a, **_k: _fake_run(stdout=json.dumps(_IMG_TRIVY)))
    findings = ac.audit_image("nginx:1.21")
    assert len(findings) == 1
    assert "CVE-2023-99999" in findings[0].title
    assert findings[0].control_id == "SI-2"
    assert findings[0].source_artifact == "nginx:1.21"


def test_image_missing_trivy_is_info(monkeypatch):
    def _raise(*_a, **_k):
        raise FileNotFoundError
    monkeypatch.setattr(subprocess, "run", _raise)
    findings = ac.audit_image("nginx:1.21")
    assert findings[0].severity == "info"
