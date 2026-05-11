from auditor.tools.audit_config import _check_dockerfile, _check_sshd, audit_config, detect_config_kind


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
