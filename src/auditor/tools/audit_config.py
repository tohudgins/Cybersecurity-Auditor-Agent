"""Audit infrastructure / service config files for security misconfigurations.

Mixes cheap regex heuristics with LLM-driven analysis so we catch the obvious
issues fast and let the model reason about the rest.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Sequence

from auditor.models import Finding
from auditor.prompts.audit import CONFIG_AUDIT_PROMPT
from auditor.retrieval.retriever import format_docs, retrieve
from auditor.tools._findings_llm import run_findings_chain


# ---- File type detection ---------------------------------------------------

def detect_config_kind(filename: str, content: str = "") -> str:
    name = filename.lower()
    if name.endswith(".tf") or name.endswith(".tfvars"):
        return "Terraform"
    if name == "dockerfile" or name.endswith(".dockerfile") or name.startswith("dockerfile"):
        return "Dockerfile"
    if "sshd_config" in name:
        return "sshd_config"
    if "nginx" in name and (name.endswith(".conf") or name.endswith(".cfg")):
        return "nginx"
    if name.endswith((".yaml", ".yml")):
        if re.search(r"^\s*(apiVersion|kind):", content, re.MULTILINE):
            return "Kubernetes"
        return "YAML"
    if name.endswith(".conf"):
        return "generic config"
    return "unknown config"


# ---- Heuristic checks per kind --------------------------------------------

def _check_sshd(content: str) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (
            r"^\s*PermitRootLogin\s+yes\b",
            "Root SSH login is enabled",
            "high",
            "CIS Controls v8.1",
            "5.4",
            "Set `PermitRootLogin no` and require named user accounts with sudo.",
        ),
        (
            r"^\s*PasswordAuthentication\s+yes\b",
            "Password-based SSH authentication is enabled",
            "high",
            "NIST SP 800-53 Rev. 5",
            "IA-2",
            "Set `PasswordAuthentication no` and require key-based or MFA authentication.",
        ),
        (
            r"^\s*PermitEmptyPasswords\s+yes\b",
            "Empty SSH passwords are permitted",
            "critical",
            "NIST SP 800-53 Rev. 5",
            "IA-5",
            "Set `PermitEmptyPasswords no`.",
        ),
        (
            r"^\s*Protocol\s+1\b",
            "Insecure SSH protocol version 1 enabled",
            "critical",
            "NIST SP 800-53 Rev. 5",
            "SC-8",
            "Use only `Protocol 2` (default in modern OpenSSH).",
        ),
        (
            r"^\s*X11Forwarding\s+yes\b",
            "X11 forwarding is enabled",
            "low",
            "CIS Controls v8.1",
            "4.8",
            "Disable unless explicitly required: `X11Forwarding no`.",
        ),
    ]
    for pattern, title, sev, fw, ctrl, rec in patterns:
        m = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
        if m:
            findings.append(
                Finding(
                    title=title,
                    severity=sev,  # type: ignore[arg-type]
                    framework=fw,
                    control_id=ctrl,
                    evidence=m.group(0).strip(),
                    recommendation=rec,
                )
            )
    return findings


def _check_dockerfile(content: str) -> list[Finding]:
    findings: list[Finding] = []
    has_user = re.search(r"^\s*USER\s+(?!root\b)\S+", content, re.MULTILINE)
    if not has_user:
        findings.append(
            Finding(
                title="Container runs as root (no non-root USER directive)",
                severity="high",
                framework="CIS Controls v8.1",
                control_id="4.7",
                evidence="No `USER <non-root>` directive found in Dockerfile.",
                recommendation="Add `USER appuser` (or similar) after creating a non-root user.",
            )
        )
    if re.search(r"^\s*FROM\s+\S+:latest\b", content, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                title="Base image pinned to mutable `:latest` tag",
                severity="medium",
                framework="NIST SP 800-53 Rev. 5",
                control_id="CM-2",
                evidence="`FROM ...:latest` directive present.",
                recommendation="Pin to a specific image digest or version tag.",
            )
        )
    if re.search(r"^\s*ADD\s+https?://", content, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                title="`ADD` used with remote URL (no integrity check)",
                severity="medium",
                framework="NIST SP 800-53 Rev. 5",
                control_id="SI-7",
                evidence="`ADD <url>` directive present.",
                recommendation="Download with `RUN curl ... && sha256sum -c` so integrity is verified.",
            )
        )
    return findings


def _check_nginx(content: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"server_tokens\s+on\s*;", content):
        findings.append(
            Finding(
                title="nginx version disclosure enabled",
                severity="low",
                framework="OWASP ASVS 4.0.3",
                control_id="V14.3.2",
                evidence="`server_tokens on;` directive present.",
                recommendation="Set `server_tokens off;` to suppress version banners.",
            )
        )
    if re.search(r"ssl_protocols\b[^;]*\b(SSLv[23]|TLSv1(\.0|\.1)?)\b", content):
        findings.append(
            Finding(
                title="Weak TLS / SSL protocol version enabled",
                severity="high",
                framework="NIST SP 800-53 Rev. 5",
                control_id="SC-8(1)",
                evidence="`ssl_protocols` directive permits SSLv2/v3 or TLS 1.0/1.1.",
                recommendation="Restrict to `ssl_protocols TLSv1.2 TLSv1.3;`.",
            )
        )
    return findings


def _check_terraform(content: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"\s*\]", content):
        findings.append(
            Finding(
                title="Security group allows ingress from 0.0.0.0/0",
                severity="high",
                framework="NIST SP 800-53 Rev. 5",
                control_id="SC-7",
                evidence='`cidr_blocks = ["0.0.0.0/0"]` ingress rule.',
                recommendation="Restrict CIDRs to known-good ranges (corp VPN, peered VPCs, etc.).",
            )
        )
    if re.search(r'acl\s*=\s*"public-read', content):
        findings.append(
            Finding(
                title="S3 bucket ACL set to public-read",
                severity="critical",
                framework="NIST SP 800-53 Rev. 5",
                control_id="AC-3",
                evidence='`acl = "public-read"` on S3 bucket.',
                recommendation="Use `acl = \"private\"` and grant access via IAM policies / signed URLs.",
            )
        )
    return findings


def _check_kubernetes(content: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"privileged:\s*true", content):
        findings.append(
            Finding(
                title="Pod runs in privileged mode",
                severity="critical",
                framework="CIS Controls v8.1",
                control_id="4.7",
                evidence="`privileged: true` in pod/container securityContext.",
                recommendation="Set `privileged: false`; grant only the specific capabilities required.",
            )
        )
    if re.search(r"hostNetwork:\s*true", content):
        findings.append(
            Finding(
                title="Pod uses host network namespace",
                severity="high",
                framework="NIST SP 800-53 Rev. 5",
                control_id="SC-7",
                evidence="`hostNetwork: true` in pod spec.",
                recommendation="Remove `hostNetwork: true` unless absolutely required.",
            )
        )
    if re.search(r"runAsUser:\s*0\b", content):
        findings.append(
            Finding(
                title="Pod explicitly runs as UID 0 (root)",
                severity="high",
                framework="CIS Controls v8.1",
                control_id="4.7",
                evidence="`runAsUser: 0` in securityContext.",
                recommendation="Set `runAsNonRoot: true` and use a non-zero `runAsUser`.",
            )
        )
    return findings


_CHECKS: dict[str, Callable[[str], list[Finding]]] = {
    "sshd_config": _check_sshd,
    "Dockerfile": _check_dockerfile,
    "nginx": _check_nginx,
    "Terraform": _check_terraform,
    "Kubernetes": _check_kubernetes,
}


# ---- Public entry point ----------------------------------------------------

def audit_config(
    content: str,
    filename: str,
    frameworks: Sequence[str] | None = None,
) -> list[Finding]:
    kind = detect_config_kind(filename, content)
    heuristic = _CHECKS.get(kind, lambda _c: [])(content)
    for f in heuristic:
        f.source_artifact = filename

    probe = f"{kind} security configuration hardening best practices"
    docs = retrieve(probe, frameworks=frameworks, k=10)

    heuristic_summary = (
        "\n".join(f"- {f.title} ({f.severity}): {f.evidence}" for f in heuristic)
        or "(no heuristic findings)"
    )

    llm_findings = run_findings_chain(
        CONFIG_AUDIT_PROMPT,
        {
            "config_kind": kind,
            "config_text": content[:30_000],
            "context": format_docs(docs),
            "frameworks": ", ".join(frameworks) if frameworks else "all configured frameworks",
            "heuristic_findings": heuristic_summary,
        },
        source_artifact=filename,
    )

    # De-dup: drop LLM findings whose title closely matches a heuristic one.
    seen_titles = {f.title.lower() for f in heuristic}
    deduped = [f for f in llm_findings if f.title.lower() not in seen_titles]
    return heuristic + deduped


def audit_config_file(path: Path, frameworks: Sequence[str] | None = None) -> list[Finding]:
    return audit_config(path.read_text(encoding="utf-8", errors="replace"), path.name, frameworks)
