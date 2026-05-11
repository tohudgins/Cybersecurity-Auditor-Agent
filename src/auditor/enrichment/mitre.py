"""MITRE ATT&CK technique tagging for Findings.

Hand-curated keyword → technique mapping tuned to the finding types this agent
actually produces. Compared to fuzzy-matching the full STIX bundle (~20MB), this
is faster, deterministic, and more precise: each entry was chosen because the
mapping is unambiguous for THIS auditor's findings.

References:
- https://attack.mitre.org/techniques/enterprise/
"""
from __future__ import annotations

from auditor.models import Finding

# technique_id → list of lowercase substrings that, if present in a finding's
# title/evidence/recommendation, indicate the technique applies.
_TECHNIQUE_KEYWORDS: dict[str, tuple[str, ...]] = {
    # Initial Access / Public-facing exploitation
    "T1190": (
        "0.0.0.0/0",
        "public-facing",
        "exposed service",
        "open ingress",
        "ingress from anywhere",
        "cve-",
    ),
    # Valid Accounts (and sub-techniques)
    "T1078": ("valid account", "shared credential", "default credential"),
    "T1078.003": ("permitrootlogin", "root ssh", "root login", "local account"),
    # Brute Force (and sub-techniques)
    "T1110": ("brute force", "brute-force"),
    "T1110.001": ("password guess", "failed password", "failed login"),
    "T1110.004": ("credential stuffing", "empty password", "permitemptypasswords"),
    # Supply chain / image integrity
    "T1195.002": (
        ":latest tag",
        "mutable tag",
        "no integrity check",
        "supply chain",
        "unverified download",
        "add http",
    ),
    # Cloud-storage data exfil
    "T1530": ("public-read", "publicly accessible bucket", "public bucket", "cloud storage exposure"),
    # Escape to host / container privilege
    "T1611": (
        "privileged",
        "host network",
        "hostnetwork",
        "runasuser: 0",
        "container escape",
        "runs as root",
        "no user directive",
    ),
    # Impair Defenses (logging tampering)
    "T1562.012": ("disable audit", "without audit trail", "no logging", "log tampering"),
    # Input Capture
    "T1056.002": ("x11 forwarding",),
}


def _haystack(finding: Finding) -> str:
    parts = [finding.title, finding.evidence, finding.recommendation]
    return " ".join(p for p in parts if p).lower()


def tag_finding(finding: Finding) -> list[str]:
    """Return the MITRE ATT&CK technique IDs this finding maps to.

    Deterministic substring matching against a curated keyword map. Returns an
    empty list if no technique matches.
    """
    hay = _haystack(finding)
    matches: list[str] = []
    for technique_id, keywords in _TECHNIQUE_KEYWORDS.items():
        if any(k in hay for k in keywords):
            matches.append(technique_id)
    return matches


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Annotate each finding in-place with its matching ATT&CK technique IDs."""
    for f in findings:
        techniques = tag_finding(f)
        if techniques:
            f.attack_techniques = techniques
    return findings
