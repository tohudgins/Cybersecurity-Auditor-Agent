"""Route a query to the indexed framework(s) it names, to scope retrieval.

At ~40k chunks across 56 frameworks, semantic similarity alone can't tell *which*
standard a user means — "SOC 2 CC6.1 logical access" would surface CMMC/NIST
access-control text just as strongly. When a query explicitly names a framework
we scope retrieval to it, so a SOC 2 question gets a SOC 2 answer.

Detection is deliberately conservative: only explicit framework names/IDs route
(so "access control best practices" stays corpus-wide). Labels returned here
match the chunk ``framework`` metadata exactly, so they drop straight into
``retrieve(frameworks=...)``.
"""
from __future__ import annotations

import re
from functools import lru_cache

from auditor.config import settings
from auditor.ingest.pdf_loader import framework_for

# NIST label helpers.
_53 = "NIST SP 800-53 Rev. 5"
_53A = "NIST SP 800-53A Rev. 5 (Assessment Procedures)"
_171 = "NIST SP 800-171 Rev. 3"
_171A = "NIST SP 800-171A Rev. 3 (Assessment Procedures)"
_172 = "NIST SP 800-172 (Enhanced Security Requirements for CUI)"
_172A = "NIST SP 800-172A (Enhanced Requirements Assessment)"
_CMMC = [f"CMMC 2.0 Level {n} (Assessment Guide)" for n in (1, 2, 3)]
_OWASP_ALL = [
    "OWASP Top 10 2025", "OWASP ASVS 5.0",
    "OWASP API Security Top 10 2023", "OWASP Cheat Sheet Series",
]

# Ordered (specific → general). Each (pattern, labels); ALL matching rules union.
_ROUTES: list[tuple[re.Pattern[str], list[str]]] = [
    (re.compile(r"\bPCI(?:[-\s]?DSS)?\b", re.I), ["PCI DSS v4.0.1"]),
    (re.compile(r"\bSOC[-\s]?2\b|\btrust services\b|\bTSC\b", re.I), ["SOC 2 Trust Services Criteria"]),
    (re.compile(r"\bHIPAA\b|\b164\.\d{3}\b", re.I), ["HIPAA Security Rule (45 CFR Part 164)"]),
    (re.compile(r"\bCMMC\b.*\b(level\s*1|l1)\b|\b(level\s*1|l1)\b.*\bCMMC\b", re.I), [_CMMC[0]]),
    (re.compile(r"\bCMMC\b.*\b(level\s*2|l2)\b|\b(level\s*2|l2)\b.*\bCMMC\b", re.I), [_CMMC[1]]),
    (re.compile(r"\bCMMC\b.*\b(level\s*3|l3)\b|\b(level\s*3|l3)\b.*\bCMMC\b", re.I), [_CMMC[2]]),
    # Generic CMMC only when no level was named (else the level rule above wins).
    (re.compile(r"\bCMMC\b(?!.*\b(?:level\s*[123]|l[123])\b)", re.I), _CMMC),
    (re.compile(r"800[-\s]?53A", re.I), [_53A]),
    (re.compile(r"800[-\s]?53\b", re.I), [_53, _53A]),
    (re.compile(r"800[-\s]?171A", re.I), [_171A]),
    (re.compile(r"800[-\s]?171\b", re.I), [_171, _171A]),
    (re.compile(r"800[-\s]?172A", re.I), [_172A]),
    (re.compile(r"800[-\s]?172\b", re.I), [_172, _172A]),
    (re.compile(r"\bCSF\b|cybersecurity framework", re.I), ["NIST Cybersecurity Framework 2.1"]),
    (re.compile(r"800[-\s]?218|\bSSDF\b", re.I), ["NIST SP 800-218 (SSDF)"]),
    (re.compile(r"800[-\s]?63", re.I), [
        "NIST SP 800-63A (Identity Proofing and Enrollment)",
        "NIST SP 800-63B (Digital Identity / Authentication)",
        "NIST SP 800-63C (Federation and Assertions)",
    ]),
    (re.compile(r"800[-\s]?207|zero[-\s]?trust\s+arch", re.I), [
        "NIST SP 800-207 (Zero Trust Architecture)", "CISA Zero Trust Maturity Model v2",
    ]),
    (re.compile(r"800[-\s]?190", re.I), ["NIST SP 800-190 (Application Container Security)"]),
    (re.compile(r"800[-\s]?161", re.I), ["NIST SP 800-161 Rev. 1 (Supply Chain Risk Management)"]),
    (re.compile(r"800[-\s]?61\b", re.I), ["NIST SP 800-61 Rev. 3 (Incident Response)"]),
    (re.compile(r"\bAI\s*RMF\b", re.I), ["NIST AI 100-1 (AI Risk Management Framework)"]),
    (re.compile(r"ATT&CK|\bATTACK\b|\bMITRE\b", re.I), ["MITRE ATT&CK Enterprise"]),
    (re.compile(r"\bASVS\b", re.I), ["OWASP ASVS 5.0"]),
    (re.compile(r"\bOWASP\b.*\bAPI\b|\bAPI\b.*\bOWASP\b", re.I), ["OWASP API Security Top 10 2023"]),
    (re.compile(r"\bOWASP\b", re.I), _OWASP_ALL),
    (re.compile(r"\bCIS\b.*\bcontrols?\b|\bcontrols?\b.*\bCIS\b", re.I), ["CIS Controls v8.1"]),
]

# CIS Benchmark product keyword → substring that identifies the benchmark label.
_BENCHMARK_KEYWORDS = {
    "aws": "Amazon", "amazon": "Amazon", "azure": "Azure", "gcp": "Google Cloud",
    "google cloud": "Google Cloud", "workspace": "Google Workspace", "m365": "Microsoft 365",
    "microsoft 365": "Microsoft 365", "office 365": "Microsoft 365", "windows 10": "Windows 10",
    "windows 11": "Windows 11", "windows server": "Windows Server", "ubuntu": "Ubuntu",
    "linux": "Ubuntu", "macos": "macOS", "ipados": "iPadOS", "docker": "Docker",
    "kubernetes": "Kubernetes", "k8s": "Kubernetes", "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL", "chrome": "Chrome", "vmware": "VMware", "esxi": "VMware",
}


@lru_cache(maxsize=1)
def _benchmark_labels() -> list[str]:
    """The exact framework labels of the CIS Benchmarks present on disk."""
    bench_dir = settings.data_dir / "benchmarks"
    if not bench_dir.exists():
        return []
    return sorted({framework_for(p.name) for p in bench_dir.rglob("*.pdf")})


def _benchmark_route(query: str) -> list[str]:
    if not re.search(r"\bCIS\b.*bench|bench.*\bCIS\b|\bbenchmark\b|\bhardening\b", query, re.I):
        return []
    labels = _benchmark_labels()
    ql = query.lower()
    matched = [
        lbl for kw, needle in _BENCHMARK_KEYWORDS.items()
        if kw in ql for lbl in labels if needle in lbl
    ]
    # A generic "CIS benchmark …" with no product → don't over-scope (all benchmarks).
    return sorted(set(matched))


def detect_frameworks(query: str) -> list[str]:
    """Framework metadata labels a query explicitly names (empty if none)."""
    if not query:
        return []
    found: list[str] = []
    for pattern, labels in _ROUTES:
        if pattern.search(query):
            for lbl in labels:
                if lbl not in found:
                    found.append(lbl)
    for lbl in _benchmark_route(query):
        if lbl not in found:
            found.append(lbl)
    return found


def reset_cache() -> None:
    _benchmark_labels.cache_clear()
