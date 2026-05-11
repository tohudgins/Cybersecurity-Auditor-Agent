"""Tests for KEV catalog lookup and MITRE ATT&CK technique tagging."""
from __future__ import annotations

import json

from auditor.enrichment import kev as kev_mod
from auditor.enrichment.mitre import enrich_findings, tag_finding
from auditor.models import Finding

# ---- KEV -------------------------------------------------------------------

_FAKE_KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.05.10",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2"},
        {"cveID": "CVE-2023-99999", "vendorProject": "Acme", "product": "Widget"},
    ],
}


def _real_is_kev(cve_id: str) -> bool:
    """Bypass conftest's autouse `is_kev` stub by reading the module's set directly."""
    if kev_mod._cve_set is None:
        kev_mod._cve_set = kev_mod._build_cve_set()
    return (cve_id or "").upper().strip() in kev_mod._cve_set


def test_is_kev_hits_known_cve(monkeypatch):
    monkeypatch.setattr(kev_mod, "_load_catalog", lambda: _FAKE_KEV)
    monkeypatch.setattr(kev_mod, "_cve_set", None)  # force rebuild from _FAKE_KEV

    assert _real_is_kev("CVE-2021-44228") is True
    assert _real_is_kev("cve-2023-99999") is True  # case-insensitive
    assert _real_is_kev("CVE-9999-00000") is False
    assert _real_is_kev("") is False


def test_load_catalog_uses_fresh_cache(monkeypatch, tmp_path):
    cache_file = tmp_path / "kev.json"
    cache_file.write_text(json.dumps(_FAKE_KEV), encoding="utf-8")

    monkeypatch.setattr(kev_mod, "_CACHE_PATH", cache_file)
    monkeypatch.setattr(kev_mod, "_cache_is_fresh", lambda: True)

    # Should NOT call _download_kev when cache is fresh.
    def _explode() -> bytes:
        raise AssertionError("network should not be hit when cache is fresh")

    monkeypatch.setattr(kev_mod, "_download_kev", _explode)

    catalog = kev_mod._load_catalog()
    assert len(catalog["vulnerabilities"]) == 2


def test_load_catalog_downloads_when_stale(monkeypatch, tmp_path):
    cache_file = tmp_path / "kev.json"
    monkeypatch.setattr(kev_mod, "_CACHE_PATH", cache_file)
    monkeypatch.setattr(kev_mod, "_cache_is_fresh", lambda: False)
    monkeypatch.setattr(kev_mod, "_download_kev", lambda: json.dumps(_FAKE_KEV).encode())

    catalog = kev_mod._load_catalog()
    assert len(catalog["vulnerabilities"]) == 2
    assert cache_file.exists()  # cache written


# ---- MITRE ATT&CK ----------------------------------------------------------


def _f(title: str, evidence: str = "", recommendation: str = "stub") -> Finding:
    return Finding(title=title, evidence=evidence or title, recommendation=recommendation)


def test_tag_brute_force():
    f = _f("Brute-force pattern: 9 failed logins from 1.2.3.4")
    techniques = tag_finding(f)
    assert "T1110" in techniques


def test_tag_root_ssh_login():
    f = _f(
        "Root SSH login is enabled",
        evidence="PermitRootLogin yes",
        recommendation="Set PermitRootLogin no",
    )
    techniques = tag_finding(f)
    assert "T1078.003" in techniques


def test_tag_open_security_group():
    f = _f(
        "Security group allows ingress from 0.0.0.0/0",
        evidence='cidr_blocks = ["0.0.0.0/0"]',
    )
    assert "T1190" in tag_finding(f)


def test_tag_public_s3_bucket():
    f = _f("S3 bucket ACL set to public-read")
    assert "T1530" in tag_finding(f)


def test_tag_privileged_pod():
    f = _f("Pod runs in privileged mode", evidence="privileged: true")
    assert "T1611" in tag_finding(f)


def test_tag_unrelated_finding_yields_nothing():
    f = _f("Generic info-level note", evidence="nothing actionable")
    assert tag_finding(f) == []


def test_enrich_findings_populates_attack_techniques():
    findings = [
        _f("Brute-force pattern from 1.2.3.4"),
        _f("Unrelated info"),
    ]
    enrich_findings(findings)
    assert findings[0].attack_techniques == ["T1110"]
    assert findings[1].attack_techniques == []
