from auditor.tools.audit_logs import _heuristic_log_findings, audit_logs


def test_brute_force_pattern_triggers_finding():
    log = "\n".join(
        f"Mar 10 12:00:0{i} sshd[111]: Failed password for root from 10.0.0.5 port 22 ssh2"
        for i in range(6)
    )
    findings = _heuristic_log_findings(log)
    assert any("Brute-force" in f.title for f in findings)
    assert any(f.control_id == "AC-7" for f in findings)


def test_root_ssh_login_flagged():
    log = "Mar 10 12:00:00 host sshd[222]: Accepted password for root from 1.2.3.4 port 22 ssh2"
    findings = _heuristic_log_findings(log)
    assert any("root SSH login" in f.title for f in findings)


def test_audit_logs_combines_heuristic_and_llm():
    log = "\n".join(
        "Failed password for admin from 9.9.9.9 port 22 ssh2" for _ in range(6)
    )
    out = audit_logs(log)
    assert any("Brute-force" in f.title for f in out)
    assert any(f.title == "LLM stub finding" for f in out)


def test_successful_login_after_brute_force_flagged_critical():
    lines = [
        "Failed password for admin from 8.8.8.8 port 22 ssh2" for _ in range(6)
    ]
    lines.append("Accepted password for admin from 8.8.8.8 port 22 ssh2")
    findings = _heuristic_log_findings("\n".join(lines))
    compromise = [f for f in findings if "Successful login from brute-forcing source" in f.title]
    assert len(compromise) == 1
    assert compromise[0].severity == "critical"
    assert "8.8.8.8" in compromise[0].title


def test_accepted_login_without_brute_force_is_not_flagged():
    log = "Accepted publickey for deploy from 10.0.0.9 port 22 ssh2"
    findings = _heuristic_log_findings(log)
    assert not any("Successful login from brute-forcing source" in f.title for f in findings)


def test_web_attack_signatures_detected():
    log = (
        '1.2.3.4 - - "GET /p?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200\n'
        '1.2.3.4 - - "GET /../../../../etc/passwd HTTP/1.1" 404\n'
        '1.2.3.4 - - "GET /s?q=<script>alert(1)</script> HTTP/1.1" 200\n'
    )
    findings = _heuristic_log_findings(log)
    titles = " ".join(f.title for f in findings)
    assert "SQL injection" in titles
    assert "Path-traversal" in titles
    assert "Cross-site scripting" in titles
    assert all(
        f.control_id in ("SI-10", "AC-3")
        for f in findings
        if "attempt" in f.title.lower() or "detected in logs" in f.title
    )


def test_log_tampering_detected():
    log = "Mar 10 03:14:00 host bash[9]: user ran: rm /var/log/auth.log"
    findings = _heuristic_log_findings(log)
    tamper = [f for f in findings if "log tampering" in f.title.lower()]
    assert len(tamper) == 1
    assert tamper[0].control_id == "AU-9"
    assert tamper[0].severity == "high"
