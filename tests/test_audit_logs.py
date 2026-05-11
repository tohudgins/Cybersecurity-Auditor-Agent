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
