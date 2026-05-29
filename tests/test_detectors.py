import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.parser import parse_auth_log, parse_nginx_log
from analyzer.detectors import (
    detect_ssh_brute_force,
    detect_web_scanning,
    detect_sensitive_paths,
    detect_suspicious_user_agents,
    detect_repeated_401_403,
    run_all_detectors,
)

SAMPLE = Path(__file__).parent.parent / "sample_logs"


def _auth_events():
    evs, _ = parse_auth_log(str(SAMPLE / "auth.log"))
    return evs


def _nginx_events():
    evs, _ = parse_nginx_log(str(SAMPLE / "nginx_access.log"))
    return evs


def test_brute_force_detects_high_volume_ip():
    findings = detect_ssh_brute_force(_auth_events())
    ips = [f.source_ip for f in findings]
    assert "185.234.218.4" in ips


def test_brute_force_medium_threshold():
    findings = detect_ssh_brute_force(_auth_events())
    medium = [f for f in findings if f.severity == "Medium"]
    high_crit = [f for f in findings if f.severity in ("High", "Critical")]
    assert len(findings) > 0
    assert len(medium) + len(high_crit) == len(findings)


def test_brute_force_has_evidence():
    findings = detect_ssh_brute_force(_auth_events())
    for f in findings:
        assert f.evidence
        assert f.related_events_count > 0


def test_web_scanning_detects_nikto():
    findings = detect_web_scanning(_nginx_events())
    ips = [f.source_ip for f in findings]
    assert "185.199.109.10" in ips


def test_web_scanning_above_threshold():
    findings = detect_web_scanning(_nginx_events())
    for f in findings:
        assert f.related_events_count > 30


def test_sensitive_paths_detected():
    findings = detect_sensitive_paths(_nginx_events())
    assert len(findings) > 0
    all_evidence = " ".join(" ".join(f.evidence) for f in findings)
    assert any(p in all_evidence for p in ("/.env", "/wp-login.php", "/admin", "/phpinfo.php"))


def test_suspicious_user_agents_sqlmap_nikto():
    findings = detect_suspicious_user_agents(_nginx_events())
    ips = [f.source_ip for f in findings]
    assert len(findings) > 0
    # sqlmap or nikto should be in evidence
    all_uas = " ".join(" ".join(f.evidence) for f in findings).lower()
    assert "sqlmap" in all_uas or "nikto" in all_uas


def test_repeated_401_403_detected():
    findings = detect_repeated_401_403(_nginx_events())
    # 198.51.100.99 has many 401 responses
    assert len(findings) > 0
    for f in findings:
        assert f.related_events_count > 20


def test_run_all_detectors_returns_findings():
    all_events = _auth_events() + _nginx_events()
    findings = run_all_detectors(all_events)
    assert len(findings) > 0
    types = {f.finding_type for f in findings}
    assert "ssh_brute_force" in types
    assert "web_scanning" in types
