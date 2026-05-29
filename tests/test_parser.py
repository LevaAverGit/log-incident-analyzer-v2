import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.parser import parse_auth_log, parse_nginx_log, parse_syslog

SAMPLE = Path(__file__).parent.parent / "sample_logs"


def test_auth_failed_login_parsed():
    events, _ = parse_auth_log(str(SAMPLE / "auth.log"))
    failed = [e for e in events if e.event_type == "failed_login"]
    assert len(failed) > 10


def test_auth_accepted_login_parsed():
    events, _ = parse_auth_log(str(SAMPLE / "auth.log"))
    accepted = [e for e in events if e.event_type == "accepted_login"]
    assert len(accepted) >= 2


def test_auth_invalid_user_parsed():
    events, _ = parse_auth_log(str(SAMPLE / "auth.log"))
    invalid = [e for e in events if e.event_type == "invalid_user"]
    assert len(invalid) >= 1


def test_auth_source_ip_extracted():
    events, _ = parse_auth_log(str(SAMPLE / "auth.log"))
    failed = [e for e in events if e.event_type == "failed_login"]
    ips = [e.source_ip for e in failed if e.source_ip]
    assert len(ips) > 0
    assert "185.234.218.4" in ips


def test_auth_event_type_is_parsed_event():
    events, _ = parse_auth_log(str(SAMPLE / "auth.log"))
    from analyzer.models import ParsedEvent
    assert all(isinstance(e, ParsedEvent) for e in events)
    assert all(e.log_type == "auth" for e in events)


def test_nginx_events_parsed():
    events, _ = parse_nginx_log(str(SAMPLE / "nginx_access.log"))
    assert len(events) > 20


def test_nginx_status_codes():
    events, _ = parse_nginx_log(str(SAMPLE / "nginx_access.log"))
    codes = {e.status_code for e in events}
    assert 200 in codes
    assert 404 in codes


def test_nginx_user_agent_extracted():
    events, _ = parse_nginx_log(str(SAMPLE / "nginx_access.log"))
    uas = [e.user_agent for e in events if e.user_agent]
    assert any("Nikto" in ua for ua in uas)


def test_nginx_url_extracted():
    events, _ = parse_nginx_log(str(SAMPLE / "nginx_access.log"))
    assert any(e.url == "/.env" for e in events)


def test_invalid_line_does_not_crash():
    import tempfile, os
    content = "totally invalid log line\nMay 20 08:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 100 ssh2\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        events, errors = parse_auth_log(fname)
        assert errors >= 1
        assert len(events) >= 1
    finally:
        os.unlink(fname)


def test_syslog_parsed():
    events, _ = parse_syslog(str(SAMPLE / "syslog"))
    assert len(events) > 5
    errors = [e for e in events if e.event_type == "syslog_error"]
    assert len(errors) > 0
