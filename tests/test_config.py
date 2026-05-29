import sys
from pathlib import Path
from unittest.mock import patch
import tempfile
import textwrap

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.config import load_config
from analyzer.detectors import detect_ssh_brute_force
from analyzer.models import ParsedEvent


def _auth_event(ip: str = "1.2.3.4") -> ParsedEvent:
    return ParsedEvent(
        log_type="auth", timestamp="Jan 1 00:00:01", source_ip=ip,
        event_type="failed_login", username="root",
        method=None, url=None, status_code=None, user_agent=None,
        raw_line="",
    )


def test_load_config_returns_dict():
    cfg = load_config()
    assert isinstance(cfg, dict)


def test_default_config_has_ssh_section():
    cfg = load_config()
    assert "ssh_brute_force" in cfg


def test_default_config_has_scoring_section():
    cfg = load_config()
    assert "scoring" in cfg


def test_default_config_min_attempts_is_10():
    cfg = load_config()
    assert cfg["ssh_brute_force"]["min_attempts"] == 10


def test_default_config_multi_indicator_bonus_is_20():
    cfg = load_config()
    assert cfg["scoring"]["multi_indicator_bonus"] == 20


def test_custom_config_loaded_from_file():
    yaml_content = textwrap.dedent("""\
        ssh_brute_force:
          min_attempts: 5
          medium_threshold: 10
          high_threshold: 50
        web_scanning:
          min_404_count: 10
          high_threshold: 40
        repeated_auth_errors:
          min_count: 5
          high_threshold: 20
        scoring:
          multi_indicator_bonus: 10
          max_score: 100
    """)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        tmp_path = f.name

    cfg = load_config(tmp_path)
    assert cfg["ssh_brute_force"]["min_attempts"] == 5
    assert cfg["scoring"]["multi_indicator_bonus"] == 10


def test_missing_config_file_returns_defaults():
    cfg = load_config("/nonexistent/path/rules.yml")
    assert cfg["ssh_brute_force"]["min_attempts"] == 10


def test_low_threshold_triggers_detection():
    # With min_attempts=3, 5 events should produce a finding
    cfg = {
        "ssh_brute_force": {"min_attempts": 3, "medium_threshold": 10, "high_threshold": 50},
        "web_scanning": {"min_404_count": 30, "high_threshold": 80},
        "repeated_auth_errors": {"min_count": 20, "high_threshold": 50},
        "scoring": {"multi_indicator_bonus": 20, "max_score": 100},
    }
    events = [_auth_event("10.0.0.1")] * 5
    findings = detect_ssh_brute_force(events, cfg)
    assert len(findings) == 1


def test_high_threshold_suppresses_detection():
    # With min_attempts=100, only 5 events → no finding
    cfg = {
        "ssh_brute_force": {"min_attempts": 100, "medium_threshold": 200, "high_threshold": 500},
        "web_scanning": {"min_404_count": 30, "high_threshold": 80},
        "repeated_auth_errors": {"min_count": 20, "high_threshold": 50},
        "scoring": {"multi_indicator_bonus": 20, "max_score": 100},
    }
    events = [_auth_event("10.0.0.2")] * 5
    findings = detect_ssh_brute_force(events, cfg)
    assert findings == []
