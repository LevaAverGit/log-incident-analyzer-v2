import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.scoring import score_to_severity, combine_incident_score, calculate_incident_severity
from analyzer.models import Finding


def _make_finding(ftype, score):
    return Finding(
        finding_type=ftype, source_ip="1.2.3.4", severity="Medium",
        score=score, description="", evidence=[], recommendation="",
        related_events_count=0, first_seen=None, last_seen=None,
    )


def test_score_to_severity_low():
    assert score_to_severity(0) == "Low"
    assert score_to_severity(20) == "Low"


def test_score_to_severity_medium():
    assert score_to_severity(21) == "Medium"
    assert score_to_severity(50) == "Medium"


def test_score_to_severity_high():
    assert score_to_severity(51) == "High"
    assert score_to_severity(80) == "High"


def test_score_to_severity_critical():
    assert score_to_severity(81) == "Critical"
    assert score_to_severity(100) == "Critical"


def test_combine_single_finding():
    f = _make_finding("ssh_brute_force", 30)
    assert combine_incident_score([f]) == 30


def test_multi_indicator_bonus_applied():
    f1 = _make_finding("ssh_brute_force", 30)
    f2 = _make_finding("web_scanning", 25)
    score = combine_incident_score([f1, f2])
    assert score == min(30 + 25 + 20, 100)


def test_no_bonus_for_same_type():
    f1 = _make_finding("ssh_brute_force", 30)
    f2 = _make_finding("ssh_brute_force", 30)
    score = combine_incident_score([f1, f2])
    assert score == min(60, 100)  # no bonus — same type


def test_score_capped_at_100():
    findings = [_make_finding(f"type_{i}", 40) for i in range(5)]
    assert combine_incident_score(findings) == 100


def test_empty_findings_score_zero():
    assert combine_incident_score([]) == 0


def test_calculate_incident_severity():
    f1 = _make_finding("ssh_brute_force", 55)
    f2 = _make_finding("web_scanning", 25)
    sev = calculate_incident_severity([f1, f2])
    assert sev == "Critical"  # 55+25+20=100 → Critical
