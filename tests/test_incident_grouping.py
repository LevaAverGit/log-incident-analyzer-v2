import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.models import Finding
from analyzer.incident_grouping import group_findings_into_incidents
from analyzer.scoring import combine_incident_score


def _finding(ftype, ip, score):
    return Finding(
        finding_type=ftype, source_ip=ip, severity="Medium",
        score=score, description=f"{ftype} from {ip}", evidence=[f"count: {score}"],
        recommendation="block ip", related_events_count=score,
        first_seen="May 20 08:00:00", last_seen="May 20 09:00:00",
    )


def test_findings_grouped_by_ip():
    findings = [
        _finding("ssh_brute_force", "1.2.3.4", 55),
        _finding("web_scanning", "1.2.3.4", 25),
        _finding("ssh_brute_force", "5.6.7.8", 30),
    ]
    incidents = group_findings_into_incidents(findings)
    ips = {inc.source_ip for inc in incidents}
    assert "1.2.3.4" in ips
    assert "5.6.7.8" in ips
    assert len(incidents) == 2


def test_incident_has_score_and_severity():
    findings = [_finding("ssh_brute_force", "1.2.3.4", 55)]
    incidents = group_findings_into_incidents(findings)
    assert incidents[0].total_score > 0
    assert incidents[0].severity in ("Low", "Medium", "High", "Critical")


def test_incident_id_generated():
    findings = [_finding("ssh_brute_force", "1.2.3.4", 55)]
    incidents = group_findings_into_incidents(findings)
    assert incidents[0].incident_id.startswith("INC-")


def test_multi_indicator_bonus_reflected_in_incident():
    findings = [
        _finding("ssh_brute_force", "1.2.3.4", 30),
        _finding("web_scanning", "1.2.3.4", 25),
    ]
    incidents = group_findings_into_incidents(findings)
    inc = next(i for i in incidents if i.source_ip == "1.2.3.4")
    # 30 + 25 + 20 bonus = 75 → High
    assert inc.total_score == 75
    assert inc.severity == "High"


def test_incident_finding_types_listed():
    findings = [
        _finding("ssh_brute_force", "1.2.3.4", 55),
        _finding("web_scanning", "1.2.3.4", 25),
    ]
    incidents = group_findings_into_incidents(findings)
    inc = next(i for i in incidents if i.source_ip == "1.2.3.4")
    assert "ssh_brute_force" in inc.finding_types
    assert "web_scanning" in inc.finding_types


def test_incident_has_recommendations():
    findings = [_finding("ssh_brute_force", "1.2.3.4", 55)]
    incidents = group_findings_into_incidents(findings)
    assert len(incidents[0].recommendations) > 0


def test_sorted_by_score_descending():
    findings = [
        _finding("ssh_brute_force", "low.ip", 10),
        _finding("web_scanning", "high.ip", 55),
    ]
    incidents = group_findings_into_incidents(findings)
    assert incidents[0].total_score >= incidents[1].total_score
