import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.models import Finding, Incident, TimelineEvent
from analyzer.reporter import generate_markdown_report, generate_json_report


def _sample_finding():
    return Finding(
        finding_type="ssh_brute_force", source_ip="1.2.3.4", severity="High",
        score=55, description="SSH brute force from 1.2.3.4",
        evidence=["Total failed attempts: 40", "Targeted usernames: root, admin"],
        recommendation="Block IP in firewall.",
        related_events_count=40, first_seen="May 20 08:00:01", last_seen="May 20 08:01:05",
    )


def _sample_incident():
    return Incident(
        incident_id="INC-001", source_ip="1.2.3.4", severity="High",
        total_score=75, finding_types=["ssh_brute_force"],
        summary="SSH brute force detected from 1.2.3.4.",
        evidence=["Total failed attempts: 40"],
        recommendations=["Block IP in firewall."],
        first_seen="May 20 08:00:01", last_seen="May 20 08:01:05",
    )


def _sample_timeline():
    return [TimelineEvent(
        timestamp="May 20 08:00:01", source_ip="1.2.3.4",
        event_type="ssh_brute_force", short_description="SSH brute force from 1.2.3.4",
        severity="High",
    )]


def test_markdown_report_has_title():
    md = generate_markdown_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    assert "Log Incident Analysis Report" in md


def test_markdown_report_has_incidents_section():
    md = generate_markdown_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    assert "Detected Incidents" in md
    assert "INC-001" in md


def test_markdown_report_has_timeline():
    md = generate_markdown_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    assert "Timeline" in md


def test_markdown_report_has_limitations():
    md = generate_markdown_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    assert "Limitations" in md
    assert "educational" in md.lower() or "rules-based" in md.lower()


def test_markdown_report_shows_ip():
    md = generate_markdown_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    assert "1.2.3.4" in md


def test_json_report_is_valid_json():
    js = generate_json_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    data = json.loads(js)
    assert "incidents" in data
    assert "findings" in data
    assert "timeline" in data
    assert "limitations" in data


def test_json_report_incidents_contain_data():
    js = generate_json_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    data = json.loads(js)
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["incident_id"] == "INC-001"
    assert data["incidents"][0]["source_ip"] == "1.2.3.4"


def test_json_report_summary():
    js = generate_json_report([_sample_finding()], [_sample_incident()], _sample_timeline(), 100, 0, "test")
    data = json.loads(js)
    assert data["summary"]["total_events"] == 100
    assert data["summary"]["total_incidents"] == 1
