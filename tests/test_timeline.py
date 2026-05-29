import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.models import Finding
from analyzer.incident_grouping import group_findings_into_incidents
from analyzer.timeline import build_timeline


def _finding(ftype, ip, score, first, last=None):
    return Finding(
        finding_type=ftype, source_ip=ip, severity="High",
        score=score, description=f"{ftype} on {ip}", evidence=[],
        recommendation="block", related_events_count=score,
        first_seen=first, last_seen=last or first,
    )


def test_timeline_contains_events():
    findings = [_finding("ssh_brute_force", "1.2.3.4", 55, "May 20 08:00:00")]
    incidents = group_findings_into_incidents(findings)
    tl = build_timeline(findings, incidents)
    assert len(tl) > 0


def test_timeline_includes_finding_types():
    findings = [
        _finding("ssh_brute_force", "1.2.3.4", 55, "May 20 08:00:00"),
        _finding("web_scanning", "5.6.7.8", 25, "May 20 09:00:00"),
    ]
    incidents = group_findings_into_incidents(findings)
    tl = build_timeline(findings, incidents)
    types = {e.event_type for e in tl}
    assert "ssh_brute_force" in types or any("ssh" in t for t in types)


def test_timeline_sorted_by_timestamp():
    findings = [
        _finding("web_scanning", "5.6.7.8", 25, "May 20 10:00:00"),
        _finding("ssh_brute_force", "1.2.3.4", 55, "May 20 08:00:00"),
    ]
    incidents = group_findings_into_incidents(findings)
    tl = build_timeline(findings, incidents)
    ts_with_values = [e.timestamp for e in tl if e.timestamp]
    assert ts_with_values == sorted(ts_with_values)


def test_none_timestamp_events_at_end():
    findings = [
        _finding("ssh_brute_force", "1.2.3.4", 55, None),
        _finding("web_scanning", "5.6.7.8", 25, "May 20 08:00:00"),
    ]
    incidents = group_findings_into_incidents(findings)
    tl = build_timeline(findings, incidents)
    # Events with None timestamp should come after ones with timestamps
    non_none = [e for e in tl if e.timestamp is not None]
    none_events = [e for e in tl if e.timestamp is None]
    if non_none and none_events:
        last_non_none_idx = max(tl.index(e) for e in non_none)
        first_none_idx = min(tl.index(e) for e in none_events)
        assert last_non_none_idx < first_none_idx
