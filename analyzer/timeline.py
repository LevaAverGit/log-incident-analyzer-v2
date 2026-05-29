from __future__ import annotations

from typing import List

from .models import Finding, Incident, TimelineEvent


def build_timeline(findings: List[Finding], incidents: List[Incident]) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []

    for f in findings:
        ts = f.first_seen
        events.append(TimelineEvent(
            timestamp=ts,
            source_ip=f.source_ip,
            event_type=f.finding_type,
            short_description=f.description[:80],
            severity=f.severity,
        ))
        if f.last_seen and f.last_seen != f.first_seen:
            events.append(TimelineEvent(
                timestamp=f.last_seen,
                source_ip=f.source_ip,
                event_type=f"{f.finding_type}_end",
                short_description=f"Last activity: {f.description[:60]}",
                severity=f.severity,
            ))

    def _sort_key(e: TimelineEvent):
        return e.timestamp or "~"  # None → end

    events.sort(key=_sort_key)
    return events
