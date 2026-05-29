from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ParsedEvent:
    log_type: str  # auth / nginx / syslog
    timestamp: Optional[str]
    source_ip: Optional[str]
    event_type: str
    username: Optional[str]
    method: Optional[str]
    url: Optional[str]
    status_code: Optional[int]
    user_agent: Optional[str]
    raw_line: str


@dataclass
class Finding:
    finding_type: str
    source_ip: str
    severity: str
    score: int
    description: str
    evidence: List[str]
    recommendation: str
    related_events_count: int
    first_seen: Optional[str]
    last_seen: Optional[str]


@dataclass
class Incident:
    incident_id: str
    source_ip: str
    severity: str
    total_score: int
    finding_types: List[str]
    summary: str
    evidence: List[str]
    recommendations: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]


@dataclass
class TimelineEvent:
    timestamp: Optional[str]
    source_ip: str
    event_type: str
    short_description: str
    severity: str
