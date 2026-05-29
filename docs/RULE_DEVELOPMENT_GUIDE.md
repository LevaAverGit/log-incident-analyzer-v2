# Rule Development Guide

This guide walks through implementing a new detection rule from scratch.

---

## Anatomy of a Detector Function

```python
from __future__ import annotations
from collections import defaultdict
from typing import Dict, Any, List, Optional

from .models import Finding, ParsedEvent
from .config import load_config


def detect_my_pattern(
    events: List[ParsedEvent],
    cfg: Optional[Dict[str, Any]] = None,
) -> List[Finding]:
    """Detect <pattern description> from parsed log events."""
    c = (cfg or load_config()).get("my_rule", {})
    min_count = c.get("min_count", 10)
    high_threshold = c.get("high_threshold", 50)

    # Group relevant events by source IP
    hits: dict = defaultdict(list)
    for e in events:
        if e.log_type == "nginx" and e.status_code == 500 and e.source_ip:
            hits[e.source_ip].append(e)

    findings = []
    for ip, evs in hits.items():
        cnt = len(evs)
        if cnt <= min_count:
            continue

        score, sev = (45, "High") if cnt > high_threshold else (20, "Medium")
        first = next((e.timestamp for e in evs if e.timestamp), None)
        last = next((e.timestamp for e in reversed(evs) if e.timestamp), None)

        findings.append(Finding(
            finding_type="my_pattern",
            source_ip=ip,
            severity=sev,
            score=score,
            description=f"Description of what was detected from {ip} ({cnt} events)",
            evidence=[
                f"Event count: {cnt}",
                f"Sample: {evs[0].raw_line[:80]}",
            ],
            recommendation="Actionable step the analyst should take.",
            related_events_count=cnt,
            first_seen=first,
            last_seen=last,
        ))
    return findings
```

---

## Required Finding Fields

| Field | Type | Notes |
|---|---|---|
| `finding_type` | str | Snake_case identifier, e.g. `ssh_brute_force` |
| `source_ip` | str | The IP that triggered the rule |
| `severity` | str | `Critical` / `High` / `Medium` / `Low` |
| `score` | int | 0–100; used for incident scoring and sorting |
| `description` | str | One sentence: what happened and from where |
| `evidence` | List[str] | 2–5 bullet-point evidence strings |
| `recommendation` | str | Actionable analyst instruction |
| `related_events_count` | int | Number of events that triggered this finding |
| `first_seen` | str or None | Earliest timestamp from matching events |
| `last_seen` | str or None | Latest timestamp from matching events |

---

## Score and Severity Guidelines

| Score | Severity | Use when |
|---|---|---|
| 81–100 | Critical | Confirmed or near-certain compromise pattern |
| 51–80 | High | Strong indicator requiring immediate investigation |
| 21–50 | Medium | Notable pattern, investigate in normal queue |
| 0–20 | Low | Informational; low priority |

Scores within each band are calibrated relative to other detectors.
For reference: `ssh_brute_force` at >100 attempts = 90 (Critical).

---

## Registering the Rule

In `analyzer/detectors.py`, add to `run_all_detectors()`:

```python
def run_all_detectors(events, cfg=None):
    resolved_cfg = cfg or load_config()
    findings = []
    ...
    findings.extend(detect_my_pattern(events, resolved_cfg))
    return findings
```

---

## Configuration

Add thresholds to `config/default_rules.yml`:

```yaml
my_rule:
  min_count: 10       # fewer than this → not reported
  high_threshold: 50  # > this → High severity; otherwise Medium
```

Access in detector:
```python
c = (cfg or load_config()).get("my_rule", {})
min_count = c.get("min_count", 10)
```

Always provide sensible defaults — the analyzer works without a config file.

---

## Writing Tests

Add to `tests/test_detectors.py`:

```python
from analyzer.models import ParsedEvent
from analyzer.detectors import detect_my_pattern


def _make_nginx_event(ip: str, status: int) -> ParsedEvent:
    return ParsedEvent(
        log_type="nginx", timestamp="01/Jan/2026:10:00:00 +0000",
        source_ip=ip, event_type="request", username=None,
        method="GET", url="/some/path", status_code=status,
        user_agent="curl/7.0", raw_line="raw",
    )


def test_my_pattern_not_triggered_below_threshold():
    events = [_make_nginx_event("10.0.0.1", 500) for _ in range(5)]
    findings = detect_my_pattern(events, {"my_rule": {"min_count": 10}})
    assert findings == []


def test_my_pattern_medium_severity():
    events = [_make_nginx_event("10.0.0.1", 500) for _ in range(15)]
    findings = detect_my_pattern(events, {"my_rule": {"min_count": 10, "high_threshold": 50}})
    assert len(findings) == 1
    assert findings[0].severity == "Medium"
    assert findings[0].source_ip == "10.0.0.1"


def test_my_pattern_high_severity():
    events = [_make_nginx_event("10.0.0.1", 500) for _ in range(60)]
    findings = detect_my_pattern(events, {"my_rule": {"min_count": 10, "high_threshold": 50}})
    assert findings[0].severity == "High"


def test_my_pattern_ignores_other_ips():
    events = (
        [_make_nginx_event("10.0.0.1", 500) for _ in range(15)] +
        [_make_nginx_event("10.0.0.2", 500) for _ in range(5)]
    )
    findings = detect_my_pattern(events, {"my_rule": {"min_count": 10, "high_threshold": 50}})
    ips = {f.source_ip for f in findings}
    assert "10.0.0.1" in ips
    assert "10.0.0.2" not in ips
```

Minimum test coverage per rule:
- Below threshold → no finding
- Medium severity scenario
- High severity scenario
- Evidence fields populated
- Multiple IPs handled independently

---

## Documentation

Add a section to `docs/DETECTION_RULES.md`:
- Rule name, log source, trigger condition
- Threshold table
- Evidence collected
- Recommendation

Update `config/default_rules.yml` with the new section.
