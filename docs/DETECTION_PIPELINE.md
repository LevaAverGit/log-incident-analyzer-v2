# Detection Pipeline

This document describes the full data processing pipeline from raw log files
to a structured incident report.

---

## Pipeline Overview

```
Log files (auth.log, nginx_access.log, syslog)
    │
    ▼
[1] Parser          → List[ParsedEvent]
    │
    ▼
[2] Detectors       → List[Finding]
    │
    ▼
[3] Incident Grouping → List[Incident]
    │
    ├──────────────────────────────────────────┐
    ▼                                          ▼
[4] Timeline Builder  → List[TimelineEvent]   [5] Severity Scoring (within grouping)
    │
    ▼
[6] Report Generator  → Markdown or JSON string
    │
    ▼
    File output (reports/)
```

---

## Stage 1: Parser (`analyzer/parser.py`)

**Input:** Path to a log file (string)
**Output:** `(List[ParsedEvent], int)` — events and error count

Three parsers:
- `parse_auth_log(filepath)` — parses `/var/log/auth.log` using regex
- `parse_nginx_log(filepath)` — parses Nginx combined log format
- `parse_syslog(filepath)` — parses `/var/log/syslog`

Each `ParsedEvent` captures:
```python
log_type: str           # "auth" | "nginx" | "syslog"
timestamp: str | None   # raw timestamp string
source_ip: str | None   # extracted IPv4 address
event_type: str         # "failed_login" | "request" | "service_error" | ...
username: str | None    # for auth events
method: str | None      # for nginx: GET, POST, etc.
url: str | None         # for nginx: requested path
status_code: int | None # for nginx: HTTP response code
user_agent: str | None  # for nginx
raw_line: str           # original log line preserved for context
```

Lines that cannot be parsed are counted as errors and skipped.

---

## Stage 2: Detectors (`analyzer/detectors.py`)

**Input:** `List[ParsedEvent]`, optional config dict
**Output:** `List[Finding]`

Five detectors run sequentially via `run_all_detectors()`:

| Detector function | Finding type | Log source |
|---|---|---|
| `detect_ssh_brute_force()` | `ssh_brute_force` | auth |
| `detect_web_scanning()` | `web_scanning` | nginx |
| `detect_sensitive_paths()` | `sensitive_path_access` | nginx |
| `detect_suspicious_user_agents()` | `suspicious_user_agent` | nginx |
| `detect_repeated_401_403()` | `repeated_auth_errors` | nginx |

Each detector:
1. Filters events by `log_type` and `event_type`
2. Groups by `source_ip`
3. Applies a threshold (from config or defaults)
4. Returns zero or more `Finding` objects — one per source IP that triggers

Each `Finding` contains:
```python
finding_type: str
source_ip: str
severity: str       # Critical / High / Medium / Low
score: int          # 0–100
description: str
evidence: List[str]
recommendation: str
related_events_count: int
first_seen: str | None
last_seen: str | None
```

---

## Stage 3: Incident Grouping (`analyzer/incident_grouping.py`)

**Input:** `List[Finding]`
**Output:** `List[Incident]`

Groups findings by `source_ip`. For each IP:
1. Collects all findings for that IP
2. Sums scores
3. Applies a `multi_indicator_bonus` (+20) if the IP has more than one finding type
4. Caps the total score at 100
5. Derives the severity from the final score:
   - 81–100: Critical
   - 51–80: High
   - 21–50: Medium
   - 0–20: Low

Each `Incident` is the authoritative risk summary for a single source IP.

---

## Stage 4: Timeline Builder (`analyzer/timeline.py`)

**Input:** `List[Finding]`, `List[Incident]`
**Output:** `List[TimelineEvent]`

Extracts `first_seen`/`last_seen` timestamps from findings and incidents,
sorts them chronologically, and creates a timeline of significant events.
Used in the Markdown report's timeline section.

---

## Stage 5: Report Generator (`analyzer/reporter.py`)

**Input:** `List[Finding]`, `List[Incident]`, `List[TimelineEvent]`, event counts
**Output:** Formatted string (Markdown or JSON)

`generate_markdown_report()` produces a structured Markdown document:
- Summary table (total events, findings, incidents by severity)
- Top source IPs
- Incident details (per IP: findings, evidence, recommendations)
- Timeline
- General recommendations
- Limitations

`generate_json_report()` produces a JSON string with the same data structured
for machine consumption.

`save_report()` writes the string to the output path, creating parent directories
if needed.

---

## Configuration Flow

Config is loaded by `analyzer/config.py` → `load_config(path: str | None = None)`.

If `path` is `None`, it looks for `config/default_rules.yml`. If not found,
returns a hardcoded default dict. This ensures the analyzer always has valid
thresholds even if the config file is missing.

Thresholds from config propagate to detectors via `cfg` dict passed to
`run_all_detectors(events, cfg)`.

---

## Entry Point (`main.py`)

`main()` orchestrates the pipeline:
1. Parse CLI arguments
2. Load log files → `List[ParsedEvent]`
3. Load config
4. Run `run_all_detectors(events, cfg)` → `List[Finding]`
5. Run `group_findings_into_incidents(findings, cfg)` → `List[Incident]`
6. Run `build_timeline(findings, incidents)` → `List[TimelineEvent]`
7. Generate report string
8. Save to output path
