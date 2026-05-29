# Developer Guide

## Repository Structure

```
log-incident-analyzer/
├── main.py                    # CLI entry point — pipeline orchestrator
├── analyzer/
│   ├── models.py              # ParsedEvent, Finding, Incident, TimelineEvent dataclasses
│   ├── parser.py              # Log parsers: auth_log, nginx_access, syslog
│   ├── detectors.py           # Detection rules: 5 detectors + run_all_detectors()
│   ├── incident_grouping.py   # Group findings by IP, apply multi-indicator bonus
│   ├── scoring.py             # score_to_severity() helper
│   ├── timeline.py            # Build timeline from findings and incidents
│   ├── reporter.py            # Markdown + JSON report generation
│   └── config.py              # YAML config loader with defaults
├── config/
│   └── default_rules.yml      # Detection thresholds (configurable)
├── sample_logs/
│   ├── auth.log
│   ├── nginx_access.log
│   └── syslog
├── reports/                   # Pre-generated example reports
├── tests/
│   ├── test_parser.py
│   ├── test_detectors.py
│   ├── test_scoring.py
│   ├── test_incident_grouping.py
│   ├── test_timeline.py
│   ├── test_reporter.py
│   └── test_config.py
├── docs/
├── requirements.txt
├── requirements-dev.txt       # + ruff
├── pyproject.toml
├── Makefile
└── CONTRIBUTING.md
```

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

---

## Common Commands

```bash
make test    # run pytest
make lint    # ruff check (non-blocking)
make run     # analyze sample_logs/ and write to reports/
make install # create venv + install deps
make clean   # remove __pycache__ and .pytest_cache

# Run with custom config
python3 main.py --all-samples --config config/default_rules.yml --output reports/report.md

# JSON output
python3 main.py --all-samples --format json --output reports/report.json
```

---

## Adding a New Detection Rule

See `docs/RULE_DEVELOPMENT_GUIDE.md` for the complete walkthrough.

Short version:
1. Add `detect_*(events, cfg)` to `analyzer/detectors.py`
2. Register in `run_all_detectors()`
3. Add config section to `config/default_rules.yml`
4. Write tests in `tests/test_detectors.py`

---

## Debugging

Test a single detector against a sample log:

```python
from analyzer.parser import parse_auth_log
from analyzer.detectors import detect_ssh_brute_force

events, errors = parse_auth_log("sample_logs/auth.log")
findings = detect_ssh_brute_force(events)
for f in findings:
    print(f.finding_type, f.severity, f.source_ip, f.score)
```

Run tests for one module:

```bash
python3 -m pytest tests/test_detectors.py -v
python3 -m pytest tests/test_parser.py::test_parse_failed_login -v
```

Inspect full incident grouping:

```python
from analyzer.detectors import run_all_detectors
from analyzer.incident_grouping import group_findings_into_incidents
from analyzer.parser import parse_auth_log, parse_nginx_log

auth_events, _ = parse_auth_log("sample_logs/auth.log")
nginx_events, _ = parse_nginx_log("sample_logs/nginx_access.log")
findings = run_all_detectors(auth_events + nginx_events)
incidents = group_findings_into_incidents(findings)
for inc in incidents:
    print(inc.source_ip, inc.severity, inc.total_score, inc.finding_types)
```

---

## Module Relationships

```
main.py
  ↓ imports
  ├── parser.py              → (List[ParsedEvent], int)
  ├── detectors.py           → List[Finding]
  │     └── config.py        → dict (thresholds)
  ├── incident_grouping.py   → List[Incident]
  │     └── scoring.py       → str (severity)
  ├── timeline.py            → List[TimelineEvent]
  └── reporter.py            → str (report content)
```

All modules depend only on `models.py`. No circular imports.
