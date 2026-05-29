# Log Incident Analyzer

[![CI](https://github.com/LevaAverGit/Log-incident-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/LevaAverGit/Log-incident-analyzer/actions/workflows/ci.yml)

Python CLI tool for rule-based analysis of Linux auth logs, Nginx access logs, and syslog. Parses raw logs, detects suspicious patterns, groups findings into incidents by source IP, assigns severity scores, builds a timeline, and generates Markdown and JSON reports.

---

## Engineering Highlights

- **Staged pipeline** — parse → detect → group → timeline → report; each stage
  is independently testable and produces typed output (`List[ParsedEvent]`,
  `List[Finding]`, `List[Incident]`)
- **Config-driven thresholds** — detection thresholds live in `config/default_rules.yml`
  and are passed through the pipeline; no hardcoded values in detector functions
- **Uniform detector interface** — all detectors take `(events, cfg) → List[Finding]`;
  adding a new rule requires no changes to the pipeline or report code
- **Multi-indicator bonus** — an IP that triggers more than one rule type receives
  a +20 score bonus in incident grouping, surfacing correlated attack patterns
- **Dual output format** — same data model serialised to both Markdown
  (structured incident report) and JSON (diffable, machine-readable)
- **58 tests, 0 external dependencies in tests** — all detectors tested with inline
  synthetic `ParsedEvent` objects; no log files required to run the test suite

## Detection Pipeline

```
auth.log + nginx_access.log + syslog
         ↓
    [1] Parser        → List[ParsedEvent]
         ↓
    [2] Detectors     → List[Finding]        (5 rules, configurable thresholds)
         ↓
    [3] Incident      → List[Incident]       (group by IP, apply multi-indicator bonus)
         Grouping
         ↓
    [4] Timeline      → List[TimelineEvent]
         ↓
    [5] Report        → Markdown / JSON
         Generator
```

See `docs/DETECTION_PIPELINE.md` for the full stage-by-stage breakdown.

## How to Add a New Detection Rule

1. Add `detect_*(events, cfg)` to `analyzer/detectors.py`
2. Register in `run_all_detectors()`
3. Add thresholds to `config/default_rules.yml`
4. Write tests in `tests/test_detectors.py`

See `docs/RULE_DEVELOPMENT_GUIDE.md` for the complete walkthrough.

## Problem

Raw server logs are noisy. During initial triage it is useful to quickly identify:

- repeated authentication failures from a single IP
- web directory scanning patterns
- access to sensitive paths (`.env`, `/admin`, `/wp-login.php`, etc.)
- requests from known scanner user-agents (Nikto, sqlmap, gobuster)
- repeated 401/403 responses suggesting credential stuffing or forced browsing

Doing this manually across multiple log files is slow. This tool automates the detection and produces a structured, human-readable incident report.

---

## Solution

```
raw logs → parsed events → findings → incident grouping → severity scoring → timeline → Markdown/JSON report
```

---

## Features

- `auth.log` parsing: failed logins, accepted logins, invalid users, sudo events
- Nginx `access.log` parsing: method, URL, status code, user-agent
- `syslog` parsing: service errors and warnings
- **SSH brute-force** pattern detection (threshold-based)
- **Web directory scanning** detection (404 volume per IP)
- **Sensitive path access** detection
- **Suspicious user-agent** detection (sqlmap, nikto, gobuster, masscan, etc.)
- **Repeated 401/403** detection
- Incident grouping by source IP with combined severity score
- Multi-indicator bonus: score +20 when an IP triggers more than one finding type
- Timeline of suspicious events sorted by timestamp
- Markdown report with summary, incidents, timeline, recommendations, limitations
- JSON report for downstream processing
- `pytest` test suite — 58 tests

---

## Project Structure

```
log-incident-analyzer/
├── analyzer/
│   ├── models.py            # ParsedEvent, Finding, Incident, TimelineEvent
│   ├── parser.py            # Log parsers
│   ├── detectors.py         # Detection rules
│   ├── scoring.py           # Severity scoring
│   ├── incident_grouping.py # Group findings into incidents by IP
│   ├── timeline.py          # Timeline builder
│   └── reporter.py          # Markdown and JSON report generation
├── sample_logs/
│   ├── auth.log
│   ├── nginx_access.log
│   └── syslog
├── reports/                 # Example generated reports
├── tests/
├── main.py
├── requirements.txt
└── LICENSE
```

---

## Installation

```bash
git clone https://github.com/LevaAverGit/Log-incident-analyzer.git
cd log-incident-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

Analyze all sample logs, output Markdown report:

```bash
python3 main.py --all-samples --output reports/incident_report.md
```

JSON report:

```bash
python3 main.py --all-samples --format json --output reports/incident_report.json
```

Analyze a single auth log:

```bash
python3 main.py --auth sample_logs/auth.log --output reports/auth_report.md
```

Analyze a single Nginx log:

```bash
python3 main.py --nginx sample_logs/nginx_access.log --output reports/nginx_report.md
```

All options:

```
--auth FILE      path to auth.log
--nginx FILE     path to nginx access log
--syslog FILE    path to syslog
--all-samples    use all files in sample_logs/
--format md|json output format (default: md)
--output PATH    output file or directory (default: reports/incident_report.md)
--config FILE    path to YAML rules config (default: config/default_rules.yml)
```

With a custom config:

```bash
python3 main.py --all-samples --config config/default_rules.yml --output reports/incident_report.md
```

---

## Example Output

Running `--all-samples` on the included sample logs:

```
$ python3 main.py --all-samples --output reports/incident_report.md
[*] auth:  100 events, 0 errors — sample_logs/auth.log
[*] nginx: 100 events, 0 errors — sample_logs/nginx_access.log
[*] syslog: 29 events, 0 errors — sample_logs/syslog
[+] findings: 9, incidents: 5
[+] Report saved: reports/incident_report.md
```

```
$ python3 main.py --all-samples --format json --output reports/incident_report.json
[*] auth:  100 events, 0 errors — sample_logs/auth.log
[*] nginx: 100 events, 0 errors — sample_logs/nginx_access.log
[*] syslog: 29 events, 0 errors — sample_logs/syslog
[+] findings: 9, incidents: 5
[+] Report saved: reports/incident_report.json
```

```
$ python3 -m pytest tests/ -v
...
58 passed
```

Summary from the generated report:

| Field | Value |
|---|---|
| Total parsed events | 229 |
| Total findings | 9 |
| Total incidents | 5 |
| Critical incidents | 2 |
| High incidents | 1 |
| Medium incidents | 1 |
| Low incidents | 1 |

---

## Reports

Example reports are in `reports/`:

- `reports/incident_report.md` — full Markdown report
- `reports/incident_report.json` — machine-readable JSON

The Markdown report includes: Summary, Top Source IPs, Detected Incidents (with evidence and recommendations), Timeline, General Recommendations, and Limitations.

---

## Documentation

| Document | Description |
|---|---|
| [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md) | Full detection rule specifications: triggers, thresholds, evidence, recommendations |
| [`docs/TRIAGE_PLAYBOOK.md`](docs/TRIAGE_PLAYBOOK.md) | Step-by-step triage procedures for each finding type |
| [`docs/INCIDENT_RESPONSE_MAPPING.md`](docs/INCIDENT_RESPONSE_MAPPING.md) | How findings map to IR phases (NIST SP 800-61) and SOC L1 workflow |
| [`docs/SIEM_MAPPING.md`](docs/SIEM_MAPPING.md) | Mapping to SIEM use cases, JSON integration, comparison to production SIEM |
| [`docs/DETECTION_PIPELINE.md`](docs/DETECTION_PIPELINE.md) | Stage-by-stage pipeline breakdown with input/output types |
| [`docs/RULE_DEVELOPMENT_GUIDE.md`](docs/RULE_DEVELOPMENT_GUIDE.md) | How to implement and test a new detection rule |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Config file schema, threshold tuning, false positive guidance |
| [`docs/ARCHITECTURE_DECISIONS.md`](docs/ARCHITECTURE_DECISIONS.md) | Why the architecture was designed this way |
| [`docs/QUALITY_ASSURANCE.md`](docs/QUALITY_ASSURANCE.md) | Test strategy, patterns, and manual validation checklist |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Local setup, running tests, adding rules and parsers |

---

## Testing Strategy

```bash
python3 -m pytest tests/ -v
# or
make test
```

**58 tests passing.** All tests run without log files or external services —
detectors are tested with synthetic `ParsedEvent` objects constructed inline.

Coverage: `test_parser`, `test_detectors`, `test_scoring`, `test_incident_grouping`,
`test_timeline`, `test_reporter`, `test_config`.

See `docs/QUALITY_ASSURANCE.md` for the test strategy and patterns.

---

## Detection Logic

Each detector produces a **Finding** with:
- `finding_type` — category of suspicious activity
- `source_ip` — origin IP
- `severity` — Low / Medium / High / Critical
- `score` — numeric score (0–100)
- `evidence` — observed data points
- `recommendation` — suggested follow-up action

Findings are grouped into **Incidents** per source IP. If an IP triggers more than one finding type, a multi-indicator bonus of +20 is added to the combined score.

**Severity scale:**

| Score | Severity |
|---|---|
| 0–20 | Low |
| 21–50 | Medium |
| 51–80 | High |
| 81–100 | Critical |

**SSH brute-force thresholds:**

| Failed attempts | Score | Severity |
|---|---|---|
| > 10 | 30 | Medium |
| > 30 | 55 | High |
| > 100 | 90 | Critical |

---

## Limitations

- Rules-based detection only — thresholds are fixed and tuned for sample data
- Not a replacement for SIEM or EDR
- Does not confirm compromise automatically
- No attribution — source IPs may be spoofed or belong to exit nodes
- Sample logs are synthetic and for demonstration purposes only
- All findings require manual triage before any action is taken
- No support for log rotation, compressed files, or multi-file merging per log type
- Timestamps are stored as raw strings; no cross-log time correlation

---

## Data and Scale Limitations

The included `sample_logs/` files are **synthetic and demo-scale** (~100 events per file, ~300 events total). They exist to demonstrate the tool's pipeline and produce a representative report.

This tool has **not been tested on production-scale log files**. Real server logs can contain hundreds of thousands to millions of lines per day. The current implementation reads files fully into memory, which is adequate for small files but may not be suitable for large volumes without modification.

Detection thresholds (e.g., brute-force trigger at >10 failed attempts) are fixed in code and calibrated for the sample data. In a real environment, appropriate thresholds depend on the server's traffic profile and should be configurable.

Key limitations to be aware of:
- Not tested on logs larger than a few MB
- Rule-based only — no statistical or ML-based anomaly detection
- Thresholds are not configurable without code changes (planned for a future version)
- Timestamps from different log sources are not correlated by time window
- The tool is a learning and demonstration project — manual validation is required before acting on any output

---

## How This Maps to Real SOC Work

Log analysis is the core task of a SOC L1 analyst during initial triage.
This tool automates the detection phase of that workflow against static log files.

| This tool | Real SOC / SIEM equivalent |
|---|---|
| Log parsers (`parser.py`) | Log source connectors and normalization layer |
| Detection rules (`detectors.py`) | SIEM correlation rules (use cases) |
| Finding with severity and score | SIEM alert with priority level |
| Incident grouping by source IP | Entity-based correlation |
| Multi-indicator bonus | Multi-event AND condition in correlation rule |
| JSON report | Alert payload for SOAR / ticketing integration |
| YAML thresholds (`config/`) | Rule tuning parameters in SIEM admin console |

In a real SOC:
- Log sources feed into a SIEM (MaxPatrol SIEM, KUMA, Splunk, ELK) in real time
- Correlation rules fire automatically and create tickets in an incident management system
- L1 analysts triage alerts using playbooks, then escalate or close
- Metrics like MTTD (mean time to detect) and MTTR (mean time to respond) are tracked

This tool demonstrates the detection rule logic and triage workflow for that process
against a static batch of logs. See [`docs/SIEM_MAPPING.md`](docs/SIEM_MAPPING.md)
for a detailed comparison and [`docs/TRIAGE_PLAYBOOK.md`](docs/TRIAGE_PLAYBOOK.md)
for the step-by-step triage procedures.

## MITRE ATT&CK Alignment

The detection rules in this tool map to the following MITRE ATT&CK techniques:

| Detection | MITRE Technique | Tactic |
|---|---|---|
| SSH brute force | T1110.001 Brute Force: Password Guessing | Credential Access (TA0006) |
| Successful login after failures | T1078 Valid Accounts | Initial Access (TA0001) |
| Web directory scanning / 404 flood | T1595.002 Active Scanning: Vulnerability Scanning | Reconnaissance (TA0043) |
| Sensitive path access (/.env, /.git) | T1083 File and Directory Discovery | Discovery (TA0007) |
| Scanner user-agent strings | T1595 Active Scanning | Reconnaissance (TA0043) |
| Repeated 401/403 responses | T1110 Brute Force | Credential Access (TA0006) |

> For a more complete SOC detection pipeline with FastAPI backend, SQLite persistence,
> YAML-configurable rules, and MITRE ATT&CK mapping in the rule schema,
> see [mini-siem-detection-lab](https://github.com/LevaAverGit/mini-siem-detection-lab).

---

## What This Project Demonstrates for Security Roles

- Linux log format knowledge: `auth.log`, Nginx access log, syslog
- SOC L1 triage logic: severity prioritization, escalation criteria, containment steps
- Rule-based detection: threshold tuning, false-positive reasoning, multi-signal aggregation
- Mapping findings to IR phases (NIST SP 800-61 detection and analysis)
- Structured incident reporting: evidence collection, timeline reconstruction
- SIEM conceptual understanding: use cases, correlation rules, alert payload format
- MITRE ATT&CK technique awareness: tagging detections to tactic/technique IDs
- pytest design for detection modules with controlled input fixtures

---

## License

MIT — see [LICENSE](LICENSE).
