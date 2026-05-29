# Quality Assurance

## Test Strategy

58 tests across 7 test files. All tests run without external files,
network access, or a running service.

```bash
python3 -m pytest tests/ -v
# or
make test
```

---

## Test Structure

| Test file | Module covered | What is tested |
|---|---|---|
| `test_parser.py` | `parser.py` | Auth log regex, nginx format, syslog parsing, error counting |
| `test_detectors.py` | `detectors.py` | Each rule at/below threshold, medium/high severity, multi-IP |
| `test_scoring.py` | `scoring.py` | Score-to-severity mapping |
| `test_incident_grouping.py` | `incident_grouping.py` | Single-finding, multi-finding, bonus, score cap |
| `test_timeline.py` | `timeline.py` | Timeline construction from findings and incidents |
| `test_reporter.py` | `reporter.py` | Markdown structure, JSON keys, file save |
| `test_config.py` | `config.py` | Default fallback, key access, custom values |

---

## Unit vs. Integration Tests

**Unit tests (all 58):** Use synthetic `ParsedEvent` objects constructed inline.
No log files are read during test runs.

**Integration tests (not implemented):** End-to-end run against `sample_logs/`.
This is a manual step — run `make run` and inspect `reports/` output.

---

## Test Patterns

### Parser test pattern

```python
from analyzer.parser import parse_auth_log
import tempfile, os

def test_parse_failed_login():
    line = "Jan  1 10:00:00 server sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(line)
        path = f.name
    try:
        events, errors = parse_auth_log(path)
        assert len(events) == 1
        assert events[0].event_type == "failed_login"
        assert events[0].source_ip == "10.0.0.1"
    finally:
        os.unlink(path)
```

### Detector test pattern

```python
from analyzer.models import ParsedEvent
from analyzer.detectors import detect_ssh_brute_force

def _auth_event(ip: str, event_type: str = "failed_login") -> ParsedEvent:
    return ParsedEvent(
        log_type="auth", timestamp=None, source_ip=ip,
        event_type=event_type, username="root",
        method=None, url=None, status_code=None,
        user_agent=None, raw_line="raw",
    )

def test_brute_force_medium():
    events = [_auth_event("10.0.0.1")] * 15
    cfg = {"ssh_brute_force": {"min_attempts": 10, "medium_threshold": 30, "high_threshold": 100}}
    findings = detect_ssh_brute_force(events, cfg)
    assert len(findings) == 1
    assert findings[0].severity == "Medium"
```

---

## What Is Intentionally Not Tested

- **`main()` CLI function** — tested indirectly via `make run` on sample logs
- **Sample log files** — content is synthetic and for demonstration purposes
- **Report file path resolution** — tested with temp paths in `test_reporter.py`
- **Config file parsing edge cases** — YAML parsing is delegated to `pyyaml`

---

## Manual Validation Checklist

Before updating `reports/` with new example output:

- [ ] `make test` passes with 58 passed, 0 failures
- [ ] `python3 main.py --all-samples --output reports/incident_report.md` completes
- [ ] Report shows expected incident count (5 incidents for default sample logs)
- [ ] `python3 main.py --all-samples --format json --output reports/incident_report.json`
- [ ] JSON report is valid: `python3 -m json.tool reports/incident_report.json`

---

## CI

GitHub Actions CI (`ci.yml`) runs on every push and pull request to `main`:
- Python 3.11
- Install dependencies from `requirements.txt`
- Run `python -m pytest tests/ -q`
