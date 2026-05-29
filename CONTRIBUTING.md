# Contributing

## Local Setup

```bash
git clone https://github.com/LevaAverGit/Log-incident-analyzer.git
cd log-incident-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Running Tests

```bash
python3 -m pytest tests/ -v
# or
make test
```

All tests run without any external files — sample log parsing is tested
with inline strings, not files on disk.

## Running the Analyzer

```bash
# Analyze all sample logs
python3 main.py --all-samples --output reports/incident_report.md

# JSON output
python3 main.py --all-samples --format json --output reports/incident_report.json

# Custom config
python3 main.py --all-samples --config config/default_rules.yml --output reports/incident_report.md
```

## Code Style

- Python 3.11+, type hints on all public functions
- `ruff` for linting — `make lint` or `ruff check analyzer/ tests/`
- Detector functions return `List[Finding]`, parsers return `(List[ParsedEvent], int)`
- No bare `except:` — always catch specific exceptions

## Adding a New Detection Rule

1. Add detector function to `analyzer/detectors.py`:
   ```python
   def detect_my_pattern(events: List[ParsedEvent], cfg: dict | None = None) -> List[Finding]:
       ...
   ```
2. Register in `run_all_detectors()` at the bottom of `detectors.py`
3. Add thresholds to `config/default_rules.yml` if configurable
4. Write tests in `tests/test_detectors.py`

See `docs/RULE_DEVELOPMENT_GUIDE.md` for the full walkthrough.

## Adding a New Log Parser

1. Add `parse_mylog(filepath: str) -> tuple[list[ParsedEvent], int]` in `analyzer/parser.py`
2. Add `--mylog FILE` argument to `main.py`
3. Wire into `_load_events()` in `main.py`
4. Write tests in `tests/test_parser.py`

## Branch and Commit Convention

- Branch: `feature/<short-name>`, `fix/<short-name>`, `docs/<short-name>`
- Commit: imperative present tense — `Add FTP brute-force detector`, `Fix SSH threshold config`
- Keep commits focused — one logical change per commit

## Detection Thresholds

Do not hardcode thresholds in detector functions. Read them from `cfg`:
```python
def detect_something(events, cfg=None):
    c = (cfg or load_config()).get("my_rule", {})
    threshold = c.get("min_count", 10)
```

This keeps thresholds tunable without code changes.

## Limitations

- The analyzer reads entire log files into memory — not suitable for very large files
- No log rotation or compressed file support
- Timestamps are stored as raw strings — no cross-log time correlation
- Detection rules are rule-based; no statistical or ML-based anomaly detection
