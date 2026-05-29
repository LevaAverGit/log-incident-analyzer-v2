# Configuration

The analyzer's detection thresholds are controlled by a YAML configuration file.

## Default Config File

`config/default_rules.yml` — loaded automatically if no `--config` flag is provided.

## Full Schema

```yaml
ssh_brute_force:
  min_attempts: 10        # Fewer than this → finding not reported
  medium_threshold: 30    # > min_attempts and <= this → Medium, score 30
  high_threshold: 100     # > medium_threshold and <= this → High, score 55
                          # > high_threshold → Critical, score 90

web_scanning:
  min_404_count: 30       # Fewer than this → not reported
  high_threshold: 80      # > this → High, score 55; otherwise Medium, score 25

repeated_auth_errors:
  min_count: 20           # Fewer than this → not reported
  high_threshold: 50      # > this → High, score 45; otherwise Medium, score 20

scoring:
  multi_indicator_bonus: 20   # Added to incident score when IP has >1 finding type
  max_score: 100
```

## Using a Custom Config

```bash
python3 main.py --all-samples --config path/to/my_rules.yml --output reports/report.md
```

Custom config does not need to include all keys — missing keys fall back to hardcoded
defaults in the detector functions. This means you can create a minimal config with
only the thresholds you want to change:

```yaml
# strict.yml — lower thresholds for high-security environments
ssh_brute_force:
  min_attempts: 3
  medium_threshold: 10
  high_threshold: 30
```

## Threshold Tuning Guide

### For high-traffic servers

Real servers may have many legitimate 404s (broken links, bots, crawlers).
Raise thresholds to reduce false positives:

```yaml
web_scanning:
  min_404_count: 100    # raise from 30
  high_threshold: 300   # raise from 80
```

### For high-security / low-traffic environments

Lower thresholds to catch low-and-slow patterns:

```yaml
ssh_brute_force:
  min_attempts: 3
  medium_threshold: 10
  high_threshold: 30
```

### False Positive Patterns

**ssh_brute_force:** CI/CD systems, backup agents, and monitoring tools can trigger
failed logins. Consider adding IP allowlist logic if internal IPs are generating findings.

**web_scanning:** Search engine crawlers following broken sitemaps can generate many
404s. Review `sample_paths` in the finding evidence — crawler patterns look different
from directory enumeration (structured paths vs. wordlist names).

**repeated_auth_errors:** Load balancers with health checks that return 401 can
trigger this rule. Check whether the IP is an internal service address.

## Config Loading Priority

1. `--config` flag argument (if provided)
2. `config/default_rules.yml` (if file exists)
3. Hardcoded defaults in `analyzer/config.py`

The analyzer always has valid thresholds — missing config file is not an error.

## Adding Config for a New Rule

1. Add a section to `config/default_rules.yml`
2. Read it in the detector: `c = (cfg or load_config()).get("my_rule", {})`
3. Document the keys and their meaning in this file
