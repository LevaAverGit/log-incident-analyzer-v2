# Architecture Decisions

This document records the key design choices and the reasoning behind them.

---

## Why Rule-Based Detection Instead of ML/Statistical

**Decision:** Implement detection rules as threshold-based Python functions,
not statistical anomaly detection or ML models.

**Rationale:**
- Deterministic — same input always produces the same output; easy to test and audit
- Explainable — every finding maps directly to an observable count or pattern
- Configurable — thresholds in `config/default_rules.yml` can be tuned per environment
- No training data, model files, or inference dependencies required
- Appropriate for a portfolio project: the goal is to demonstrate detection logic,
  not deploy a production anomaly detection system

**Trade-off:** Cannot detect low-and-slow attacks that stay below threshold,
or patterns that aren't expressible as counts per IP. Accepted — the scope is
demonstrating common high-signal detection patterns.

---

## Why a Pipeline Architecture

**Decision:** Separate the pipeline into discrete stages: parse → detect → group → timeline → report.

**Rationale:**
- Each stage has a clear input/output type and can be tested independently
- Parsers don't know about detectors; detectors don't know about reports
- Easy to add new stages (e.g., enrichment, deduplication) without touching existing stages
- Standard pattern for log processing pipelines (mirrors SIEM processing architecture)

**Trade-off:** Requires loading all events into memory before processing.
Acceptable for the current scale (hundreds to low thousands of events).

---

## Why Group by Source IP

**Decision:** Incidents are grouped by `source_ip`, not by time window, rule type,
or session.

**Rationale:**
- Source IP is the most commonly actionable attribute in early triage —
  it's what an analyst blocks at the firewall
- Grouping by IP surfaces the multi-indicator bonus naturally:
  an IP that triggers both `ssh_brute_force` and `web_scanning` is
  more concerning than one that triggers either alone
- Time-window grouping would require timestamp parsing and normalization
  across log sources with different formats — adds complexity for marginal benefit
  in a portfolio-scale tool

**Trade-off:** IP-based grouping conflates multiple actors behind NAT or VPN.
In a real SOC, session-level correlation and geolocation enrichment would be added.

---

## Why Separate Config from Code

**Decision:** Thresholds live in `config/default_rules.yml`, not hardcoded in
detector functions.

**Rationale:**
- Different environments have different baselines (busy web server vs. internal API)
- Allows threshold tuning without code changes
- Demonstrates the configuration management pattern used in real detection platforms

**Trade-off:** Adds a config loading step at startup. Handled gracefully —
missing file falls back to hardcoded defaults.

---

## Why Dual Report Format (Markdown + JSON)

**Decision:** Generate both Markdown and JSON from the same data model.

**Rationale:**
- Markdown renders in GitHub and is readable as a text file — good for humans
- JSON is structured and diffable — good for CI pipelines or SIEM integration
- Both represent the same findings; different representations for different consumers

---

## Why Not a Web API

**Decision:** A CLI tool, not a FastAPI service.

**Rationale:**
- A CLI is simpler to deploy, test, and demonstrate — no server process required
- The use case (batch log file analysis) fits a CLI better than a request/response API
- A web API would add authentication, connection handling, and deployment complexity
  that isn't justified by the feature set

A web API variant (similar to pd-scanner) would be a natural extension.

---

## Known Limitations

- Single-threaded processing — detector functions run sequentially
- No log rotation or compressed file support
- Timestamps stored as raw strings — no cross-log time correlation
- Sensitive path list is hardcoded in `detectors.py` — should move to config
- No deduplication of findings across partial log files
