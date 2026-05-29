#!/usr/bin/env python3
"""Log Incident Analyzer — SOC-style security log analysis."""

import argparse
import sys
from pathlib import Path
from typing import List

from analyzer.models import ParsedEvent
from analyzer.parser import parse_auth_log, parse_nginx_log, parse_syslog
from analyzer.detectors import run_all_detectors
from analyzer.incident_grouping import group_findings_into_incidents
from analyzer.timeline import build_timeline
from analyzer.reporter import generate_markdown_report, generate_json_report, save_report
from analyzer.config import load_config


def _load_events(auth: str = None, nginx: str = None, syslog: str = None):
    all_events: List[ParsedEvent] = []
    total_errors = 0
    sources = []

    if auth:
        evs, errs = parse_auth_log(auth)
        all_events.extend(evs)
        total_errors += errs
        sources.append(auth)
        print(f"[*] auth: {len(evs)} events, {errs} errors — {auth}", file=sys.stderr)

    if nginx:
        evs, errs = parse_nginx_log(nginx)
        all_events.extend(evs)
        total_errors += errs
        sources.append(nginx)
        print(f"[*] nginx: {len(evs)} events, {errs} errors — {nginx}", file=sys.stderr)

    if syslog:
        evs, errs = parse_syslog(syslog)
        all_events.extend(evs)
        total_errors += errs
        sources.append(syslog)
        print(f"[*] syslog: {len(evs)} events, {errs} errors — {syslog}", file=sys.stderr)

    return all_events, total_errors, ", ".join(sources) or "unknown"


def main() -> int:
    p = argparse.ArgumentParser(description="SOC-style log incident analyzer")
    p.add_argument("--auth", metavar="FILE", help="auth.log file")
    p.add_argument("--nginx", metavar="FILE", help="nginx access log file")
    p.add_argument("--syslog", metavar="FILE", help="syslog file")
    p.add_argument("--all-samples", action="store_true", help="Use all sample_logs/")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--output", metavar="PATH", default="reports/incident_report.md",
                   help="Output file or directory (default: reports/incident_report.md)")
    p.add_argument("--config", metavar="FILE", default=None,
                   help="Path to YAML rules config (default: config/default_rules.yml)")
    args = p.parse_args()

    auth_f = args.auth
    nginx_f = args.nginx
    syslog_f = args.syslog

    if args.all_samples:
        base = Path("sample_logs")
        auth_f = str(base / "auth.log") if (base / "auth.log").exists() else auth_f
        nginx_f = str(base / "nginx_access.log") if (base / "nginx_access.log").exists() else nginx_f
        syslog_f = str(base / "syslog") if (base / "syslog").exists() else syslog_f

    if not any([auth_f, nginx_f, syslog_f]):
        print("Error: specify --auth/--nginx/--syslog or --all-samples", file=sys.stderr)
        return 1

    cfg = load_config(args.config)
    events, errors, source_desc = _load_events(auth_f, nginx_f, syslog_f)
    findings = run_all_detectors(events, cfg)
    incidents = group_findings_into_incidents(findings, cfg)
    timeline = build_timeline(findings, incidents)

    print(f"[+] findings: {len(findings)}, incidents: {len(incidents)}", file=sys.stderr)

    output = args.output
    fmt = args.format

    # If output ends in .md but format is json, adjust
    out_path = Path(output)
    if fmt == "json":
        if out_path.suffix == ".md":
            output = str(out_path.with_suffix(".json"))
        elif out_path.is_dir() or not out_path.suffix:
            output = str(out_path / "incident_report.json")
        report = generate_json_report(findings, incidents, timeline, len(events), errors, source_desc)
    else:
        report = generate_markdown_report(findings, incidents, timeline, len(events), errors, source_desc)

    saved = save_report(report, output, fmt)
    print(f"[+] Report saved: {saved}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
