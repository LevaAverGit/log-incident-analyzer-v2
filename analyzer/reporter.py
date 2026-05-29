from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import Finding, Incident, TimelineEvent

LIMITATIONS = [
    "Rules-based detection only — tuned for sample data, not a production ruleset.",
    "Does not replace SIEM/EDR/SOC platforms.",
    "Cannot perform attribution or confirm compromise automatically.",
    "Findings require manual triage before any remediation action.",
    "This is an educational MVP project.",
]

GENERAL_RECS = [
    "Cross-reference successful logins that occurred after failed login windows.",
    "Review firewall and WAF rules for blocking confirmed scanner IPs.",
    "Correlate auth log events with nginx access logs by timestamp.",
    "Do not treat any Finding as proof of compromise without manual verification.",
    "Consider deploying fail2ban or equivalent for SSH protection.",
    "Temporarily restrict suspicious IPs at perimeter if activity is confirmed.",
]


def _severity_emoji(sev: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")


def generate_markdown_report(
    findings: List[Finding],
    incidents: List[Incident],
    timeline: List[TimelineEvent],
    total_events: int,
    parsing_errors: int,
    source_desc: str,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_counts = {s: 0 for s in ("Critical", "High", "Medium", "Low")}
    for inc in incidents:
        sev_counts[inc.severity] = sev_counts.get(inc.severity, 0) + 1

    lines: List[str] = []
    lines.append("# Log Incident Analysis Report")
    lines.append(f"\n_Generated: {now}_\n")

    lines.append("## Summary\n")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Source | `{source_desc}` |")
    lines.append(f"| Total parsed events | {total_events} |")
    lines.append(f"| Parsing errors | {parsing_errors} |")
    lines.append(f"| Total findings | {len(findings)} |")
    lines.append(f"| Total incidents | {len(incidents)} |")
    for sev, cnt in sev_counts.items():
        if cnt:
            lines.append(f"| {_severity_emoji(sev)} {sev} incidents | {cnt} |")
    lines.append("")

    if incidents:
        lines.append("## Top Source IPs\n")
        lines.append("| IP | Severity | Score | Finding Types |")
        lines.append("|---|---|---|---|")
        for inc in incidents[:10]:
            ftypes = ", ".join(inc.finding_types)
            lines.append(f"| `{inc.source_ip}` | {_severity_emoji(inc.severity)} {inc.severity} | {inc.total_score} | {ftypes} |")
        lines.append("")

    lines.append("## Detected Incidents\n")
    if not incidents:
        lines.append("_No incidents detected._\n")
    for inc in incidents:
        lines.append(f"### {inc.incident_id} — `{inc.source_ip}`\n")
        lines.append(f"- **Severity:** {_severity_emoji(inc.severity)} {inc.severity}")
        lines.append(f"- **Score:** {inc.total_score}/100")
        lines.append(f"- **Finding types:** {', '.join(inc.finding_types)}")
        lines.append(f"- **Summary:** {inc.summary}")
        if inc.first_seen:
            lines.append(f"- **First seen:** `{inc.first_seen}`")
        if inc.last_seen:
            lines.append(f"- **Last seen:** `{inc.last_seen}`")
        if inc.evidence:
            lines.append("\n**Evidence:**")
            for ev in inc.evidence:
                lines.append(f"- {ev}")
        if inc.recommendations:
            lines.append("\n**Recommendations:**")
            for rec in inc.recommendations:
                lines.append(f"- {rec}")
        lines.append("")

    lines.append("## Timeline\n")
    if timeline:
        lines.append("| Time | Source IP | Event Type | Severity | Description |")
        lines.append("|---|---|---|---|---|")
        for ev in timeline[:50]:
            ts = ev.timestamp or "—"
            lines.append(
                f"| `{ts}` | `{ev.source_ip}` | {ev.event_type} "
                f"| {_severity_emoji(ev.severity)} {ev.severity} | {ev.short_description} |"
            )
        lines.append("")
    else:
        lines.append("_No timeline events._\n")

    lines.append("## General Recommendations\n")
    for rec in GENERAL_RECS:
        lines.append(f"- {rec}")
    lines.append("")

    lines.append("## Limitations\n")
    for lim in LIMITATIONS:
        lines.append(f"- {lim}")
    lines.append("")

    return "\n".join(lines)


def generate_json_report(
    findings: List[Finding],
    incidents: List[Incident],
    timeline: List[TimelineEvent],
    total_events: int,
    parsing_errors: int,
    source_desc: str,
) -> str:
    def _finding_dict(f: Finding) -> dict:
        return {
            "finding_type": f.finding_type,
            "source_ip": f.source_ip,
            "severity": f.severity,
            "score": f.score,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
            "related_events_count": f.related_events_count,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen,
        }

    def _incident_dict(i: Incident) -> dict:
        return {
            "incident_id": i.incident_id,
            "source_ip": i.source_ip,
            "severity": i.severity,
            "total_score": i.total_score,
            "finding_types": i.finding_types,
            "summary": i.summary,
            "evidence": i.evidence,
            "recommendations": i.recommendations,
            "first_seen": i.first_seen,
            "last_seen": i.last_seen,
        }

    def _tl_dict(e: TimelineEvent) -> dict:
        return {
            "timestamp": e.timestamp,
            "source_ip": e.source_ip,
            "event_type": e.event_type,
            "short_description": e.short_description,
            "severity": e.severity,
        }

    data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "source": source_desc,
            "total_events": total_events,
            "parsing_errors": parsing_errors,
            "total_findings": len(findings),
            "total_incidents": len(incidents),
        },
        "incidents": [_incident_dict(i) for i in incidents],
        "findings": [_finding_dict(f) for f in findings],
        "timeline": [_tl_dict(e) for e in timeline],
        "limitations": LIMITATIONS,
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def save_report(content: str, output: str, fmt: str) -> Path:
    out = Path(output)
    if out.suffix in (".md", ".json", ".txt"):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content)
        return out
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out / f"incident_report_{ts}.{fmt}"
    filename.write_text(content)
    return filename
