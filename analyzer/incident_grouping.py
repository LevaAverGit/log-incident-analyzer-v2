from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from .models import Finding, Incident
from .scoring import combine_incident_score, calculate_incident_severity


def _build_summary(ip: str, finding_types: List[str]) -> str:
    type_labels = {
        "ssh_brute_force": "SSH brute force",
        "web_scanning": "web directory scanning",
        "sensitive_path_access": "sensitive path access",
        "suspicious_user_agent": "automated scanner",
        "repeated_auth_errors": "repeated 401/403 errors",
    }
    labels = [type_labels.get(t, t) for t in finding_types]
    if len(labels) == 1:
        return f"{labels[0].capitalize()} detected from {ip}."
    listed = ", ".join(labels[:-1]) + f" and {labels[-1]}"
    return f"Multiple suspicious indicators from {ip}: {listed}."


def group_findings_into_incidents(findings: List[Finding], cfg: Optional[Dict[str, Any]] = None) -> List[Incident]:
    by_ip: dict = defaultdict(list)
    for f in findings:
        by_ip[f.source_ip or "unknown"].append(f)

    incidents: List[Incident] = []
    for idx, (ip, ip_findings) in enumerate(
        sorted(by_ip.items(), key=lambda kv: -combine_incident_score(kv[1], cfg)), start=1
    ):
        total_score = combine_incident_score(ip_findings, cfg)
        severity = calculate_incident_severity(ip_findings, cfg)
        ftypes = sorted({f.finding_type for f in ip_findings})
        evidence: List[str] = []
        recs: List[str] = []
        for f in ip_findings:
            evidence.extend(f.evidence)
            if f.recommendation not in recs:
                recs.append(f.recommendation)

        timestamps = [f.first_seen for f in ip_findings if f.first_seen] + \
                     [f.last_seen for f in ip_findings if f.last_seen]
        first = min(timestamps) if timestamps else None
        last = max(timestamps) if timestamps else None

        incidents.append(Incident(
            incident_id=f"INC-{idx:03d}",
            source_ip=ip,
            severity=severity,
            total_score=total_score,
            finding_types=ftypes,
            summary=_build_summary(ip, ftypes),
            evidence=evidence,
            recommendations=recs,
            first_seen=first,
            last_seen=last,
        ))
    return incidents
