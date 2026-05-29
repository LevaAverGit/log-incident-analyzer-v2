from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, Any, List, Optional

from .models import Finding, ParsedEvent
from .scoring import score_to_severity
from .config import load_config

SENSITIVE_PATHS = (
    "/admin", "/login", "/wp-login.php", "/phpmyadmin", "/.env",
    "/.git", "/config", "/backup", "/server-status", "/actuator",
    "/debug", "/phpinfo.php",
)

SCANNER_UAS = (
    "sqlmap", "nikto", "nmap", "masscan", "acunetix",
    "dirbuster", "gobuster", "zgrab",
)


def _first_last(timestamps: List) -> tuple:
    ts = [t for t in timestamps if t]
    return (ts[0] if ts else None, ts[-1] if ts else None)


def detect_ssh_brute_force(events: List[ParsedEvent], cfg: Optional[Dict[str, Any]] = None) -> List[Finding]:
    c = (cfg or load_config()).get("ssh_brute_force", {})
    min_attempts = c.get("min_attempts", 10)
    medium_threshold = c.get("medium_threshold", 30)
    high_threshold = c.get("high_threshold", 100)

    failed: dict = defaultdict(list)
    for e in events:
        if e.log_type == "auth" and e.event_type == "failed_login" and e.source_ip:
            failed[e.source_ip].append(e)

    findings = []
    for ip, evs in failed.items():
        cnt = len(evs)
        if cnt <= min_attempts:
            continue
        if cnt > high_threshold:
            score, sev = 90, "Critical"
        elif cnt > medium_threshold:
            score, sev = 55, "High"
        else:
            score, sev = 30, "Medium"

        usernames = list({e.username for e in evs if e.username})
        first, last = _first_last([e.timestamp for e in evs])
        findings.append(Finding(
            finding_type="ssh_brute_force",
            source_ip=ip,
            severity=sev,
            score=score,
            description=f"Potential SSH brute-force pattern: {cnt} failed login attempts from {ip}",
            evidence=[
                f"Total failed attempts: {cnt}",
                f"Targeted usernames: {', '.join(usernames[:10])}",
            ],
            recommendation="Potential brute-force pattern — verify manually. If confirmed: block IP at firewall, review successful logins in the same window, consider fail2ban.",
            related_events_count=cnt,
            first_seen=first,
            last_seen=last,
        ))
    return findings


def detect_web_scanning(events: List[ParsedEvent], cfg: Optional[Dict[str, Any]] = None) -> List[Finding]:
    c = (cfg or load_config()).get("web_scanning", {})
    min_404_count = c.get("min_404_count", 30)
    high_threshold = c.get("high_threshold", 80)

    not_found: dict = defaultdict(list)
    for e in events:
        if e.log_type == "nginx" and e.status_code == 404 and e.source_ip:
            not_found[e.source_ip].append(e)

    findings = []
    for ip, evs in not_found.items():
        cnt = len(evs)
        if cnt <= min_404_count:
            continue
        score, sev = (55, "High") if cnt > high_threshold else (25, "Medium")
        sample_paths = list({e.url for e in evs if e.url})[:5]
        first, last = _first_last([e.timestamp for e in evs])
        findings.append(Finding(
            finding_type="web_scanning",
            source_ip=ip,
            severity=sev,
            score=score,
            description=f"Possible web directory scanning: {cnt} HTTP 404 responses from {ip}",
            evidence=[f"404 count: {cnt}", f"Sample paths: {', '.join(sample_paths)}"],
            recommendation="Suspicious scanning pattern — verify manually. If confirmed: rate-limit or block IP in WAF, review access logs for successful resource discovery.",
            related_events_count=cnt,
            first_seen=first,
            last_seen=last,
        ))
    return findings


def detect_sensitive_paths(events: List[ParsedEvent]) -> List[Finding]:
    hits: dict = defaultdict(list)
    for e in events:
        if e.log_type == "nginx" and e.url and e.source_ip:
            if any(e.url.startswith(p) or e.url == p for p in SENSITIVE_PATHS):
                hits[e.source_ip].append(e)

    findings = []
    for ip, evs in hits.items():
        cnt = len(evs)
        score, sev = (35, "High") if cnt >= 3 else (15, "Medium")
        paths_hit = list({e.url for e in evs})[:8]
        first, last = _first_last([e.timestamp for e in evs])
        findings.append(Finding(
            finding_type="sensitive_path_access",
            source_ip=ip,
            severity=sev,
            score=score,
            description=f"Access to {cnt} sensitive endpoint(s) from {ip}",
            evidence=[f"Paths accessed: {', '.join(paths_hit)}"],
            recommendation="Review whether sensitive paths return 403/404. Check if any config or credentials were exposed. Manual triage required.",
            related_events_count=cnt,
            first_seen=first,
            last_seen=last,
        ))
    return findings


def detect_suspicious_user_agents(events: List[ParsedEvent]) -> List[Finding]:
    hits: dict = defaultdict(list)
    for e in events:
        if e.log_type == "nginx" and e.user_agent and e.source_ip:
            ua_lower = e.user_agent.lower()
            if any(s in ua_lower for s in SCANNER_UAS):
                hits[e.source_ip].append(e)

    findings = []
    for ip, evs in hits.items():
        uas = list({e.user_agent for e in evs if e.user_agent})[:3]
        first, last = _first_last([e.timestamp for e in evs])
        findings.append(Finding(
            finding_type="suspicious_user_agent",
            source_ip=ip,
            severity="Medium",
            score=20,
            description=f"Possible automated security scanner activity from {ip}",
            evidence=[f"User-agents: {', '.join(uas)}", f"Request count: {len(evs)}"],
            recommendation="Automated scanner detected — correlate with sensitive path hits and 4xx responses. Block after manual confirmation.",
            related_events_count=len(evs),
            first_seen=first,
            last_seen=last,
        ))
    return findings


def detect_repeated_401_403(events: List[ParsedEvent], cfg: Optional[Dict[str, Any]] = None) -> List[Finding]:
    c = (cfg or load_config()).get("repeated_auth_errors", {})
    min_count = c.get("min_count", 20)
    high_threshold = c.get("high_threshold", 50)

    blocked: dict = defaultdict(list)
    for e in events:
        if e.log_type == "nginx" and e.status_code in (401, 403) and e.source_ip:
            blocked[e.source_ip].append(e)

    findings = []
    for ip, evs in blocked.items():
        cnt = len(evs)
        if cnt <= min_count:
            continue
        score, sev = (45, "High") if cnt > high_threshold else (20, "Medium")
        first, last = _first_last([e.timestamp for e in evs])
        findings.append(Finding(
            finding_type="repeated_auth_errors",
            source_ip=ip,
            severity=sev,
            score=score,
            description=f"Repeated 401/403 responses ({cnt}) from {ip} — possible credential stuffing or forced browsing pattern",
            evidence=[f"Total 401/403 responses: {cnt}"],
            recommendation="Review authentication logs. Consider IP block if pattern continues.",
            related_events_count=cnt,
            first_seen=first,
            last_seen=last,
        ))
    return findings


def run_all_detectors(events: List[ParsedEvent], cfg: Optional[Dict[str, Any]] = None) -> List[Finding]:
    resolved_cfg = cfg or load_config()
    findings: List[Finding] = []
    findings.extend(detect_ssh_brute_force(events, resolved_cfg))
    findings.extend(detect_web_scanning(events, resolved_cfg))
    findings.extend(detect_sensitive_paths(events))
    findings.extend(detect_suspicious_user_agents(events))
    findings.extend(detect_repeated_401_403(events, resolved_cfg))
    return findings
