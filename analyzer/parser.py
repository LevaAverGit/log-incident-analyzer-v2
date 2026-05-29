from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, List, Tuple

from .models import ParsedEvent

AUTH_LOG_RE = re.compile(
    r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$'
)
NGINX_RE = re.compile(
    r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"[^"]*"\s+"([^"]*)"'
)
SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$'
)


def _classify_auth(service: str, message: str) -> Tuple[str, str, str]:
    """Returns (event_type, username, source_ip)."""
    if service == "sudo":
        m = re.match(r'^(\S+)\s+:', message)
        return ("sudo", m.group(1) if m else "", "")

    patterns = [
        (r'Failed password for (?:invalid user )?(\S+) from (\S+)', "failed_login"),
        (r'Accepted (?:password|publickey) for (\S+) from (\S+)', "accepted_login"),
        (r'Invalid user (\S+) from (\S+)', "invalid_user"),
        (r'session opened for user (\S+)', "session_open"),
        (r'session closed for user (\S+)', "session_close"),
        (r'Disconnected from (?:invalid user )?(\S+) (\S+)', "disconnect"),
    ]
    for pattern, etype in patterns:
        m = re.search(pattern, message)
        if m:
            user = m.group(1)
            ip = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
            return (etype, user, ip)
    return ("other", "", "")


def parse_auth_log(path: str) -> Tuple[List[ParsedEvent], int]:
    events, errors = [], 0
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        m = AUTH_LOG_RE.match(line)
        if not m:
            errors += 1
            continue
        ts, _host, service, _pid, message = m.groups()
        etype, user, ip = _classify_auth(service, message)
        events.append(ParsedEvent(
            log_type="auth",
            timestamp=ts,
            source_ip=ip or None,
            event_type=etype,
            username=user or None,
            method=None,
            url=None,
            status_code=None,
            user_agent=None,
            raw_line=line,
        ))
    return events, errors


def parse_nginx_log(path: str) -> Tuple[List[ParsedEvent], int]:
    events, errors = [], 0
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        m = NGINX_RE.match(line)
        if not m:
            errors += 1
            continue
        ip, ts, method, url, status, _size, ua = m.groups()
        events.append(ParsedEvent(
            log_type="nginx",
            timestamp=ts,
            source_ip=ip,
            event_type="http_request",
            username=None,
            method=method,
            url=url,
            status_code=int(status),
            user_agent=ua,
            raw_line=line,
        ))
    return events, errors


def parse_syslog(path: str) -> Tuple[List[ParsedEvent], int]:
    events, errors = [], 0
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_RE.match(line)
        if not m:
            errors += 1
            continue
        ts, _host, service, _pid, message = m.groups()
        msg_l = message.lower()
        if any(w in msg_l for w in ("error", "fail", "critical", "emerg")):
            etype = "syslog_error"
        elif any(w in msg_l for w in ("warn", "notice")):
            etype = "syslog_warning"
        else:
            etype = "syslog_info"
        events.append(ParsedEvent(
            log_type="syslog",
            timestamp=ts,
            source_ip=None,
            event_type=etype,
            username=None,
            method=None,
            url=None,
            status_code=None,
            user_agent=None,
            raw_line=line,
        ))
    return events, errors
