# Detection Rules

This document describes each detection rule implemented in the analyzer,
including the log sources it operates on, the triggering conditions, the
evidence it collects, and the severity thresholds.

---

## Rule: `ssh_brute_force`

**Log source:** `auth.log`  
**Trigger:** Multiple failed SSH login attempts from a single source IP  
**Pattern:** Lines matching `Failed password for [invalid user] <user> from <ip>`

### Thresholds

| Attempts from single IP | Severity | Score |
|---|---|---|
| ≤ 10 | Not reported | — |
| 11 – 30 | Medium | 30 |
| 31 – 100 | High | 55 |
| > 100 | Critical | 90 |

### Evidence collected

- Source IP
- Count of failed attempts
- Usernames targeted (up to 10 shown)
- Timestamp of first and last attempt

### Recommendation

Block the source IP at the firewall or fail2ban. Verify whether any
attempts succeeded by checking for `Accepted password` or `Accepted publickey`
events from the same IP.

---

## Rule: `web_scanning`

**Log source:** Nginx `access.log`  
**Trigger:** High volume of HTTP 404 responses from a single source IP  
**Pattern:** Requests returning status `404` attributed to a single IP

### Thresholds

| 404 count from single IP | Severity | Score |
|---|---|---|
| ≤ 30 | Not reported | — |
| 31 – 80 | Medium | 25 |
| > 80 | High | 55 |

### Evidence collected

- Source IP
- Count of 404 responses
- Sample of requested paths

### Recommendation

Examine requested paths for directory enumeration patterns (sequential paths,
wordlist-style names). Check whether any 200 responses follow in a subsequent
time window from the same IP. Consider rate limiting or IP blocking.

---

## Rule: `sensitive_path_access`

**Log source:** Nginx `access.log`  
**Trigger:** Request to a path known to expose credentials, configuration, or admin interfaces  
**Pattern:** URL path matches a blocklist of sensitive patterns

### Sensitive paths (default blocklist)

```
/admin          /login          /wp-login.php   /phpmyadmin
/.env           /.git           /config         /backup
/server-status  /actuator       /debug          /phpinfo.php
```

A request matches when its URL equals a blocklist entry or starts with it. The
list is defined as `SENSITIVE_PATHS` in `analyzer/detectors.py`.

### Severity

| Sensitive paths hit from single IP | Severity | Score |
|---|---|---|
| 1 – 2 | Low | 15 |
| 3 or more | Medium | 35 |

### Evidence collected

- Source IP
- Distinct sensitive paths accessed (up to 8)
- Timestamp of first and last hit

### Recommendation

Check the response status the server returned for each path. A 200/302 to a
sensitive path is a likely exposure; 403/404 still warrants confirming the body
carried no partial content. Manual triage required.

---

## Rule: `suspicious_user_agent`

**Log source:** Nginx `access.log`  
**Trigger:** Request `User-Agent` header matches a known scanner or exploit tool signature  
**Pattern:** Substring match against a signature list

### Signatures (default)

```
sqlmap       nikto        nmap         masscan
acunetix     dirbuster    gobuster     zgrab
```

Matched as a case-insensitive substring of the `User-Agent`. The list is defined
as `SCANNER_UAS` in `analyzer/detectors.py`.

### Severity

All matches: **Low**, score **20**. A raw User-Agent match is a weak, spoofable
signal on its own; it escalates through the multi-indicator bonus when the same
IP also trips another rule.

### Evidence collected

- Matched User-Agent strings (up to 3)
- Request count

### Recommendation

Correlate with sensitive-path hits and 4xx responses from the same IP. A
User-Agent is attacker-controlled, so treat the match as a lead, not proof —
block after manual confirmation.

---

## Rule: `repeated_auth_errors`

**Log source:** Nginx `access.log`  
**Trigger:** High volume of HTTP `401`/`403` responses from a single source IP —
possible credential stuffing against an app login, or forced browsing of
protected paths  
**Pattern:** Requests with status code `401` or `403` attributed to a single IP

The rule name predates the current implementation; despite "auth", it operates
on Nginx access logs, not `auth.log`.

### Thresholds

| 401/403 responses from single IP | Severity | Score |
|---|---|---|
| ≤ 20 | Not reported | — |
| 21 – 50 | Low | 20 |
| > 50 | Medium | 45 |

### Evidence collected

- Source IP
- Count of 401/403 responses

### Recommendation

Review the application's authentication logs for the same IP and time window.
Consider an IP block if the pattern continues.

---

## Multi-Indicator Bonus

When a single source IP triggers **more than one finding type**, the incident
score receives a **+20 bonus** added to the combined score. This reflects that
an IP conducting multiple attack patterns simultaneously is more likely to be
an active threat actor, not a misconfigured script or scan bot.

---

## Configuration

Thresholds are defined in `config/default_rules.yml` and loaded at runtime.
To tune for your environment:

```yaml
ssh_brute_force:
  min_attempts: 10        # minimum to trigger a finding
  medium_threshold: 30
  high_threshold: 100

web_scanning:
  min_404_count: 30
  high_threshold: 80

repeated_auth_errors:
  min_count: 20
  high_threshold: 50

scoring:
  multi_indicator_bonus: 20
  max_score: 100
```

Pass a custom config with `--config path/to/rules.yml`.
