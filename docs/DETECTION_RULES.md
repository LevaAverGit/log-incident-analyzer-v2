# Detection Rules

This document describes each detection rule implemented in the analyzer,
including the log sources it operates on, the triggering conditions, the
evidence it collects, and the severity thresholds.

---

## Rule: `ssh_brute_force`

**Log source:** `auth.log`  
**Trigger:** Multiple failed SSH login attempts from a single source IP  
**Pattern:** Lines matching `Failed password for` or `Failed publickey for`

### Thresholds

| Attempts from single IP | Severity | Score |
|---|---|---|
| < 10 | Not reported | — |
| 10 – 30 | Medium | 30 |
| 31 – 100 | High | 55 |
| > 100 | Critical | 90 |

### Evidence collected

- Source IP
- Count of failed attempts
- Usernames targeted (up to 5 shown)
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
| < 30 | Not reported | — |
| 30 – 80 | Medium | 25 |
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
/.env           /wp-login.php     /admin          /phpmyadmin
/config.php     /backup           /.git/HEAD      /.htaccess
/etc/passwd     /proc/self/       /api/debug
```

(Configurable via `config/default_rules.yml`)

### Severity

All matches: **High**, score **60**.

### Evidence collected

- Matched path
- HTTP response status
- Source IP
- Timestamp

### Recommendation

If the server returned 200 or 302 for a sensitive path, treat as a confirmed exposure.
If 404 or 403, verify that the response did not include partial content.

---

## Rule: `suspicious_user_agent`

**Log source:** Nginx `access.log`  
**Trigger:** Request `User-Agent` header matches a known scanner or exploit tool signature  
**Pattern:** Substring match against a signature list

### Signatures (default)

```
sqlmap       nikto        gobuster     dirb
masscan      nmap         zgrab        nuclei
curl/7.      python-requests  scrapy
```

### Severity

All matches: **High**, score **65**.

### Evidence collected

- Matched User-Agent string
- Source IP
- Requested URL
- HTTP response status

### Recommendation

Block the source IP. Scanner tools rarely produce false positives on
User-Agent matching — if a known scanner string appears, treat as hostile
reconnaissance.

---

## Rule: `repeated_auth_errors`

**Log source:** `auth.log`  
**Trigger:** High volume of authentication-related errors (invalid user, pam errors,
connection closed without auth) from a single source IP  
**Pattern:** Lines matching `Invalid user` or `error: maximum authentication attempts exceeded`

### Thresholds

| Auth errors from single IP | Severity | Score |
|---|---|---|
| < 20 | Not reported | — |
| 20 – 50 | Medium | 20 |
| > 50 | High | 45 |

### Evidence collected

- Source IP
- Count of auth errors
- Sample of usernames attempted

### Recommendation

Correlate with `ssh_brute_force` findings — repeated auth errors and failed
password attempts from the same IP confirm active brute-force. Consider disabling
password authentication entirely and requiring key-based auth.

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
