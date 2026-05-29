# Log Incident Analysis Report

_Generated: 2026-05-24 12:11:42_

## Summary

| Field | Value |
|---|---|
| Source | `sample_logs/auth.log, sample_logs/nginx_access.log, sample_logs/syslog` |
| Total parsed events | 229 |
| Parsing errors | 0 |
| Total findings | 9 |
| Total incidents | 5 |
| 🔴 Critical incidents | 2 |
| 🟠 High incidents | 1 |
| 🟡 Medium incidents | 1 |
| 🟢 Low incidents | 1 |

## Top Source IPs

| IP | Severity | Score | Finding Types |
|---|---|---|---|
| `185.199.109.10` | 🔴 Critical | 100 | sensitive_path_access, suspicious_user_agent, web_scanning |
| `198.51.100.99` | 🔴 Critical | 95 | repeated_auth_errors, sensitive_path_access, suspicious_user_agent |
| `185.234.218.4` | 🟠 High | 55 | ssh_brute_force |
| `91.201.67.133` | 🟡 Medium | 30 | ssh_brute_force |
| `10.0.0.5` | 🟢 Low | 15 | sensitive_path_access |

## Detected Incidents

### INC-001 — `185.199.109.10`

- **Severity:** 🔴 Critical
- **Score:** 100/100
- **Finding types:** sensitive_path_access, suspicious_user_agent, web_scanning
- **Summary:** Multiple suspicious indicators from 185.199.109.10: sensitive path access, automated scanner and web directory scanning.
- **First seen:** `20/May/2026:08:01:00 +0000`
- **Last seen:** `20/May/2026:08:01:35 +0000`

**Evidence:**
- 404 count: 31
- Sample paths: /wp-config.php.bak, /api/v1/status, /Dockerfile, /config/, /.env
- Paths accessed: /server-status, /config/, /admin/, /.env, /wp-login.php, /actuator/env, /.git/config, /debug
- User-agents: Nikto/2.1.6
- Request count: 36

**Recommendations:**
- Suspicious scanning pattern — verify manually. If confirmed: rate-limit or block IP in WAF, review access logs for successful resource discovery.
- Review whether sensitive paths return 403/404. Check if any config or credentials were exposed. Manual triage required.
- Automated scanner detected — correlate with sensitive path hits and 4xx responses. Block after manual confirmation.

### INC-002 — `198.51.100.99`

- **Severity:** 🔴 Critical
- **Score:** 95/100
- **Finding types:** repeated_auth_errors, sensitive_path_access, suspicious_user_agent
- **Summary:** Multiple suspicious indicators from 198.51.100.99: repeated 401/403 errors, sensitive path access and automated scanner.
- **First seen:** `20/May/2026:08:03:00 +0000`
- **Last seen:** `20/May/2026:08:03:30 +0000`

**Evidence:**
- Paths accessed: /login?id=1+UNION+SELECT+NULL--, /admin/login, /.env, /admin/, /login?id=1+AND+1=2, /login?id=1+AND+1=1, /admin/users, /login?id=1%27
- User-agents: sqlmap/1.7.8#stable
- Request count: 31
- Total 401/403 responses: 23

**Recommendations:**
- Review whether sensitive paths return 403/404. Check if any config or credentials were exposed. Manual triage required.
- Automated scanner detected — correlate with sensitive path hits and 4xx responses. Block after manual confirmation.
- Review authentication logs. Consider IP block if pattern continues.

### INC-003 — `185.234.218.4`

- **Severity:** 🟠 High
- **Score:** 55/100
- **Finding types:** ssh_brute_force
- **Summary:** Ssh brute force detected from 185.234.218.4.
- **First seen:** `May 20 08:00:01`
- **Last seen:** `May 20 11:00:10`

**Evidence:**
- Total failed attempts: 45
- Targeted usernames: deploy, www-data, vagrant, mysql, postgres, kafka, jenkins, zabbix, git, user

**Recommendations:**
- Potential brute-force pattern — verify manually. If confirmed: block IP at firewall, review successful logins in the same window, consider fail2ban.

### INC-004 — `91.201.67.133`

- **Severity:** 🟡 Medium
- **Score:** 30/100
- **Finding types:** ssh_brute_force
- **Summary:** Ssh brute force detected from 91.201.67.133.
- **First seen:** `May 20 08:05:00`
- **Last seen:** `May 20 11:45:02`

**Evidence:**
- Total failed attempts: 16
- Targeted usernames: test, root, ubuntu, admin, ftp, oracle, deploy, git, www-data

**Recommendations:**
- Potential brute-force pattern — verify manually. If confirmed: block IP at firewall, review successful logins in the same window, consider fail2ban.

### INC-005 — `10.0.0.5`

- **Severity:** 🟢 Low
- **Score:** 15/100
- **Finding types:** sensitive_path_access
- **Summary:** Sensitive path access detected from 10.0.0.5.
- **First seen:** `20/May/2026:09:00:00 +0000`
- **Last seen:** `20/May/2026:09:00:00 +0000`

**Evidence:**
- Paths accessed: /admin

**Recommendations:**
- Review whether sensitive paths return 403/404. Check if any config or credentials were exposed. Manual triage required.

## Timeline

| Time | Source IP | Event Type | Severity | Description |
|---|---|---|---|---|
| `20/May/2026:08:01:00 +0000` | `185.199.109.10` | sensitive_path_access | 🟠 High | Access to 12 sensitive endpoint(s) from 185.199.109.10 |
| `20/May/2026:08:01:00 +0000` | `185.199.109.10` | suspicious_user_agent | 🟡 Medium | Possible automated security scanner activity from 185.199.109.10 |
| `20/May/2026:08:01:02 +0000` | `185.199.109.10` | web_scanning | 🟡 Medium | Possible web directory scanning: 31 HTTP 404 responses from 185.199.109.10 |
| `20/May/2026:08:01:19 +0000` | `185.199.109.10` | sensitive_path_access_end | 🟠 High | Last activity: Access to 12 sensitive endpoint(s) from 185.199.109.10 |
| `20/May/2026:08:01:35 +0000` | `185.199.109.10` | web_scanning_end | 🟡 Medium | Last activity: Possible web directory scanning: 31 HTTP 404 responses from  |
| `20/May/2026:08:01:35 +0000` | `185.199.109.10` | suspicious_user_agent_end | 🟡 Medium | Last activity: Possible automated security scanner activity from 185.199.10 |
| `20/May/2026:08:03:00 +0000` | `198.51.100.99` | sensitive_path_access | 🟠 High | Access to 11 sensitive endpoint(s) from 198.51.100.99 |
| `20/May/2026:08:03:00 +0000` | `198.51.100.99` | suspicious_user_agent | 🟡 Medium | Possible automated security scanner activity from 198.51.100.99 |
| `20/May/2026:08:03:06 +0000` | `198.51.100.99` | repeated_auth_errors | 🟡 Medium | Repeated 401/403 responses (23) from 198.51.100.99 — possible credential stuffin |
| `20/May/2026:08:03:22 +0000` | `198.51.100.99` | sensitive_path_access_end | 🟠 High | Last activity: Access to 11 sensitive endpoint(s) from 198.51.100.99 |
| `20/May/2026:08:03:30 +0000` | `198.51.100.99` | suspicious_user_agent_end | 🟡 Medium | Last activity: Possible automated security scanner activity from 198.51.100 |
| `20/May/2026:08:03:30 +0000` | `198.51.100.99` | repeated_auth_errors_end | 🟡 Medium | Last activity: Repeated 401/403 responses (23) from 198.51.100.99 — possibl |
| `20/May/2026:09:00:00 +0000` | `10.0.0.5` | sensitive_path_access | 🟡 Medium | Access to 1 sensitive endpoint(s) from 10.0.0.5 |
| `May 20 08:00:01` | `185.234.218.4` | ssh_brute_force | 🟠 High | Potential SSH brute-force pattern: 45 failed login attempts from 185.234.218.4 |
| `May 20 08:05:00` | `91.201.67.133` | ssh_brute_force | 🟡 Medium | Potential SSH brute-force pattern: 16 failed login attempts from 91.201.67.133 |
| `May 20 11:00:10` | `185.234.218.4` | ssh_brute_force_end | 🟠 High | Last activity: Potential SSH brute-force pattern: 45 failed login attempts  |
| `May 20 11:45:02` | `91.201.67.133` | ssh_brute_force_end | 🟡 Medium | Last activity: Potential SSH brute-force pattern: 16 failed login attempts  |

## General Recommendations

- Cross-reference successful logins that occurred after failed login windows.
- Review firewall and WAF rules for blocking confirmed scanner IPs.
- Correlate auth log events with nginx access logs by timestamp.
- Do not treat any Finding as proof of compromise without manual verification.
- Consider deploying fail2ban or equivalent for SSH protection.
- Temporarily restrict suspicious IPs at perimeter if activity is confirmed.

## Limitations

- Rules-based detection only — tuned for sample data, not a production ruleset.
- Does not replace SIEM/EDR/SOC platforms.
- Cannot perform attribution or confirm compromise automatically.
- Findings require manual triage before any remediation action.
- This is an educational MVP project.
