# Log Incident Analysis Report

_Generated: 2026-09-11 02:13:17_

## Summary

| Field | Value |
|---|---|
| Source | `sample_logs/nginx_access.log` |
| Total parsed events | 100 |
| Parsing errors | 0 |
| Total findings | 7 |
| Total incidents | 3 |
| 🔴 Critical incidents | 2 |
| 🟢 Low incidents | 1 |

## Top Source IPs

| IP | Severity | Score | Finding Types |
|---|---|---|---|
| `185.199.109.10` | 🔴 Critical | 100 | sensitive_path_access, suspicious_user_agent, web_scanning |
| `198.51.100.99` | 🔴 Critical | 95 | repeated_auth_errors, sensitive_path_access, suspicious_user_agent |
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
- Sample paths: /shell.php, /composer.json, /backup/, /wp-config.php.bak, /api/v1/status
- Paths accessed: /config/, /actuator/env, /server-status, /login, /.env, /phpmyadmin/, /backup/, /phpinfo.php
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
- Paths accessed: /admin/users, /login?id=1+AND+1=2, /login, /.env, /phpmyadmin/, /login?id=1%27, /login?id=1+AND+1=1, /phpinfo.php
- User-agents: sqlmap/1.7.8#stable
- Request count: 31
- Total 401/403 responses: 23

**Recommendations:**
- Review whether sensitive paths return 403/404. Check if any config or credentials were exposed. Manual triage required.
- Automated scanner detected — correlate with sensitive path hits and 4xx responses. Block after manual confirmation.
- Review authentication logs. Consider IP block if pattern continues.

### INC-003 — `10.0.0.5`

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
| `20/May/2026:08:01:00 +0000` | `185.199.109.10` | sensitive_path_access | 🟡 Medium | Access to 12 sensitive endpoint(s) from 185.199.109.10 |
| `20/May/2026:08:01:00 +0000` | `185.199.109.10` | suspicious_user_agent | 🟢 Low | Possible automated security scanner activity from 185.199.109.10 |
| `20/May/2026:08:01:02 +0000` | `185.199.109.10` | web_scanning | 🟡 Medium | Possible web directory scanning: 31 HTTP 404 responses from 185.199.109.10 |
| `20/May/2026:08:01:19 +0000` | `185.199.109.10` | sensitive_path_access_end | 🟡 Medium | Last activity: Access to 12 sensitive endpoint(s) from 185.199.109.10 |
| `20/May/2026:08:01:35 +0000` | `185.199.109.10` | web_scanning_end | 🟡 Medium | Last activity: Possible web directory scanning: 31 HTTP 404 responses from  |
| `20/May/2026:08:01:35 +0000` | `185.199.109.10` | suspicious_user_agent_end | 🟢 Low | Last activity: Possible automated security scanner activity from 185.199.10 |
| `20/May/2026:08:03:00 +0000` | `198.51.100.99` | sensitive_path_access | 🟡 Medium | Access to 11 sensitive endpoint(s) from 198.51.100.99 |
| `20/May/2026:08:03:00 +0000` | `198.51.100.99` | suspicious_user_agent | 🟢 Low | Possible automated security scanner activity from 198.51.100.99 |
| `20/May/2026:08:03:06 +0000` | `198.51.100.99` | repeated_auth_errors | 🟢 Low | Repeated 401/403 responses (23) from 198.51.100.99 — possible credential stuffin |
| `20/May/2026:08:03:22 +0000` | `198.51.100.99` | sensitive_path_access_end | 🟡 Medium | Last activity: Access to 11 sensitive endpoint(s) from 198.51.100.99 |
| `20/May/2026:08:03:30 +0000` | `198.51.100.99` | suspicious_user_agent_end | 🟢 Low | Last activity: Possible automated security scanner activity from 198.51.100 |
| `20/May/2026:08:03:30 +0000` | `198.51.100.99` | repeated_auth_errors_end | 🟢 Low | Last activity: Repeated 401/403 responses (23) from 198.51.100.99 — possibl |
| `20/May/2026:09:00:00 +0000` | `10.0.0.5` | sensitive_path_access | 🟢 Low | Access to 1 sensitive endpoint(s) from 10.0.0.5 |

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
