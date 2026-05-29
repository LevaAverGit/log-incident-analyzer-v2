# Log Incident Analysis Report

_Generated: 2026-05-24 11:46:51_

## Summary

| Field | Value |
|---|---|
| Source | `sample_logs/auth.log` |
| Total parsed events | 78 |
| Parsing errors | 0 |
| Total findings | 2 |
| Total incidents | 2 |
| 🟠 High incidents | 1 |
| 🟡 Medium incidents | 1 |

## Top Source IPs

| IP | Severity | Score | Finding Types |
|---|---|---|---|
| `185.234.218.4` | 🟠 High | 55 | ssh_brute_force |
| `91.201.67.133` | 🟡 Medium | 30 | ssh_brute_force |

## Detected Incidents

### INC-001 — `185.234.218.4`

- **Severity:** 🟠 High
- **Score:** 55/100
- **Finding types:** ssh_brute_force
- **Summary:** Ssh brute force detected from 185.234.218.4.
- **First seen:** `May 20 08:00:01`
- **Last seen:** `May 20 09:10:08`

**Evidence:**
- Total failed attempts: 40
- Targeted usernames: oracle, postgres, ubuntu, admin, deploy, ftp, kafka, root, vagrant, guest

**Recommendations:**
- Block IP in firewall. Review successful logins after attack window. Enable fail2ban.

### INC-002 — `91.201.67.133`

- **Severity:** 🟡 Medium
- **Score:** 30/100
- **Finding types:** ssh_brute_force
- **Summary:** Ssh brute force detected from 91.201.67.133.
- **First seen:** `May 20 08:05:00`
- **Last seen:** `May 20 10:00:02`

**Evidence:**
- Total failed attempts: 14
- Targeted usernames: oracle, root, ubuntu, admin, test, deploy, www-data, ftp, git

**Recommendations:**
- Block IP in firewall. Review successful logins after attack window. Enable fail2ban.

## Timeline

| Time | Source IP | Event Type | Severity | Description |
|---|---|---|---|---|
| `May 20 08:00:01` | `185.234.218.4` | ssh_brute_force | 🟠 High | SSH brute force: 40 failed login attempts from 185.234.218.4 |
| `May 20 08:05:00` | `91.201.67.133` | ssh_brute_force | 🟡 Medium | SSH brute force: 14 failed login attempts from 91.201.67.133 |
| `May 20 09:10:08` | `185.234.218.4` | ssh_brute_force_end | 🟠 High | Last activity: SSH brute force: 40 failed login attempts from 185.234.218.4 |
| `May 20 10:00:02` | `91.201.67.133` | ssh_brute_force_end | 🟡 Medium | Last activity: SSH brute force: 14 failed login attempts from 91.201.67.133 |

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
