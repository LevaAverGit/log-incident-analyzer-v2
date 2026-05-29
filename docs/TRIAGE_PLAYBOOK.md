# Triage Playbook

Triage procedures for each finding type produced by the Log Incident Analyzer.
Each procedure covers: what the finding means, how to confirm it, what to check
next, and when to escalate.

---

## General Triage Principles

1. **Read the evidence.** The finding includes the source IP, count, and sample
   log lines. Start there before running any commands.
2. **Check for success.** A brute-force attempt with no successful logins is
   different from one with a confirmed login. Always check.
3. **Look at the timeline.** If an IP appears in multiple finding types,
   the timeline section of the report shows the sequence.
4. **Escalate Critical findings immediately.** Do not wait for end-of-shift review.
5. **Document before you act.** Record the finding, your verification steps,
   and the containment action taken.

---

## ssh_brute_force

**What it means:** A source IP made many failed SSH login attempts.
This could be an automated credential-stuffing attack or targeted brute-force.

**Step 1 — Check for successful logins:**
```bash
grep "Accepted" /var/log/auth.log | grep "<source_ip>"
```
- If any results: **escalate immediately** — potential compromised account.
- If no results: continue to Step 2.

**Step 2 — Check if still active:**
```bash
grep "<source_ip>" /var/log/auth.log | tail -10
```
- Look at timestamps. Is the last attempt recent?

**Step 3 — Identify targeted accounts:**
```bash
grep "Failed password for" /var/log/auth.log | grep "<source_ip>" | awk '{print $9}' | sort | uniq -c | sort -rn
```

**Step 4 — Contain:**
- Block IP at firewall: `iptables -I INPUT -s <source_ip> -j DROP`
- Or add to fail2ban: `fail2ban-client set sshd banip <source_ip>`

**Escalate when:**
- Successful login found from the same IP
- Attack is ongoing and has been running > 30 minutes
- More than 500 attempts (suggests dedicated targeting)

---

## web_scanning

**What it means:** A source IP generated many HTTP 404 responses, indicating
directory enumeration or path scanning.

**Step 1 — Review requested paths:**
```bash
grep "<source_ip>" /var/log/nginx/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -30
```
- Look for patterns: sequential numbers, wordlist names (`admin`, `backup`, `config`).

**Step 2 — Check for any 200 responses:**
```bash
grep "<source_ip>" /var/log/nginx/access.log | awk '$9 == "200" {print $7}' | head -20
```
- If any paths returned 200: note them and check `sensitive_path_access` findings.

**Step 3 — Check time window:**
- How long did the scan last? A burst over 2 minutes differs from a scan over 2 hours.
- `grep "<source_ip>" /var/log/nginx/access.log | awk '{print $4}' | head -1` → first request
- `grep "<source_ip>" /var/log/nginx/access.log | awk '{print $4}' | tail -1` → last request

**Contain:**
- Block IP at Nginx or firewall if scan is ongoing or confirmed malicious tool.

**Escalate when:**
- Scanner found paths returning 200 that should not be public
- User-agent matches a known tool (check `suspicious_user_agent` in same report)
- Scan duration > 10 minutes or request rate > 50/minute

---

## sensitive_path_access

**What it means:** A request was made to a path that typically exposes credentials
or configuration (e.g., `/.env`, `/admin`, `/wp-login.php`).

**Step 1 — Check the HTTP response status:**
```bash
grep "<path>" /var/log/nginx/access.log | awk '{print $7, $9}'
```
- **200 or 302:** Potential exposure. Treat as a confirmed finding.
- **403 or 404:** Server protected the path. Verify the response body was empty.

**Step 2 — For 200 responses — check response size:**
```bash
grep "<source_ip>" /var/log/nginx/access.log | awk '{print $7, $9, $10}'
# $10 is response bytes
```
- Non-zero bytes on a 200 for `.env` = likely credential exposure.

**Step 3 — Identify what was exposed:**
- For `/.env`: rotate all credentials in that file immediately.
- For `/admin` or `/phpmyadmin`: verify authentication was required.
- For `/.git/HEAD` or `/.git/config`: repository may be partially cloneable.

**Escalate when:**
- Status 200 + non-zero response body for any sensitive path
- Always escalate `.env` exposure — treat as confirmed credential leak

---

## suspicious_user_agent

**What it means:** A request was made with a User-Agent string matching a known
security tool (sqlmap, nikto, gobuster, etc.).

**Step 1 — Identify the full request:**
```bash
grep "<source_ip>" /var/log/nginx/access.log | grep -i "<tool_name>"
```

**Step 2 — Check what URLs were targeted:**
```bash
grep -i "<tool_name>" /var/log/nginx/access.log | awk '{print $7, $9}' | sort | uniq -c
```

**Step 3 — Check for successful findings by the tool:**
- If sqlmap: look for anomalous response sizes to the same URL.
- If gobuster/dirb: look for 200 responses in the same time window from the same IP.

**Contain:**
- Block IP immediately. Known tool User-Agents are almost never false positives.

**Escalate when:**
- Tool is sqlmap: potential SQL injection attempt, check application and DB logs
- Any 200 responses found during the tool session

---

## repeated_auth_errors

**What it means:** A source IP generated a high volume of authentication errors
(invalid user, maximum auth attempts exceeded) beyond what normal user behavior produces.

**Step 1 — Distinguish from brute-force:**
- `repeated_auth_errors` often occurs together with `ssh_brute_force` when
  the attacker cycles through many non-existent usernames.
- Check: is this IP also in `ssh_brute_force` findings?

**Step 2 — Check auth error types:**
```bash
grep "<source_ip>" /var/log/auth.log | grep -E "Invalid user|maximum authentication" | head -20
```

**Step 3 — Check for valid accounts targeted:**
- If errors are all `Invalid user <random>`, it's a username enumeration attempt.
- If errors are for real usernames (root, ubuntu), it's credential brute-force.

**Contain:**
- Block IP if still active. Add to deny list.

**Escalate when:**
- Valid username targeted repeatedly (different from random enumeration)
- Combined with ssh_brute_force finding from the same IP

---

## Multi-Indicator Incidents (Critical)

When an incident has multiple finding types from one IP, review all of them together
before taking action. The sequence matters:

- **scanning → sensitive_path_access → suspicious_user_agent** = systematic targeted attack
- **ssh_brute_force → repeated_auth_errors** = credential-stuffing campaign

For Critical incidents: **always escalate before containment** if you are unsure
of the scope, unless the attack is clearly still in progress (containment first, then escalate).

---

## After Triage

For every finding that resulted in action, document:

1. IP address and finding type
2. Evidence that confirmed the finding (or ruled it out)
3. Action taken (blocked/monitored/escalated)
4. Timestamp of triage
5. Whether any data or access was confirmed compromised

This documentation feeds into the post-incident review and helps tune detection
thresholds for the next analysis cycle.
