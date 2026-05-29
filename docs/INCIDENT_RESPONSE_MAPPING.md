# Incident Response Mapping

This document maps the tool's detection output to standard incident
response phases and describes how the findings would be used in a
real SOC L1 triage workflow.

---

## How This Tool Fits into Incident Response

A typical incident response process follows the phases defined in NIST SP 800-61:

1. **Preparation** — monitoring in place, log sources configured
2. **Detection and Analysis** — suspicious activity identified, severity assessed
3. **Containment, Eradication, Recovery** — threat actor blocked, damage reversed
4. **Post-Incident Activity** — lessons learned, controls improved

This tool addresses **phase 2 (Detection and Analysis)** — specifically the
initial triage step where raw logs are scanned for indicators of compromise
and prioritized for analyst review.

---

## Mapping: Findings to IR Phases

| Tool Output | IR Phase | What a SOC Analyst Does Next |
|---|---|---|
| `ssh_brute_force` finding | Detection | Verify if any attempts succeeded; escalate to Containment if yes |
| `web_scanning` finding | Detection | Review requested paths; determine if sensitive files were reached |
| `sensitive_path_access` finding | Detection | Check HTTP response codes; escalate to Containment if status 200/302 |
| `suspicious_user_agent` finding | Detection | Identify tool being used; cross-reference with threat intel |
| Multi-indicator incident (Critical) | Detection → Containment | Block IP at perimeter; open incident ticket |
| Incident timeline | Post-incident | Reconstruct attack sequence for PIR |
| JSON report | All phases | Feed into SIEM/SOAR for correlation and enrichment |

---

## Finding Severity → Analyst Priority

| Severity | Score | SOC L1 Action |
|---|---|---|
| Critical (81–100) | Top priority | Immediate escalation; likely active intrusion attempt or confirmed tool |
| High (51–80) | High priority | Investigate within current shift; may require containment |
| Medium (21–50) | Normal queue | Scheduled review; document and monitor |
| Low (0–20) | Low priority | Log for awareness; no immediate action required |

---

## Example: SSH Brute-Force Triage Flow

```
1. Log Incident Analyzer finds ssh_brute_force from 203.0.113.45
   → 312 failed attempts, severity: Critical, score: 90

2. SOC L1 checks for success:
   grep "Accepted" auth.log | grep "203.0.113.45"
   → 0 results: no successful login

3. SOC L1 checks for timing context:
   grep "203.0.113.45" auth.log | tail -5
   → last attempt 4 minutes ago: still active

4. Containment:
   iptables -I INPUT -s 203.0.113.45 -j DROP
   (or via firewall management console / fail2ban)

5. Document:
   - IP: 203.0.113.45
   - Duration: 18 minutes
   - Attempts: 312
   - Usernames targeted: root, admin, ubuntu, postgres, git
   - Outcome: blocked, no successful logins
   - Ticket created: INC-20260501-004
```

---

## Example: Web Scanning + Sensitive Path (Escalation)

```
1. Analyzer finds web_scanning from 198.51.100.7
   → 94 x 404 responses, severity: High, score: 55

2. Analyzer finds sensitive_path_access from 198.51.100.7
   → /.env accessed, HTTP 200 returned

3. Multi-indicator bonus applied: combined score 55 + 60 + 20 = 100 (capped)
   → Severity: Critical

4. SOC L1 escalates to SOC L2:
   "IP 198.51.100.7 conducted directory enumeration AND accessed /.env (HTTP 200).
    Possible credential exposure. Urgent review required."

5. L2 actions:
   - Retrieve .env content that was served
   - Rotate any credentials that may have been exposed
   - Block IP at perimeter
   - Assess whether attacker has made further requests
```

---

## Report → SIEM Integration

The JSON report (`--format json`) is structured for downstream processing:

```json
{
  "incidents": [
    {
      "source_ip": "203.0.113.45",
      "severity": "critical",
      "score": 90,
      "findings": [...],
      "evidence": {...}
    }
  ]
}
```

This structure can be ingested by a SIEM (MaxPatrol SIEM, KUMA, Splunk, ELK)
as a custom log source or via a connector to:
- Create alerts based on severity threshold
- Correlate IPs across multiple log sources
- Feed into threat intelligence platforms for IOC tagging

---

## Limitations in the IR Context

- **Not real-time:** The tool analyzes log files batch-by-batch, not as a streaming feed.
  In a real SOC, this output would supplement a SIEM, not replace it.
- **No confirmation:** A finding of `ssh_brute_force` does not confirm that access was
  obtained. Manual verification is always required.
- **No attribution:** Source IPs may be VPNs, Tor exit nodes, or compromised
  infrastructure. Blocking an IP blocks that infrastructure, not the actor.
- **Sample data only:** The included `sample_logs/` are synthetic. Thresholds and
  severity calibration should be reviewed before applying to a real environment.
