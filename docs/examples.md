# Qualys MCP — Example Q&A Pairs

These examples show how real security questions map to MCP tool calls. Use this as a guide when building prompts or asking an AI assistant.

---

## Daily Operations

```
Q: What happened overnight? Any new threats I should know about?
→ get_morning_report()

Q: What should my team focus on this week?
→ get_weekly_priorities()

Q: Give me our overall security posture — how are we doing?
→ get_security_posture()

Q: What new vulnerabilities dropped in the last 7 days?
→ get_new_vulns(days=7)

Q: What new Critical vulnerabilities showed up this month?
→ get_new_vulns(days=30)

Q: What should we improve in our security program?
→ get_recommendations()
```

---

## CVE Investigation

```
Q: Are we affected by Log4Shell?
→ investigate_cve(cve="CVE-2021-44228")

Q: Show me everything about CVE-2024-3400
→ investigate_cve(cve="CVE-2024-3400")

Q: Is PrintNightmare still in our environment?
→ investigate_cve(cve="CVE-2021-34527")

Q: Tell me about these three CVEs
→ get_cve_details(cves="CVE-2024-1234,CVE-2024-5678,CVE-2024-9012")

Q: Compare CVE-2023-44487 and CVE-2024-3400 — which is worse for us?
→ get_cve_details(cves="CVE-2023-44487,CVE-2024-3400")

Q: What do we know about CVE-2024-21413? What's the patch?
→ investigate_cve(cve="CVE-2024-21413")
```

---

## Threat Intelligence

```
Q: What vulnerabilities have active ransomware associations?
→ get_threat_intel(threat_type="Ransomware")

Q: Show me vulns with public exploits in the wild
→ get_threat_intel(threat_type="Exploit_Public")

Q: What zero-days are we currently exposed to?
→ get_threat_intel(threat_type="Active_Attacks")

Q: Which of our vulns are in the CISA Known Exploited list?
→ get_threat_intel(threat_type="Cisa_Known_Exploited_Vulns")

Q: Show me all wormable vulnerabilities in our environment
→ get_threat_intel(threat_type="Wormable")

Q: Which vulns could lead to remote code execution?
→ get_threat_intel(threat_type="Remote_Code_Execution")

Q: What privilege escalation vulnerabilities are we exposed to?
→ get_threat_intel(threat_type="Privilege_Escalation")

Q: What's our threat exposure from the last 2 weeks?
→ get_threat_intel(days=14)
```

---

## QID Lookups

```
Q: What is QID 105233?
→ get_qid_details(qids="105233")

Q: Show me details for these QIDs
→ get_qid_details(qids="105233,91360,376267")

Q: Which assets have QID 376267?
→ get_qid_details(qids="376267")
```

---

## Software-Specific Vulnerabilities

```
Q: What vulnerabilities affect Apache in our environment?
→ get_vulns_by_software(software="Apache")

Q: Show me all Log4j vulnerabilities
→ get_vulns_by_software(software="log4j")

Q: Are we running any vulnerable versions of OpenSSL?
→ get_vulns_by_software(software="OpenSSL")

Q: What VMware ESXi vulnerabilities do we have?
→ get_vulns_by_software(software="VMware ESXi")

Q: Show me all Microsoft Office vulnerabilities
→ get_vulns_by_software(software="Microsoft Office")

Q: What vulnerabilities exist for our Cisco devices?
→ get_vulns_by_software(software="Cisco")

Q: Show me all Chrome and Edge vulnerabilities
→ get_vulns_by_software(software="Chrome")
```

---

## Asset Risk

```
Q: Why is asset 233946644 showing up as high risk?
→ get_asset_risk(asset_id="233946644")

Q: Walk me through the risk profile for server prod-web-01
→ get_asset_risk(asset_id="<id for prod-web-01>")

Q: How many EOL systems do we have? What are they?
→ get_tech_debt()

Q: Which Windows 2012 servers are still in our environment?
→ get_tech_debt()
```

---

## Patching

```
Q: What's our overall patching coverage?
→ get_patch_status()

Q: Which assets have the most missing patches?
→ get_patch_status()

Q: What are the highest-priority patches we should deploy?
→ get_patch_status()
```

---

## TruRisk Eliminate

```
Q: What's the status of our Eliminate program?
→ get_eliminate_status()

Q: How many vulnerabilities have we mitigated vs patched?
→ get_eliminate_status()

Q: Are there any active patch or mitigation jobs?
→ get_eliminate_status()

Q: What's in our Eliminate mitigation catalog?
→ get_eliminate_status()
```

---

## ETM Findings

```
Q: Show me all confirmed findings across our environment
→ get_etm_findings()

Q: What confirmed findings have the highest QDS scores?
→ get_etm_findings()

Q: Show me ETM findings for our web servers (using QQL)
→ get_etm_findings(qql="asset.tags.name:'Web Servers'")

Q: Pull the ETM report
→ get_etm_findings(report_id="<report_id>")
```

---

## Cloud Security

```
Q: What's our cloud security posture?
→ get_cloud_risk()

Q: How many CIS controls are failing in AWS?
→ get_cloud_risk()

Q: What cloud threats were detected this week?
→ get_cdr_findings(days=7)

Q: Show me critical CDR findings in AWS
→ get_cdr_findings(severity="CRITICAL", cloud_provider="AWS")

Q: Are there any crypto-miners detected in our cloud?
→ get_cdr_findings(days=30)

Q: Show me Azure threat detections from last month
→ get_cdr_findings(days=30, cloud_provider="AZURE")
```

---

## Container Security

```
Q: What vulnerabilities are in our production container images?
→ get_image_vulns(image_id="<production_image_id>")

Q: Show me all Critical vulns in the nginx:latest image
→ get_image_vulns(image_id="<nginx_image_id>", limit=20)
```

---

## Scanner Health

```
Q: Are all my scanners healthy?
→ get_scanner_health()

Q: Which scanners are offline or out of date?
→ get_scanner_health()

Q: When did each scanner last update its signatures?
→ get_scanner_health()
```

---

## Web Application Security

```
Q: What web application vulnerabilities were found this week?
→ get_webapp_vulns(days=7)

Q: Show me all Critical web app findings
→ get_webapp_vulns(severity=5)

Q: Show me all WAS findings for customer-portal
→ get_webapp_vulns(app_name="customer-portal")

Q: What web app vulns do we have across all apps?
→ get_webapp_vulns(severity=4, days=30)
```

---

## Certificate Monitoring

```
Q: Which SSL certs expire in the next 30 days?
→ get_expiring_certs(days=30)

Q: Are any certificates already expired?
→ get_expiring_certs(include_expired=True)

Q: Show me all certs expiring in the next 90 days
→ get_expiring_certs(days=90)

Q: Which certs use weak algorithms like SHA1?
→ get_expiring_certs(days=365)
```

---

## EDR / Endpoint Detection

```
Q: What malware was detected this week?
→ get_edr_events(days=7)

Q: Show me all critical endpoint threat detections
→ get_edr_events(severity="Critical")

Q: Are any hosts showing ransomware behavior?
→ get_edr_events(category="ransomware", days=30)

Q: Show me all EDR events for host DESKTOP-ABC123
→ get_edr_events(host="DESKTOP-ABC123")
```

---

## File Integrity Monitoring

```
Q: What file changes happened on production servers today?
→ get_fim_events(days=1)

Q: Which critical system files were modified this week?
→ get_fim_events(days=7, severity="HIGH")

Q: Show me all FIM events for /etc/passwd
→ get_fim_events(path="/etc/passwd", days=7)

Q: Were there any off-hours file changes last night?
→ get_fim_events(days=1)
```

---

## Compliance

```
Q: What's our CIS Benchmark compliance score?
→ get_compliance_posture(framework="CIS")

Q: Show me all failing PCI-DSS controls
→ get_compliance_posture(framework="PCI-DSS")

Q: What's our Linux policy compliance rate?
→ get_compliance_posture(platform="Linux")

Q: Which systems are failing the most compliance checks?
→ get_compliance_posture()
```

---

## Patch Management

```
Q: Show me active patch deployment jobs
→ get_pm_status()

Q: What Windows patches are outstanding?
→ get_pm_status(platform="Windows")

Q: What's our patch coverage for Linux?
→ get_pm_status(platform="Linux")
```

---

## Scan Management

```
Q: Show me all running scans right now
→ get_scan_status(state="Running")

Q: What scans failed in the last 24 hours?
→ get_scan_status(state="Error", days=1)

Q: Show me scan history for the past week
→ get_scan_status(days=7)

Q: Which scans are currently queued?
→ get_scan_status(state="Queued")
```

---

## Asset Inventory

```
Q: Show me all Windows assets seen in the last 30 days
→ get_asset_inventory(os="Windows", days_since_seen=30)

Q: Which assets are tagged as production?
→ get_asset_inventory(tag="production")

Q: Show me all EOL assets
→ get_asset_inventory(eol_only=True)

Q: Find assets matching "web-server"
→ get_asset_inventory(query="web-server")
```

---

## Vulnerability Exceptions

```
Q: What vulnerability exceptions do we have?
→ get_vuln_exceptions()

Q: Which exceptions are expiring in the next 30 days?
→ get_vuln_exceptions(days_to_expiry=30)

Q: Show me all false positive exceptions
→ get_vuln_exceptions(vuln_type="false_positive")
```

---

## Multi-Tool Workflows

Some questions are best answered by combining multiple tools:

```
Q: We got a security alert about a new critical CVE. What do I need to know?
→ 1. investigate_cve(cve="CVE-XXXX-XXXX")    — Are we affected? How many assets?
→ 2. get_threat_intel()                       — Is it actively exploited?
→ 3. get_patch_status()                       — Is there a patch? What's our coverage?

Q: Prepare me for the weekly security standup.
→ 1. get_morning_report()                     — What's new since last week?
→ 2. get_weekly_priorities()                  — What should the team work on?
→ 3. get_eliminate_status()                   — How is remediation progressing?

Q: We're about to go through a PCI-DSS audit. Where do we stand?
→ 1. get_security_posture()                   — Overall risk posture
→ 2. get_cloud_risk()                         — Cloud compliance status
→ 3. get_tech_debt()                          — EOL systems (fails PCI-DSS)
→ 4. get_compliance_posture(framework="PCI-DSS")  — Policy compliance pass/fail rates
→ 5. get_expiring_certs()                     — Cert expiry and weak algorithms

Q: Is our cloud environment secure?
→ 1. get_cloud_risk()                         — Misconfig / CIS benchmark failures
→ 2. get_cdr_findings(days=30)                — Active cloud threats
→ 3. get_security_posture()                   — Cloud stats in overall posture

Q: I need to brief the CISO on our security program.
→ 1. get_security_posture()                   — Health score, risk distribution
→ 2. get_threat_intel()                       — Active threat exposure
→ 3. get_weekly_priorities()                  — Top risks by TruRisk
→ 4. get_patch_status()                       — Patching coverage
→ 5. get_recommendations()                    — Improvement opportunities
```

---

## Tips for AI Assistants

- **For "what happened" questions** → Start with `get_morning_report()` or `get_new_vulns()`
- **For specific CVE questions** → `investigate_cve()` gives full context; `get_cve_details()` for bulk
- **For "what should we fix" questions** → `get_weekly_priorities()` ranks by TruRisk
- **For asset-specific questions** → `get_asset_risk(asset_id=...)` with the asset's numeric ID
- **For cloud questions** → `get_cloud_risk()` for posture, `get_cdr_findings()` for active threats
- **For software vulnerability searches** → `get_vulns_by_software(software="<product name>")`
- **For threat hunting** → `get_threat_intel(threat_type="<category>")` — see all available RTI tags
- **For program health** → `get_security_posture()` → `get_recommendations()` → `get_scanner_health()`
