# Qualys MCP Server

A lightweight MCP server that connects AI assistants to Qualys security data. **32 tools**, pure Python, zero config beyond credentials. Install with `uvx` and start asking security questions in plain English.

## Setup

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qualys": {
      "command": "uvx",
      "args": ["qualys-mcp"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_BASE_URL": "qualysapi.qualys.com",
        "QUALYS_GATEWAY_URL": "gateway.qg1.apps.qualys.com"
      }
    }
  }
}
```

Requires [uv](https://docs.astral.sh/uv/): `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Alternative

```bash
pip install qualys-mcp
qualys-mcp
```

### Self-Signed Certificates

For environments with self-signed certs, add `"QUALYS_SSL_VERIFY": "false"` to the env block.

## Tools

32 tools covering vulnerability management, threat intelligence, asset risk, cloud security, containers, web application security, certificate monitoring, endpoint detection, file integrity monitoring, patch management, compliance, aggregator tools, and security program coaching.

### Daily Operations & Coaching

| Tool | What it answers |
|------|----------------|
| `get_morning_report` | What happened overnight? New vulns, ransomware/exploit flags, top risks, action items |
| `get_recommendations` | What should we improve? Module gaps, risk reduction opportunities, prioritized next steps |
| `get_eliminate_status` | What's our patching and mitigation status? Patch jobs, mitigation jobs, catalog coverage |
| `get_etm_findings` | What confirmed vulnerabilities exist across all sources? ETM findings with QID, QDS, TruRisk, CVE, patch status |
| `get_scanner_health` | Are our scanners healthy? Appliance status, failed scans, capacity utilization, signature updates |

### Security Posture & Priorities

| Tool | What it answers |
|------|----------------|
| `get_security_posture` | How secure are we overall? Health score, risk distribution, container and cloud stats |
| `get_weekly_priorities` | What should my team fix this week? Top risk assets ranked by TruRisk |
| `get_patch_status` | What's our patching coverage? Risk distribution and assets needing remediation |
| `get_scan_status` | What scans are running, queued, or failed? Duration, target, scanner name |
| `get_compliance_posture` | What's our policy compliance rate? Pass/fail by framework (PCI-DSS, CIS, NIST, HIPAA) |

### Vulnerability Intelligence

| Tool | What it answers |
|------|----------------|
| `investigate_cve` | Are we affected by CVE-XXXX? QIDs, severity, patches, threat intel |
| `get_cve_details` | Tell me about these 5 CVEs. Bulk lookup with concurrent fetching |
| `get_new_vulns` | What new vulns dropped this week? Severity breakdown, RTI tags, patch status |
| `get_vulns_by_software` | What vulns affect Apache? Search by software, vendor, or product name |
| `get_threat_intel` | What vulns have ransomware/active exploits? RTI breakdown across 12+ threat categories |
| `get_vuln_exceptions` | What vulnerabilities have approved exceptions? Risk acceptances, false positives, expiring exceptions |

### Asset & Infrastructure Risk

| Tool | What it answers |
|------|----------------|
| `get_asset_risk` | Why is this asset risky? TruRisk score, software inventory, EOL status |
| `get_asset_full_profile` | Full single-asset profile combining CSAM + ETM + VMDR detections in parallel (~5-8s) |
| `get_risk_by_tag` | Risk distribution for a tagged asset group (e.g., 'PCI', 'Production', 'AWS') |
| `get_environment_summary` | Fast all-CSAM environment snapshot: OS, cloud, EOL, criticality tiers (<3s) |
| `get_asset_inventory` | What assets do we have? Search by OS, tag, or query; EOL filtering, platform breakdown |
| `get_tech_debt` | How many EOL/EOS systems do we have? OS and hardware lifecycle status |
| `get_cloud_risk` | What's our cloud security posture? AWS/Azure/GCP accounts and failed controls |
| `get_image_vulns` | What vulns are in this container image? Severity breakdown and fixes |

### Web & Application Security

| Tool | What it answers |
|------|----------------|
| `get_webapp_vulns` | What web app vulnerabilities were found? Per-app breakdown, OWASP categories, critical/high findings |
| `get_expiring_certs` | Which SSL/TLS certs expire soon? Expiring/expired certs, weak algorithms (SHA1/MD5) |

### Threat Detection

| Tool | What it answers |
|------|----------------|
| `get_edr_events` | What endpoint threats were detected? Process injections, lateral movement, suspicious executions |
| `get_fim_events` | What file changes happened? Critical path alerts (/etc/passwd, registry run keys) |
| `get_cdr_findings` | What cloud threats were detected? CDR findings from TotalCloud (malware, C2, crypto-miners) |

### Patch Management

| Tool | What it answers |
|------|----------------|
| `get_pm_status` | What's our patch deployment status? Jobs, patch counts by severity, asset coverage |

### QID Lookups

| Tool | What it answers |
|------|----------------|
| `get_qid_details` | What is this QID? Severity, CVEs, threat intel, affected assets |

### Admin

| Tool | What it answers |
|------|----------------|
| `cache_status` | What's cached? KB entries, detection cache age; use clear=True to reset |

### Threat Intel Categories

`get_threat_intel` supports filtering by any RTI (Real-Time Threat Indicator) tag:

`Ransomware` `Malware` `Active_Attacks` `Exploit_Public` `Easy_Exploit` `Wormable` `Cisa_Known_Exploited_Vulns` `Denial_of_Service` `Privilege_Escalation` `Remote_Code_Execution` `Predicted_High_Risk` `Unauthenticated_Exploitation`

## Example Conversations

### Daily Operations
```
"What happened overnight?"                     → get_morning_report()
"What should my team focus on this week?"      → get_weekly_priorities()
"How secure are we?"                           → get_security_posture()
"What new vulns came out this week?"           → get_new_vulns(days=7)
"What modules should we add?"                  → get_recommendations()
```

### CVE Investigation
```
"Are we affected by Log4Shell?"                → investigate_cve("CVE-2021-44228")
"Show me everything about CVE-2024-3400"       → investigate_cve("CVE-2024-3400")
"Compare CVE-2024-3400 and CVE-2023-4966"      → get_cve_details("CVE-2024-3400,CVE-2023-4966")
```

### Threat Intelligence
```
"What vulns have active ransomware?"           → get_threat_intel(threat_type="Ransomware")
"Show me vulns with public exploits"           → get_threat_intel(threat_type="Exploit_Public")
"Which CISA KEV vulns are we exposed to?"      → get_threat_intel(threat_type="Cisa_Known_Exploited_Vulns")
```

### Software Vulnerabilities
```
"Show me Apache vulnerabilities"               → get_vulns_by_software("Apache")
"Are we running vulnerable Log4j?"            → get_vulns_by_software("log4j")
"What OpenSSL vulnerabilities do we have?"    → get_vulns_by_software("OpenSSL")
```

### Asset & Patching
```
"What should we patch first?"                  → get_patch_status()
"What's wrong with asset 233946644?"           → get_asset_risk("233946644")
"How many EOL systems do we have?"             → get_tech_debt()
"What's our patch/mitigate status?"            → get_eliminate_status()
"Show me all Windows assets"                   → get_asset_inventory(os="Windows")
"What's our patching pipeline for Linux?"      → get_pm_status(platform="Linux")
```

### Cloud & Infrastructure
```
"What's our cloud posture?"                    → get_cloud_risk()
"What cloud threats were detected this week?"  → get_cdr_findings(days=7)
"Show me critical AWS CDR findings"            → get_cdr_findings(severity="CRITICAL", cloud_provider="AWS")
"Are our scanners healthy?"                    → get_scanner_health()
"What scans are running right now?"            → get_scan_status(state="Running")
```

### ETM Findings
```
"Show me all confirmed critical findings"      → get_etm_findings(qql="vulnerabilities.vulnerability.severity:5")
"Am I affected by Log4Shell across all sources?" → get_etm_findings(qql="vulnerabilities.vulnerability.cveIds:CVE-2021-44228")
```

### Web App & Certificate Security
```
"What web app vulnerabilities do we have?"     → get_webapp_vulns()
"Show me critical WAS findings for our portal" → get_webapp_vulns(severity=5, app_name="portal")
"Which SSL certs expire this month?"           → get_expiring_certs(days=30)
"Are any certs already expired?"               → get_expiring_certs(include_expired=True)
```

### Endpoint & File Integrity
```
"What malware was detected this week?"         → get_edr_events(days=7)
"Show me critical endpoint threats"            → get_edr_events(severity="Critical")
"What file changes happened today?"            → get_fim_events(days=1)
"Were /etc/passwd or sudoers modified?"        → get_fim_events(path="/etc/passwd")
```

### Compliance
```
"What's our PCI-DSS compliance score?"        → get_compliance_posture(framework="PCI-DSS")
"Show me failing CIS controls"                 → get_compliance_posture(framework="CIS")
"What exceptions expire soon?"                 → get_vuln_exceptions(days_to_expiry=30)
```

### Multi-Tool Workflows
```
"New critical CVE just dropped — what do I need to know?"
→ investigate_cve() → get_threat_intel() → get_patch_status()

"Prepare me for the weekly security standup"
→ get_morning_report() → get_weekly_priorities() → get_eliminate_status()

"Briefing the CISO on our security program"
→ get_security_posture() → get_threat_intel() → get_patch_status() → get_recommendations()

"We're about to go through a PCI-DSS audit. Where do we stand?"
→ get_security_posture() → get_cloud_risk() → get_tech_debt() → get_compliance_posture(framework="PCI-DSS") → get_expiring_certs()
```

See [docs/examples.md](docs/examples.md) for the full Q&A reference with 100+ mapped examples.

## Qualys PODs

| POD | BASE_URL | GATEWAY_URL |
|-----|----------|-------------|
| US1 | qualysapi.qualys.com | gateway.qg1.apps.qualys.com |
| US2 | qualysapi.qg2.apps.qualys.com | gateway.qg2.apps.qualys.com |
| US3 | qualysapi.qg3.apps.qualys.com | gateway.qg3.apps.qualys.com |
| EU1 | qualysapi.qualys.eu | gateway.qg1.apps.qualys.eu |
| EU2 | qualysapi.qg2.apps.qualys.eu | gateway.qg2.apps.qualys.eu |

## License

MIT - Copyright (c) 2026 Andrew Nelson
