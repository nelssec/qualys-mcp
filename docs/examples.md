# Qualys MCP v0.1.0 -- Example Q&A Pairs

These examples show how real security questions map to the 7 workflow tools.

---

## Investigation

```
Q: Are we affected by Log4Shell?
-> investigate(target="CVE-2021-44228")

Q: Tell me everything about CVE-2024-3400
-> investigate(target="CVE-2024-3400", depth="deep")

Q: Are we exposed to Lazarus Group?
-> investigate(target="Lazarus Group")

Q: What ransomware vulnerabilities exist in our environment?
-> investigate(target="ransomware", threat_type="Ransomware")

Q: What's happening on 10.0.0.1?
-> investigate(target="10.0.0.1", scope="all")

Q: What vulnerabilities affect Apache in our environment?
-> investigate(target="Apache", software="Apache")

Q: Show me EDR events for the past week
-> investigate(target="endpoint threats", scope="edr", days=7)

Q: Were there any suspicious file changes on production servers?
-> investigate(target="production", scope="fim", days=1)
```

---

## Risk Assessment

```
Q: What's our overall risk posture?
-> assess_risk()

Q: Show me cloud risk in AWS
-> assess_risk(scope="cloud", provider="aws")

Q: What are our top risky assets?
-> assess_risk(scope="assets", sort_by="trurisk")

Q: Container image vulnerabilities
-> assess_risk(scope="containers")

Q: Which certificates are expiring soon?
-> assess_risk(scope="certs", days=30)

Q: Show me EOL systems
-> assess_risk(scope="assets", eol_only=True)

Q: Risk breakdown for our Production environment
-> assess_risk(tag="Production", breakdown_by="tag")

Q: Web application vulnerabilities in customer-portal
-> assess_risk(scope="web", app_name="customer-portal")

Q: Any weak ciphers or TLS 1.0 usage?
-> assess_risk(scope="certs", weak_ciphers=True, protocol_filter="TLSv1.0")

Q: Why is asset 233946644 high risk?
-> assess_risk(asset_id="233946644")
```

---

## Compliance

```
Q: Are we PCI compliant?
-> check_compliance(framework="PCI")

Q: Show me all failing CIS controls
-> check_compliance(framework="CIS")

Q: HIPAA compliance posture
-> check_compliance(framework="HIPAA")

Q: What risk acceptances are expiring soon?
-> check_compliance(include_exceptions=True, days_to_expiry=30)

Q: What frameworks do we have?
-> check_compliance()

Q: Linux compliance rate
-> check_compliance(platform="linux")
```

---

## Remediation Planning

```
Q: What should we patch first?
-> plan_remediation()

Q: Outstanding Windows patches
-> plan_remediation(scope="patches", platform="windows")

Q: Is there a mitigation for CVE-2024-3400?
-> plan_remediation(scope="mitigations", cves=["CVE-2024-3400"])

Q: Patch deployment status
-> plan_remediation(scope="patches", status="Running")

Q: What's missing from our security program?
-> plan_remediation(scope="program")

Q: Critical severity patches only
-> plan_remediation(severity="critical")
```

---

## Security Overview

```
Q: Morning security briefing
-> security_overview(period="today")

Q: What happened this week?
-> security_overview(period="week")

Q: Quick environment snapshot
-> security_overview(quick=True)

Q: Any new critical vulns today?
-> security_overview(period="today", severity="5")

Q: Scanner status
-> security_overview(scope="infrastructure")

Q: Monthly security summary
-> security_overview(period="month")
```

---

## Reports

```
Q: List all available reports
-> reports(action="list")

Q: Show me report templates
-> reports(action="templates")

Q: Generate a PDF report using template 12345
-> reports(action="generate", template_id="12345", output_format="pdf")

Q: Check report status
-> reports(action="status", report_id="67890")

Q: Download report
-> reports(action="download", report_id="67890")
```

---

## Cache Management

```
Q: What's cached right now?
-> cache_status()

Q: Clear all caches
-> cache_status(clear=True)
```

---

## Multi-turn Conversation Examples

### CVE Investigation Drilldown

```
Turn 1: "Are we affected by Log4Shell?"
  -> investigate(target="CVE-2021-44228")

Turn 2: "What's the risk for our production assets?"
  -> assess_risk(tag="Production")

Turn 3: "What patches are available?"
  -> plan_remediation(cves=["CVE-2021-44228"])
```

### Security Standup Prep

```
Turn 1: "Give me the morning briefing"
  -> security_overview(period="today")

Turn 2: "What should we prioritize this week?"
  -> plan_remediation()

Turn 3: "How's our compliance?"
  -> check_compliance()
```

### PCI Audit Prep

```
Turn 1: "Are we PCI compliant?"
  -> check_compliance(framework="PCI")

Turn 2: "What's our cloud risk?"
  -> assess_risk(scope="cloud")

Turn 3: "Any expiring certificates?"
  -> assess_risk(scope="certs", days=90)

Turn 4: "Outstanding patches for PCI scope?"
  -> plan_remediation(tag="PCI")
```

---

## Tips for AI Assistants

- **For "what happened" questions** -> `security_overview(period="today")` or `security_overview(period="week")`
- **For specific CVE questions** -> `investigate(target="CVE-XXXX-XXXX")`
- **For "what should we fix" questions** -> `plan_remediation()`
- **For risk posture questions** -> `assess_risk()` with appropriate scope
- **For compliance questions** -> `check_compliance(framework="...")`
- **For cloud/container/web/cert questions** -> `assess_risk(scope="cloud|containers|web|certs")`
- **For threat hunting** -> `investigate(target="...", threat_type="Ransomware")`
- **For asset-specific questions** -> `assess_risk(asset_id="...")`
- **For environment orientation** -> `security_overview(quick=True)`
- **For scanner/infrastructure health** -> `security_overview(scope="infrastructure")`
