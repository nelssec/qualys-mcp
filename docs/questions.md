# Qualys MCP v0.1.0 -- Example Questions by Category

How each question maps to the 7 workflow tools.

---

## Investigation Questions

- Investigate CVE-2021-44228 (Log4Shell) completely -> `investigate(target="CVE-2021-44228", depth="deep")`
- Are we exposed to Lazarus Group? -> `investigate(target="Lazarus Group")`
- What's happening on this IP? -> `investigate(target="10.0.0.1")`
- What ransomware vulns exist? -> `investigate(target="ransomware", threat_type="Ransomware")`
- Deep dive on Log4Shell -> `investigate(target="CVE-2021-44228", depth="deep")`
- What vulnerabilities affect Apache? -> `investigate(target="Apache", software="Apache")`
- Show me EDR events this week -> `investigate(target="endpoint threats", scope="edr", days=7)`
- File changes on production servers -> `investigate(target="production", scope="fim", days=1)`
- What CISA KEV vulns affect us? -> `investigate(target="CISA KEV", threat_type="Cisa_Known_Exploited_Vulns")`
- What do we know about QID 376267? -> `investigate(target="QID 376267")`

---

## Risk Assessment Questions

- What's our overall risk? -> `assess_risk()`
- Cloud risk in AWS -> `assess_risk(scope="cloud", provider="aws")`
- Top risky assets -> `assess_risk(scope="assets", sort_by="trurisk")`
- Container vulnerabilities -> `assess_risk(scope="containers")`
- Expiring certificates -> `assess_risk(scope="certs", days=30)`
- EOL systems -> `assess_risk(scope="assets", eol_only=True)`
- Risk for Production -> `assess_risk(tag="Production")`
- Web app vulns -> `assess_risk(scope="web")`
- Weak ciphers? -> `assess_risk(scope="certs", weak_ciphers=True)`
- Why is this asset risky? -> `assess_risk(asset_id="233946644")`
- Stale assets not seen in 90 days -> `assess_risk(scope="assets", days_since_seen=90)`
- Azure cloud posture -> `assess_risk(scope="cloud", provider="azure")`

---

## Compliance Questions

- Are we PCI compliant? -> `check_compliance(framework="PCI")`
- Failing CIS controls -> `check_compliance(framework="CIS")`
- HIPAA posture -> `check_compliance(framework="HIPAA")`
- Expiring risk acceptances -> `check_compliance(include_exceptions=True, days_to_expiry=30)`
- What frameworks do we have? -> `check_compliance()`
- Linux compliance -> `check_compliance(platform="linux")`
- NIST compliance -> `check_compliance(framework="NIST")`
- SOC2 posture -> `check_compliance(framework="SOC2")`

---

## Remediation Questions

- What should we patch? -> `plan_remediation()`
- Outstanding Windows patches -> `plan_remediation(scope="patches", platform="windows")`
- Mitigation for CVE-2024-3400? -> `plan_remediation(scope="mitigations", cves=["CVE-2024-3400"])`
- Patch deployment status -> `plan_remediation(scope="patches")`
- Program gaps -> `plan_remediation(scope="program")`
- Critical patches -> `plan_remediation(severity="critical")`
- Linux patch status -> `plan_remediation(scope="patches", platform="linux")`

---

## Overview Questions

- Morning briefing -> `security_overview(period="today")`
- What happened this week? -> `security_overview(period="week")`
- Quick health check -> `security_overview(quick=True)`
- New critical vulns? -> `security_overview(period="today", severity="5")`
- Scanner status -> `security_overview(scope="infrastructure")`
- Monthly summary -> `security_overview(period="month")`
- What needs attention today? -> `security_overview(period="today")`

---

## Report Questions

- List reports -> `reports(action="list")`
- Report templates -> `reports(action="templates")`
- Generate a report -> `reports(action="generate", template_id="12345")`
- Download report -> `reports(action="download", report_id="67890")`
- Report status -> `reports(action="status", report_id="67890")`

---

## Admin Questions

- What's cached? -> `cache_status()`
- Clear caches -> `cache_status(clear=True)`
