# Qualys MCP — Gap Analysis & New Tool Designs

This document maps coverage gaps to new tool designs. Tools are ordered by priority (highest impact / most common questions first).

---

## Priority 1: Zero-Coverage Modules (Immediate)

These modules have **zero MCP coverage** today despite having internal helpers ready to expose. They answer entire question categories.

---

### Tool: `get_webapp_vulns`

**Priority:** 🔴 Critical — WAS affects 50/500 questions (10%), all currently uncovered.

**Questions it answers:**
- "What web application vulnerabilities were found this week?"
- "Show me all OWASP Top 10 findings across our apps."
- "Are any of our web apps vulnerable to SQL injection?"
- "Which web apps have the most critical vulnerabilities?"
- "Show me all XSS vulnerabilities across our app portfolio."

**Description:**
Web application vulnerabilities from Qualys WAS/TotalAppSec. Shows active findings across your web application portfolio with OWASP category mapping, severity breakdown, and affected app details.

**Parameters:**
```python
severity: int = 0           # Filter: 4=Critical, 3=High, 2=Medium, 1=Low, 0=all
days: int = 30              # Findings detected within N days (0=all active)
app_name: str = ""          # Filter to a specific web application name
owasp_category: str = ""    # Filter by OWASP category (e.g., "A03" for injection)
limit: int = 50             # Max results
```

**API endpoint:** `POST /qps/rest/3.0/search/was/finding`
XML body with filters for status=ACTIVE, severity, date range, webApp name

**Returns:**
```json
{
  "summary": {"total": 42, "critical": 5, "high": 15, "medium": 18, "low": 4},
  "byApp": [{"appName": "customer-portal", "critical": 3, "high": 7}],
  "byCategory": {"SQL Injection": 2, "XSS": 12, "CSRF": 3},
  "owaspTop10": {"A01-BrokenAccessControl": 5, "A03-Injection": 2},
  "findings": [
    {
      "id": "12345",
      "qid": 150001,
      "name": "Cross-Site Scripting",
      "severity": 3,
      "url": "https://app.example.com/search",
      "webAppName": "customer-portal",
      "status": "ACTIVE",
      "detectedDate": "2024-01-15",
      "cves": ["CVE-2024-1234"]
    }
  ]
}
```

**Implementation notes:** Internal `get_was_findings()` helper already exists and calls the correct endpoint. Wrap it with aggregation, OWASP mapping, and the MCP `@mcp.tool()` decorator.

---

### Tool: `get_expiring_certs`

**Priority:** 🔴 Critical — Cert expiry is one of the most common operational questions. 30/500 questions (6%), all uncovered. Expired certs cause outages.

**Questions it answers:**
- "Which SSL/TLS certificates expire in the next 30 days?"
- "Are any certificates already expired?"
- "Which servers are using weak cipher suites?"
- "Are any servers still using TLS 1.0?"
- "Show me all self-signed certificates in production."
- "Which certificates have SHA-1 signatures?"

**Description:**
SSL/TLS certificate inventory and expiry monitoring from Qualys CertView. Shows certificates expiring soon, expired certs, weak ciphers, insecure TLS versions, and configuration issues.

**Parameters:**
```python
days: int = 90              # Show certs expiring within N days (0=all certs)
include_expired: bool = True # Include already-expired certs
weak_only: bool = False      # Show only certs with weak config
limit: int = 100
```

**API endpoint:** `GET /certview/v1/certificates?pageSize={limit}&filter=validTo:<{future_date}`

**Returns:**
```json
{
  "summary": {
    "total": 156,
    "expired": 3,
    "expiring30Days": 8,
    "expiring90Days": 22,
    "weakCiphers": 5,
    "tls10or11": 12,
    "selfSigned": 7
  },
  "expiringSoon": [
    {
      "subject": "*.example.com",
      "issuer": "Let's Encrypt",
      "expiryDate": "2024-02-15",
      "daysRemaining": 12,
      "host": "api.example.com",
      "port": 443,
      "grade": "A",
      "issues": []
    }
  ],
  "issues": [
    {
      "host": "legacy.example.com",
      "issue": "TLS 1.0 enabled",
      "severity": "HIGH"
    }
  ]
}
```

**Implementation notes:** Internal `get_certificates()` helper exists. Internal `get_expiring_certs()` stub exists but not exposed. Enrich with config issue detection.

---

### Tool: `get_edr_events`

**Priority:** 🔴 High — EDR detections are critical security operations data. 35/500 questions (7%), all uncovered. Part of the same workflow as vulnerability management.

**Questions it answers:**
- "What malware was detected on endpoints this week?"
- "Show me all ransomware detections."
- "Which endpoints have active threat detections?"
- "Are any hosts showing signs of C2 communication?"
- "What suspicious process executions were detected?"

**Description:**
Endpoint Detection and Response events from Qualys Multi-Vector EDR. Shows active threat detections including malware, ransomware, C2 callbacks, suspicious processes, and behavioral anomalies.

**Parameters:**
```python
days: int = 7               # Events in the last N days
severity: str = ""          # CRITICAL, HIGH, MEDIUM, LOW
category: str = ""          # malware, ransomware, c2, lateral_movement, etc.
host: str = ""              # Filter to specific hostname or IP
limit: int = 50
```

**API endpoint:** `GET /edr/v1/events?pageSize={limit}&filter=severity:{severity}`

**Returns:**
```json
{
  "summary": {
    "total": 23,
    "critical": 2,
    "high": 8,
    "medium": 13,
    "affectedHosts": 7
  },
  "byCategory": {"Malware": 5, "Suspicious Process": 12, "C2": 1},
  "events": [
    {
      "id": "evt-123",
      "severity": "CRITICAL",
      "category": "Malware",
      "name": "Emotet Trojan",
      "hostname": "DESKTOP-ABC123",
      "ip": "10.0.1.45",
      "user": "jsmith",
      "timestamp": "2024-01-20T14:23:00Z",
      "status": "ACTIVE",
      "details": "Malicious file detected in C:\\Users\\..."
    }
  ]
}
```

**Implementation notes:** Internal `get_edr_events()` helper exists. Needs wrapping with aggregation and the `@mcp.tool()` decorator.

---

### Tool: `get_fim_events`

**Priority:** 🔴 High — FIM is a core compliance control for PCI-DSS, SOX, HIPAA. 35 questions in EDR/FIM category, all uncovered.

**Questions it answers:**
- "What file changes were detected in the last 24 hours?"
- "Which critical system files were modified?"
- "Were any configuration files changed outside maintenance windows?"
- "Show me all FIM events on production servers."
- "Are there unauthorized changes to Windows registry keys?"

**Description:**
File Integrity Monitoring events from Qualys FIM. Shows file and registry changes, filtered by criticality, time window, and host. Essential for compliance (PCI-DSS 10.5, SOX change management).

**Parameters:**
```python
days: int = 1               # Events in the last N days
severity: str = ""          # HIGH, MEDIUM, LOW
host: str = ""              # Filter to hostname or IP
path: str = ""              # Filter by file path (prefix match)
limit: int = 100
```

**API endpoint:** `GET /fim/v2/events?filter=dateTime:[{start}...{end}]&pageSize={limit}`

**Returns:**
```json
{
  "summary": {
    "total": 847,
    "critical": 12,
    "high": 45,
    "affectedHosts": 23,
    "newFiles": 156,
    "modified": 634,
    "deleted": 57
  },
  "topHosts": [{"hostname": "prod-db-01", "eventCount": 234}],
  "criticalChanges": [
    {
      "id": "fim-789",
      "hostname": "prod-web-01",
      "path": "/etc/passwd",
      "action": "MODIFIED",
      "timestamp": "2024-01-20T03:45:00Z",
      "user": "root",
      "severity": "HIGH",
      "expected": false
    }
  ]
}
```

**Implementation notes:** Internal `get_fim_events()` helper exists. Needs wrapping with aggregation logic.

---

### Tool: `get_compliance_posture`

**Priority:** 🔴 High — 45/500 questions (9%) around compliance, all uncovered. Qualys has a full Policy Compliance module but zero MCP exposure.

**Questions it answers:**
- "What's our CIS Benchmark compliance score?"
- "Show me all failing CIS controls for Windows Server."
- "What's our PCI-DSS compliance status?"
- "Which systems are failing the most compliance checks?"
- "Show me compliance failures by severity."

**Description:**
Policy Compliance posture from Qualys PC module. Shows pass/fail rates by framework (CIS, PCI-DSS, HIPAA, NIST, SOC2), top failing controls, and non-compliant assets.

**Parameters:**
```python
framework: str = ""         # CIS, PCI-DSS, HIPAA, NIST, SOC2, ISO27001 (empty=all)
platform: str = ""          # Windows, Linux, Network, Database (empty=all)
limit: int = 20             # Top N failing controls
```

**API endpoint:** Qualys PC v2 API — `GET /api/2.0/fo/compliance/posture/info/` or VM `/api/2.0/fo/compliance/control/`

**Returns:**
```json
{
  "summary": {
    "totalControls": 450,
    "passing": 312,
    "failing": 138,
    "passRate": 69.3,
    "affectedAssets": 145,
    "frameworks": ["CIS", "PCI-DSS", "NIST-800-53"]
  },
  "topFailingControls": [
    {
      "controlId": "CIS-1.1.1",
      "title": "Ensure mounting of cramfs filesystems is disabled",
      "framework": "CIS Linux Benchmark",
      "failingAssets": 87,
      "severity": "HIGH"
    }
  ],
  "byFramework": {
    "CIS": {"passRate": 72.1, "failing": 45},
    "PCI-DSS": {"passRate": 81.5, "failing": 22}
  }
}
```

**API research needed:** PC module API differs from VM API; may use `/api/2.0/fo/report/` with compliance report type, or dedicated PC API. Needs endpoint verification.

---

## Priority 2: High-Impact Extensions

---

### Tool: `get_scan_status`

**Priority:** 🟡 High — Scanner/scan management is 20 questions, with 14 uncovered. Operators constantly need to check scan status.

**Questions it answers:**
- "Show me all running scans right now."
- "What scans are queued?"
- "Show me scan history for the last 7 days."
- "What scans failed in the last 24 hours?"
- "Show me the scan schedule."

**Description:**
VM scan status and history — running, queued, completed, and failed scans. Shows what's happening with your vulnerability scans right now.

**Parameters:**
```python
state: str = "Running,Paused,Queued,Error"  # Scan states to include
days: int = 7                                # History window
limit: int = 50
```

**API endpoint:** `GET /api/2.0/fo/scan/?action=list&state={state}&show_status=1`

**Returns:**
```json
{
  "active": [
    {
      "ref": "scan/123456789.12345",
      "title": "Weekly Internal Scan",
      "state": "Running",
      "type": "API",
      "target": "10.0.0.0/8",
      "launched": "2024-01-20T08:00:00Z",
      "duration": "01:23:45",
      "scanner": "Internal Scanner 1",
      "progress": 67
    }
  ],
  "recent": [...],
  "summary": {
    "running": 2,
    "queued": 1,
    "errors": 3,
    "completedToday": 8
  }
}
```

**Implementation notes:** Internal `get_scan_list()` helper exists. Needs wrapping + aggregation.

---

### Tool: `get_pm_status` -- CONSOLIDATED

**Status:** REMOVED -- use `get_eliminate_status()` instead.

Patch Management functionality has been consolidated into `get_eliminate_status()`, which combines TruRisk Eliminate mitigation/patch data with PM deployment job status and patch coverage.

---

### Tool: `get_asset_inventory`

**Priority:** 🟡 Medium — Asset search/filtering is 35+ uncovered questions. CSAM provides rich asset data not currently surfaced.

**Questions it answers:**
- "Find all assets with hostname containing 'prod'."
- "Show me all assets in the 10.0.0.0/8 subnet."
- "Which assets have a specific software installed?"
- "Show me all assets without any tags assigned."
- "Which assets haven't been seen in 30+ days."

**Description:**
Asset inventory search and filtering using CSAM. Find assets by hostname, IP, software, tag, OS, or last seen date.

**Parameters:**
```python
query: str = ""             # Free text: hostname, IP, OS, software name
tag: str = ""               # Asset tag filter
os: str = ""                # OS filter (Windows, Linux, macOS)
days_since_seen: int = 0    # Assets not seen in N days
eol_only: bool = False      # Show only EOL assets
limit: int = 50
```

**API endpoints:**
- `POST /qps/rest/2.0/search/am/asset` — CSAM search with QQL
- `GET /qps/rest/2.0/count/am/asset` — count

**Returns:**
```json
{
  "total": 1247,
  "assets": [
    {
      "id": "123456",
      "name": "prod-web-01",
      "ip": "10.0.1.10",
      "os": "Ubuntu 22.04",
      "lastSeen": "2024-01-20T08:00:00Z",
      "tags": ["Production", "Web"],
      "truRiskScore": 750,
      "openVulns": 12,
      "criticalVulns": 2,
      "eol": false
    }
  ],
  "summary": {
    "byOS": {"Windows": 450, "Linux": 389, "macOS": 87},
    "byTag": {"Production": 234, "DMZ": 45}
  }
}
```

---

### Tool: `get_vuln_trends`

**Priority:** 🟡 Medium — Trend/reporting questions account for 20+ gaps. Executives and security managers need week-over-week and month-over-month data.

**Questions it answers:**
- "How has our Critical vulnerability count changed month over month?"
- "Show me a trend: new vulns detected vs closed over 30 days."
- "What's our remediation rate for the past quarter?"
- "Show me TruRisk trend for the past 90 days."
- "Which teams have the highest average vulnerability age?"

**Description:**
Vulnerability trend analysis — counts over time, open vs closed, remediation velocity, TruRisk score history. Draws from detection date data to compute trends.

**Parameters:**
```python
days: int = 30              # Trend window
severity: int = 0           # 0=all, 4=Critical, 3=High
group_by: str = "week"      # day, week, month
```

**Returns:**
```json
{
  "period": "30 days",
  "trend": [
    {
      "period": "2024-01-01",
      "newDetections": 45,
      "closed": 38,
      "openCritical": 23,
      "openHigh": 87,
      "truRiskScore": 743
    }
  ],
  "summary": {
    "netChange": +7,
    "remediationRate": 84.4,
    "avgAgeOpen": 18.5,
    "criticalTrend": "improving"
  }
}
```

**Implementation notes:** Requires computing from `get_detections()` with date filtering. May need to be approximate since VMDR API doesn't provide historical snapshots natively — compute from current detections with firstFound/lastFixed dates.

---

### Tool: `get_vuln_exceptions`

**Priority:** 🟡 Medium — Exception management is ~10 uncovered questions. Common in regulated environments.

**Questions it answers:**
- "Which exceptions are about to expire?"
- "How many vulnerabilities have active exceptions/waivers?"
- "Show me all accepted risk vulnerabilities."
- "What vulnerabilities have been marked as false positives?"
- "Which exceptions expire this month?"

**Description:**
Vulnerability exception status — active waivers, false positives, ignored findings, and approaching expiry. Helps manage exception lifecycle.

**Parameters:**
```python
status: str = "Active"      # Active, Expired, Pending
type: str = ""              # Accepted, FalsePositive, Exception
days_to_expiry: int = 30    # Show exceptions expiring within N days
limit: int = 50
```

**API endpoint:** `GET /api/2.0/fo/exception/vuln/?action=list&status={status}`

**Returns:**
```json
{
  "summary": {
    "total": 134,
    "active": 112,
    "expiringSoon": 8,
    "expired": 22,
    "byType": {"Accepted": 45, "FalsePositive": 67}
  },
  "expiringSoon": [
    {
      "id": "exc-123",
      "qid": 91360,
      "title": "OpenSSL vuln",
      "expiryDate": "2024-02-10",
      "assetCount": 12,
      "reason": "Compensating control in place",
      "approvedBy": "security-team"
    }
  ]
}
```

---

## Priority 3: Valuable Extensions

---

### Tool: `get_cloud_inventory`

Answers cloud account/connector questions (15 gaps). Shows all connected AWS/Azure/GCP accounts, connector health, and coverage stats.

**Parameters:** `provider: str = ""` (aws/azure/gcp/empty=all)

**API endpoints:** `get_connectors()` + evaluation metadata

---

### Tool: `get_cloud_compliance`

Answers CIS cloud benchmark compliance questions (10 gaps). Shows compliance by framework/account with control-level detail.

**Parameters:** `framework: str = "CIS"`, `provider: str = ""`, `account_id: str = ""`

**API endpoints:** `get_evaluations()` enriched with control metadata

---

### Tool: `get_container_inventory`

Answers container runtime inventory questions (10 gaps). Shows running containers, their images, hosts, and vulnerability status.

**Parameters:** `limit: int = 50`, `vuln_only: bool = False`

**API endpoints:** `/container-security/v2/containers` or existing `get_containers()` helper

---

### Tool: `get_webapp_inventory`

Answers WAS scan coverage questions (10 gaps). Lists web applications in scope, last scan date, and scan health.

**Parameters:** `limit: int = 50`

**API endpoints:** `GET /qps/rest/3.0/search/was/webapp` — lists configured web applications

---

## Gap Summary by Tool

| New Tool | Questions Answered | Priority | API Ready? |
|----------|-------------------|----------|------------|
| `get_webapp_vulns` | 50 | 🔴 Critical | ✅ Helper exists |
| `get_expiring_certs` | 30 | 🔴 Critical | ✅ Helper exists |
| `get_edr_events` | 35 | 🔴 High | ✅ Helper exists |
| `get_fim_events` | 35 | 🔴 High | ✅ Helper exists |
| `get_compliance_posture` | 45 | 🔴 High | ⚠️ PC API research needed |
| `get_scan_status` | 14 | 🟡 High | ✅ Helper exists |
| ~~`get_pm_status`~~ | 42 | CONSOLIDATED | Use `get_eliminate_status()` |
| `get_asset_inventory` | 35 | 🟡 Medium | ✅ CSAM API works |
| `get_vuln_trends` | 20 | 🟡 Medium | ⚠️ Computed from detections |
| `get_vuln_exceptions` | 10 | 🟡 Medium | ⚠️ Exceptions API |
| `get_cloud_inventory` | 15 | 🟢 Low | ✅ Connectors API |
| `get_cloud_compliance` | 10 | 🟢 Low | ✅ Evaluations API |
| `get_container_inventory` | 10 | 🟢 Low | ✅ Container API |
| `get_webapp_inventory` | 10 | 🟢 Low | ✅ WAS API |

**Total new coverage:** ~361 additional questions (~72% improvement, from 23% to 95%+)

---

## Partially-Covered Tools — Enhancement Suggestions

| Tool | Current Gap | Enhancement |
|------|-------------|-------------|
| `get_asset` | Only single-asset lookup | Add bulk mode for list of IDs |
| `get_cloud_risk` | Only first cloud account | Iterate all accounts |
| `get_scanner_health` | No scan history | Link to `get_scan_status` |
| `get_security_posture` | No WAS/compliance data | Add WAS and PC summary once tools exist |
| `get_morning_report` | No FIM/EDR/certs | Add summaries once new tools are live |
| `get_recommendations` | Cloud-only compliance | Add PC compliance gaps once tool exists |
