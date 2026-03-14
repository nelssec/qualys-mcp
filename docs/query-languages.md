# Qualys Query Languages — Complete Reference

Qualys has **six distinct query syntaxes** across its APIs. Each module uses a different filtering language. This document is the definitive reference for each, with examples for the 20 most common use cases.

---

## Quick Reference

| Module | Syntax | Used In |
|--------|--------|---------|
| ETM | QQL string | `get_etm_findings(qql=...)` |
| CSAM v2 | JSON filter objects | `csam_search()`, `csam_count()`, `get_asset_inventory()` |
| VMDR Classic | URL query parameters | `get_detections()`, `get_new_vulns()` |
| WAS/QPS | XML `<Criteria>` body | `get_was_findings()`, `get_webapp_vulns()` |
| Container Security | URL filter string | `get_images()`, `get_containers()` |
| TotalCloud/CDR | URL query params | `get_cloud_risk(include_threats=True)`, `get_connectors()` |

---

## 1. ETM QQL (Enterprise TruRisk Management)

ETM uses a **rich string-based query language** similar to Jira JQL. The most flexible and powerful query language in Qualys.

### Syntax

```
field:value                    # Contains / fuzzy match
field='value'                  # Exact match
field>value field<value        # Numeric comparisons
field:[start...end]            # Range
(expr1 AND expr2)              # Boolean AND
(expr1 OR expr2)               # Boolean OR
NOT field:value                # Negation
field:*                        # Wildcard — has any value
```

### Asset Fields

| Field | Example | Notes |
|-------|---------|-------|
| `asset.id` | `asset.id:123456` | CSAM asset ID |
| `asset.name` | `asset.name:prod-web` | Hostname contains |
| `asset.name='prod-web-01'` | `asset.name='prod-web-01'` | Exact hostname |
| `asset.address` | `asset.address:10.0.1` | IP contains |
| `asset.operatingSystem` | `asset.operatingSystem:Windows` | OS name contains |
| `asset.tags.name` | `asset.tags.name:'Production'` | Has tag (exact) |
| `asset.tags.name` | `asset.tags.name:'Web Servers'` | Multi-word needs quotes |
| `asset.criticality` | `asset.criticality>8` | Criticality score 1-10 |
| `asset.riskScore` | `asset.riskScore>700` | TruRisk score 0-1000 |

### Vulnerability Fields

| Field | Example | Notes |
|-------|---------|-------|
| `vulnerabilities.vulnerability.qid` | `vulnerabilities.vulnerability.qid:376267` | Specific QID |
| `vulnerabilities.vulnerability.cveIds` | `vulnerabilities.vulnerability.cveIds:CVE-2021-44228` | CVE lookup |
| `vulnerabilities.vulnerability.severity` | `vulnerabilities.vulnerability.severity:5` | 1-5 scale |
| `vulnerabilities.vulnerability.isPatchAvailable` | `vulnerabilities.vulnerability.isPatchAvailable:true` | Has patch |
| `vulnerabilities.vulnerability.qds` | `vulnerabilities.vulnerability.qds>80` | QDS score |
| `vulnerabilities.qds` | `vulnerabilities.qds>90` | Detection-level QDS |
| `vulnerabilities.status` | `vulnerabilities.status:ACTIVE` | ACTIVE, FIXED, NEW |
| `vulnerabilities.firstFound` | `vulnerabilities.firstFound>2024-01-01` | Detection date |
| `vulnerabilities.lastFound` | `vulnerabilities.lastFound>2024-01-01` | Last seen date |
| `vulnerabilities.isRansomware` | `vulnerabilities.isRansomware:true` | RTI: ransomware |
| `vulnerabilities.isExploitAvailable` | `vulnerabilities.isExploitAvailable:true` | RTI: exploit |
| `vulnerabilities.isMalware` | `vulnerabilities.isMalware:true` | RTI: malware |

### Date Syntax

ETM uses ISO 8601 dates:
- `>2024-01-01` — after date
- `<2024-12-31` — before date
- `[2024-01-01...2024-12-31]` — date range

### 20 Common ETM QQL Examples

```bash
# 1. Find all Log4Shell (CVE-2021-44228) affected assets
vulnerabilities.vulnerability.cveIds:CVE-2021-44228

# 2. Critical severity vulns on production assets
(vulnerabilities.vulnerability.severity:5 AND asset.tags.name:'Production')

# 3. Ransomware-associated vulnerabilities
vulnerabilities.isRansomware:true

# 4. Patchable vulns with QDS > 90
(vulnerabilities.vulnerability.isPatchAvailable:true AND vulnerabilities.qds>90)

# 5. Windows assets with active critical vulns
(asset.operatingSystem:Windows AND vulnerabilities.vulnerability.severity:5 AND vulnerabilities.status:ACTIVE)

# 6. Assets in DMZ tag with high severity vulns
(asset.tags.name:'DMZ' AND vulnerabilities.vulnerability.severity>=4)

# 7. Vulns detected in the last 7 days
vulnerabilities.firstFound>2024-01-14

# 8. CVE list lookup (multiple CVEs)
(vulnerabilities.vulnerability.cveIds:CVE-2024-3400 OR vulnerabilities.vulnerability.cveIds:CVE-2024-21413)

# 9. High-criticality assets with any active vuln
(asset.criticality>8 AND vulnerabilities.status:ACTIVE)

# 10. Assets with CISA KEV vulnerabilities
vulnerabilities.isCisaKev:true

# 11. Specific QID across all assets
vulnerabilities.vulnerability.qid:105233

# 12. EOL operating systems with active vulns
(asset.operatingSystem:Server 2012 AND vulnerabilities.status:ACTIVE)

# 13. Assets without recent scans (risky assets)
asset.riskScore>500

# 14. Wormable vulnerabilities
vulnerabilities.isWormable:true

# 15. Web-facing assets with unauthenticated exploits
(asset.tags.name:'Internet Facing' AND vulnerabilities.isUnauthExploit:true)

# 16. Assets in 10.0.1.0/24 subnet
asset.address:10.0.1.

# 17. Remote code execution vulnerabilities
vulnerabilities.isRemoteCodeExecution:true

# 18. Vulns with active attacks and no patch
(vulnerabilities.isActiveAttack:true AND vulnerabilities.vulnerability.isPatchAvailable:false)

# 19. Specific asset by hostname
asset.name='server-prod-db-01'

# 20. High-priority assets: crit + ransomware + patchable
(asset.criticality>7 AND vulnerabilities.isRansomware:true AND vulnerabilities.vulnerability.isPatchAvailable:true)
```

### ETM API Usage

```python
# In get_etm_findings:
body = {
    "filter": "vulnerabilities.vulnerability.cveIds:CVE-2021-44228",
    "pageSize": 50
}
result = etm_api('POST', '/etm/api/rest/v1/reports/findings', body)
```

---

## 2. CSAM v2 — Structured JSON Filters

CSAM v2 uses **structured JSON filter objects** (not a string syntax). Fast (~0.2–3s). Every filter is an object with `field`, `operator`, and `value`.

### Filter Object Structure

```json
{
  "filters": [
    {
      "field": "asset.truRisk",
      "operator": "GREATER",
      "value": "700"
    }
  ]
}
```

Multiple filters in the array are AND-combined.

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `EQUALS` | Exact match | `{"field": "asset.name", "operator": "EQUALS", "value": "web-01"}` |
| `NOT_EQUALS` | Not equal | `{"field": "asset.type", "operator": "NOT_EQUALS", "value": "Scanner"}` |
| `CONTAINS` | Substring match | `{"field": "asset.name", "operator": "CONTAINS", "value": "prod"}` |
| `NOT_CONTAINS` | Not containing | |
| `GREATER` | Greater than (numeric) | `{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}` |
| `LESSER` | Less than (numeric) | |
| `IN` | In a list | `{"field": "asset.id", "operator": "IN", "value": "1,2,3"}` |

### Available Filter Fields

#### Asset Identity
| Field | Notes |
|-------|-------|
| `asset.id` | CSAM assetId (numeric) |
| `asset.name` | Hostname or DNS name |
| `asset.address` | IP address |
| `asset.type` | Asset type (Physical, Virtual, etc.) |
| `asset.fqdn` | Fully qualified domain name |

#### Risk and Score
| Field | Notes |
|-------|-------|
| `asset.truRisk` | TruRisk score 0–1000 (use GREATER) |
| `asset.criticality` | Business criticality 1–10 |
| `asset.riskScore` | Risk score (alias for truRisk in some responses) |

#### Operating System
| Field | Notes |
|-------|-------|
| `operatingSystem.osName` | OS name (e.g. "Windows Server 2019") |
| `operatingSystem.category` | OS category |
| `operatingSystem.lifecycle.stage` | EOL status — use CONTAINS "EOL" |
| `operatingSystem.lifecycle.eolDate` | EOL date |

#### Hardware
| Field | Notes |
|-------|-------|
| `hardware.manufacturer` | e.g. "Dell", "HP" |
| `hardware.model` | Model name |
| `hardware.lifecycle.stage` | CONTAINS "EOL" |

#### Tags
| Field | Notes |
|-------|-------|
| `tags.name` | Asset tag name (exact match or CONTAINS) |
| `tags.id` | Tag ID |

#### Cloud
| Field | Notes |
|-------|-------|
| `cloudProvider.type` | AWS, AZURE, GCP |
| `cloudProvider.aws.ec2.instanceId` | EC2 instance ID |
| `cloudProvider.aws.ec2.region.name` | AWS region |

#### Lifecycle / Last Seen
| Field | Notes |
|-------|-------|
| `asset.lastVulnScan` | Last vulnerability scan date |
| `asset.lastComplianceScan` | Last compliance scan date |

### 20 Common CSAM Filter Examples

```python
# 1. High-risk assets (TruRisk > 700)
[{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]

# 2. Critical-risk assets (TruRisk > 900)
[{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]

# 3. EOL operating systems
[{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]

# 4. EOL hardware
[{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]

# 5. Specific asset by ID
[{"field": "asset.id", "operator": "EQUALS", "value": "233946644"}]

# 6. Assets in Production tag
[{"field": "tags.name", "operator": "EQUALS", "value": "Production"}]

# 7. Windows assets
[{"field": "operatingSystem.osName", "operator": "CONTAINS", "value": "Windows"}]

# 8. Linux assets
[{"field": "operatingSystem.osName", "operator": "CONTAINS", "value": "Linux"}]

# 9. Assets with 'prod' in hostname
[{"field": "asset.name", "operator": "CONTAINS", "value": "prod"}]

# 10. AWS cloud assets
[{"field": "cloudProvider.type", "operator": "EQUALS", "value": "AWS"}]

# 11. Assets by IP subnet (partial match)
[{"field": "asset.address", "operator": "CONTAINS", "value": "10.0.1."}]

# 12. Windows Server 2012 R2 (specific EOL version)
[{"field": "operatingSystem.osName", "operator": "CONTAINS", "value": "2012"}]

# 13. High criticality assets
[{"field": "asset.criticality", "operator": "GREATER", "value": "8"}]

# 14. AWS us-east-1 assets
[{"field": "cloudProvider.aws.ec2.region.name", "operator": "EQUALS", "value": "us-east-1"}]

# 15. Multiple tags (combine filters in array = AND)
[
    {"field": "tags.name", "operator": "EQUALS", "value": "Production"},
    {"field": "tags.name", "operator": "EQUALS", "value": "Web"}
]

# 16. Assets not in any tag (tricky — no direct NOT filter, check empty tags)
# Use the asset_inventory tool with custom QQL

# 17. Virtual machines only
[{"field": "asset.type", "operator": "EQUALS", "value": "Virtual"}]

# 18. macOS assets
[{"field": "operatingSystem.osName", "operator": "CONTAINS", "value": "macOS"}]

# 19. GCP assets
[{"field": "cloudProvider.type", "operator": "EQUALS", "value": "GCP"}]

# 20. Assets with risk score between ranges (use two GREATER/LESSER)
[
    {"field": "asset.truRisk", "operator": "GREATER", "value": "500"},
    {"field": "asset.truRisk", "operator": "LESSER", "value": "700"}
]
```

---

## 3. VMDR Classic — URL Query Parameters

The VMDR detection API uses **URL query string parameters**. This is the oldest and slowest API (~2min for large environments).

### Endpoint
```
GET /api/2.0/fo/asset/host/vm/detection/?action=list&{params}
```

### Key Parameters

| Parameter | Values | Notes |
|-----------|--------|-------|
| `severities` | `1,2,3,4,5` | Comma-separated severity levels (5=Critical) |
| `status` | `Active,New,Fixed,Re-Opened` | Detection status |
| `qds_min` | `1–100` | Minimum QDS score |
| `vm_processed_after` | `YYYY-MM-DD` | Processed after date |
| `vm_processed_before` | `YYYY-MM-DD` | Processed before date |
| `filter_superseded_qids` | `1` | Skip superseded QIDs (recommended) |
| `show_qds` | `1` | Include QDS scores in output |
| `truncation_limit` | `200` (default) | Max hosts returned |
| `qids` | `105233,91360` | Filter to specific QIDs |
| `ids` | `host_id` | Filter to specific host IDs |
| `ips` | `10.0.0.1-10.0.0.10` | IP range filter |
| `ag_ids` | `1234` | Asset group ID filter |
| `tag_set_include` | `tag_name` | Include assets with tag |

### Common URL Patterns

```python
# Active high/critical vulns, last 30 days
f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
f"&severities=4,5&status=Active&show_qds=1&filter_superseded_qids=1"
f"&vm_processed_after=2024-01-01&truncation_limit=200"

# Specific CVE via QID list
f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
f"&qids=376267,105233&status=Active&show_qds=1"

# QDS-only high priority (QDS >= 80)
f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
f"&qds_min=80&status=Active&filter_superseded_qids=1"
```

### KB Lookup Parameters

```
GET /api/2.0/fo/knowledge_base/vuln/?action=list&{params}
```

| Parameter | Notes |
|-----------|-------|
| `ids` | Comma-separated QIDs |
| `cve` | CVE ID lookup |
| `details` | `All` for full details |
| `published_after` | `YYYY-MM-DD` — new vulns since date |
| `modified_after` | `YYYY-MM-DD` — recently updated |
| `threat_intel_included` | `1` — include RTI tags |

---

## 4. WAS/QPS — XML Criteria Body

WAS uses a **POST with XML body** via the QPS (Qualys Platform Services) endpoint. Awkward but works.

### Endpoint
```
POST /qps/rest/3.0/search/was/finding
Content-Type: text/xml
```

### XML Structure

```xml
<ServiceRequest>
  <filters>
    <Criteria field="FIELD_NAME" operator="OPERATOR">VALUE</Criteria>
    <!-- Multiple criteria = AND -->
  </filters>
  <preferences>
    <limitResults>50</limitResults>
    <startFromOffset>1</startFromOffset>
  </preferences>
</ServiceRequest>
```

### Finding Filter Fields

| Field | Operators | Example |
|-------|-----------|---------|
| `status` | `EQUALS` | `ACTIVE`, `FIXED`, `NEW`, `REOPENED` |
| `severity` | `EQUALS`, `GREATER` | `4` (Critical), `3` (High) |
| `webApp.id` | `EQUALS` | Web application numeric ID |
| `webApp.name` | `CONTAINS`, `EQUALS` | Application name |
| `name` | `CONTAINS` | Vulnerability name (e.g. "SQL Injection") |
| `type` | `EQUALS` | `VULNERABILITY`, `SENSITIVE_CONTENT`, `INFORMATION_GATHERED` |
| `qid` | `EQUALS` | Qualys QID number |
| `url` | `CONTAINS` | URL path filter |
| `detectedDate` | `GREATER`, `LESSER` | Detection date `2024-01-01T00:00:00Z` |
| `lastTestedDate` | `GREATER`, `LESSER` | Last test date |
| `timesDetected` | `GREATER` | Re-occurrence count |
| `isIgnored` | `EQUALS` | `true`/`false` |

### 20 Common WAS XML Examples

```xml
<!-- 1. All active Critical findings -->
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>
<Criteria field="severity" operator="EQUALS">4</Criteria>

<!-- 2. SQL Injection findings -->
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>
<Criteria field="name" operator="CONTAINS">SQL Injection</Criteria>

<!-- 3. XSS findings -->
<Criteria field="name" operator="CONTAINS">Cross-Site Scripting</Criteria>
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>

<!-- 4. Findings for a specific web app -->
<Criteria field="webApp.name" operator="EQUALS">customer-portal</Criteria>
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>

<!-- 5. Findings detected in the last 7 days -->
<Criteria field="detectedDate" operator="GREATER">2024-01-13T00:00:00Z</Criteria>
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>

<!-- 6. High severity or above (3+) -->
<Criteria field="severity" operator="GREATER">2</Criteria>
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>

<!-- 7. Findings for URL path containing /api/ -->
<Criteria field="url" operator="CONTAINS">/api/</Criteria>
<Criteria field="status" operator="EQUALS">ACTIVE</Criteria>

<!-- 8. CSRF vulnerabilities -->
<Criteria field="name" operator="CONTAINS">Cross-Site Request Forgery</Criteria>

<!-- 9. Authentication bypass -->
<Criteria field="name" operator="CONTAINS">Authentication</Criteria>
<Criteria field="severity" operator="EQUALS">4</Criteria>

<!-- 10. Specific QID -->
<Criteria field="qid" operator="EQUALS">150079</Criteria>
```

### WAS Web Application Filter Fields

For listing web apps (`GET /qps/rest/3.0/search/was/webapp`):

| Field | Operators | Notes |
|-------|-----------|-------|
| `name` | `CONTAINS`, `EQUALS` | App name |
| `url` | `CONTAINS` | App URL |
| `tags.name` | `EQUALS` | Tag filter |
| `lastScan.status` | `EQUALS` | `FINISHED`, `RUNNING`, `ERROR` |
| `lastScan.date` | `GREATER`, `LESSER` | Last scan date |
| `isScheduled` | `EQUALS` | `true`/`false` |

---

## 5. Container Security — URL Filter Strings

Container APIs use a **URL filter string** syntax (similar to ETM QQL but simpler).

### Endpoints
```
GET /csapi/v1.3/images?pageSize=100&filter=FILTER
GET /csapi/v1.3/containers?pageSize=100&filter=FILTER
```

### Image Filter Fields

| Field | Example |
|-------|---------|
| `vulnerabilities.severity` | `filter=vulnerabilities.severity:5` |
| `repository` | `filter=repository:nginx` |
| `tag` | `filter=tag:latest` |
| `registryUri` | `filter=registryUri:docker.io` |
| `state` | `filter=state:RUNNING` |
| `isBaseImage` | `filter=isBaseImage:true` |

### Container Filter Fields

| Field | Example |
|-------|---------|
| `state` | `filter=state:RUNNING` |
| `hostName` | `filter=hostName:k8s-node-1` |
| `imageId` | `filter=imageId:abc123` |
| `privileged` | `filter=privileged:true` |

### Common Container Examples

```python
# Running containers only
f"{GATEWAY_URL}/csapi/v1.3/containers?pageSize=100&filter=state:RUNNING"

# Images with critical vulnerabilities
f"{GATEWAY_URL}/csapi/v1.3/images?pageSize=50&filter=vulnerabilities.severity:5"

# Specific image repository
f"{GATEWAY_URL}/csapi/v1.3/images?pageSize=50&filter=repository:nginx"
```

---

## 6. TotalCloud/CDR — URL Query Parameters

Cloud detection APIs use URL query parameters.

### CDR Endpoint
```
GET /cdr-api/rest/v1/findings/?startAt=ISO&endAt=ISO&{params}
```

| Parameter | Values | Notes |
|-----------|--------|-------|
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | String severity |
| `cloudProvider` | `AWS`, `AZURE`, `GCP` | Provider filter |
| `category` | `Malware`, `Ransomware`, `C2`, etc. | Threat category |
| `limit` | Integer | Max results |
| `startAt` | ISO 8601 | Start time |
| `endAt` | ISO 8601 | End time |

### Cloud Connector/Evaluation Endpoints
```
GET /cloudview-api/rest/v1/{provider}/connectors?pageSize=50
GET /cloudview-api/rest/v1/{provider}/evaluations/{account_id}?pageSize=500
```

Providers: `aws`, `azure`, `gcp`

### Common CDR Examples

```python
# Critical cloud threats, last 7 days
start = (now - timedelta(days=7)).isoformat()
f"{GATEWAY_URL}/cdr-api/rest/v1/findings/?startAt={start}Z&endAt={now.isoformat()}Z&severity=CRITICAL"

# AWS-specific threats
f"&cloudProvider=AWS"

# Ransomware category
f"&category=Ransomware"
```

---

## FIM Filter Syntax

FIM uses **CSAM-style bracket range filter** in the URL:

```
GET /fim/v2/events?filter=dateTime:[{start}...{end}]&pageSize=100
```

```python
# Last 24 hours
start = (now - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
end = now.strftime('%Y-%m-%dT%H:%M:%SZ')
f"{BASE_URL}/fim/v2/events?filter=dateTime:[{start}...{end}]&pageSize=100"
```

Additional FIM filters (combined with `AND`):
```
filter=dateTime:[...]AND severity:HIGH
filter=dateTime:[...]AND hostname:prod-server-01
filter=dateTime:[...]AND filePath:/etc
```

---

## EDR Filter Syntax

EDR uses **colon-separated URL filter** (gateway endpoint):

```
GET /edr/v1/events?pageSize=100&filter=severity:CRITICAL
```

Available filters:
- `severity:CRITICAL` / `severity:HIGH` / `severity:MEDIUM` / `severity:LOW`
- `eventType:Malware`
- `hostname:server-01`

---

## Patch Management Filters

PM APIs use URL query parameters:

```
GET /pm/v1/deploymentjobs?platform=Windows&pageSize=10&status=Active
GET /pm/v1/patches/count?platform=Windows&groupBy=vendorSeverity
GET /pm/v1/assets?platform=Windows&pageSize=10
```

| Parameter | Values |
|-----------|--------|
| `platform` | `Windows`, `Linux`, `macOS` |
| `status` | `Active`, `Completed`, `Failed` |
| `groupBy` | `vendorSeverity`, `appFamily`, `patchType` |

---

## CertView Filters

```
GET /certview/v1/certificates?pageSize=100&filter=validTo:<{date}
```

Filter fields:
- `validTo:<2024-02-15` — expires before date
- `grade:F` — TLS grade F
- `subject.commonName:*.example.com` — wildcard certs
- `issuer.commonName:Let's Encrypt` — by CA

---

## Adding QQL Support to Tool Descriptions

When adding QQL support to `get_etm_findings`, include this in the docstring:

```python
"""
QQL examples:
  vulnerabilities.vulnerability.cveIds:CVE-2021-44228
  (vulnerabilities.vulnerability.severity:5 AND asset.tags.name:'Production')
  vulnerabilities.isRansomware:true
  (asset.truRisk>700 AND vulnerabilities.status:ACTIVE)
"""
```

This helps the LLM construct valid QQL without guessing.
