# Qualys API Reference Guide

> Comprehensive reference for every Qualys API endpoint used by qualys-mcp, derived from `qualys/api.py` and `qualys/aggregators.py`.

---

## Table of Contents

- [Authentication](#authentication)
- [POD Configuration](#pod-configuration)
- [API Endpoints by Module](#api-endpoints-by-module)
  - [CSAM (CyberSecurity Asset Management)](#1-csam-cybersecurity-asset-management)
  - [VMDR (Vulnerability Management, Detection & Response)](#2-vmdr-vulnerability-management-detection--response)
  - [Knowledge Base](#3-knowledge-base)
  - [ETM (Enterprise TruRisk Management)](#4-etm-enterprise-trurisk-management)
  - [TotalCloud (Cloud Security)](#5-totalcloud-cloud-security)
  - [Container Security](#6-container-security)
  - [WAS (Web Application Scanning)](#7-was-web-application-scanning)
  - [Patch Management](#8-patch-management)
  - [Policy Compliance](#9-policy-compliance)
  - [CertView](#10-certview)
  - [EDR (Endpoint Detection & Response)](#11-edr-endpoint-detection--response)
  - [FIM (File Integrity Monitoring)](#12-fim-file-integrity-monitoring)
  - [Scanners & Scans](#13-scanners--scans)
- [Pagination Patterns](#pagination-patterns)
- [Rate Limiting & Retry Logic](#rate-limiting--retry-logic)
- [Caching Strategy](#caching-strategy)
- [SSL & Network Configuration](#ssl--network-configuration)

---

## Authentication

qualys-mcp uses two authentication methods, selected based on which Qualys API platform the endpoint belongs to.

### Basic Auth (Classic VMDR/PC APIs)

Used for all endpoints under `BASE_URL` (e.g., `qualysapi.qualys.com`).

```
Authorization: Basic <base64(username:password)>
```

Credentials are read from environment variables:

| Variable | Description |
|----------|-------------|
| `QUALYS_USERNAME` | Qualys platform username |
| `QUALYS_PASSWORD` | Qualys platform password |

The Base64-encoded credential string is computed once at module load:

```python
BASIC_AUTH = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
```

Every request via `api_get(url, gateway=False)` attaches `Authorization: Basic {BASIC_AUTH}`.

### Bearer Token (Gateway APIs)

Used for all endpoints under `GATEWAY_URL` (e.g., `gateway.qg1.apps.qualys.com`).

```
Authorization: Bearer <token>
```

**Token acquisition:**

| Property | Value |
|----------|-------|
| Endpoint | `POST {GATEWAY_URL}/auth` |
| Content-Type | `application/x-www-form-urlencoded` |
| Body | `username=...&password=...&token=true` |
| Response | Raw token string (plain text) |
| Token lifetime | 4 hours (server-side) |
| Refresh threshold | 3.5 hours (client-side, 12600 seconds) |

The token is cached globally (`BEARER_TOKEN`, `BEARER_TOKEN_TIME`) and refreshed automatically when the age exceeds 3.5 hours. Token refresh is thread-safe via `AUTH_LOCK` to prevent concurrent token fetches.

**Fallback behavior:** If the bearer token cannot be obtained, gateway requests fall back to Basic Auth:

```python
req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
```

### Common Headers

All API requests include:

```
X-Requested-With: qualys-mcp
```

CSAM and ETM requests additionally include:

```
Content-Type: application/json
Accept: application/json
```

---

## POD Configuration

qualys-mcp supports 12 Qualys PODs (Points of Delivery). Each POD maps to a pair of URLs: a **Base URL** for classic APIs and a **Gateway URL** for modern APIs.

### URL Resolution Priority

1. Explicit `QUALYS_BASE_URL` and `QUALYS_GATEWAY_URL` environment variables
2. `QUALYS_POD` environment variable (e.g., `US1`, `EU2`, `IN1`)
3. Error with guidance (deferred to runtime)

### POD Map

| POD | Base URL (Classic APIs) | Gateway URL (Modern APIs) |
|-----|------------------------|--------------------------|
| `US1` | `qualysapi.qualys.com` | `gateway.qg1.apps.qualys.com` |
| `US2` | `qualysapi.qg2.apps.qualys.com` | `gateway.qg2.apps.qualys.com` |
| `US3` | `qualysapi.qg3.apps.qualys.com` | `gateway.qg3.apps.qualys.com` |
| `US4` | `qualysapi.qg4.apps.qualys.com` | `gateway.qg4.apps.qualys.com` |
| `EU1` | `qualysapi.qualys.eu` | `gateway.qg1.apps.qualys.eu` |
| `EU2` | `qualysapi.qg2.apps.qualys.eu` | `gateway.qg2.apps.qualys.eu` |
| `EU3` | `qualysapi.qg3.apps.qualys.eu` | `gateway.qg3.apps.qualys.eu` |
| `IN1` | `qualysapi.qg1.apps.qualys.in` | `gateway.qg1.apps.qualys.in` |
| `CA1` | `qualysapi.qg1.apps.qualys.ca` | `gateway.qg1.apps.qualys.ca` |
| `AE1` | `qualysapi.qg1.apps.qualys.ae` | `gateway.qg1.apps.qualys.ae` |
| `UK1` | `qualysapi.qg1.apps.qualys.co.uk` | `gateway.qg1.apps.qualys.co.uk` |
| `AU1` | `qualysapi.qg1.apps.qualys.com.au` | `gateway.qg1.apps.qualys.com.au` |
| `KSA1` | `qualysapi.qg1.apps.qualys.sa` | `gateway.qg1.apps.qualys.sa` |

---

## API Endpoints by Module

### 1. CSAM (CyberSecurity Asset Management)

CSAM provides the modern asset inventory via Gateway APIs. All CSAM requests use `POST` with JSON bodies and Bearer token authentication.

#### Count Assets

| Property | Value |
|----------|-------|
| Function | `csam_count(filters=None)` |
| URL | `POST {GATEWAY_URL}/rest/2.0/count/am/asset` |
| Auth | Bearer token |
| Content-Type | `application/json` |
| Request body | `{"filters": [...]}` |
| Response | JSON — `{"count": <int>}` |
| Timeout | 15 seconds |
| Pagination | None (returns single count) |
| Cache | In-memory, 5-minute TTL (`_CSAM_COUNT_CACHE_TTL = 300`) |
| Rate limiting | Semaphore-limited to 4 concurrent requests (`CSAM_MAX_CONCURRENT`) |

**Filter format:**

```json
{"filters": [
  {"field": "asset.tags.name", "operator": "EQUALS", "value": "Production"},
  {"field": "asset.assetGroups.name", "operator": "EQUALS", "value": "Servers"}
]}
```

#### Search Assets

| Property | Value |
|----------|-------|
| Function | `csam_search(filters=None, limit=100, fields=None, fetch_all=True)` |
| URL | `POST {GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={n}&includeFields={fields}&lastSeenAssetId={id}` |
| Auth | Bearer token |
| Content-Type | `application/json` |
| Request body | `{"filters": [...]}` |
| Response | JSON — `{"assetListData": {"asset": [...]}, "hasMore": true/false}` |
| Timeout | 30 seconds |
| Pagination | Cursor-based via `lastSeenAssetId` parameter |
| Page size | 100 (max) |
| Cache | In-memory, 5-minute TTL (`_CSAM_SEARCH_CACHE_TTL = 300`) |
| Rate limiting | Semaphore-limited to 4 concurrent requests |

The `tagList` field is always included automatically.

#### Get Asset by ID

| Property | Value |
|----------|-------|
| Function | `get_asset_by_id(asset_id)` |
| Mechanism | Calls `csam_search` with filter `{"field": "asset.id", "operator": "EQUALS", "value": "<id>"}` |

#### Fetch EOL Assets

| Property | Value |
|----------|-------|
| Function | `fetch_all_eol(eol_type, limit=0, max_pages=0, cutoff_date=None)` |
| URL | `POST {GATEWAY_URL}/rest/2.0/search/am/asset?pageSize=100&lastSeenAssetId={id}` |
| Auth | Bearer token |
| Content-Type | `application/json` |
| Request body | `{"filters": [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]}` (or `hardware.lifecycle.stage`) |
| Response | JSON — same structure as CSAM search |
| Pagination | Cursor-based via `lastSeenAssetId` |
| Deduplication | Tracks `assetId` in a `seen` set |

---

### 2. VMDR (Vulnerability Management, Detection & Response)

VMDR uses the classic XML API at `BASE_URL` with Basic Auth.

#### List Detections (Bulk)

| Property | Value |
|----------|-------|
| Function | `get_detections(severity=5, limit=0, use_cache=True, days=30, qds_min=0, fetch_all=True)` |
| URL | `GET {BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 180 seconds |
| Pagination | `id_min` based (see [Pagination Patterns](#pagination-patterns)) |
| Cache | L1: in-memory, 30-minute TTL (`VMDR_CACHE_TTL`). L2: SQLite disk, 4-hour TTL (`CACHE_TTL_VMDR`) |

**Query parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `severities` | Severity level (1-5) | `5` |
| `status` | Detection status | `Active` |
| `show_qds` | Include QDS scores | `1` |
| `filter_superseded_qids` | Exclude superseded QIDs | `1` |
| `vm_processed_after` | Date filter | 30 days ago |
| `qds_min` | Minimum QDS score filter | omitted if 0 |
| `id_min` | Pagination cursor (host ID) | omitted on first request |

**XML response structure:**

```xml
<HOST_LIST_VM_DETECTION_OUTPUT>
  <WARNING><CODE>1980</CODE></WARNING>  <!-- truncation indicator -->
  <HOST>
    <ID>12345</ID>
    <IP>10.0.0.1</IP>
    <DNS>server.example.com</DNS>
    <DETECTION>
      <QID>90001</QID>
      <SEVERITY>5</SEVERITY>
      <STATUS>Active</STATUS>
      <QDS>95</QDS>
      <FIRST_FOUND_DATETIME>2024-01-15T00:00:00Z</FIRST_FOUND_DATETIME>
    </DETECTION>
  </HOST>
</HOST_LIST_VM_DETECTION_OUTPUT>
```

#### List Detections (Per Host)

| Property | Value |
|----------|-------|
| Function | `get_host_detections(host_id, severity=4, days=30)` |
| URL | `GET {BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list&ids={host_id}&severities={severity}&show_qds=1&filter_superseded_qids=1&vm_processed_after={date}` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 120 seconds |
| Pagination | None (single host) |

#### Get QDS for QIDs

| Property | Value |
|----------|-------|
| Function | `get_qds_for_qids(qids)` |
| URL | `GET {BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list&qids={qid_csv}&show_qds=1&status=Active&filter_superseded_qids=1` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 60 seconds |
| Batching | 50 QIDs per request |
| Cache | In-memory (`QDS_CACHE`), TTL = `VMDR_CACHE_TTL` (30 min default) |

---

### 3. Knowledge Base

The Knowledge Base API provides vulnerability details for QIDs. Uses classic XML API with Basic Auth.

#### Get Single QID

| Property | Value |
|----------|-------|
| Function | `get_kb(qid)` |
| URL | `GET {BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={qid}&details=All` |
| Auth | Basic Auth |
| Response | XML |
| Cache | In-memory (`KB_CACHE`), 1-hour TTL per QID |
| Special | Returns `'KB_BUSY'` sentinel on HTTP 409 (concurrent export) |

#### Get Batch QIDs

| Property | Value |
|----------|-------|
| Function | `get_kb_batch(qids)` |
| URL | `GET {BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={qid_csv}&details=All` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 60 seconds |
| Batching | 50 QIDs per request |
| Cache | In-memory (`KB_CACHE`), 1-hour TTL per QID |

#### Search by CVE

| Property | Value |
|----------|-------|
| Function | `get_cve_qids(cve)` |
| URL | `GET {BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All&cve={cve}` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 60 seconds |

**KB XML response fields parsed:**

| Field | XML Path |
|-------|----------|
| QID | `VULN/QID` |
| Title | `VULN/TITLE` |
| Severity | `VULN/SEVERITY_LEVEL` |
| QDS | `VULN/QDS` |
| QDS Factors | `VULN/QDS_FACTORS` |
| CVSS v3 Base | `VULN/CVSS_V3/BASE` |
| CVSS v3 Temporal | `VULN/CVSS_V3/TEMPORAL` |
| CVSS v3 Vector | `VULN/CVSS_V3/VECTOR_STRING` |
| CVEs | `VULN/CVE_LIST/CVE/ID` |
| Solution | `VULN/SOLUTION` |
| Diagnosis | `VULN/DIAGNOSIS` |
| Patchable | `VULN/PATCHABLE` (1 = yes) |
| Has Exploit | `VULN/EXPLOIT_LIST/EXPLOIT` (presence check) |
| Threat Intel | `VULN/THREAT_INTELLIGENCE/THREAT_INTEL` |

---

### 4. ETM (Enterprise TruRisk Management)

ETM uses Gateway APIs with Bearer token authentication via a dedicated `etm_api()` helper.

#### Generic ETM API Call

| Property | Value |
|----------|-------|
| Function | `etm_api(method, path, body=None, timeout=60)` |
| URL | `{method} {GATEWAY_URL}{path}` |
| Auth | Bearer token |
| Content-Type | `application/json` |
| Response | JSON |
| Special | Returns `ETM_401_SENTINEL` on 401 (subscription not available), `None` on 404 |

#### Download ETM Report Resource

| Property | Value |
|----------|-------|
| Function | `etm_download(report_id, resource_name, timeout=60)` |
| URL | `GET {GATEWAY_URL}/etm/api/rest/v1/reports/{report_id}/resources/{resource_name}` |
| Auth | Bearer token |
| Response | JSON (list) |

#### Get ETM Mitigations

| Property | Value |
|----------|-------|
| Function | `get_etm_mitigations(page_size=100)` |
| URLs tried | `GET {GATEWAY_URL}/etm/api/rest/v1/mitigations?pageSize={n}` then `GET {GATEWAY_URL}/mtg/v1/mitigations?pageSize={n}` |
| Auth | Bearer token |
| Response | JSON — list or `{"data": [...]}` or `{"mitigations": [...]}` |
| Fallback | Tries two endpoint paths; returns first successful result |

---

### 5. TotalCloud (Cloud Security)

TotalCloud uses the CloudView Gateway API with Bearer token auth.

#### List Connectors

| Property | Value |
|----------|-------|
| Function | `get_connectors(provider='aws', limit=50)` |
| URL | `GET {GATEWAY_URL}/cloudview-api/rest/v1/{provider}/connectors` |
| Auth | Bearer token |
| Response | JSON — `{"content": [...], "totalElements": N}` |
| Pagination | `pageNo` (0-based) / `pageSize` |
| 404 handling | Returns empty list (not an error) |

Supported providers: `aws`, `azure`, `gcp`

#### List Evaluations

| Property | Value |
|----------|-------|
| Function | `get_evaluations(account_id, provider='aws', limit=500)` |
| URL | `GET {GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}` |
| Auth | Bearer token |
| Response | JSON — `{"content": [...], "totalElements": N}` |
| Pagination | `pageNo` (0-based) / `pageSize` |

#### Get Evaluation Count (Fast)

| Property | Value |
|----------|-------|
| Function | `get_evaluation_count(account_id, provider='aws', filter_str='')` |
| URL | `GET {GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}?pageSize=1&pageNo=0` |
| Auth | Bearer token |
| Response | JSON — `{"totalElements": N, "content": [...]}` |
| Timeout | 15 seconds |

#### List Evaluations (Filtered)

| Property | Value |
|----------|-------|
| Function | `get_evaluations_filtered(account_id, provider='aws', limit=500, filter_str='')` |
| URL | `GET {GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}?filter={filter_str}` |
| Auth | Bearer token |
| Response | JSON |
| Pagination | `pageNo` (0-based) / `pageSize` |

#### CDR (Cloud Detection & Response) Findings

| Property | Value |
|----------|-------|
| Function | `get_cdr(days=7, limit=100, severity=None, cloud_provider=None, category=None)` |
| URL | `GET {GATEWAY_URL}/cdr-api/rest/v1/findings/?startAt={iso}&endAt={iso}` |
| Auth | Bearer token |
| Response | JSON — `{"content": [...], "totalElements": N}` |
| Pagination | `pageNumber` / `limit` |
| Server error | Returns `'CDR_UNAVAILABLE'` sentinel on HTTP 500 |

**Optional query parameters:**

| Parameter | Description |
|-----------|-------------|
| `severity` | Filter by severity level |
| `cloudProvider` | Filter by cloud provider (aws, azure, gcp) |
| `category` | Filter by finding category |

---

### 6. Container Security

Container Security uses the CSAPI Gateway endpoints with Bearer token auth.

#### List Images

| Property | Value |
|----------|-------|
| Function | `get_images(limit=100, severity=None, count_only=False)` |
| URL | `GET {GATEWAY_URL}/csapi/v1.3/images?sort=created:desc` |
| Auth | Bearer token |
| Response | JSON — `{"data": [...], "count": N}` |
| Pagination | `pageNumber` / `pageSize` |
| Optional filter | `filter=vulnerabilities.severity:{severity}` |

#### List Images by Vulnerability Count

| Property | Value |
|----------|-------|
| Function | `get_images_by_vulns(limit=50)` |
| URL | `GET {GATEWAY_URL}/csapi/v1.3/images?sort=vulnerabilities.severity5:desc` |
| Auth | Bearer token |
| Response | JSON |
| Pagination | `pageNumber` / `pageSize` |

#### List Containers

| Property | Value |
|----------|-------|
| Function | `get_containers(limit=100, count_only=False, filter_str=None)` |
| URL | `GET {GATEWAY_URL}/csapi/v1.3/containers?filter={filter}` |
| Auth | Bearer token |
| Response | JSON — `{"data": [...], "count": N}` |
| Default filter | `state:RUNNING` |
| Pagination | `pageNumber` / `pageSize` |

#### Get Image Details

| Property | Value |
|----------|-------|
| Function | `get_image_details(image_id)` |
| URL | `GET {GATEWAY_URL}/csapi/v1.3/images/{image_id}` |
| Auth | Bearer token |
| Response | JSON (single object) |

#### Get Image Vulnerabilities

| Property | Value |
|----------|-------|
| Function | `get_image_vulns_api(image_id)` |
| URL | `GET {GATEWAY_URL}/csapi/v1.3/images/{image_id}/vuln` |
| Auth | Bearer token |
| Response | JSON — `{"data": [...]}` |

#### Container Vulnerability Summary

| Property | Value |
|----------|-------|
| Function | `get_container_vulns_summary()` |
| URLs | `GET {GATEWAY_URL}/csapi/v1.3/vuln?pageSize=1&pageNumber=1` (count) and `GET {GATEWAY_URL}/csapi/v1.3/vuln/count?groupBy=severity` (breakdown) |
| Auth | Bearer token |
| Response | JSON |

---

### 7. WAS (Web Application Scanning)

WAS uses a hybrid approach: the endpoint is at `BASE_URL` but uses the QPS REST API path (`/qps/rest/3.0/`). Auth is Basic.

#### Search Findings

| Property | Value |
|----------|-------|
| Function | `get_was_findings(limit=100, severity=None, days=None, app_name=None)` |
| URL | `POST {BASE_URL}/qps/rest/3.0/search/was/finding` |
| Auth | Basic Auth |
| Content-Type | `text/xml` |
| Request body | XML ServiceRequest with Criteria filters |
| Response | XML |
| Timeout | 60 seconds |
| Cache | L1: in-memory, 10-minute TTL. L2: SQLite disk, 4-hour TTL (`CACHE_TTL_WAS`) |

**Request body format:**

```xml
<ServiceRequest>
  <filters>
    <Criteria field="status" operator="EQUALS">ACTIVE</Criteria>
    <Criteria field="severity" operator="EQUALS">5</Criteria>
    <Criteria field="detectedDate" operator="GREATER">2024-01-01T00:00:00Z</Criteria>
    <Criteria field="webApp.name" operator="CONTAINS">MyApp</Criteria>
  </filters>
  <preferences>
    <limitResults>100</limitResults>
  </preferences>
</ServiceRequest>
```

**Response fields parsed:**

| Field | XML Path |
|-------|----------|
| ID | `Finding/id` |
| QID | `Finding/qid` |
| Name | `Finding/name` |
| Severity | `Finding/severity` |
| URL | `Finding/url` |
| Web App ID | `Finding/webApp/id` |
| Web App Name | `Finding/webApp/name` |
| Detected Date | `Finding/detectedDate` |
| Type | `Finding/type` |

---

### 8. Patch Management

Patch Management uses Gateway APIs with Bearer token auth. All endpoints return JSON.

#### List Deployment Jobs

| Property | Value |
|----------|-------|
| Function | `get_pm_jobs(platform='Windows', limit=10, status=None)` |
| URL | `GET {GATEWAY_URL}/pm/v1/deploymentjobs?platform={platform}&pageSize={limit}` |
| Auth | Bearer token |
| Response | JSON (list) |
| Optional parameter | `status` (Running, Completed, Failed) |

#### Get Patch Counts

| Property | Value |
|----------|-------|
| Function | `get_pm_patches_count(platform='Windows', group_by=None, status=None)` |
| URL | `GET {GATEWAY_URL}/pm/v1/patches/count?platform={platform}` |
| Auth | Bearer token |
| Response | JSON (object) |
| Optional parameters | `groupBy` (vendorSeverity, appFamily), `status` (Missing, Deployed, Installed) |

#### List Patches

| Property | Value |
|----------|-------|
| Function | `get_pm_patches(platform='Windows', status='Missing', page_size=50)` |
| URL | `GET {GATEWAY_URL}/pm/v1/patches?platform={platform}&status={status}&pageSize={page_size}` |
| Auth | Bearer token |
| Response | JSON (list) |

#### List PM Assets

| Property | Value |
|----------|-------|
| Function | `get_pm_assets(platform='Windows', limit=10)` |
| URL | `GET {GATEWAY_URL}/pm/v1/assets?platform={platform}&pageSize={limit}` |
| Auth | Bearer token |
| Response | JSON (list) |

#### Get Job Summary

| Property | Value |
|----------|-------|
| Function | `get_pm_job_summary(job_id)` |
| URL | `GET {GATEWAY_URL}/pm/v1/deploymentjob/{job_id}/deploymentjobresult/summary` |
| Auth | Bearer token |
| Response | JSON (object) |

#### TruRisk Mitigate Jobs

| Property | Value |
|----------|-------|
| Function | `get_mtg_jobs(platform='Windows', limit=10, status=None)` |
| URL | `GET {GATEWAY_URL}/mtg/v1/deploymentjobs?platform={platform}&pageSize={limit}` |
| Auth | Bearer token |
| Response | JSON (list) |

#### TruRisk Mitigate Job Detail

| Property | Value |
|----------|-------|
| Function | `get_mtg_job_detail(job_id)` |
| URL | `GET {GATEWAY_URL}/mtg/v1/deploymentjob/{job_id}` |
| Auth | Bearer token |
| Response | JSON (object) |

---

### 9. Policy Compliance

Policy Compliance uses classic APIs at `BASE_URL` with Basic Auth. Endpoints return XML. These are called from `qualys/aggregators.py` rather than being wrapped in `api.py`.

#### List Policies (v4)

| Property | Value |
|----------|-------|
| URL | `GET {BASE_URL}/api/4.0/fo/compliance/policy/?action=list` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 120 seconds |
| Optional parameter | `search_keyword={framework}` |

#### Posture Instances Summary (v4 REST)

| Property | Value |
|----------|-------|
| URL | `GET {BASE_URL}/rest/4.0/compliance/posture/instances` |
| Auth | Basic Auth |
| Response | JSON |
| Timeout | 60 seconds |
| Optional parameter | `filter=framework:{name}` |

#### Posture Info (v2)

| Property | Value |
|----------|-------|
| URL | `GET {BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 120 seconds |
| Optional parameter | `policy_id={id}` |

#### List Controls (v2)

| Property | Value |
|----------|-------|
| URL | `GET {BASE_URL}/api/2.0/fo/compliance/control/?action=list` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 60 seconds |

#### Vulnerability Exceptions

| Property | Value |
|----------|-------|
| Function (in aggregators.py) | `vuln_exceptions(status='Active', vuln_type='', days_to_expiry=30, limit=50)` |
| URL | `GET {BASE_URL}/api/2.0/fo/exception/vuln/?action=list&status={status}` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 30 seconds |
| Optional parameter | `exception_type={type}` |

**Compliance data retrieval uses a multi-strategy fallback:**

1. v4 posture instances summary (JSON, fastest)
2. v4 policy list then v2 posture/info per policy (XML, parallel)
3. v2 posture/info without policy_id (XML)
4. v2 control list (XML)
5. Cloud compliance gaps from TotalCloud evaluations (JSON, last resort)

---

### 10. CertView

CertView uses Gateway APIs with Bearer token auth.

#### List Certificates (v1)

| Property | Value |
|----------|-------|
| Function | `get_certificates(limit=100, days_expiring=None)` |
| URL | `GET {GATEWAY_URL}/certview/v1/certificates` |
| Auth | Bearer token |
| Response | JSON — `{"data": [...], "count": N}` |
| Pagination | `pageNumber` / `pageSize` |
| Optional filter | `filter=validTo:<{future_date}` (URL-encoded) |

#### List Certificates (v2, Filtered)

| Property | Value |
|----------|-------|
| Function | `get_certificates_filtered(filter_str, limit=100)` |
| URL | `GET {GATEWAY_URL}/certview/v2/certificates?pageSize={n}&filter={filter_str}` |
| Auth | Bearer token |
| Response | JSON |
| Pagination | `pageNumber` / `pageSize` |

---

### 11. EDR (Endpoint Detection & Response)

EDR events are fetched through the unified IOC events endpoint at the Gateway.

#### Fetch IOC Events

| Property | Value |
|----------|-------|
| Function | `_fetch_ioc_events(limit=200)` |
| URL | `GET {GATEWAY_URL}/ioc/v1/events?pageSize={limit}` |
| Auth | Bearer token |
| Response | JSON — list or `{"data": [...]}` or `{"events": [...]}` or `{"items": [...]}` |
| Timeout | 30 seconds |

#### EDR Events (Filtered)

| Property | Value |
|----------|-------|
| Function | `_fetch_edr_events_raw(limit=100, severity=None)` |
| Mechanism | Calls `_fetch_ioc_events(limit * 3)` and filters out FIM event types |
| EDR types | All events where `eventSource` is NOT `FIM`, `FILE`, `FILE_CHANGE`, or `FILE CHANGE` |

---

### 12. FIM (File Integrity Monitoring)

FIM events are also fetched through the unified IOC events endpoint.

#### FIM Events (Filtered)

| Property | Value |
|----------|-------|
| Function | `_fetch_fim_events_raw(limit=100, days=7, host='')` |
| Mechanism | Calls `_fetch_ioc_events(limit * 3)` and keeps only FIM event types |
| FIM types | Events where `eventSource` is `FIM`, `FILE`, `FILE_CHANGE`, or `FILE CHANGE` |

---

### 13. Scanners & Scans

Scanner and scan management use classic APIs at `BASE_URL` with Basic Auth. Responses are XML.

#### List Scanner Appliances

| Property | Value |
|----------|-------|
| Function | `get_scanner_list()` |
| URL | `GET {BASE_URL}/api/2.0/fo/appliance/?action=list&output_mode=full` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 30 seconds |
| Cache | L1: in-memory, 5-minute TTL. L2: SQLite disk, 12-hour TTL (`CACHE_TTL_SCANNERS`) |

**Parsed fields:**

| Field | XML Path |
|-------|----------|
| ID | `APPLIANCE/ID` |
| Name | `APPLIANCE/NAME` |
| Status | `APPLIANCE/STATUS` |
| Type | `APPLIANCE/TYPE` |
| Model | `APPLIANCE/MODEL_NUMBER` |
| Running Scan Count | `APPLIANCE/RUNNING_SCAN_COUNT` |
| Running Slices | `APPLIANCE/RUNNING_SLICES_COUNT` |
| Max Capacity | `APPLIANCE/MAX_CAPACITY_UNITS` |
| Heartbeats Missed | `APPLIANCE/HEARTBEATS_MISSED` |
| Software Version | `APPLIANCE/SOFTWARE_VERSION` |
| VulnSigs Version | `APPLIANCE/VULNSIGS_VERSION` |
| VulnSigs Latest | `APPLIANCE/VULNSIGS_LATEST` |
| Last Updated | `APPLIANCE/LAST_UPDATED_DATE` |
| SS Connection | `APPLIANCE/SS_CONNECTION` |
| SS Last Connected | `APPLIANCE/SS_LAST_CONNECTED` |

#### List Scans

| Property | Value |
|----------|-------|
| Function | `get_scan_list(states='Running,Paused,Queued,Error,Finished', limit=100)` |
| URL | `GET {BASE_URL}/api/2.0/fo/scan/?action=list&state={states}&show_status=1` |
| Auth | Basic Auth |
| Response | XML |
| Timeout | 30 seconds |

**Parsed fields:**

| Field | XML Path |
|-------|----------|
| Ref | `SCAN/REF` |
| Title | `SCAN/TITLE` |
| State | `SCAN/STATUS/STATE` |
| Type | `SCAN/TYPE` |
| Target | `SCAN/TARGET` (truncated to 200 chars) |
| Launched | `SCAN/LAUNCH_DATETIME` |
| Duration | `SCAN/DURATION` |
| Scanner Name | `SCAN/SCANNER_APPLIANCE/FRIENDLY_NAME` |

---

## Pagination Patterns

qualys-mcp implements three distinct pagination strategies depending on the API.

### 1. XML `id_min` Pagination (VMDR Detections)

Used by: `get_detections()`

The VMDR detection API signals truncation via WARNING CODE 1980 in the XML response. When detected:

1. Extract the maximum `HOST/ID` from the current page
2. Set `id_min = max_host_id + 1` for the next request
3. Continue until no truncation warning or `max_host_id == 0`

```
Page 1: /api/2.0/fo/asset/host/vm/detection/?action=list&severities=5...
Page 2: ...&id_min=10001
Page 3: ...&id_min=20001
```

Safety cap: `MAX_PAGES` env var (default 0 = unlimited).

### 2. Cursor-Based Pagination (CSAM)

Used by: `csam_search()`, `fetch_all_eol()`

CSAM uses `lastSeenAssetId` as a cursor. The response includes `hasMore: true/false`.

```
Page 1: /rest/2.0/search/am/asset?pageSize=100
Page 2: ...&lastSeenAssetId=abc-123
Page 3: ...&lastSeenAssetId=def-456
```

### 3. JSON `pageNumber`/`pageSize` Pagination (Generic)

Used by: Container Security, CertView, CDR, CloudView evaluations

The generic `_paginate_json()` helper handles this pattern:

```
Page 1: ?pageSize=100&pageNumber=1
Page 2: ?pageSize=100&pageNumber=2
```

Stops when: batch is empty, batch size < page size, or page cap reached.

**Variant: 0-based `pageNo`/`pageSize`** (CloudView connectors & evaluations):

```
Page 1: ?pageSize=100&pageNo=0
Page 2: ?pageSize=100&pageNo=1
```

The `_paginate_json()` function accepts `page_start` (0 or 1), `page_param`, and `size_param` to handle both variants.

### Pagination Safety

All pagination loops respect `MAX_PAGES` (env var `QUALYS_MAX_PAGES`, default 0 = unlimited):

```python
MAX_PAGES = int(os.environ.get('QUALYS_MAX_PAGES', '0'))
```

---

## Rate Limiting & Retry Logic

### General Retry Strategy (`api_get`)

| Property | Value |
|----------|-------|
| Retryable status codes | 429, 502, 503 |
| Max retries | 4 (`MAX_RETRIES`) |
| Backoff | Exponential: `2^attempt + random(0, 1)` seconds |
| Retry-After header | Honored when present (overrides exponential backoff) |

### KB Conflict Retry (409)

| Property | Value |
|----------|-------|
| Trigger | HTTP 409 (Knowledge Base export busy) |
| Max retries | 3 (`KB_CONFLICT_MAX_RETRIES`) |
| Base delay | 3 seconds + random(0, 2) |
| Sentinel | Returns `'KB_BUSY'` string after exhausting retries |

### CSAM-Specific Retry (`_csam_request`)

| Property | Value |
|----------|-------|
| Retryable status codes | 429, 502, 503 |
| Max retries | 3 (default, configurable via `CSAM_MAX_RETRIES` env var) |
| Backoff | Same exponential with Retry-After support |
| Concurrency limiter | Semaphore limiting to 4 concurrent requests (`CSAM_MAX_CONCURRENT` env var) |
| Degraded response | Returns `{"_degraded": True, "_message": "..."}` after exhausting retries |

### ETM Retry

| Property | Value |
|----------|-------|
| No automatic retry | ETM uses `etm_api()` which does not retry |
| 401 handling | Returns `ETM_401_SENTINEL` (subscription not available) |
| 404 handling | Returns `None` |

### Special Handling

| Status Code | Behavior |
|-------------|----------|
| 404 | Returns `None` when `not_found_ok=True` (treats as empty, not error) |
| 500 | Returns `server_error_sentinel` value when configured (e.g., CDR returns `'CDR_UNAVAILABLE'`) |

---

## Caching Strategy

qualys-mcp implements a two-tier cache architecture to minimize API calls and provide fast responses.

### L1: In-Memory Cache

Volatile, per-process. Cleared on restart.

| Cache | Key Pattern | TTL | Notes |
|-------|------------|-----|-------|
| `DETECTION_CACHE` | `detections_{severity}_{days}_{qds_min}` | 30 min (`VMDR_CACHE_TTL`) | Env override: `VMDR_CACHE_TTL_SECONDS` |
| `KB_CACHE` | QID (integer) | 1 hour (3600s) | Per-entry TTL |
| `QDS_CACHE` | QID (integer) | 30 min (`VMDR_CACHE_TTL`) | Bulk invalidation |
| `WAS_CACHE` | `was_{limit}_{severity}_{days}_{app_name}` | 10 min (600s) | Per-key TTL |
| `SCANNER_CACHE` | Singleton | 5 min (300s) | Single list |
| `ETM_RESULT_CACHE` | Singleton | 1 hour (3600s) | Single result dict |
| `_CSAM_COUNT_CACHE` | JSON-serialized filters | 5 min (300s) | Count-only cache |
| `_CSAM_SEARCH_CACHE` | JSON-serialized params | 5 min (300s) | Search result cache |

### L2: SQLite Disk Cache

Persistent across restarts. Stored at `~/.cache/qualys-mcp/cache.db` (configurable via `QUALYS_MCP_CACHE_DIR`).

| Data Type | Default TTL | Env Override |
|-----------|------------|--------------|
| VMDR detections | 4 hours | `CACHE_TTL_VMDR` |
| CSAM assets | 6 hours | `CACHE_TTL_CSAM` |
| Certificates | 12 hours | `CACHE_TTL_CERTS` |
| Cloud data | 6 hours | `CACHE_TTL_CLOUD` |
| Patches | 1 hour | `CACHE_TTL_PATCH` |
| Compliance | 1 hour | `CACHE_TTL_COMPLIANCE` |
| Scanners | 12 hours | `CACHE_TTL_SCANNERS` |
| WAS findings | 4 hours | `CACHE_TTL_WAS` |
| ETM data | 2 hours | `CACHE_TTL_ETM` |
| Containers | 6 hours | `CACHE_TTL_CONTAINERS` |
| Default | 4 hours | `CACHE_TTL_DEFAULT` |

### Cache Lookup Flow

```
Request → L1 memory check → L2 disk check → API fetch → store in L1 + L2
```

The `_get_or_fetch()` helper provides:
- Thread-safe access via `_inflight_lock`
- In-flight request deduplication (concurrent callers for the same key wait on a `threading.Event` instead of issuing duplicate API calls)
- Automatic L2 write-through after successful fetch

### Cache Warm-Up

On startup, a background thread (`_warmup_vmdr_cache`) pre-fetches VMDR detections for severities 5, 4, and 3 (30-day window). It checks L2 disk cache first and only hits the API on cache miss.

### Cache Invalidation

`clear_memory_cache(key=None)` clears all L1 caches (or a specific key). L2 entries expire naturally based on their TTL.

---

## SSL & Network Configuration

| Env Variable | Description | Default |
|-------------|-------------|---------|
| `QUALYS_SSL_VERIFY` | Set to `0`, `false`, or `no` to disable SSL verification | SSL verification enabled |

When SSL verification is disabled, a custom `ssl.SSLContext` is created with `check_hostname = False` and `verify_mode = CERT_NONE`. This context is passed to all `urlopen()` calls.

### Timeouts

| Operation | Default Timeout |
|-----------|----------------|
| Bearer token auth | 30 seconds |
| General API calls | 30 seconds |
| VMDR detections (bulk) | 180 seconds |
| VMDR detections (per host) | 120 seconds |
| KB batch lookups | 60 seconds |
| WAS findings | 60 seconds |
| ETM API calls | 60 seconds |
| CSAM count | 15 seconds |
| CSAM search | 30 seconds |
| Policy compliance | 60-120 seconds |

### Performance Logging

Opt-in via `MCP_PERF_LOG` env var (set to a file path). Logs JSONL entries for `api_call` and `cache_hit`/`cache_miss` events with timestamps and provider attribution.
