# Qualys MCP — Architecture Design Doc

## Router, Cache, and Concurrency

---

## 1. Current Architecture Overview

```
AI Assistant
    │
    ▼ MCP tool call (one at a time)
FastMCP (qualys_mcp.py)
    │
    ├── 19 @mcp.tool() functions
    │     └── Each calls: api_get(), csam_search(), etm_api(), etc.
    │
    ├── _run_concurrent() — ThreadPoolExecutor(max_workers=8)
    │     Used in: get_morning_report, get_weekly_priorities,
    │              get_security_posture, get_patch_status,
    │              get_image_vulns, get_tech_debt (6/19 tools)
    │
    └── In-memory caches:
          BEARER_TOKEN — 3.5h TTL (good)
          DETECTION_CACHE — 5-min TTL, keyed by severity_limit_qds
          QDS_CACHE — 5-min TTL
          KB_CACHE — no TTL (grows unbounded)
```

---

## 2. Problems with Current Architecture

### 2.1 Cache Problems

| Problem | Impact | Tool Affected |
|---------|--------|---------------|
| Detection cache keyed by `severity_limit_qds` | Cache miss if you call with limit=10 vs limit=20 | get_detections |
| KB_CACHE has no TTL | Could serve 24h+ stale data after KB update | All KB-backed tools |
| ETM reports not cached | Every `get_etm_findings()` call re-polls or re-creates the report | get_etm_findings |
| WAS results not cached | Each call to get_webapp_vulns re-fetches WAS findings | get_webapp_vulns |
| Scanner list not cached | get_scanner_health fetches fresh on every call | get_scanner_health |
| PM jobs not cached | Each get_eliminate_status fetches fresh | get_eliminate_status |

### 2.2 Concurrency Gaps

| Tool | Issue |
|------|-------|
| `get_cloud_risk` | Sequential loop over AWS/Azure/GCP connectors (could be parallel) |
| `get_cloud_risk` | Sequential loop over evaluations for each account |
| `get_asset` | Sequential: CSAM lookup → host detections → software parsing |
| `get_tech_debt` | ✅ Already concurrent (os + hardware parallel) |
| `get_recommendations` | Sequential connector loops |
| `get_security_posture` | Sequential cloud connector loops |
| `get_etm_findings` | Sequential: report list → detail → download |
| `get_patch_status` | ✅ Already concurrent |
| `get_eliminate_status` | ✅ Already concurrent |
| `get_morning_report` | ✅ Already concurrent |

### 2.3 No Tool Router

The LLM picks tools based on docstrings. For ambiguous questions like "show me what happened this week" the LLM must guess between `get_morning_report`, `get_new_vulns`, `get_weekly_priorities`. No meta-tool exists to route or aggregate multi-source answers. Consolidated tools with parameter-based routing (e.g., `get_asset` with `detail` param) reduce tool count and improve selection accuracy.

---

## 3. Cache Architecture Redesign

### 3.1 Tiered Cache Design

```python
# Proposed cache tier structure
CACHE = {
    # L1 — Hot: 5-minute TTL (volatile operational data)
    'detections':   {'data': None, 'ts': None, 'ttl': 300},
    'qds_scores':   {'data': {}, 'ts': None, 'ttl': 300},
    'scanner_list': {'data': None, 'ts': None, 'ttl': 300},
    'was_findings': {'data': None, 'ts': None, 'ttl': 600},  # 10 min

    # L2 — Warm: 1-hour TTL (slow-changing reference data)
    'kb_entries':    {'data': {}, 'ts': None, 'ttl': 3600},
    'etm_report':   {'data': None, 'ts': None, 'ttl': 3600},
    'pm_jobs':      {'data': None, 'ts': None, 'ttl': 3600},
    'cloud_conns':  {'data': None, 'ts': None, 'ttl': 3600},
    'cloud_evals':  {'data': {}, 'ts': None, 'ttl': 1800},  # 30 min

    # L3 — Cold: 3.5h TTL (auth/token)
    'bearer_token': {'data': None, 'ts': None, 'ttl': 12600},
}

CACHE_LOCK = {}  # Per-key locks for request deduplication

def _cache_get(key: str):
    """Get from cache if not expired. Returns (hit: bool, data)."""
    entry = CACHE.get(key)
    if not entry or entry['data'] is None or entry['ts'] is None:
        return False, None
    age = (datetime.now(timezone.utc) - entry['ts']).total_seconds()
    if age > entry['ttl']:
        return False, None
    return True, entry['data']

def _cache_set(key: str, data, ttl: int = None):
    """Set cache entry with optional TTL override."""
    if key not in CACHE:
        CACHE[key] = {'data': None, 'ts': None, 'ttl': ttl or 300}
    CACHE[key]['data'] = data
    CACHE[key]['ts'] = datetime.now(timezone.utc)
    if ttl:
        CACHE[key]['ttl'] = ttl
```

### 3.2 Request Deduplication

Extend the `AUTH_LOCK` pattern to all expensive calls:

```python
FETCH_LOCKS = {}  # key → threading.Lock()

def _get_or_fetch(cache_key: str, fetch_fn, ttl: int = 300):
    """Get from cache or fetch with request deduplication.
    
    If two threads request the same uncached key simultaneously,
    only one will fetch — the other waits and gets the result.
    
    Pattern: used for VMDR detections, ETM reports, WAS findings.
    """
    # Fast path — cache hit, no lock needed
    hit, data = _cache_get(cache_key)
    if hit:
        return data

    # Slow path — need to fetch, serialize with per-key lock
    if cache_key not in FETCH_LOCKS:
        FETCH_LOCKS[cache_key] = Lock()

    with FETCH_LOCKS[cache_key]:
        # Double-check after acquiring lock
        hit, data = _cache_get(cache_key)
        if hit:
            return data

        # Actually fetch
        data = fetch_fn()
        if data is not None:
            _cache_set(cache_key, data, ttl)
        return data
```

### 3.3 Detection Cache Key Fix

Current: `f"{severity}_{limit}_{qds_min}"` — causes cache misses for different limit values.

**Fix:** Always fetch the maximum (limit=500 or per-environment default) and slice at response time:

```python
def get_detections(severity=5, limit=200, use_cache=True, days=30, qds_min=0):
    # Cache by severity+days+qds_min only (not limit)
    cache_key = f"detections_{severity}_{days}_{qds_min}"
    
    def _fetch():
        # Always fetch max; slice at return time
        url = (f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
               f"&severities={severity}&truncation_limit=500&status=Active"
               f"&show_qds=1&filter_superseded_qids=1"
               f"&vm_processed_after={after_date}")
        ...
    
    all_dets = _get_or_fetch(cache_key, _fetch, ttl=300)
    return all_dets[:limit] if all_dets else []
```

### 3.4 ETM Report Cache

```python
ETM_REPORT_CACHE = {}   # report_id → {'data': [...], 'ts': datetime, 'ttl': 3600}
ETM_LATEST_LOCK = Lock()

def get_etm_report_cached():
    """Get latest ETM report, using 1-hour cache for completed reports.
    
    If no completed report exists, create one and return immediately
    with a status='pending' flag (async pattern).
    """
    # Check for cached completed report
    hit, data = _cache_get('etm_latest')
    if hit:
        return data, True  # (data, from_cache)
    
    with ETM_LATEST_LOCK:
        hit, data = _cache_get('etm_latest')
        if hit:
            return data, True
        
        # Fetch latest completed report
        reports = etm_api('POST', '/etm/api/rest/v1/reports/list', {'pageSize': 50})
        for r in (reports or {}).get('data', []):
            if r.get('status') == 'COMPLETED':
                detail = etm_api('GET', f'/etm/api/rest/v1/reports/{r["id"]}')
                if detail:
                    _cache_set('etm_latest', detail, ttl=3600)
                    return detail, False
        
        return None, False
```

### 3.5 Background Pre-Fetch on Startup

Pre-warm the cache when the MCP server starts, so the first real query is fast:

```python
import threading

def _background_prefetch():
    """Pre-warm cache for highest-frequency data on server startup."""
    _log("Starting background cache pre-fetch...")
    
    def _warm():
        try:
            # Token first (needed for all other calls)
            get_bearer_token()
            _log("Bearer token warmed")
            
            # CSAM counts are fast and used by many tools
            csam_count()
            csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}])
            _log("CSAM counts warmed")
            
            # ETM latest report
            etm_api('POST', '/etm/api/rest/v1/reports/list', {'pageSize': 10})
            _log("ETM report list warmed")
            
            # Scanner list
            get_scanner_list()
            _log("Scanner list warmed")
            
        except Exception as e:
            _log(f"Background prefetch error: {e}")
    
    t = threading.Thread(target=_warm, daemon=True)
    t.start()

# Call at module load time (after all functions defined)
# _background_prefetch()  # Uncomment to enable
```

**Note:** Background prefetch adds ~5s of startup overhead. Recommend enabling only in persistent/long-running server deployments, not `uvx` ephemeral sessions.

---

## 4. Concurrency Audit and Fixes

### 4.1 `get_cloud_risk` — Major Concurrency Gap

**Current:** Sequential loop over providers → sequential evaluation fetch
```python
# CURRENT (sequential — ~15s for 3 providers)
for p in ['aws', 'azure', 'gcp']:
    for c in get_connectors(p, 50):
        acc = ...
        result['accounts'].append(...)

if result['accounts']:
    acc = result['accounts'][0]
    for e in get_evaluations(acc['id'], acc['provider'].lower(), 500):
        ...
```

**Fix:** Parallel provider fetches
```python
# PROPOSED (parallel — ~5s)
concurrent = _run_concurrent(
    aws_conn=lambda: get_connectors('aws', 50),
    azure_conn=lambda: get_connectors('azure', 50),
    gcp_conn=lambda: get_connectors('gcp', 50),
)

# Gather all accounts from parallel results
all_accounts = []
for provider, conns in [('AWS', concurrent['aws_conn']),
                         ('AZURE', concurrent['azure_conn']),
                         ('GCP', concurrent['gcp_conn'])]:
    for c in (conns or []):
        acc_id = c.get('awsAccountId') or c.get('azureSubscriptionId') or c.get('gcpProjectId')
        if acc_id:
            all_accounts.append({'id': acc_id, 'provider': provider.lower()})

# Parallel evaluation fetches for first account per provider
eval_tasks = {f"eval_{a['provider']}": lambda p=a: get_evaluations(p['id'], p['provider'], 500)
              for a in all_accounts[:3]}
eval_results = _run_concurrent(**eval_tasks) if eval_tasks else {}
```

**Estimated speedup:** 15s → 5s (3x)

### 4.2 `get_asset` — Sequential Calls

**Current:**
```python
# CURRENT (sequential — ~4s)
asset = get_asset_by_id(asset_id)       # ~1s CSAM
dets = get_host_detections(host_id)     # ~2s VMDR (only called if we need detections)
```

**The tool is actually fast for its current scope** — it doesn't call `get_host_detections` (checking the code). But `get_asset(detail="full")` should parallelize:
```python
concurrent = _run_concurrent(
    asset=lambda: get_asset_by_id(asset_id),
    detections=lambda: get_host_detections(asset_id),
    was=lambda: get_was_findings_for_asset(asset_id),
)
```

### 4.3 `get_recommendations` — Sequential Cloud Loops

**Current:** Same sequential connector loop as `get_cloud_risk`.

**Fix:** Apply same parallel provider pattern.

### 4.4 Tools Already Using Concurrency Correctly ✅

- `get_morning_report` — 6 parallel calls
- `get_weekly_priorities` — 9 parallel calls
- `get_security_posture` — 10 parallel calls
- `get_patch_status` — concurrent
- `get_eliminate_status` — concurrent
- `get_image_vulns` — 2 parallel calls (image details + vulns)
- `get_tech_debt` — OS + hardware parallel

---

## 5. Router / Coordinator Tool Design

### 5.1 Intent Classification

Rather than a full router tool (which would add latency), the better approach is **rich docstrings with routing hints** that help the LLM pick correctly.

**Current docstring pattern:**
```python
"""[Risk Management] Weekly top risks..."""
```

**Enhanced docstring pattern:**
```python
"""[Risk Management] Weekly top risks...
Use when asked: 'what should we fix this week', 'top vulnerabilities', 'prioritize',
'what are our biggest risks', 'what to patch first'
NOT for: single CVE lookups (use investigate_cve), morning updates (use get_morning_report)
"""
```

### 5.2 Meta-Aggregator Tools

Some questions genuinely need data from multiple tools. Three aggregator tools are worth implementing:

#### `get_asset(asset_id, detail="full")`
Combines CSAM + VMDR + ETM for a single asset (when detail="full"):
```python
concurrent = _run_concurrent(
    csam=lambda: get_asset_by_id(asset_id),
    detections=lambda: get_host_detections(asset_id, severity=3),
    etm=lambda: get_etm_findings.fn(qql=f"asset.id:{asset_id}"),
)
```

Returns: asset metadata + vulnerability list + risk score + software inventory + patch status. With detail="summary" (default), returns only CSAM risk data.

#### `get_morning_report(quick=True)`
Fast cross-module summary (~3s, all CSAM + cached):
```python
concurrent = _run_concurrent(
    total=lambda: csam_count(),
    high_risk=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
    eol=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
    cloud=lambda: get_connectors('aws', 1),
    images=lambda: get_images(10, 5),
)
```

Returns: asset count, risk distribution, EOL count, cloud accounts, critical images

#### `get_risk_by_tag(tag)`
All risk data filtered to a specific asset tag:
```python
filters = [{"field": "tags.name", "operator": "EQUALS", "value": tag}]
concurrent = _run_concurrent(
    count=lambda: csam_count(filters),
    high_risk=lambda: csam_count(filters + [{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
    assets=lambda: csam_search(filters, limit=20),
    eol=lambda: csam_count(filters + [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
)
```

Returns: count, risk distribution, top assets with risk scores, EOL count for the tag group

---

## 6. QQL Helper in Tool Descriptions

The current `get_etm_findings` docstring mentions QQL briefly. Enhance it with concrete examples:

```python
@mcp.tool()
def get_etm_findings(qql: str = "", report_id: str = "") -> dict:
    """[ETM] Confirmed vulnerability findings from Enterprise TruRisk Management.
    
    QQL filter examples:
      vulnerabilities.vulnerability.cveIds:CVE-2021-44228   (Log4Shell)
      vulnerabilities.vulnerability.severity:5              (Critical only)
      asset.tags.name:'Production'                          (Production assets)
      (vulnerabilities.isRansomware:true AND vulnerabilities.status:ACTIVE)
      (asset.truRisk>700 AND vulnerabilities.vulnerability.isPatchAvailable:true)
      vulnerabilities.firstFound>2024-01-01                 (Detected after date)
      asset.operatingSystem:Windows                         (Windows assets)
    
    Combine conditions: (condA AND condB), (condA OR condB), NOT condA
    """
```

---

## 7. Performance Architecture

### 7.1 Response Time Budget

For a 10-second total target:

| Phase | Budget | What happens |
|-------|--------|--------------|
| Token check | 0ms | Memory lookup |
| Parallel API calls | 3–8s | Actual Qualys API calls |
| Data processing | <0.5s | XML/JSON parsing, sorting |
| Response assembly | <0.1s | Dict construction |

### 7.2 Bottleneck Priority

1. **VMDR classic API (~2min)** — Use ETM instead for all detection queries. ETM cached reports return in <1s.
2. **ETM report creation (~1–5min)** — Always cache the last completed report (1h TTL). For new environments, return `status: 'warming'` and background-create the report.
3. **Cloud evaluation loops (~10s)** — Parallelize provider fetches (fix in §4.1).
4. **WAS findings (~unknown)** — Add 10-min cache to `get_webapp_vulns`.

### 7.3 VMDR → ETM Migration Strategy

VMDR classic is slow but ETM covers the same data. When ETM is available, prefer it:

```python
def get_detections_smart(severity=4, limit=200):
    """Get detections via ETM (fast, cached) or VMDR classic (slow fallback)."""
    # Try ETM first — much faster
    etm_result = get_etm_findings.fn(qql=f"vulnerabilities.vulnerability.severity:{severity}")
    if etm_result and etm_result.get('findings'):
        return _convert_etm_to_detection_format(etm_result['findings'])
    
    # Fall back to VMDR classic (slow, ~2min)
    _log("ETM not available, falling back to VMDR classic (slow)")
    return get_detections(severity, limit)
```

---

## 8. Implementation Priorities

| Priority | Change | Impact | Effort |
|----------|--------|--------|--------|
| 🔴 P1 | Fix detection cache key (remove `limit` from key) | Eliminates redundant VMDR calls | 30 min |
| 🔴 P1 | Add KB_CACHE TTL (1h) | Prevents stale KB data | 30 min |
| 🔴 P1 | Cache WAS findings (10 min) | Makes get_webapp_vulns fast | 1h |
| 🔴 P1 | Cache ETM report result (1h) | Makes get_etm_findings instant | 2h |
| 🟡 P2 | Parallelize get_cloud_risk | 3x speedup | 2h |
| 🟡 P2 | Parallelize get_recommendations | 2x speedup | 1h |
| 🟡 P2 | Add _get_or_fetch() deduplication helper | Prevent duplicate parallel requests | 2h |
| 🟢 P3 | Enhanced docstrings with routing hints | Better LLM tool selection | 2h |
| 🟢 P3 | get_asset(detail="full") aggregator mode | Better single-asset UX | 4h |
| 🟢 P3 | Background pre-fetch on startup | <2s first query | 2h |
| 🟢 P3 | benchmark.py script | Measure improvements | 2h |
