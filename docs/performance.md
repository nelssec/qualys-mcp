# Qualys MCP — Performance Analysis

## Current Benchmarks, Targets, and Improvement Plan

---

## 1. API Latency Baseline

| API / Endpoint | Typical Latency | Notes |
|----------------|-----------------|-------|
| CSAM v2 count | 0.2–0.5s | Fast JSON API |
| CSAM v2 search (100 assets) | 0.5–3s | Depends on result set |
| VMDR detection list | 60–180s | XML, slow for >200 hosts |
| VMDR KB lookup (single QID) | 0.5–1s | |
| VMDR KB lookup (50 QIDs) | 2–4s | |
| VMDR KB published_after | 2–5s | Depends on date range |
| ETM report list | 0.5–2s | |
| ETM report detail | 1–3s | |
| ETM report create (async) | 60–300s | Creates; must poll for completion |
| ETM report download | 1–5s | After it's ready |
| WAS findings | 5–30s | Depends on finding count |
| Bearer token refresh | 1–2s | 3.5h cache |
| Container images list | 1–3s | |
| TotalCloud connectors | 0.5–2s per provider | |
| TotalCloud evaluations | 2–8s per account | |
| CDR findings | 1–5s | |
| PM jobs | 1–3s | |
| Scanner appliance list | 1–3s | XML |
| FIM events | 1–5s | |
| EDR events | 1–5s | |
| CertView certificates | 1–5s | |

---

## 2. Current Tool Latencies (Estimated)

### Cold cache (first call), warm cache (subsequent within TTL)

| Tool | Cold Estimate | Warm Estimate | Notes |
|------|--------------|---------------|-------|
| `get_morning_report` | 8–15s | 3–5s | 6 concurrent calls |
| `get_weekly_priorities` | 5–10s | 1–2s | 9 parallel CSAM calls |
| `get_security_posture` | 8–15s | 1–2s | 10 parallel calls |
| `get_patch_status` | 5–10s | 1–2s | Mixed concurrent |
| `get_threat_intel` | 5–30s | 5–30s | VMDR detection (no cache hit if params differ) |
| `get_new_vulns` | 3–8s | 3–8s | KB API, no cache |
| `investigate_cve` | 8–20s | 3–5s | KB + CSAM + QDS concurrent |
| `get_cve_details` | 10–30s | 3–5s | Multi-CVE KB lookups |
| `get_qid_details` | 3–8s | 0.1s | KB cache |
| `get_vulns_by_software` | 3–8s | 3–8s | KB API, no cache |
| `get_asset` | 2–5s | 0.5s | CSAM (cached by asset) |
| `get_tech_debt` | 15–60s | 5–10s | Paginated CSAM |
| `get_cloud_risk` | 15–30s | 5–10s | Sequential provider loops ⚠️ |
| `get_cloud_risk` (threats) | 2–8s | 2–8s | No cache |
| `get_image_vulns` | 2–6s | 2–6s | No cache |
| `get_etm_findings` | 5–300s | 5–10s | Depends on report existence |
| `get_scanner_health` | 3–8s | 3–8s | No cache |
| `get_eliminate_status` | 5–15s | 2–5s | Concurrent PM+MTG calls |
| `get_recommendations` | 15–30s | 5–10s | Sequential cloud loops ⚠️ |

**⚠️ = known performance problems**

---

## 3. Performance Targets

| Query Type | Cold Target | Warm Target | Current Status |
|------------|-------------|-------------|----------------|
| Asset count / posture | < 3s | < 0.5s | ✅ 0.2–3s |
| Single CVE lookup | < 5s | < 1s | ✅ ~8s cold → fix cache |
| Weekly priorities | < 8s | < 1s | ✅ 5–10s |
| Morning report | < 15s | < 2s | ✅ 8–15s |
| ETM findings (cached) | < 3s | < 1s | ⚠️ 5–10s → add cache |
| ETM findings (new) | Return async | — | ⚠️ blocks for 5 min |
| VMDR detections | < 30s first | < 0.5s cached | ⚠️ 60–180s |
| Cloud risk | < 8s | < 2s | ⚠️ 15–30s → parallelize |
| WAS findings | < 10s | < 2s | ❓ unknown → add cache |
| Scanner health | < 5s | < 1s | ⚠️ no cache → add |
| Asset full profile (`get_asset` detail=full) | < 8s | < 2s | 📋 not yet built |
| Tech debt | < 30s | < 5s | ✅ (paginated correctly) |

---

## 4. Improvement Plan

### Phase 1: Cache Fixes (~1 day, 3–5x speedup for repeat queries)

#### 4.1 Fix Detection Cache Key
**Problem:** `cache_key = f"{severity}_{limit}_{qds_min}"` causes cache misses.
**Fix:** Remove `limit` from cache key; always fetch max, slice at return time.

```python
# Before
cache_key = f"{severity}_{limit}_{qds_min}"

# After
cache_key = f"detections_{severity}_{days}_{qds_min}"
# Always fetch 500, return dets[:limit]
```

**Impact:** Tools that call `get_detections` with different `limit` values now share cached data.

#### 4.2 Add KB_CACHE TTL
**Problem:** KB_CACHE grows unbounded, can return 24h+ stale data.

```python
KB_CACHE_TIME = {}  # qid → datetime

def _kb_cache_get(qid):
    if qid not in KB_CACHE:
        return None
    ts = KB_CACHE_TIME.get(qid)
    if ts and (datetime.now(timezone.utc) - ts).total_seconds() > 3600:
        del KB_CACHE[qid]
        del KB_CACHE_TIME[qid]
        return None
    return KB_CACHE[qid]

def _kb_cache_set(qid, data):
    KB_CACHE[qid] = data
    KB_CACHE_TIME[qid] = datetime.now(timezone.utc)
```

**Impact:** Prevents serving stale vulnerability data after Qualys KB updates.

#### 4.3 Add WAS Findings Cache
**Problem:** `get_webapp_vulns` re-fetches on every call.

```python
WAS_CACHE = {}
WAS_CACHE_TIME = None
WAS_CACHE_TTL = 600  # 10 minutes

def get_was_findings(limit=100, severity=None):
    global WAS_CACHE, WAS_CACHE_TIME
    cache_key = f"was_{severity}_{limit}"
    now = datetime.now(timezone.utc)
    
    if (WAS_CACHE_TIME and (now - WAS_CACHE_TIME).total_seconds() < WAS_CACHE_TTL 
            and cache_key in WAS_CACHE):
        return WAS_CACHE[cache_key]
    
    # ... fetch ...
    WAS_CACHE[cache_key] = findings
    WAS_CACHE_TIME = now
    return findings
```

**Impact:** Repeat WAS queries become instant (<0.1s).

#### 4.4 Cache ETM Report Result
**Problem:** `get_etm_findings` blocks up to 5 minutes waiting for a new report.

```python
ETM_RESULT_CACHE = None
ETM_RESULT_CACHE_TIME = None
ETM_RESULT_CACHE_TTL = 3600  # 1 hour

def _get_cached_etm_report():
    global ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    now = datetime.now(timezone.utc)
    if (ETM_RESULT_CACHE is not None and ETM_RESULT_CACHE_TIME
            and (now - ETM_RESULT_CACHE_TIME).total_seconds() < ETM_RESULT_CACHE_TTL):
        return ETM_RESULT_CACHE, True  # (data, from_cache)
    return None, False

# In get_etm_findings:
# 1. Check cache first → return immediately if hit
# 2. If QQL provided → create new report (don't cache QQL-filtered results)
# 3. If no QQL → try cache, then latest completed report, then create new
# 4. Return immediately with status='creating' if report is still running
```

**Impact:** Repeated ETM queries go from 5–10s to <0.5s. Initial call still async.

#### 4.5 Add Scanner List Cache
```python
SCANNER_CACHE = None
SCANNER_CACHE_TIME = None

def get_scanner_list():
    global SCANNER_CACHE, SCANNER_CACHE_TIME
    now = datetime.now(timezone.utc)
    if (SCANNER_CACHE and SCANNER_CACHE_TIME 
            and (now - SCANNER_CACHE_TIME).total_seconds() < 300):
        return SCANNER_CACHE
    # ... fetch XML ...
    SCANNER_CACHE = scanners
    SCANNER_CACHE_TIME = now
    return scanners
```

### Phase 2: Concurrency Fixes (~1 day, 2–3x speedup for cloud tools)

#### 4.5 Parallelize `get_cloud_risk`

Replace sequential provider loop with `_run_concurrent`:

```python
# Before: sequential ~15–30s
for p in ['aws', 'azure', 'gcp']:
    for c in get_connectors(p, 50):
        ...

# After: parallel ~5–8s
conn_results = _run_concurrent(
    aws=lambda: get_connectors('aws', 50),
    azure=lambda: get_connectors('azure', 50),
    gcp=lambda: get_connectors('gcp', 50),
)
```

#### 4.6 Parallelize `get_recommendations`
Same pattern as `get_cloud_risk` — sequential cloud loops become parallel.

### Phase 3: Advanced Features (~2 days)

#### 4.7 Request Deduplication (`_get_or_fetch`)
Prevents two simultaneous tool calls from making duplicate expensive requests.
See `docs/architecture.md §3.2` for implementation.

#### 4.8 ETM Async Pattern
For uncached reports, return immediately with a `status: 'creating'` response
instead of blocking for 5 minutes.

```python
# Proposed ETM response for new report
{
    "status": "creating",
    "message": "ETM report is being generated. Call again in 2-3 minutes for results.",
    "reportId": "abc123",
    "estimatedReadyAt": "2024-01-20T10:25:00Z"
}
```

#### 4.9 Background Pre-fetch
Fire cache warming on startup. See `docs/architecture.md §3.5`.

---

## 5. Benchmark Script

`benchmark.py` — measures actual latency for every tool call.

### Design

```python
#!/usr/bin/env python3
"""
Qualys MCP Benchmark — measures tool latency cold and warm.

Usage:
    python benchmark.py              # Run all benchmarks
    python benchmark.py --tool get_morning_report  # Single tool
    python benchmark.py --csv results.csv           # Save CSV

Requires: QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL, QUALYS_GATEWAY_URL
"""

import time
import json
import sys
import os

# Add parent dir to path so we can import qualys_mcp directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qualys_mcp

BENCHMARKS = [
    # (tool_name, args, description)
    ("get_security_posture", {}, "Security posture (CSAM-heavy, concurrent)"),
    ("get_weekly_priorities", {"limit": 10}, "Weekly priorities (9 parallel CSAM)"),
    ("get_new_vulns", {"days": 7}, "New vulns (KB API)"),
    ("get_threat_intel", {"threat_type": "Ransomware"}, "Threat intel (VMDR)"),
    ("get_patch_status", {"limit": 10}, "Patch status"),
    ("get_scanner_health", {}, "Scanner health (appliance XML)"),
    ("get_etm_findings", {}, "ETM findings (report API)"),
    ("get_cloud_risk", {}, "Cloud risk (sequential providers)"),
    ("get_cloud_risk", {"include_threats": True, "days": 7}, "Cloud threats (CDR findings)"),
    ("get_morning_report", {}, "Morning report (multi-concurrent)"),
    ("get_tech_debt", {"limit": 20}, "Tech debt (paginated CSAM)"),
    ("investigate_cve", {"cve": "CVE-2021-44228"}, "CVE investigation"),
]

def run_benchmark(tool_name, args, description, runs=2):
    tool_fn = getattr(qualys_mcp, tool_name, None)
    if tool_fn is None:
        return None
    
    times = []
    errors = []
    
    for i in range(runs):
        start = time.perf_counter()
        try:
            if hasattr(tool_fn, 'fn'):
                result = tool_fn.fn(**args)
            else:
                result = tool_fn(**args)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        except Exception as e:
            elapsed = time.perf_counter() - start
            errors.append(str(e))
            times.append(elapsed)
    
    return {
        "tool": tool_name,
        "description": description,
        "runs": runs,
        "cold_s": round(times[0], 2),
        "warm_s": round(min(times[1:]), 2) if len(times) > 1 else None,
        "errors": errors,
    }

def main():
    print(f"{'Tool':<30} {'Cold (s)':>10} {'Warm (s)':>10} {'Status':>10}")
    print("-" * 65)
    
    results = []
    for tool_name, args, desc in BENCHMARKS:
        sys.stdout.write(f"  Testing {tool_name}...")
        sys.stdout.flush()
        
        r = run_benchmark(tool_name, args, desc)
        if r:
            status = "✅" if r['warm_s'] and r['warm_s'] < 5 else "⚠️"
            print(f"\r{r['tool']:<30} {r['cold_s']:>10.2f} {str(r.get('warm_s', 'N/A')):>10} {status:>10}")
            results.append(r)
    
    print("\n--- Summary ---")
    slow = [r for r in results if r.get('warm_s') and r['warm_s'] > 5]
    if slow:
        print(f"⚠️  Slow warm queries (>5s): {', '.join(r['tool'] for r in slow)}")
    
    really_slow = [r for r in results if r.get('cold_s') and r['cold_s'] > 30]
    if really_slow:
        print(f"🐢 Very slow cold queries (>30s): {', '.join(r['tool'] for r in really_slow)}")

if __name__ == "__main__":
    main()
```

### Expected Output (before optimizations)

```
Tool                           Cold (s)   Warm (s)     Status
-----------------------------------------------------------------
get_security_posture               4.2       1.1          ✅
get_weekly_priorities              6.8       1.3          ✅
get_new_vulns                      3.1       3.1          ⚠️ (no cache)
get_threat_intel                  45.2      45.2          ⚠️ (VMDR slow)
get_patch_status                   7.4       1.8          ✅
get_scanner_health                 4.1       4.1          ⚠️ (no cache)
get_etm_findings                  12.5       8.3          ⚠️ (no report cache)
get_cloud_risk                    22.3       8.1          ⚠️ (sequential providers)
get_cloud_risk (threats)           3.8       3.8          ⚠️ (no cache)
get_morning_report                14.2       4.1          ✅
get_tech_debt                     28.4       9.2          ⚠️ (paginated)
investigate_cve                    8.9       1.2          ✅
```

### Expected Output (after Phase 1 + 2 optimizations)

```
Tool                           Cold (s)   Warm (s)     Status
-----------------------------------------------------------------
get_security_posture               4.0       0.8          ✅
get_weekly_priorities              6.5       0.9          ✅
get_new_vulns                      3.0       3.0          ⚠️ (KB no cache — by design)
get_threat_intel                  12.0       0.3          ✅ (VMDR cache fixed)
get_patch_status                   6.8       1.2          ✅
get_scanner_health                 4.0       0.2          ✅ (scanner cache added)
get_etm_findings                   9.0       0.2          ✅ (ETM cache)
get_cloud_risk                     6.5       1.8          ✅ (parallel providers)
get_cloud_risk (threats)           3.5       0.2          ✅ (CDR cache)
get_morning_report                12.0       2.1          ✅
get_tech_debt                     26.0       8.5          ⚠️ (paginated — expected)
investigate_cve                    7.5       0.8          ✅
```

---

## 6. VMDR Classic vs ETM — Decision Guide

| Scenario | Use VMDR | Use ETM |
|----------|----------|---------|
| Real-time new detections today | ✅ | ❌ (report may be stale) |
| Cached weekly priorities | ❌ | ✅ (1-hour cache) |
| CVE-specific search | ETM QQL is easier | ✅ |
| QDS-filtered results | ✅ (qds_min param) | ✅ (qql qds filter) |
| Large environments (>10k hosts) | ❌ Too slow | ✅ Preferred |
| Single-host detections | ✅ (specific host ID) | ⚠️ |

**Recommendation:** ETM should be the default detection source for all non-real-time queries. VMDR classic kept as fallback and for `get_threat_intel` (which needs current RTI data).

---

## 7. Quick Wins Summary

| Change | Lines of Code | Speedup |
|--------|---------------|---------|
| Fix detection cache key | ~5 | 2x for repeated threat intel queries |
| Add KB TTL | ~15 | Safety fix (not perf) |
| Add WAS cache | ~10 | 10x for repeated webapp queries |
| Cache scanner list | ~10 | 10x for repeated scanner checks |
| Cache ETM result | ~30 | 10x for repeated ETM queries |
| Parallelize cloud risk | ~20 | 3x for cloud queries |
| Parallelize recommendations | ~15 | 2x |
| **Total** | **~105 lines** | **2–10x across most tools** |

---

## 8. Implemented Changes (Issue #21)

### Phase 1: Cache Fixes — Implemented

| Fix | What Changed | Expected Warm Speedup |
|-----|-------------|----------------------|
| Detection cache key | Removed `limit` from key; always fetch 500, slice at return | 2–5x (cache hit for different limit values) |
| KB TTL (1 hour) | `KB_CACHE_TIME` dict + TTL check in `get_kb` and `get_kb_batch` | Safety: prevents stale data >1h |
| WAS cache (10 min) | `WAS_CACHE` + `WAS_CACHE_TIME` per key in `get_was_findings` | 10x (instant on 2nd call) |
| Scanner cache (5 min) | `SCANNER_CACHE` + `SCANNER_CACHE_TIME` in `get_scanner_list` | 10x for `get_scanner_health` warm |
| ETM result cache (1 hour) | `ETM_RESULT_CACHE` in `get_etm_findings`; async status returns `"creating"` | 10x for unfiltered ETM warm |
| `cache_status()` extended | Now clears WAS, ETM, scanner, and QDS caches when `clear=True` | — |

### Phase 2: Concurrency Fixes — Implemented

| Fix | What Changed | Expected Cold Speedup |
|-----|-------------|----------------------|
| `get_cloud_risk` parallelized | Sequential `for p in providers` → parallel `_run_concurrent(aws=..., azure=..., gcp=...)` + parallel evals | ~3x: ~20s → ~6s |
| `get_security_posture` cloud | Sequential provider loop → parallel connectors + parallel eval fetches | ~2x for cloud section |
| `_get_first_cloud_evals` | Sequential 3-provider check → parallel connector fetch | ~3x for recommendations cloud check |

### Phase 3: Enhanced Docstrings — Implemented

| Tool | Enhancement |
|------|------------|
| `get_etm_findings` | 10+ QQL examples, all filter types, operator reference, async flow explanation |
| `get_threat_intel` | All 12 RTI tag names with descriptions, common query examples |
| `get_weekly_priorities` | "Use when / NOT for" routing hints |
| `get_morning_report` | "Use when / NOT for" routing hints |
| `get_security_posture` | "Use when / NOT for" routing hints |
| `get_recommendations` | "Use when / NOT for" routing hints |
| `get_cloud_risk` | Cross-reference to `get_cloud_risk(include_threats=True)` for CDR findings |

### Phase 4: Aggregator Tools — Implemented

| New Tool | Description | Expected Latency |
|----------|-------------|-----------------|
| `get_asset(asset_id, detail="full")` | CSAM + ETM (cached or async) + VMDR host detections in parallel | ~5-8s cold, ~2s warm |
| `get_risk_by_tag(tag, limit)` | 6 parallel CSAM count/search queries for tagged asset group | ~3s |
| `get_morning_report(quick=True)` | 11 parallel CSAM count queries: OS, cloud, EOL, criticality | <3s |

### Updated Tool Count

Tools consolidated via parameterized interfaces. New tools added to README Tools table and test_tools.sh.

### Post-Implementation Targets (Estimated)

| Tool | Before (warm) | After (warm) | Change |
|------|--------------|--------------|--------|
| `get_scanner_health` | 3–8s | <0.5s | Scanner 5-min cache |
| `get_etm_findings` (unfiltered) | 5–10s | <0.5s | 1-hour ETM result cache |
| `get_cloud_risk` | 15–30s cold | ~6s cold | Parallel providers |
| `get_security_posture` (cloud section) | 8–15s | ~5s | Parallel cloud connectors |
| `get_was_findings` | 5–30s | <0.1s warm | 10-min WAS cache |
| WAS-based tools (2nd call) | 5–30s | <0.1s | WAS cache hit |
| `get_morning_report(quick=True)` | new | <3s | 11-way parallel CSAM |
| `get_risk_by_tag` | new | ~3s | 6-way parallel CSAM |
| `get_asset(detail="full")` | new | ~5-8s cold / ~2s warm | 3-way parallel + ETM cache |

### Phase 5: Request Deduplication — Implemented (Issue #16)

| Fix | What Changed | Impact |
|-----|-------------|--------|
| `_get_or_fetch` helper | Thread-safe cache helper with per-key locking prevents duplicate concurrent API requests | Eliminates redundant API calls when multiple tools request the same data simultaneously |
| `get_detections` dedup | Migrated to `_get_or_fetch` (TTL 300s). `DETECTION_CACHE_TIME` converted to per-key dict | Concurrent detection queries share a single API call |
| `get_was_findings` dedup | Migrated to `_get_or_fetch` (TTL 600s). Removed manual cache management | Concurrent WAS queries share a single API call |

### Cache TTL Summary

| Cache | TTL | Key Strategy |
|-------|-----|-------------|
| Bearer token | 3.5 hours | Single global token |
| KB entries | 1 hour | Per-QID with `KB_CACHE_TIME` dict |
| VMDR detections | 5 minutes | Per `{severity}_{days}_{qds_min}`, limit excluded |
| QDS scores | 5 minutes | Per-QID, bulk-cleared on expiry |
| WAS findings | 10 minutes | Per `{limit}_{severity}_{days}_{app_name}` |
| Scanner list | 5 minutes | Single global list |
| ETM results | 1 hour | Single global (unfiltered only) |
