# Performance Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 5 performance bottlenecks causing 15-105 minute response times on large (89K asset) environments.

**Architecture:** Targeted fixes in `api.py` and `aggregators.py` only — no workflow layer changes. Each fix adds bounds to unbounded operations: date filters on KB fetches, `fetch_all=False` on container/image calls, parallelized compliance policy loops, and capped recommendation calls.

**Tech Stack:** Python 3.9+, existing `qualys.api` functions, `_run_concurrent` for parallelization.

---

## File Map

| File | Action | Changes |
|------|--------|---------|
| `qualys/api.py` | Modify | Fix `get_images()` and `get_containers()` to default `fetch_all=False` |
| `qualys/aggregators.py` | Modify | 5 targeted fixes in specific functions |

---

### Task 1: Fix container/image pagination defaults in api.py

The root cause: `get_images()` and `get_containers()` call `_paginate_json()` which defaults to `fetch_all=True`. On large environments this fetches thousands of pages.

**Files:**
- Modify: `qualys/api.py:1070-1088`

- [ ] **Step 1: Fix `get_images()` to use `fetch_all=False`**

Change line 1075 in `get_images()`:
```python
return _paginate_json(url, limit, count_only=count_only, fetch_all=False)
```

- [ ] **Step 2: Fix `get_containers()` to use `fetch_all=False`**

Change line 1088 in `get_containers()`:
```python
return _paginate_json(url, limit, count_only=count_only, fetch_all=False)
```

- [ ] **Step 3: Verify imports still work**

Run: `python3 -c "from qualys.api import get_images, get_containers; print('OK')"`

- [ ] **Step 4: Commit**

```bash
git add qualys/api.py
git commit -m "perf: fix container/image pagination — default fetch_all=False"
```

---

### Task 2: Fix threat_actor_exposure_agg unbounded KB fetch

The root cause: `threat_actor_exposure_agg()` at line 1500-1503 fetches the ENTIRE Qualys KB (100K+ vulns) without any date filter or pagination. On large environments this times out or takes 17+ minutes.

**Fix:** Add a `published_after` date filter (last 2 years covers all actively relevant threat intel) and increase timeout.

**Files:**
- Modify: `qualys/aggregators.py:1500-1504`

- [ ] **Step 1: Add date boundary to KB fetch in threat_actor_exposure_agg**

Replace lines 1500-1504:
```python
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&show_supported_modules_info=0",
        timeout=60
    )
```

With:
```python
    kb_after = (datetime.now(timezone.utc) - timedelta(days=730)).strftime('%Y-%m-%d')
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&show_supported_modules_info=0&published_after={kb_after}",
        timeout=120
    )
```

This limits the KB fetch to vulns published in the last 2 years (still covers all relevant threat intel) and doubles the timeout.

- [ ] **Step 2: Verify function still imports**

Run: `python3 -c "from qualys.aggregators import threat_actor_exposure_agg; print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add qualys/aggregators.py
git commit -m "perf: bound threat_actor KB fetch to last 2 years + increase timeout"
```

---

### Task 3: Fix search_vulns_agg timeout

The root cause: `search_vulns_agg()` at line 1384-1388 already has a `published_after` date filter (good), but the timeout is only 30 seconds — insufficient for large KB responses.

**Fix:** Increase timeout to 120 seconds.

**Files:**
- Modify: `qualys/aggregators.py:1384-1388`

- [ ] **Step 1: Increase search_vulns_agg timeout**

Replace line 1387-1388:
```python
        timeout=30
    )
```

With:
```python
        timeout=120
    )
```

- [ ] **Step 2: Commit**

```bash
git add qualys/aggregators.py
git commit -m "perf: increase search_vulns_agg KB timeout to 120s"
```

---

### Task 4: Fix morning_report 4x concurrent KB fetches

The root cause: `morning_report(quick=False)` at lines 2523-2526 fires 4 concurrent `search_vulns_agg()` calls, each fetching the KB independently. This means 4 copies of the same KB XML are downloaded and parsed simultaneously.

**Fix:** Fetch KB once, then filter locally for each threat type.

**Files:**
- Modify: `qualys/aggregators.py:2520-2532`

- [ ] **Step 1: Replace 4 concurrent KB fetches with single fetch + local filtering**

Replace lines 2520-2532:
```python
    concurrent = _run_concurrent(
        posture=lambda: get_security_posture(),
        priorities=lambda: weekly_priorities(),
        new_vulns=lambda: search_vulns_agg(days=1),
        ransomware=lambda: search_vulns_agg(days=1, threat_type='Ransomware'),
        active=lambda: search_vulns_agg(days=1, threat_type='Active_Attacks'),
        cisa=lambda: search_vulns_agg(days=1, threat_type='Cisa_Known_Exploited_Vulns'),
        trurisk_now=lambda: csam_search(limit=100, fields="truRisk"),
        trurisk_7d=lambda: csam_search(
            filters=[{"field": "asset.lastModifiedDate", "operator": "LESS",
                      "value": (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT00:00:00Z')}],
            limit=100, fields="truRisk", fetch_all=False),
    )
```

With:
```python
    concurrent = _run_concurrent(
        posture=lambda: get_security_posture(),
        priorities=lambda: weekly_priorities(),
        new_vulns=lambda: search_vulns_agg(days=1),
        trurisk_now=lambda: csam_search(limit=100, fields="truRisk"),
        trurisk_7d=lambda: csam_search(
            filters=[{"field": "asset.lastModifiedDate", "operator": "LESS",
                      "value": (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT00:00:00Z')}],
            limit=100, fields="truRisk", fetch_all=False),
    )
```

Then after `concurrent` resolves, derive threat-type breakdowns from the single `new_vulns` result instead of making 3 more KB calls. After the existing `new = concurrent.get('new_vulns') or {}` line, add:

```python
    all_new_vulns = new.get('vulns', [])
    def _count_threat_type(vulns, threat_tag):
        tag_lower = threat_tag.lower()
        return sum(1 for v in vulns if any(tag_lower in t.lower() for t in v.get('threat_intel', [])))

    ransomware_count = _count_threat_type(all_new_vulns, 'Ransomware')
    active_count = _count_threat_type(all_new_vulns, 'Active_Attacks')
    cisa_count = _count_threat_type(all_new_vulns, 'Cisa_Known_Exploited_Vulns')
```

Then update the threat section that previously read from separate concurrent results. Find where `concurrent.get('ransomware')`, `concurrent.get('active')`, and `concurrent.get('cisa')` are used and replace with the local counts.

- [ ] **Step 2: Update threat section references**

Find the lines that reference `concurrent.get('ransomware')` etc. (around lines 2544-2580) and replace:

```python
    ransomware = concurrent.get('ransomware') or {}
```
becomes:
```python
    ransomware = {'totalVulns': ransomware_count}
```

And similarly for `active` and `cisa`.

- [ ] **Step 3: Verify morning_report still works**

Run: `python3 -c "from qualys.aggregators import morning_report; print('OK')"`

- [ ] **Step 4: Commit**

```bash
git add qualys/aggregators.py
git commit -m "perf: morning_report single KB fetch instead of 4 concurrent"
```

---

### Task 5: Fix compliance sequential policy loops

The root cause: `compliance_posture()` at lines 4947-4963 fetches up to 5 policies sequentially, each with a 120-second timeout. Total: up to 600 seconds of sequential waiting.

**Fix:** Parallelize the policy fetches using `_run_concurrent`.

**Files:**
- Modify: `qualys/aggregators.py:4945-4963`

- [ ] **Step 1: Parallelize policy posture fetches**

Replace lines 4945-4963:
```python
    if policy_ids:
        _log(f"Compliance posture: found {len(policy_ids)} policies, fetching posture (max 5)...")
        for pid in policy_ids[:5]:
            posture_data = api_get(
                f"{BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list&policy_id={pid}",
                timeout=120
            )
            if posture_data:
                try:
                    root = ET.fromstring(posture_data if isinstance(posture_data, (str, bytes)) else posture_data)
                    parsed = _parse_controls(root)
                    if parsed:
                        parsed['source'] = 'pc_posture_v4'
                        out = _add_compliance_followups(parsed)
                        result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                        disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                        return result
                except ET.ParseError:
                    continue
```

With:
```python
    if policy_ids:
        _log(f"Compliance posture: found {len(policy_ids)} policies, fetching posture (max 5) in parallel...")
        policy_tasks = {
            f"policy_{pid}": (lambda p=pid: api_get(
                f"{BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list&policy_id={p}",
                timeout=120
            ))
            for pid in policy_ids[:5]
        }
        policy_results = _run_concurrent(**policy_tasks)
        for pid in policy_ids[:5]:
            posture_data = policy_results.get(f"policy_{pid}")
            if posture_data:
                try:
                    root = ET.fromstring(posture_data if isinstance(posture_data, (str, bytes)) else posture_data)
                    parsed = _parse_controls(root)
                    if parsed:
                        parsed['source'] = 'pc_posture_v4'
                        out = _add_compliance_followups(parsed)
                        result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                        disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                        return result
                except ET.ParseError:
                    continue
```

This changes sequential 5 × 120s = 600s to parallel max(120s) = 120s.

- [ ] **Step 2: Commit**

```bash
git add qualys/aggregators.py
git commit -m "perf: parallelize compliance policy posture fetches"
```

---

### Task 6: Fix recommendations unbounded calls

The root cause: `recommendations()` at lines 1637-1648 calls `get_images(10)` and `get_containers(10)` which default to `fetch_all=True`, plus includes `search_vulns_agg(days=30, threat_type='Ransomware')` which fetches the full KB.

**Fix:** After Task 1 fixes the defaults, images/containers are already fixed. Just need to replace the ransomware KB fetch with a bounded version.

**Files:**
- Modify: `qualys/aggregators.py:1648`

- [ ] **Step 1: Cap the ransomware vuln search in recommendations**

Replace line 1648:
```python
        ransomware_vulns=lambda: search_vulns_agg(days=30, threat_type='Ransomware'),
```

With:
```python
        ransomware_vulns=lambda: search_vulns_agg(days=7, threat_type='Ransomware', limit=10),
```

This reduces from 30-day full KB scan to 7-day with limit 10 (recommendations only needs a count and sample, not full results).

- [ ] **Step 2: Commit**

```bash
git add qualys/aggregators.py
git commit -m "perf: cap recommendations ransomware search to 7 days + limit 10"
```

---

### Task 7: Run integration test to verify improvements

- [ ] **Step 1: Run all unit tests to verify no regressions**

Run: `python3 -m pytest tests/ --ignore=tests/conversations --ignore=tests/run_conversations.py -q`
Expected: 282 passed

- [ ] **Step 2: Run quick integration smoke test (US2)**

```bash
export QUALYS_USERNAME="$QUALYS_USERNAME" QUALYS_PASSWORD="$QUALYS_PASSWORD" QUALYS_POD="US2"
python3 -c "
import time
from qualys.workflows.overview import security_overview
from qualys.workflows.investigate import investigate
from qualys.workflows.remediation import plan_remediation

tests = [
    ('overview quick', lambda: security_overview(quick=True)),
    ('investigate CVE', lambda: investigate(target='CVE-2024-3400', depth='quick')),
    ('remediation patches', lambda: plan_remediation(scope='patches')),
]
for name, fn in tests:
    start = time.time()
    r = fn()
    ms = int((time.time() - start) * 1000)
    print(f'{name}: {ms}ms — {r[\"summary\"][\"headline\"][:60]}')
"
```

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -m "chore: verify performance fixes pass integration tests"
```
