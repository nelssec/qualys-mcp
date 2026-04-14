# QDS-Driven Cache + Pre-Scan Exposure Assessment

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace severity-based aggressive cache warmup with QDS-driven lazy caching, add per-module cache control, and build a pre-scan CVE exposure assessment capability.

**Architecture:** Three changes: (1) Replace the startup warmup thread with a configurable lazy-fetch system that prioritizes QDS >= 70 detections. (2) Make cache module-scoped so only modules the user queries get fetched. (3) Add an `assess_exposure` aggregator that estimates vulnerability exposure using KB + CSAM software inventory before any scan runs.

**Tech Stack:** Python 3.11+, existing qualys.api / qualys.cache modules, VMDR KB API, CSAM search API.

---

### Task 1: Add cache mode configuration

**Files:**
- Modify: `qualys/api.py:82-91` (constants section)
- Modify: `qualys/api.py:2039-2057` (`_warmup_vmdr_cache`)
- Modify: `qualys_mcp.py:256` (warmup thread launch)
- Test: `tests/test_concurrency.py`

- [ ] **Step 1: Write failing test for cache mode**

```python
# tests/test_concurrency.py — add to existing file
class TestCacheMode:
    def test_cache_mode_default_is_lazy(self):
        from qualys.api import CACHE_MODE
        assert CACHE_MODE in ("lazy", "aggressive", "none")

    def test_cache_mode_none_disables_disk_cache(self):
        import os
        os.environ["QUALYS_CACHE_MODE"] = "none"
        try:
            from importlib import reload
            import qualys.api
            reload(qualys.api)
            assert qualys.api.CACHE_MODE == "none"
        finally:
            os.environ.pop("QUALYS_CACHE_MODE", None)
            reload(qualys.api)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=. python3 -m pytest tests/test_concurrency.py::TestCacheMode -v`
Expected: FAIL with `cannot import name 'CACHE_MODE'`

- [ ] **Step 3: Add CACHE_MODE constant to api.py**

In `qualys/api.py` after the CSAM constants (around line 91), add:

```python
CACHE_MODE = os.environ.get("QUALYS_CACHE_MODE", "lazy").lower()
if CACHE_MODE not in ("lazy", "aggressive", "none"):
    CACHE_MODE = "lazy"
```

- [ ] **Step 4: Update warmup to respect CACHE_MODE**

In `qualys/api.py`, modify `_warmup_vmdr_cache`:

```python
def _warmup_vmdr_cache():
    if CACHE_MODE != "aggressive":
        _log(f"Cache mode '{CACHE_MODE}' — skipping startup warmup")
        return
    import time
    time.sleep(2)
    for sev in (5, 4, 3):
        try:
            cache_key = f"detections_{sev}_30_0"
            disk_hit = disk_cache.get(cache_key)
            if disk_hit is not None:
                DETECTION_CACHE[cache_key] = disk_hit
                DETECTION_CACHE_TIME[cache_key] = datetime.now(timezone.utc)
                _log(f"Disk cache hit during warmup for {cache_key}")
                continue
            _log(f"Cache warm-up: fetching severity {sev} detections...")
            get_detections(severity=sev, use_cache=False)
            _log(f"Cache warm-up: severity {sev} done")
        except Exception as e:
            _log(f"Cache warm-up: severity {sev} failed: {e}")
    _log("Cache warm-up: complete")
```

- [ ] **Step 5: Update qualys_mcp.py to only start warmup thread when mode is aggressive**

In `qualys_mcp.py`, update the warmup launch in `main()`:

```python
    if CACHE_MODE == "aggressive":
        warmup = Thread(target=_warmup_vmdr_cache, daemon=True, name="vmdr-cache-warmup")
        warmup.start()
```

Add `CACHE_MODE` to the import line:
```python
from qualys.api import BASE_URL, GATEWAY_URL, _resolved_pod, _log, _warmup_vmdr_cache, CACHE_MODE
```

- [ ] **Step 6: Run tests**

Run: `PYTHONPATH=. python3 -m pytest tests/test_concurrency.py::TestCacheMode -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add qualys/api.py qualys_mcp.py tests/test_concurrency.py
git commit -m "feat: add QUALYS_CACHE_MODE env var (lazy/aggressive/none)"
```

---

### Task 2: Add QDS-tier detection fetching

**Files:**
- Modify: `qualys/api.py:775-822` (`get_detections`)
- Create: `qualys/api.py` — new `get_detections_by_qds` function
- Test: `tests/test_concurrency.py`

- [ ] **Step 1: Write failing test**

```python
class TestQDSDetections:
    def test_get_detections_by_qds_signature(self):
        from qualys.api import get_detections_by_qds
        import inspect
        sig = inspect.signature(get_detections_by_qds)
        assert "qds_min" in sig.parameters
        assert "days" in sig.parameters
        assert "limit" in sig.parameters

    def test_get_detections_by_qds_returns_list(self):
        from qualys.api import get_detections_by_qds
        result = get_detections_by_qds(qds_min=90, days=7, limit=10)
        assert isinstance(result, list)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=. python3 -m pytest tests/test_concurrency.py::TestQDSDetections -v`
Expected: FAIL

- [ ] **Step 3: Implement get_detections_by_qds**

Add after `get_detections` in `qualys/api.py`:

```python
def get_detections_by_qds(qds_min=70, days=30, limit=0, use_cache=True):
    """Get VMDR detections filtered by QDS minimum score.
    QDS >= 70 = high exploitability. QDS >= 90 = critical/actively exploited.
    Much smaller dataset than severity-based fetch — ideal for lazy cache."""
    cache_key = f"detections_qds{qds_min}_{days}"

    def _fetch():
        after_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
        url = (
            f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
            f"&status=Active&show_qds=1&filter_superseded_qids=1"
            f"&qds_min={qds_min}"
            f"&vm_processed_after={after_date}"
        )
        all_dets = []
        id_min = 0
        pages = 0
        max_page_cap = MAX_PAGES if MAX_PAGES > 0 else 0
        while True:
            if max_page_cap > 0 and pages >= max_page_cap:
                break
            fetch_url = url
            if id_min > 0:
                fetch_url += f"&id_min={id_min}"
            data = api_get(fetch_url, timeout=120)
            if not data:
                break
            dets, is_truncated, max_host_id = _parse_detections_xml(data)
            all_dets.extend(dets)
            pages += 1
            if not is_truncated or max_host_id == 0:
                break
            id_min = max_host_id + 1
        if pages > 1:
            _log(f"QDS detections (>={qds_min}): {len(all_dets)} records across {pages} pages")
        return all_dets

    if not use_cache:
        result = _fetch()
        DETECTION_CACHE[cache_key] = result
        DETECTION_CACHE_TIME[cache_key] = datetime.now(timezone.utc)
        disk_cache.set(cache_key, result, DISK_TTL_VMDR)
        return result

    return _get_or_fetch(DETECTION_CACHE, DETECTION_CACHE_TIME, cache_key, _fetch, VMDR_CACHE_TTL, disk_ttl=DISK_TTL_VMDR)
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=. python3 -m pytest tests/test_concurrency.py::TestQDSDetections -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add qualys/api.py tests/test_concurrency.py
git commit -m "feat: add get_detections_by_qds — QDS-driven detection fetch"
```

---

### Task 3: Build pre-scan exposure assessment aggregator

**Files:**
- Modify: `qualys/aggregators.py` — add `assess_exposure` function
- Test: `tests/test_synthesis.py`

- [ ] **Step 1: Write failing test**

```python
class TestAssessExposure:
    def test_assess_exposure_signature(self):
        from qualys.aggregators import assess_exposure
        import inspect
        sig = inspect.signature(assess_exposure)
        assert "cve" in sig.parameters
        assert "detail" in sig.parameters

    def test_assess_exposure_returns_dict(self):
        from qualys.aggregators import assess_exposure
        result = assess_exposure(cve="CVE-9999-99999")
        assert isinstance(result, dict)
        assert "exposure" in result or "summary" in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=. python3 -m pytest tests/test_synthesis.py::TestAssessExposure -v`
Expected: FAIL

- [ ] **Step 3: Implement assess_exposure**

Add to end of `qualys/aggregators.py`:

```python
def assess_exposure(cve: str = "", qid: int = 0, software: str = "", detail: str = "standard") -> dict:
    """Pre-scan exposure assessment — estimate vulnerability exposure using
    KB data + CSAM software inventory before any scan runs.

    Flow: CVE/QID → KB lookup (affected software) → CSAM count (assets with that software)
    → exposure estimate with asset count and risk context."""
    result = {
        'exposure': {'potentialAssets': 0, 'softwareMatches': [], 'riskContext': {}},
        'summary': '',
        'kb': {},
    }

    qids_to_check = []
    if cve:
        qids_to_check = get_cve_qids(cve)
        if not qids_to_check:
            result['summary'] = f'{cve} not found in Qualys Knowledge Base — it may be too new or not applicable to your scanned technologies.'
            result['exposure']['status'] = 'unknown'
            return _with_meta(result)
    elif qid:
        qids_to_check = [qid]

    if qids_to_check:
        kb_data = get_kb_batch(qids_to_check[:20])
    else:
        kb_data = {}

    best_kb = None
    max_sev = 0
    all_cves = set()
    for q in qids_to_check:
        kb = kb_data.get(q)
        if kb and kb.get('severity', 0) > max_sev:
            max_sev = kb['severity']
            best_kb = kb
        if kb:
            all_cves.update(kb.get('cves', []))

    if best_kb:
        result['kb'] = {
            'qid': best_kb.get('qid'),
            'title': best_kb.get('title', ''),
            'severity': best_kb.get('severity', 0),
            'qds': best_kb.get('qds', 0),
            'cvss_v3': best_kb.get('cvss_v3'),
            'cves': list(all_cves),
            'patchAvailable': best_kb.get('patch_available', False),
            'hasExploit': best_kb.get('has_exploit', False),
            'ransomware': best_kb.get('ransomware', False),
            'threatIntel': best_kb.get('threat_intel', []),
        }
        import re
        diag = best_kb.get('diagnosis', '') or ''
        clean_diag = re.sub(r'<[^>]+>', '', diag)
        result['kb']['diagnosis'] = clean_diag[:300]
        sol = best_kb.get('solution', '') or ''
        clean_sol = re.sub(r'<[^>]+>', '', sol)
        result['kb']['solution'] = clean_sol[:300]

    sw_keywords = _extract_software_keywords(best_kb.get('title', '') if best_kb else software) if best_kb or software else []
    if software and software not in sw_keywords:
        sw_keywords.append(software)

    if not sw_keywords and not software:
        title = best_kb.get('title', '') if best_kb else ''
        title_lower = title.lower()
        for candidate in ('OpenSSH', 'Apache', 'nginx', 'Windows', 'Linux', 'Chrome', 'Firefox',
                          'Java', 'Python', 'Node', 'PHP', 'MySQL', 'PostgreSQL', 'Oracle',
                          'VMware', 'Cisco', 'Fortinet', 'Palo Alto', 'F5'):
            if candidate.lower() in title_lower:
                sw_keywords.append(candidate)
                break

    if sw_keywords:
        sw_tasks = {}
        for kw in sw_keywords[:5]:
            sw_tasks[kw] = lambda k=kw: (
                csam_count([{'field': 'software.name', 'operator': 'CONTAINS', 'value': k}]),
            )
        sw_results = _run_concurrent(**sw_tasks)

        total_potential = 0
        for kw, val in sw_results.items():
            count = 0
            if isinstance(val, tuple):
                count = val[0] if val[0] else 0
            elif isinstance(val, int):
                count = val
            if count > 0:
                result['exposure']['softwareMatches'].append({
                    'software': kw,
                    'assetCount': count,
                })
                total_potential = max(total_potential, count)
        result['exposure']['potentialAssets'] = total_potential

    total_assets = csam_count()
    result['exposure']['totalAssets'] = total_assets

    severity = best_kb.get('severity', 0) if best_kb else 0
    qds = best_kb.get('qds', 0) if best_kb else 0
    has_exploit = best_kb.get('has_exploit', False) if best_kb else False
    is_ransomware = best_kb.get('ransomware', False) if best_kb else False
    potential = result['exposure']['potentialAssets']

    if potential == 0:
        risk = 'none'
        result['exposure']['status'] = 'not_exposed'
    elif is_ransomware or has_exploit:
        risk = 'critical'
        result['exposure']['status'] = 'likely_exposed'
    elif severity >= 5 or qds >= 90:
        risk = 'critical'
        result['exposure']['status'] = 'likely_exposed'
    elif severity >= 4 or qds >= 70:
        risk = 'high'
        result['exposure']['status'] = 'likely_exposed'
    elif severity >= 3:
        risk = 'medium'
        result['exposure']['status'] = 'possibly_exposed'
    else:
        risk = 'low'
        result['exposure']['status'] = 'low_exposure'
    result['exposure']['riskContext'] = {
        'risk': risk,
        'severity': severity,
        'qds': qds,
        'hasExploit': has_exploit,
        'ransomware': is_ransomware,
    }

    target_name = cve or f'QID {qid}' or software
    parts = [f'{target_name}']
    if best_kb:
        parts.append(f'({best_kb.get("title", "")})')
    if potential > 0:
        pct = round(potential / total_assets * 100, 1) if total_assets else 0
        parts.append(f'— {potential} assets ({pct}% of {total_assets}) potentially exposed')
        sw_names = ', '.join(m['software'] for m in result['exposure']['softwareMatches'])
        parts.append(f'(running {sw_names})')
    else:
        parts.append(f'— no matching software found across {total_assets} assets')
    if has_exploit:
        parts.append('. Active exploit known')
    if is_ransomware:
        parts.append('. Linked to ransomware')
    if best_kb and best_kb.get('patch_available'):
        parts.append('. Patch available')
    result['summary'] = ' '.join(parts) + '.'
    result['exposure']['recommendation'] = (
        f'Prioritize scanning the {potential} assets with {sw_names} installed. '
        f'Use assess_risk(scope="assets", tag="<tag>") after scan completes to confirm exposure.'
    ) if potential > 0 else 'No matching software found — exposure unlikely. Verify with a targeted scan.'

    return _apply_detail_level(_with_meta(result), detail)
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=. python3 -m pytest tests/test_synthesis.py::TestAssessExposure -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add qualys/aggregators.py tests/test_synthesis.py
git commit -m "feat: add assess_exposure — pre-scan CVE exposure estimation"
```

---

### Task 4: Wire assess_exposure into investigate workflow

**Files:**
- Modify: `qualys/workflows/investigate.py` — add exposure assessment to CVE investigation path
- Test: `tests/test_dispatch.py`

- [ ] **Step 1: Write failing test**

```python
class TestInvestigateExposure:
    def test_cve_plan_includes_exposure(self):
        from qualys.workflows.investigate import _build_plan
        plan = _build_plan(
            target="CVE-2024-6387",
            target_type="cve",
            depth="standard",
            scope="all",
            tag="", asset_group="", threat_type="", software="",
            days=7, limit=20, detail="standard", prior_context=""
        )
        assert "exposure" in plan or "cve_deep" in plan
```

- [ ] **Step 2: Run to verify it fails or passes (baseline)**

Run: `PYTHONPATH=. python3 -m pytest tests/test_dispatch.py::TestInvestigateExposure -v`

- [ ] **Step 3: Add exposure assessment to CVE investigation plan**

In `qualys/workflows/investigate.py`, inside `_build_plan`, after the CVE deep plan entry, add:

```python
    if target_type == "cve":
        plan["cve_deep"] = lambda: investigate_cve_agg(target, detail=detail)
        plan["exposure"] = lambda: assess_exposure(cve=target, detail=detail)
```

Add `assess_exposure` to the import block:

```python
    from qualys.aggregators import (
        investigate_cve_agg,
        investigate_agg,
        search_vulns_agg,
        cve_details,
        threat_actor_exposure_agg,
        edr_events,
        fim_events,
        totalai_summary,
        cs_vulnerability_detail_agg,
        assess_exposure,
    )
```

- [ ] **Step 4: Update investigate _summarize to include exposure data**

In `qualys/workflows/investigate.py`, in the `_summarize` function, add handling for exposure data after the CVE section:

```python
    exposure = data.get("exposure")
    if isinstance(exposure, dict):
        exp = exposure.get("exposure", {})
        potential = exp.get("potentialAssets", 0)
        status = exp.get("status", "unknown")
        if potential > 0:
            sw_matches = exp.get("softwareMatches", [])
            sw_names = ", ".join(m.get("software", "") for m in sw_matches[:3])
            findings.append(f"{potential} assets potentially exposed (running {sw_names})")
            stats["potentiallyExposed"] = potential
        risk_ctx = exp.get("riskContext", {})
        if risk_ctx.get("hasExploit"):
            findings.append("Active exploit exists — prioritize scanning")
        if risk_ctx.get("ransomware"):
            findings.append("Linked to ransomware campaigns")
```

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=. python3 -m pytest tests/ --ignore=tests/conversations -q`
Expected: 295+ passed

- [ ] **Step 6: Commit**

```bash
git add qualys/workflows/investigate.py tests/test_dispatch.py
git commit -m "feat: wire assess_exposure into CVE investigation workflow"
```

---

### Task 5: Add cache_mode=none support (disable all caching)

**Files:**
- Modify: `qualys/api.py` — skip cache reads/writes when mode is "none"
- Modify: `qualys/cache.py` — add NullCache class
- Test: `tests/test_concurrency.py`

- [ ] **Step 1: Write failing test**

```python
class TestNullCache:
    def test_null_cache_get_returns_none(self):
        from qualys.cache import NullCache
        c = NullCache()
        c.set("key", "value", 3600)
        assert c.get("key") is None

    def test_null_cache_keys_empty(self):
        from qualys.cache import NullCache
        c = NullCache()
        assert c.keys() == []
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. python3 -m pytest tests/test_concurrency.py::TestNullCache -v`

- [ ] **Step 3: Add NullCache to cache.py**

At the end of `qualys/cache.py`, before the singleton:

```python
class NullCache:
    """No-op cache for QUALYS_CACHE_MODE=none. All operations are silent no-ops."""
    def get(self, key): return None
    def set(self, key, value, ttl): pass
    def clear(self, key=None): pass
    def age(self, key): return None
    def size_kb(self): return 0
    def keys(self): return []
```

Update the singleton to respect cache mode:

```python
_cache_mode = os.environ.get("QUALYS_CACHE_MODE", "lazy").lower()
disk_cache = NullCache() if _cache_mode == "none" else DiskCache()
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=. python3 -m pytest tests/test_concurrency.py::TestNullCache -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `PYTHONPATH=. python3 -m pytest tests/ --ignore=tests/conversations -q`
Expected: 295+ passed

- [ ] **Step 6: Commit**

```bash
git add qualys/cache.py tests/test_concurrency.py
git commit -m "feat: add NullCache for QUALYS_CACHE_MODE=none"
```

---

### Task 6: Update cache_status tool to show QDS tier info and cache mode

**Files:**
- Modify: `qualys/aggregators.py` — update `cache_status_agg`
- Test: `tests/test_synthesis.py`

- [ ] **Step 1: Write failing test**

```python
class TestCacheStatusMode:
    def test_cache_status_includes_mode(self):
        from qualys.aggregators import cache_status_agg
        result = cache_status_agg()
        assert "cacheMode" in result
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. python3 -m pytest tests/test_synthesis.py::TestCacheStatusMode -v`

- [ ] **Step 3: Add cacheMode to cache_status_agg**

In `qualys/aggregators.py`, in `cache_status_agg`, add after the result dict initialization:

```python
    result['cacheMode'] = CACHE_MODE
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=. python3 -m pytest tests/ --ignore=tests/conversations -q`
Expected: 295+ passed

- [ ] **Step 5: Commit**

```bash
git add qualys/aggregators.py tests/test_synthesis.py
git commit -m "feat: show cache mode and QDS tier info in cache_status"
```

---

### Task 7: Live validation against US2

**Files:** None (testing only)

- [ ] **Step 1: Test assess_exposure with real CVE**

```bash
QUALYS_USERNAME=$USER QUALYS_PASSWORD=$PASS QUALYS_POD=US2 PYTHONPATH=. python3 -c "
import json
from qualys.aggregators import assess_exposure
r = assess_exposure(cve='CVE-2024-6387')
print(f'Summary: {r.get(\"summary\", \"\")}')
exp = r.get('exposure', {})
print(f'Potential assets: {exp.get(\"potentialAssets\", 0)}')
print(f'Status: {exp.get(\"status\", \"\")}')
print(f'Software: {exp.get(\"softwareMatches\", [])}')
print(f'Risk: {exp.get(\"riskContext\", {})}')
"
```

Expected: ~1,611 assets with OpenSSH, status=likely_exposed

- [ ] **Step 2: Test lazy cache mode (default)**

```bash
QUALYS_CACHE_MODE=lazy QUALYS_USERNAME=$USER QUALYS_PASSWORD=$PASS QUALYS_POD=US2 PYTHONPATH=. python3 -c "
from qualys.api import CACHE_MODE
print(f'Cache mode: {CACHE_MODE}')
from qualys.workflows.overview import security_overview
r = security_overview(quick=True, detail='summary')
print(r.get('summary', {}).get('headline', ''))
"
```

Expected: No warmup log messages, lazy fetch on first query

- [ ] **Step 3: Test cache mode none**

```bash
QUALYS_CACHE_MODE=none QUALYS_USERNAME=$USER QUALYS_PASSWORD=$PASS QUALYS_POD=US2 PYTHONPATH=. python3 -c "
from qualys.cache import disk_cache
print(f'Cache type: {type(disk_cache).__name__}')
print(f'Cache get: {disk_cache.get(\"test\")}')
"
```

Expected: `NullCache`, `None`

- [ ] **Step 4: Test QDS-based detection fetch**

```bash
QUALYS_USERNAME=$USER QUALYS_PASSWORD=$PASS QUALYS_POD=US2 PYTHONPATH=. python3 -c "
import time
from qualys.api import get_detections_by_qds
t0 = time.time()
dets = get_detections_by_qds(qds_min=90, days=30)
print(f'QDS>=90 detections: {len(dets)} in {time.time()-t0:.1f}s')
t0 = time.time()
dets70 = get_detections_by_qds(qds_min=70, days=30)
print(f'QDS>=70 detections: {len(dets70)} in {time.time()-t0:.1f}s')
"
```

Expected: QDS>=90 should be much smaller than full sev-5 dataset

- [ ] **Step 5: Run full test suite**

```bash
PYTHONPATH=. python3 -m pytest tests/ --ignore=tests/conversations -q
```

Expected: 298+ passed (3 new tests added)

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "test: validate QDS cache + exposure assessment against US2"
```
