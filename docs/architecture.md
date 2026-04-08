# Qualys MCP v0.1.6 -- Architecture

## Layered Design

```
AI Assistant (Claude, etc.)
    |
    v  MCP tool call (one of 7 async workflow tools)
FastMCP Server (qualys_mcp.py)
    |
    +-- 7 async @mcp.tool() wrappers (asyncio.to_thread)
    |     investigate, assess_risk, check_compliance,
    |     plan_remediation, security_overview, reports, cache_status
    |
    +-- qualys/workflows/ (5 workflow modules)
    |     investigate.py, assess_risk.py, compliance.py,
    |     remediation.py, overview.py
    |
    +-- qualys/aggregators.py (42 aggregator functions)
    |     Each aggregator calls one or more Qualys APIs,
    |     normalizes the data, and returns structured results.
    |     New: TotalAI, Policy Audit, SaaSDR, OCI aggregators
    |
    +-- qualys/api.py (HTTP + caching layer)
          api_get(), csam_search(), csam_count(), etm_api()
          ThreadPoolExecutor(max_workers=8) via _run_concurrent()
          KB semaphore -- prevents 409 conflicts
          In-memory caches with tiered TTLs
          Request deduplication via _get_or_fetch()
```

## Key Design Decisions

### Async tools with asyncio.to_thread

MCP tool handlers are `async` functions. All blocking workflow calls are dispatched
via `asyncio.to_thread()`, preventing event loop blocking. This enables multiple
concurrent tool invocations without stalling the MCP server (#213).

### 53 tools consolidated to 7

The previous architecture exposed 53 individual MCP tools. The LLM had to guess which
tool to use for ambiguous questions. The current architecture consolidates these into 7 intent-based
workflow tools with parameter-based routing. Each workflow internally dispatches to the
appropriate aggregator functions based on scope, target, and other parameters.

### Workflow layer

Each workflow module (e.g. `qualys/workflows/investigate.py`) orchestrates multiple
aggregator calls in parallel using `_run_concurrent()`. The workflow layer handles:

- Intent classification from parameters (e.g. target="CVE-2024-3400" -> CVE investigation)
- Parallel aggregator dispatch
- Cross-source correlation
- Response envelope assembly (summary, data, correlations, actions)

### Aggregator layer

The 42 aggregator functions in `qualys/aggregators.py` are the building blocks. Each
wraps one or more Qualys API calls and returns normalized data. Examples:

- `cve_investigate_agg()` -- KB lookup + asset search + threat intel for a CVE
- `cloud_risk_agg()` -- AWS/Azure/GCP/OCI connector + evaluation data
- `compliance_posture_agg()` -- PC policy pass/fail rates
- `patch_priorities_agg()` -- outstanding patches ranked by risk
- `scanner_health_agg()` -- scanner appliance status
- `totalai_detections_agg()` -- 374 TotalAI model detections (jailbreaks, OWASP LLM Top 10)
- `policy_audit_agg()` -- 1,247 CIS/DISA STIG policies from /pcas/v1/library/
- `saasdr_controls_agg()` -- 230 SaaS security controls via /sdr/api/controls/

### KB Semaphore

A semaphore in `qualys/api.py` serializes concurrent KnowledgeBase requests,
preventing 409 Conflict errors that previously caused CVE investigation timeouts (#214, #215).

### Caching

Tiered in-memory cache in `qualys/api.py`:

| Cache | TTL | Key Strategy |
|-------|-----|-------------|
| Bearer token | 3.5 hours | Single global token |
| VMDR KB entries | 1 hour | Per-QID |
| VMDR detections | 5 minutes | Per severity_days_qds_min |
| QDS scores | 5 minutes | Per-QID |
| WAS findings | 10 minutes | Per query params |
| Scanner list | 5 minutes | Single global list |
| ETM results | 1 hour | Single global (unfiltered) |

Request deduplication via `_get_or_fetch()` prevents duplicate API calls when multiple
aggregators request the same underlying data concurrently.

### Concurrency

`ThreadPoolExecutor(max_workers=8)` via `_run_concurrent()`. Workflow modules dispatch
multiple aggregator calls in parallel. Cloud provider fetches (AWS, Azure, GCP, OCI) run
concurrently rather than sequentially.

### Cache warmup

On startup, a background thread pre-warms the VMDR detection cache so the first real
query is fast. See `_warmup_vmdr_cache()` in `qualys/api.py`.

## New Modules in v0.1.x

| Module | API Endpoint | Coverage |
|--------|-------------|---------|
| TotalAI | `/tai/api/1.0/` | 374 model detections — jailbreaks, OWASP LLM Top 10 |
| Policy Audit | `/pcas/v1/library/` | 1,247 compliance policies — CIS, DISA STIG |
| SaaS Detection & Response | `/sdr/api/controls/` | 230 SaaS security controls |
| OCI Cloud Resources | TotalCloud v2 API | OCI alongside AWS/Azure/GCP |
