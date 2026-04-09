# Qualys MCP v0.1.6 -- Performance

## Measured Benchmarks

Measured against a real Qualys tenant with 89K assets and 295 test cases.

| Tool | Typical Latency | Notes |
|------|----------------|-------|
| `security_overview` (quick=True) | ~1.7s | CSAM-heavy, cached |
| `security_overview` (full) | ~8-10s | All sources, parallel |
| `check_compliance` (cached) | <1ms | Cached compliance data |
| `check_compliance` (cold) | ~5-12s | PC API + CSAM + policy audit |
| `assess_risk` (cloud) | ~1.3s | Parallel AWS/Azure/GCP/OCI |
| `assess_risk` (containers) | ~3.1s | Container image scan |
| `assess_risk` (all) | ~4.9s | All domains in parallel |
| `assess_risk` (certs) | ~2-5s | CertView API |
| `investigate` (CVE) | ~33s | KB + CSAM + threat intel, no timeout |
| `plan_remediation` (patches) | ~2.6s | PM + CSAM parallel |
| `reports` (list) | ~2-5s | Report API |
| `cache_status` | <1ms | Memory lookup |

All standard-depth responses complete under 15 seconds. CVE investigations run ~33s
due to comprehensive KB, asset, and threat intelligence lookups. The KB semaphore
fix (#214, #215) ensures CVE investigations no longer time out.

---

## Cold Start Behavior

The first query after launching the MCP server will be slower than subsequent queries.

| Phase | Time | What happens |
|-------|------|-------------|
| Import & init | ~50ms | Python modules load, POD URLs resolve |
| Bearer token | ~300ms | First API authentication call |
| First query | 2-10s | No cache — all API calls hit Qualys cold |
| Subsequent queries | <2s typical | In-memory + disk cache populated |

### What warms up automatically

On startup, a background thread pre-fetches VMDR detections (severity 3-5) to warm the
disk cache. This runs silently and takes 30-60 seconds on large environments. Once warm,
detection-based queries (ETM findings, investigate) are significantly faster.

### Cache TTLs

| Cache | TTL | Scope |
|-------|-----|-------|
| Bearer token | 3.5 hours | Authentication |
| CSAM counts | 5 minutes | Asset counts |
| CSAM search | 5 minutes | Asset search results |
| VMDR detections | 30 minutes (memory), 4 hours (disk) | Vulnerability detections |
| Compliance posture | 6 hours (disk) | Compliance data |
| WAS findings | 10 minutes | Web app vulnerabilities |
| Cloud evaluations | 4 hours (disk) | Cloud posture |

### Tips for faster responses

- **Ask a quick overview first** — `security_overview(quick=True)` warms CSAM caches in ~1.5s
- **Compliance is slow on first call** (~2 minutes) but near-instant after (disk cached for 6 hours)
- **CVE investigations** always take ~30s due to KB + detection cross-reference — this is API-bound, not cache-bound
- **Scoped queries are faster** — `assess_risk(scope="cloud")` is faster than `assess_risk(scope="all")`

---

## Architecture Performance

### Async Tools

MCP tool handlers are `async` functions using `asyncio.to_thread` to dispatch blocking
workflow calls. This prevents event loop blocking and enables multiple concurrent tool
invocations without stalling the MCP server.

### Caching

Tiered in-memory cache eliminates redundant API calls:

| Cache | TTL | Impact |
|-------|-----|--------|
| Bearer token | 3.5 hours | Eliminates auth overhead |
| KB entries | 1 hour | Instant QID/CVE lookups on repeat |
| VMDR detections | 5 minutes | Fast threat intel queries |
| WAS findings | 10 minutes | Instant web app queries |
| Scanner list | 5 minutes | Fast scanner health |
| ETM results | 1 hour | Instant ETM queries |

### Concurrency

`ThreadPoolExecutor(max_workers=8)` runs independent aggregator calls in parallel.
Cloud providers (AWS, Azure, GCP, OCI) are fetched concurrently rather than sequentially.
Typical parallel dispatch: 3-8 aggregator calls per workflow invocation.

### KB Semaphore

A semaphore serializes concurrent KnowledgeBase requests, preventing 409 Conflict
errors that previously caused CVE investigation timeouts. Fixed in v0.1.x (#214, #215).

### Cache Warmup

On startup, `_warmup_vmdr_cache()` pre-populates the VMDR detection cache in a
background thread so the first real query is fast.

### Request Deduplication

`_get_or_fetch()` with per-key locking prevents duplicate API calls when multiple
aggregators request the same data concurrently within a single workflow invocation.

---

## API Latency Baseline

Typical single-request latencies to Qualys APIs:

| API / Endpoint | Latency |
|----------------|---------|
| CSAM v2 count | 0.2-0.5s |
| CSAM v2 search (100 assets) | 0.5-3s |
| VMDR KB lookup (single QID) | 0.5-1s |
| ETM report list/detail | 0.5-3s |
| WAS findings | 5-30s |
| Container images | 1-3s |
| TotalCloud connectors (AWS/Azure/GCP/OCI) | 0.5-2s per provider |
| CDR findings | 1-5s |
| PM jobs | 1-3s |
| Scanner appliance list | 1-3s |
| FIM/EDR events | 1-5s |
| CertView certificates | 1-5s |
| TotalAI detections | 0.5-2s |
| Policy Audit library | 0.5-2s |
| SaaSDR controls | 0.5-2s |
