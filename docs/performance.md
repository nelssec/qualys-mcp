# Qualys MCP v0.1.0 -- Performance

## Measured Benchmarks

Measured against a real Qualys tenant with 89K assets and 282 test cases.

| Tool | Typical Latency | Notes |
|------|----------------|-------|
| `security_overview` (quick=True) | ~1.7s | CSAM-heavy, cached |
| `security_overview` (full) | ~8-10s | All sources, parallel |
| `check_compliance` (cached) | ~2ms | Cached compliance data |
| `check_compliance` (cold) | ~5-12s | PC API + CSAM |
| `assess_risk` (containers) | ~3s | Container image scan |
| `assess_risk` (all) | ~5-10s | All domains in parallel |
| `assess_risk` (cloud) | ~5-8s | Parallel AWS/Azure/GCP |
| `assess_risk` (certs) | ~2-5s | CertView API |
| `investigate` (CVE, quick) | ~10s | KB + basic asset check |
| `investigate` (CVE, standard) | ~15-20s | KB + CSAM + threat intel |
| `investigate` (CVE, deep) | ~30-45s | All sources + summary |
| `plan_remediation` | ~3-8s | PM + CSAM parallel |
| `reports` (list) | ~2-5s | Report API |
| `cache_status` | <1ms | Memory lookup |

All tool responses complete under 15 seconds for standard depth.
Deep investigations may take up to 45 seconds when querying all sources.

---

## Architecture Performance

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
Cloud providers (AWS, Azure, GCP) are fetched concurrently rather than sequentially.
Typical parallel dispatch: 3-8 aggregator calls per workflow invocation.

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
| TotalCloud connectors | 0.5-2s per provider |
| CDR findings | 1-5s |
| PM jobs | 1-3s |
| Scanner appliance list | 1-3s |
| FIM/EDR events | 1-5s |
| CertView certificates | 1-5s |
