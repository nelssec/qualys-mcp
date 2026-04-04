# Qualys MCP Workflow Orchestrator Design

**Date:** 2026-04-03
**Version:** 3.0 (proposed)
**Status:** Draft

## Problem

qualys-mcp v2.16.0 exposes 53 MCP tools (38 active + 15 deprecated stubs). Research shows LLM tool selection accuracy drops ~10% going from 10 to 100 tools. Qualys spans 18 modules (VMDR, CSAM, TotalCloud, WAS, EDR, FIM, CertView, PM, PC, etc.) creating a combinatorial explosion of "get risk for X across Y" queries that overwhelms both LLMs and users.

Competitor analysis:
- falcon-mcp (CrowdStrike): ~49 tools, flat provider, no orchestration, relies on LLM to chain
- purple-mcp (SentinelOne): 22 tools, flat, read-only
- studio-mcp (Snyk): 8 tools, profile-based selection
- Recommended sweet spot: 5-15 tools per server

## Solution

Replace the 53 individual tools with 5 analytical workflow tools + 2 utility tools (7 total). Each workflow tool receives structured parameters, dispatches to existing aggregators concurrently, and returns a synthesized response with cross-domain correlations and prioritized actions.

### Design Decisions

1. **Workflow tools over single orchestrator** - Discrete, well-named tools route more accurately than a catch-all. Customers can see exactly what the MCP does from the tool list.
2. **Parameter-based dispatch over NLP routing** - The LLM fills structured parameters (what it's good at). The workflow uses parameters deterministically to select aggregators (what code is good at). No keyword parsing, no embedded LLM calls, no extra cost.
3. **Hardcoded workflow library over LLM planner** - For a published customer-facing product: predictable, testable, debuggable, zero hidden cost. No LLM API key needed inside the MCP server.
4. **Analytical synthesis over raw aggregation** - Workflows correlate findings across domains, rank by risk, and provide prioritized actions. Not just data merging.
5. **Preserve existing layers** - api.py, aggregators.py, and cache.py are untouched. Workflows are a new layer on top.

## Tool Surface

### 7 MCP Tools

#### 1. `investigate`

Threat investigation — CVE deep-dive, threat actor exposure, endpoint events, vulnerability intelligence.

```
investigate(
    target: str,                    # CVE ID, threat actor, hostname, IP, or free-text topic
    depth: str = "standard",        # "quick" | "standard" | "deep"
    scope: str = "all",             # "all" | "vulns" | "threats" | "assets" | "edr" | "fim"
    tag: str = "",                  # filter affected assets by tag
    asset_group: str = "",          # filter by asset group
    threat_type: str = "",          # RTI: Ransomware, Active_Attacks, CISA, etc.
    software: str = "",             # software name filter for KB search
    days: int = 7,                  # lookback window for events/vulns
    limit: int = 20,
    detail: str = "standard",       # "summary" | "standard" | "detailed"
    prior_context: str = "",        # chain from previous investigation
    audience: str = "technical",    # "technical" | "management" | "executive"
)
```

#### 2. `assess_risk`

Risk assessment across all domains — VMs, cloud, containers, web apps, certificates, assets.

```
assess_risk(
    scope: str = "all",             # "all" | "cloud" | "containers" | "web" | "certs" | "assets"
    tag: str = "",
    asset_group: str = "",
    asset_id: str = "",             # single asset deep-dive
    os: str = "",
    query: str = "",                # hostname/asset name search
    days_since_seen: int = 0,       # stale asset filter
    days_since_scan: int = 0,       # scan gap filter
    eol_only: bool = False,
    provider: str = "",             # "aws" | "azure" | "gcp"
    service: str = "",              # cloud service (S3, IAM, EC2, Lambda, etc.)
    account_id: str = "",
    per_account: bool = False,
    image_id: str = "",             # specific container image
    app_name: str = "",             # web app name filter
    owasp_category: str = "",
    protocol_filter: str = "",      # TLS version filter
    weak_ciphers: bool = False,
    weak_only: bool = False,
    insecure_renegotiation: bool = False,
    include_expired: bool = True,
    days: int = 30,
    limit: int = 20,
    detail: str = "standard",
    sort_by: str = "trurisk",       # "trurisk" | "severity"
    breakdown_by: str = "tag",      # "tag" | "none"
)
```

#### 3. `check_compliance`

Compliance posture — framework pass/fail, control failures, risk acceptances.

```
check_compliance(
    framework: str = "",            # "PCI" | "HIPAA" | "SOC2" | "CIS" | "NIST" | ""
    platform: str = "",
    tag: str = "",
    asset_group: str = "",
    include_exceptions: bool = False,
    exception_status: str = "Active",
    vuln_type: str = "",            # "False Positive" | "Compensating Control"
    days_to_expiry: int = 30,
    limit: int = 20,
    detail: str = "standard",
)
```

#### 4. `plan_remediation`

Remediation planning — patch priorities, deployment status, mitigation coverage, program gaps.

```
plan_remediation(
    scope: str = "all",             # "all" | "patches" | "mitigations" | "program"
    tag: str = "",
    asset_group: str = "",
    platform: str = "",             # "windows" | "linux"
    severity: str = "",             # "critical" | "high" | "moderate"
    status: str = "",               # patch job status filter
    qids: list = None,              # check mitigation coverage for specific QIDs
    cves: list = None,              # check mitigation coverage for specific CVEs
    limit: int = 20,
    detail: str = "standard",
)
```

#### 5. `security_overview`

Daily/weekly/monthly security briefing — cross-domain summary with change detection.

```
security_overview(
    period: str = "today",          # "today" | "week" | "month"
    scope: str = "all",             # "all" | "infrastructure" | "findings" | "risk"
    quick: bool = False,
    tag: str = "",
    asset_group: str = "",
    qql: str = "",                  # QQL query for ETM findings
    severity: str = "",
    scan_state: str = "Running,Paused,Queued,Error",
    limit: int = 50,
    detail: str = "standard",
)
```

#### 6. `reports` (unchanged from v2.16)

```
reports(
    action: str,                    # "list" | "templates" | "generate" | "status" | "download" | "delete"
    report_id: str = "",
    template_id: str = "",
    asset_group_ids: str = "",
    template_name: str = "",
    report_title: str = "",
    output_format: str = "pdf",
)
```

#### 7. `cache_status` (unchanged from v2.16)

```
cache_status(clear: bool = False)
```

## Dispatch Logic

Each workflow uses deterministic parameter-based routing. If a parameter is set, include the aggregator that serves it.

### `investigate` dispatch

```
target matches CVE pattern       → investigate_cve_agg + cve_details
target matches APT_MAP/INDUSTRY  → threat_actor_exposure_agg
target is hostname/IP            → asset_detail + edr_events + fim_events
scope includes "edr"             → edr_events
scope includes "fim"             → fim_events
scope includes "vulns"           → search_vulns_agg
depth == "deep"                  → all of the above + summarize_investigation_agg
always                           → investigate_agg (handles multi-source chaining)
```

### `assess_risk` dispatch

```
scope == "all" or no scope params  → trurisk_score + weekly_priorities
asset_id set                       → asset_detail (skip broad queries)
tag set (without asset_id)         → risk_by_tag
scope == "cloud" or cloud params   → cloud_risk + cloud_account_summary + cloud_controls
scope == "containers" or image_id  → container_vuln_summary + image_vulns + running_containers
scope == "web" or web params       → webapp_vulns
scope == "certs" or cert params    → expiring_certs + cert_security_posture
eol_only or staleness params       → tech_debt + asset_inventory
scope == "all"                     → all of the above (concurrent)
```

### `check_compliance` dispatch

```
always                → compliance_posture
framework == "" or "list"  → list_compliance_frameworks
include_exceptions    → vuln_exceptions
```

### `plan_remediation` dispatch

```
scope == "all"                    → patch_status + eliminate_status + outstanding_patches
scope == "patches"                → patch_status + outstanding_patches
scope == "mitigations" or qids/cves  → eliminate_coverage
scope == "program"                → recommendations
always (when scope=="all")        → eliminate_status
```

### `security_overview` dispatch

```
always                            → morning_report(quick=quick)
scope includes "infrastructure"   → scanner_health + scan_status
scope includes "findings" or qql  → etm_findings
scope == "all"                    → all of the above
period == "week"                  → sets days=7 on relevant aggregators
period == "month"                 → sets days=30
```

### Execution pattern (all workflows)

1. Evaluate dispatch rules, build list of aggregators to call
2. Run all selected aggregators concurrently via `_run_concurrent`
3. Merge results into unified response envelope
4. Apply cross-domain correlation logic
5. Apply detail level filtering

## Response Synthesis

### Unified response envelope

```json
{
    "workflow": "assess_risk",
    "aggregators_called": ["trurisk_score", "weekly_priorities", "cloud_risk"],
    "execution_time_ms": 4200,

    "summary": {
        "headline": "Critical risk: 3 CVEs with active exploitation affect 47 production assets",
        "risk_level": "critical",
        "key_findings": ["...", "...", "..."],
        "stats": {}
    },

    "data": {
        "trurisk": {},
        "cloud": {},
        "containers": {},
        "vulnerabilities": {}
    },

    "correlations": [
        {
            "finding": "CVE-2024-3400 affects 12 VMs and 3 container images",
            "severity": "critical",
            "sources": ["trurisk", "containers"]
        }
    ],

    "actions": [
        {
            "priority": 1,
            "action": "Patch CVE-2024-3400 on 12 production VMs",
            "scope": "15 assets",
            "tool_hint": "plan_remediation(cves=['CVE-2024-3400'])"
        }
    ],

    "_meta": {
        "total_results": 142,
        "returned": 20,
        "truncated": true
    }
}
```

### Vulnerability identity fields (always preserved)

Every vulnerability item in any data section or correlation includes:

- `qid`: Qualys QID
- `cve`: CVE ID(s)
- `qvs`: Qualys Vulnerability Score (QDS/QVS)
- `cvss`: CVSS score + version
- `severity`: normalized severity level
- `title`: vulnerability title
- `patch_available`: bool
- `threat_intel`: RTI tags (ransomware, active_attacks, etc.)

These are never stripped by detail level. Even `"summary"` mode keeps them on any referenced vulnerability.

### Synthesis rules per workflow

**`investigate`** — Cross-references CVE to affected assets to active EDR/FIM events. Links threat actor TTPs to detected vulnerabilities. Ranks actions by: actively exploited > patchable > mitigatable > monitor.

**`assess_risk`** — Normalizes risk across domains (TruRisk for VMs, control failures for cloud, CVSS for containers). Identifies assets appearing in multiple risk categories. Groups findings by business impact using tags.

**`check_compliance`** — Cross-references failing controls with available patches/mitigations. Flags exceptions nearing expiry. Highlights controls failing across multiple frameworks.

**`plan_remediation`** — Ranks patches by: asset count x severity x TruRisk reduction. Groups by deployment window (quick wins vs maintenance window). Cross-references with eliminate coverage.

**`security_overview`** — Compares current state to period baseline. Flags new items: new critical vulns, scanner failures, expired certs. Surfaces anything requiring immediate attention first.

### Detail level behavior

- `"summary"` — summary + actions only, data sections omitted, max 5 findings
- `"standard"` — full response, lists capped at limit
- `"detailed"` — full response, includes raw aggregator outputs in `_raw` key

## Architecture

### Current structure

```
qualys/
    __init__.py
    api.py              # 1,622 lines — HTTP, auth, caching, pagination
    aggregators.py      # 5,567 lines — 42 aggregator functions
    cache.py            # 151 lines — SQLite disk cache
qualys_mcp.py           # 1,082 lines — 53 tool wrappers
```

### Proposed structure

```
qualys/
    __init__.py
    api.py              # unchanged
    aggregators.py      # unchanged (now internal-only building blocks)
    cache.py            # unchanged
    workflows/
        __init__.py     # shared: _dispatch, _merge, _synthesize, _apply_detail, _vuln_identity
        investigate.py  # investigate() dispatch + synthesis
        assess_risk.py  # assess_risk() dispatch + synthesis
        compliance.py   # check_compliance() dispatch + synthesis
        remediation.py  # plan_remediation() dispatch + synthesis
        overview.py     # security_overview() dispatch + synthesis
qualys_mcp.py           # ~150 lines — 7 tool wrappers
```

### Layer responsibilities

```
LLM
  → qualys_mcp.py (7 tools, thin wrappers)
    → workflows/ (dispatch + synthesize) [NEW]
      → aggregators.py (42 functions, unchanged)
        → api.py (HTTP + caching, unchanged)
          → Qualys APIs
```

### What changes

| Layer | Changes? | Detail |
|-------|----------|--------|
| api.py | No | Solid, well-tested |
| cache.py | No | Clean and simple |
| aggregators.py | No | 42 functions become internal building blocks |
| qualys_mcp.py | Rewritten | 53 tools → 7 tools |
| workflows/ | New | Dispatch logic + synthesis per workflow |

### What gets deleted

- All 15 deprecated tool stubs
- All 38 individual @mcp.tool() wrappers
- APT_MAP and INDUSTRY_MAP move to workflows/investigate.py

### Shared workflow utilities (`workflows/__init__.py`)

- `_dispatch(aggregator_map)` — runs selected aggregators concurrently
- `_merge(results, workflow)` — merges outputs into unified envelope
- `_synthesize(merged, rules)` — applies correlation logic, builds actions
- `_apply_detail(response, level)` — filters by detail level
- `_vuln_identity(item)` — ensures QID/CVE/QVS/CVSS fields are always present

### Each workflow module pattern

```python
def investigate(target, depth, scope, ...):
    plan = _build_plan(target, depth, scope, ...)
    results = _dispatch(plan)
    merged = _merge(results, workflow="investigate")
    synthesized = _synthesize(merged, rules=INVESTIGATE_RULES)
    return _apply_detail(synthesized, detail)
```

## Testing Strategy

### Layer 1: Dispatch Unit Tests

No API calls, no LLM. Deterministic verification that parameter combinations trigger correct aggregators.

**Parameter to aggregator mapping (exhaustive per workflow):**

- `assess_risk(scope="cloud")` must call cloud_risk, cloud_account_summary, cloud_controls
- `assess_risk(asset_id="123")` must call asset_detail only, skip broad queries
- `assess_risk(scope="all")` must call all aggregators concurrently
- `investigate(target="CVE-2024-3400")` must call investigate_cve_agg + cve_details
- `investigate(target="Lazarus")` must call threat_actor_exposure_agg
- `investigate(target="10.0.0.1")` must call asset_detail + edr_events + fim_events
- `plan_remediation(cves=["CVE-..."])` must call eliminate_coverage
- `plan_remediation(scope="program")` must call recommendations
- `check_compliance(include_exceptions=True)` must call compliance_posture + vuln_exceptions
- `security_overview(quick=True)` must call morning_report only
- Exhaustive for every dispatch branch in every workflow

**Edge cases:**

- `assess_risk(scope="cloud", image_id="123")` — scope wins, ignores container param
- `investigate(target="")` — graceful error, not a crash
- `plan_remediation(qids=[99999999])` — returns empty coverage, not an error
- `check_compliance(framework="NONEXISTENT")` — graceful "framework not found"
- `assess_risk(days_since_seen=0, days_since_scan=0)` — treated as no filter
- `investigate(target="CVE-invalid-format")` — falls back to free-text investigation

**Parameter passthrough:**

- tag/asset_group/limit/detail forwarded correctly to every aggregator
- days maps correctly per workflow defaults (investigate=7, assess_risk=30, etc.)
- detail="summary" propagates to all aggregators

### Layer 2: Synthesis Validation Tests

Mock aggregator outputs, verify response construction.

**Response envelope correctness:**

- summary.headline always present and non-empty
- summary.key_findings is 3-5 items, ranked by severity
- summary.risk_level is one of: critical/high/medium/low
- correlations only reference sources that were actually called
- actions ordered by priority (1 to N)
- actions[].tool_hint contains valid workflow + params
- _meta.total and _meta.returned are accurate
- workflow and aggregators_called fields are correct

**Vulnerability identity preservation:**

- Every vuln item has: qid, cve, qvs, cvss, severity, title, patch_available
- These survive detail="summary" filtering
- Missing upstream fields get null, not omitted
- QVS/CVSS are numeric, not strings

**Detail level filtering:**

- detail="summary" returns only summary + actions, no data sections, max 5 findings
- detail="standard" returns full response, lists capped at limit
- detail="detailed" includes _raw key with raw aggregator outputs
- Switching detail level does not change which aggregators are called

**Partial failure handling:**

- 3 of 5 aggregators succeed: response includes successful data + error list
- All aggregators fail: returns summary with error, not an exception
- One aggregator times out: others still return, timeout noted in response
- Aggregator returns empty: section omitted from data, not present as empty {}

### Layer 3: Integration Tests

Real API calls, end-to-end validation.

**Per-workflow coverage:**

For each workflow with each scope value:
- Call with default params produces valid response envelope
- Call with scoped params produces response with only relevant sections
- Call with detail="summary" produces abbreviated response
- Call with detail="detailed" includes _raw
- Response time within benchmark targets

**Cross-workflow chaining scenarios:**

Scenario 1 — CVE triage flow:
- investigate(target="CVE-2024-3400")
- Extract affected assets from response
- plan_remediation(cves=["CVE-2024-3400"])
- Verify remediation actions reference the same assets

Scenario 2 — Risk-to-compliance flow:
- assess_risk(scope="all")
- Extract top risk areas
- check_compliance(framework="CIS")
- Verify failing controls correlate with risk findings

Scenario 3 — Overview-to-investigation flow:
- security_overview(period="week")
- Extract critical findings from summary
- investigate(target=<top finding CVE>)
- Verify investigation covers the flagged finding

Scenario 4 — Full remediation lifecycle:
- assess_risk(tag="Production", scope="assets")
- Identify top risk assets
- plan_remediation(tag="Production", severity="critical")
- check_compliance(tag="Production")
- Verify remediation plan addresses compliance gaps

### Layer 4: Routing Evaluation

LLM-based tool selection accuracy.

**Remap existing 160+ question variants:**

Every question in question_variants.json gets:
- Old mapping: which of the 38 tools it routed to
- New mapping: which of the 5 workflows it should route to
- Expected parameters: what params the LLM should fill

**New ambiguous/complex questions:**

- "How's our security posture?" — assess_risk or security_overview (either acceptable)
- "Are we vulnerable to Log4Shell and are we patched?" — investigate
- "Show me everything about our AWS account" — assess_risk(scope="cloud", provider="aws")
- "What should the board know?" — security_overview or assess_risk
- "Compare risk across business units" — assess_risk(breakdown_by="tag")
- "We got hit by ransomware, what do we do?" — investigate(target="ransomware", scope="edr")

**Accuracy targets:**

- Workflow selection accuracy: >95% (up from ~85% with 38 tools)
- Parameter fill accuracy: >90%
- No question should route to reports or cache_status unless explicitly about reports/cache

### Layer 5: Response Quality Evaluation

LLM-judged grading of synthesis output.

**Grading criteria per response (1-5 scale):**

1. Completeness: Did the response include all relevant data sources?
2. Correlation quality: Are cross-domain insights accurate and non-obvious?
3. Action quality: Are recommended actions specific, scoped, and prioritized?
4. Headline accuracy: Does the headline capture the most important finding?
5. No hallucination (pass/fail): Every claim traceable to aggregator output

**Comparison testing:**

For 50 representative questions:
- Run against old 38-tool system (LLM chains tools manually)
- Run against new 5-workflow system
- LLM judge scores both on completeness, accuracy, actionability
- New system must score equal or higher on all dimensions

### Layer 6: Regression Testing

**Backwards compatibility verification:**

For every question in the existing test suite:
- Old system: record which tools were called and final response
- New system: run same question through workflow
- Verify: every data point present in old response appears in new response
- Allowed differences: structure changes, additional correlations, different ordering
- Not allowed: missing data, different numbers, dropped vulnerabilities

**Deprecated tool coverage:**

- Verify all 15 deprecated tools are removed from tool list
- Verify no routing eval question maps to a deprecated tool name
- Document migration path in README for customers upgrading

### Layer 7: Performance Benchmarks

| Workflow | Scope | Cold target | Warm target |
|----------|-------|-------------|-------------|
| investigate | quick | <10s | <5s |
| investigate | standard | <20s | <10s |
| investigate | deep | <45s | <15s |
| assess_risk | single scope | <8s | <3s |
| assess_risk | all | <20s | <8s |
| check_compliance | single framework | <8s | <3s |
| check_compliance | all + exceptions | <12s | <5s |
| plan_remediation | patches only | <8s | <3s |
| plan_remediation | all | <15s | <8s |
| security_overview | quick | <5s | <2s |
| security_overview | full | <15s | <6s |

**Concurrency validation:**

- Verify aggregators within a workflow run concurrently, not sequentially
- Total time should approximate max(individual times), not sum
- Flag any sequential bottlenecks

## Migration

### Breaking changes (v2 → v3)

- 38 individual tools removed, replaced by 5 workflow tools
- 15 deprecated stubs removed entirely
- Response structure changes (unified envelope with summary/data/correlations/actions)

### Customer migration path

- v2.x individual tool calls map to v3 workflow calls with specific parameters
- All data previously available through individual tools is accessible via workflow parameters
- Response data is a superset of individual tool responses (additional correlations and actions)

### Migration examples

```
v2: investigate_cve(cve="CVE-2024-3400")
v3: investigate(target="CVE-2024-3400")

v2: get_cloud_risk(provider="aws") + get_cloud_controls(provider="aws")
v3: assess_risk(scope="cloud", provider="aws")

v2: get_compliance_posture(framework="PCI") + get_vuln_exceptions()
v3: check_compliance(framework="PCI", include_exceptions=True)

v2: get_patch_status() + get_outstanding_patches() + get_eliminate_status()
v3: plan_remediation(scope="all")

v2: get_morning_report() + get_scanner_health()
v3: security_overview(period="today")
```
