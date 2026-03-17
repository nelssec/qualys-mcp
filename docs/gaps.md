# Qualys MCP — Tool Coverage & Gap Analysis

Updated: 2026-03-17 | v2.15 | 29 active tools | 14 deprecated stubs | 515 customer questions

---

## Active Tool → Question Coverage Map

### Investigation & Reporting

| Tool | Covers | Notes |
|------|--------|-------|
| `investigate` | Q1–7, Q8–10 (partial) | Deep-dive on any security topic; chains other tools internally |
| `investigate_cve` | Q11–20 | CVE → QID → KB → asset inventory pipeline |
| `summarize_investigation` | Q503–504 | Narrative summaries for exec or technical audiences |
| `get_morning_report` | Q2–3, Q82–84, Q501–502 | Morning briefing with quick mode; includes `_gaps` and `_next` |
| `reports` | Q81, Q86 | Unified report ops: list, templates, generate, status, download, delete |

### Vulnerability Management

| Tool | Covers | Notes |
|------|--------|-------|
| `search_vulns` | Q1, Q5–9, Q27, Q41–50 | KB search: new vulns, RTI filtering, software-specific lookups |
| `get_cve_details` | Q16, Q19–20 | Bulk CVE lookup (1–20 CVEs at once) |
| `get_qid_details` | Q21–27 | Direct QID lookup: severity, QDS, patches, threat intel, CVEs |
| `get_etm_findings` | Q31–32 | Confirmed vuln/misconfig findings from VMDR, TotalCloud, third-party |
| `get_vuln_exceptions` | Q75–80 (partial) | Exceptions, waivers, false positives, expiry tracking |
| `get_trurisk_score` | Q51–56 | Org-level TruRisk with trending, top assets, top QIDs, tag breakdown |
| `get_weekly_priorities` | Q4, Q83 | Top high-risk assets ranked by TruRisk, severity tiers |

### Asset Management

| Tool | Covers | Notes |
|------|--------|-------|
| `get_asset` | Single-asset queries | Risk profile, OS, software, EOL, detections (summary or full) |
| `get_asset_inventory` | Q396–410 (partial), Q421–430 (partial) | Search by OS, tag, keyword, EOL, staleness; list_tags/list_groups |
| `get_tech_debt` | Q397–399, Q411–416 | EOL/EOS systems sorted by criticality and risk |
| `get_risk_by_tag` | Q55, Q58–59 | Aggregate risk for a tag group: TruRisk tiers, top assets, EOL |

### Patch Management & TruRisk Eliminate

| Tool | Covers | Notes |
|------|--------|-------|
| `get_patch_status` | Q71–74, Q91–93, Q101–103 | TruRisk by severity tier, top unpatched assets |
| `get_eliminate_status` | Q141–151 (partial) | PM jobs, MTG jobs, patch catalog size, managed asset counts |

### Cloud Security

| Tool | Covers | Notes |
|------|--------|-------|
| `get_cloud_risk` | Q171–198 (partial) | CSPM posture + CDR threats; CIS benchmark failures; connector health |

### Web Application Security

| Tool | Covers | Notes |
|------|--------|-------|
| `get_webapp_vulns` | Q281–295 (partial), Q306–310 (partial) | WAS findings: severity, OWASP categories, per-app breakdown |

### Endpoint Security

| Tool | Covers | Notes |
|------|--------|-------|
| `get_edr_events` | Q331–344 (most) | Malware, ransomware, C2, lateral movement, process injection |
| `get_fim_events` | Q346–357 (most), Q363–364 | File changes, critical modifications, path/host filtering |

### Certificates

| Tool | Covers | Notes |
|------|--------|-------|
| `get_expiring_certs` | Q366–373 (most), Q376–379, Q382, Q385–392 (partial) | Expiry monitoring, weak ciphers, TLS 1.0/1.1, self-signed, SHA-1 |

### Compliance

| Tool | Covers | Notes |
|------|--------|-------|
| `get_compliance_posture` | Q436–446 (partial) | Pass/fail by framework: CIS, PCI-DSS, HIPAA, NIST, SOC2, ISO27001 |

### Scanner & Infrastructure

| Tool | Covers | Notes |
|------|--------|-------|
| `get_scanner_health` | Q481–485 | Scanner online/offline, scan load, vuln signature currency |
| `get_scan_status` | Q486–489 | Running, queued, failed scans with duration and target info |

### Container Security

| Tool | Covers | Notes |
|------|--------|-------|
| `get_image_vulns` | Q241–249 (partial) | Image-level vuln severity breakdown with fix versions |

### Other

| Tool | Covers | Notes |
|------|--------|-------|
| `get_recommendations` | Q85 | Program recommendations; identifies coverage gaps across modules |
| `cache_status` | — | Operational: cache stats and flush (not question-facing) |

---

## Coverage Summary by Category

Counts derived from per-question annotations in `docs/questions.md`:

| Category | Total | ✅ | ⚠️ | ❌ | Coverage |
|----------|------:|---:|---:|---:|---------:|
| Investigation Chaining | 10 | 7 | 3 | 0 | 85% |
| Vulnerability Management | 90 | 58 | 14 | 18 | 72% |
| Patch Management | 50 | 7 | 5 | 38 | 19% |
| TruRisk Eliminate | 30 | 8 | 4 | 18 | 33% |
| Cloud Security | 70 | 14 | 9 | 47 | 26% |
| Container Security | 40 | 6 | 6 | 28 | 22% |
| Web Application Security | 50 | 8 | 12 | 30 | 28% |
| Endpoint / EDR + FIM | 35 | 15 | 13 | 7 | 61% |
| Certificates / CertView | 30 | 13 | 10 | 7 | 60% |
| Asset Management | 40 | 14 | 13 | 13 | 51% |
| Compliance | 45 | 7 | 4 | 34 | 20% |
| Scanner / Infrastructure | 20 | 9 | 4 | 7 | 55% |
| Growth Engine | 5 | 4 | 1 | 0 | 90% |
| **Total** | **515** | **170** | **98** | **247** | **43%** |

Coverage % = (✅ + ⚠️ × 0.5) / Total

Previous assessment (pre-v2.15): 76 ✅ / 39 ⚠️ / 385 ❌ (23%)
Current (v2.15): **170 ✅ / 98 ⚠️ / 247 ❌ (43%)**

Coverage nearly doubled since the last gap analysis. The biggest gains came from Vulnerability Management (50% → 72%), Endpoint/EDR+FIM (→ 61%), Certificates (→ 60%), and Asset Management (→ 51%).

---

## Remaining Gaps

### Gap 1: Trend & Historical Analysis (~40 questions)

**Affected questions:** Q34–40, Q57, Q60, Q87–90, Q131–140, Q183, Q202, Q224, Q249, Q329–330, Q345, Q359, Q449, Q474, Q491

**What's missing:** Week-over-week and month-over-month trend data — vulnerability trends over 90 days, remediation rates over time, TruRisk change month-over-month.

**Why it's hard:** The Qualys VMDR API does not provide historical snapshot endpoints. Trends would need to be computed from detection firstFound/lastFixed dates or from periodic snapshots stored externally.

**Recommendation:** A `get_vuln_trends` tool could approximate trends from current detection data with date filtering. Moderate effort — would cover ~40 questions.

### Gap 2: Detailed Patch Management (~30 questions)

**Affected questions:** Q96–100, Q106–130

**What's missing:** Individual patch job queries (by ID), specific KB patch lookups, patch scheduling, maintenance windows, rollback history, per-vendor patch breakdowns.

**Why it's hard:** The Qualys PM API provides job-level data, but mapping individual patches to assets requires deep PM API integration. Many of these questions assume a patch-management-centric workflow that goes beyond the current Eliminate-focused approach.

**Recommendation:** Extend `get_eliminate_status` with a `job_id` parameter for per-job detail and a `vendor` filter. Covers ~10 more questions with minimal effort. The remaining 20 (maintenance windows, exclusions, scheduling) require PM API features not yet explored.

### Gap 3: Cloud-Specific Resource Queries (~25 questions)

**Affected questions:** Q201–215, Q226–240

**What's missing:** Queries about specific cloud resource types (Lambda functions, RDS instances, S3 buckets by name), per-account connector listing, cloud asset inventory by provider.

**Why it's hard:** `get_cloud_risk` provides aggregate posture and CDR findings but doesn't support resource-type-specific queries. The TotalCloud API has granular resource endpoints that aren't yet wrapped.

**Recommendation:** A `get_cloud_resources` tool with `resource_type` and `provider` params could cover ~15 of these. Low-medium effort.

### Gap 4: Kubernetes & Container Runtime (~20 questions)

**Affected questions:** Q256–275

**What's missing:** K8s cluster inventory, namespace-level vuln breakdown, RBAC analysis, pod-level queries, container runtime inventory.

**Why it's hard:** Qualys Container Security API provides image scanning but K8s runtime data requires the Qualys K8s sensor and separate API endpoints not yet integrated.

**Recommendation:** A `get_container_runtime` tool could surface running containers and basic K8s data. Medium effort — covers ~10 questions.

### Gap 5: WAS Scan Management & Remediation (~20 questions)

**Affected questions:** Q296–305, Q316–325

**What's missing:** WAS scan status, scan scheduling, per-app scan history, web vuln remediation tracking, web vuln aging analysis.

**Why it's hard:** `get_webapp_vulns` covers findings but not the scan management side. The WAS API has separate endpoints for web app inventory and scan management.

**Recommendation:** Extend `get_webapp_vulns` with a `scan_status=True` parameter or add a `get_webapp_scans` tool. Low effort — covers ~10 questions.

### Gap 6: Granular Compliance Controls (~30 questions)

**Affected questions:** Q447–470

**What's missing:** Framework-specific deep dives (FedRAMP, DISA STIG, CMMC, Essential 8), individual control queries, compliance-to-CVE mapping.

**Why it's hard:** `get_compliance_posture` provides top-level pass/fail rates but the Qualys PC module has hundreds of controls across dozens of frameworks.

**Recommendation:** Extend `get_compliance_posture` with a `control_id` parameter for single-control lookup. Low effort — covers ~5 more questions. Full framework coverage depends on customer licensing.

### Gap 7: SLA & Business-Unit Segmentation (~15 questions)

**Affected questions:** Q30, Q33, Q38–39, Q58, Q87–88, Q90, Q132, Q134, Q406–407, Q417

**What's missing:** SLA-based queries ("What's past SLA?"), business-unit breakdowns, department-level metrics.

**Why it's hard:** SLA definitions are customer-specific and not stored in Qualys APIs. Business-unit segmentation requires tag-based grouping that varies per customer.

**Recommendation:** No new tool needed. `get_risk_by_tag` and `get_asset_inventory` approximate business-unit queries when customers use tags consistently. SLA tracking is out of scope.

---

## Deprecated Tool Stubs (14)

These return error messages redirecting users to the consolidated replacement:

| Deprecated | Replacement |
|------------|-------------|
| `get_cdr_findings` | `get_cloud_risk(include_threats=True)` |
| `get_asset_risk` | `get_asset(detail='summary')` |
| `get_asset_full_profile` | `get_asset(detail='full')` |
| `get_environment_summary` | `get_morning_report(quick=True)` |
| `get_pm_status` | `get_eliminate_status()` |
| `get_tags` | `get_asset_inventory(list_tags=True)` |
| `get_asset_groups` | `get_asset_inventory(list_groups=True)` |
| `get_assets_by_tag` | `get_asset_inventory(tag='...')` |
| `list_reports` | `reports(action='list')` |
| `list_report_templates` | `reports(action='templates')` |
| `generate_report` | `reports(action='generate')` |
| `get_report_status` | `reports(action='status')` |
| `download_report` | `reports(action='download')` |
| `delete_report` | `reports(action='delete')` |

---

## Potential New Tools (Priority Order)

| Tool | Est. Questions | Effort | Notes |
|------|---------------|--------|-------|
| `get_vuln_trends` | ~40 | Medium | Computed from detection dates; no native historical API |
| `get_cloud_resources` | ~15 | Low-Med | Resource-type-specific cloud queries via TotalCloud API |
| `get_container_runtime` | ~10 | Medium | Running containers, K8s cluster/namespace inventory |
| `get_webapp_scans` | ~10 | Low | WAS scan management and scheduling |
| Extend `get_eliminate_status` | ~10 | Low | Add `job_id` for per-job detail, `vendor` filter |
| Extend `get_compliance_posture` | ~5 | Low | Add `control_id` for single-control lookup |

Building all of these would bring total coverage from 43% to approximately 60%. The remaining 40% consists of highly granular queries (individual patch KBs, K8s RBAC, cloud resource-type specifics, SLA tracking) that require either deep API integration or customer-specific configuration.

---

## Live Eval Results — US2 Tenant (2026-03-17)

Measured against real Qualys US2 tenant using `scripts/eval_live.py`.
34 active tools tested (14 deprecated stubs skipped).

### Summary

| Metric | Value |
|--------|-------|
| Tools tested | 34 |
| ✓ Pass (ok/empty) | 29 (85.3%) |
| ✗ Error | 5 (14.7%) |
| Total latency | 272s |

### Per-Tool Results

| Tool | Status | Latency | Notes |
|------|--------|---------|-------|
| `cache_status` | ✓ ok | 0.0s | 1 returned |
| `get_scanner_health` | ✓ ok | 9.4s | 17 scanners |
| `get_scan_status` | ✓ ok | 1.9s | 68 scans (50 returned) |
| `get_morning_report` | ✓ ok | 1.2s | 1 report |
| `get_weekly_priorities` | ✓ ok | 4.9s | 0 returned (no data) |
| `search_vulns` | ✓ ok | 61.1s | 3366 vulns (10 returned) |
| `get_cve_details` | ✓ ok | 60.1s | 1 returned |
| `get_qid_details` | ✓ ok | 48.2s | 1 returned |
| `get_etm_findings` | ✓ ok | 7.1s | findings present |
| `get_patch_status` | ✓ ok | 0.8s | 0 returned (no PM data) |
| `get_eliminate_status` | ✓ ok | 1.0s | 1 returned |
| `get_recommendations` | ✓ ok | 37.0s | 6 recommendations |
| `get_asset_inventory` | ✓ ok | 0.3s | 0 returned (CSAM empty) |
| `get_tech_debt` | ✓ ok | 0.3s | 0 returned (no EOL assets) |
| `get_cloud_risk` | ✓ ok | 0.7s | 0 returned (no cloud data) |
| `get_webapp_vulns` | ✓ ok | 4.0s | 0 returned (no WAS data) |
| `get_expiring_certs` | ✓ ok | 0.2s | 0 returned |
| `get_vuln_exceptions` | ✓ ok | 0.2s | 0 returned |
| `get_compliance_posture` | ✗ error | 12.6s | PC module not licensed |
| `get_trurisk_score` | ✓ ok | 0.8s | 0 returned (no TruRisk data) |
| `get_edr_events` | ✓ ok | 0.3s | 0 returned (no EDR data) |
| `get_fim_events` | ✓ ok | 0.2s | 0 returned (no FIM data) |
| `reports_list` | ✓ ok | 4.7s | 115 reports |
| `reports_templates` | ✗ error | 0.2s | Template API endpoint not accessible |
| `get_asset_inventory_tags` | ✓ ok | 0.3s | 0 returned |
| `get_asset_inventory_groups` | ✓ ok | 0.2s | 0 returned |
| `get_asset_summary` | ✗ error | 0.0s | No asset_id (CSAM returned empty) |
| `get_asset_full` | ✗ error | 0.0s | No asset_id (CSAM returned empty) |
| `get_risk_by_tag` | ✗ error | 0.0s | No tags found in tenant |
| `get_image_vulns` | ✓ ok | 0.3s | 0 returned (no container data) |
| `investigate_cve` | ✓ ok | 7.3s | 11 results |
| `investigate` | ✓ ok | 5.1s | 2 results |
| `summarize_investigation` | ✓ ok | 0.0s | ok |
| `reports_status` | ✓ ok | 1.6s | 1 returned |

### Error Classification

| Tool | Error Type | Root Cause |
|------|-----------|------------|
| `get_compliance_posture` | Expected (not licensed) | PC module not in this subscription |
| `reports_templates` | Bug | Template API endpoint returns empty (needs investigation) |
| `get_asset_summary` | Expected (no data) | CSAM returned 0 assets for this tenant |
| `get_asset_full` | Expected (no data) | CSAM returned 0 assets for this tenant |
| `get_risk_by_tag` | Expected (no data) | No tags configured on this tenant |

### Known Fixes Applied

- **Scanner parsing** (`get_scanner_health`): Added `safe_int()` helper to handle empty XML fields — `invalid literal for int() with base 10: ''` bug fixed
- **CSAM 400 errors** were investigated; the tenant simply has no CSAM assets (not a code bug)

