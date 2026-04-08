# Qualys MCP v0.1.6 -- Known Gaps & Limitations

## Current State

v0.1.6 ships 7 async workflow tools backed by 42 aggregator functions covering 13+ Qualys modules.
295 tests pass. Tested against a tenant with 89K assets.

New in v0.1.x: TotalAI (374 model detections), Policy Audit (1,247 policies), SaaSDR (230 controls), OCI cloud.
Fixed in v0.1.x: async tools prevent event loop blocking, KB semaphore prevents 409 conflicts, CVE investigate no longer times out.

---

## Known Gaps

### Gap 1: Trend & Historical Analysis

**What's missing:** Week-over-week and month-over-month trend data. Vulnerability trends over 90 days, remediation rates over time, TruRisk change month-over-month.

**Why:** The Qualys VMDR API does not provide historical snapshot endpoints. Trends would need to be computed from detection firstFound/lastFixed dates or from periodic snapshots stored externally.

**Workaround:** Use `security_overview(period="week")` or `security_overview(period="month")` for period-scoped views. For longer trends, export data via `reports()` and analyze externally.

### Gap 2: Granular Patch Management

**What's missing:** Individual patch job queries by ID, specific KB patch lookups, patch scheduling, maintenance windows, rollback history, per-vendor patch breakdowns.

**Why:** The Qualys PM API provides job-level data, but deep patch-management workflows require more API integration. `plan_remediation()` covers priorities and deployment status but not individual job management.

**Workaround:** Use `plan_remediation(scope="patches", platform="windows")` for platform-specific views. For individual job details, use the Qualys console.

### Gap 3: Kubernetes & Container Runtime

**What's missing:** K8s cluster inventory, namespace-level vuln breakdown, RBAC analysis, pod-level queries, container runtime inventory.

**Why:** Qualys Container Security API provides image scanning but K8s runtime data requires the Qualys K8s sensor and separate API endpoints not yet integrated.

**Workaround:** Use `assess_risk(scope="containers")` for image-level vulnerability data.

### Gap 4: WAS Scan Management

**What's missing:** WAS scan status, scan scheduling, per-app scan history, web vuln remediation tracking.

**Why:** `assess_risk(scope="web")` covers findings but not the scan management side.

**Workaround:** Use `assess_risk(scope="web", app_name="...")` for findings. Manage scans through the Qualys WAS console.

### Gap 5: SLA & Business-Unit Segmentation

**What's missing:** SLA-based queries ("What's past SLA?"), business-unit breakdowns, department-level metrics.

**Why:** SLA definitions are customer-specific and not stored in Qualys APIs. Business-unit segmentation requires tag-based grouping that varies per customer.

**Workaround:** Use `assess_risk(tag="...")` and `plan_remediation(tag="...")` for tag-based segmentation.

### Gap 6: Write Operations

**What's missing:** Creating remediation tickets, scheduling scans, modifying asset tags, accepting risks.

**Why:** v0.1.6 is read-only by design. Write operations require careful access control and confirmation flows.

**Status:** Under consideration for future releases.

---

## Module Coverage

| Module | Coverage | Tool |
|--------|----------|------|
| VMDR (vulnerability detection) | High | `investigate`, `assess_risk`, `security_overview` |
| ETM (enterprise trurisk) | High | `investigate`, `security_overview` |
| CSAM (asset management) | High | `assess_risk`, `security_overview` |
| KB (knowledge base) | High | `investigate` |
| TotalCloud (AWS/Azure/GCP/OCI) | Medium | `assess_risk(scope="cloud")` |
| Container Security | Medium | `assess_risk(scope="containers")` |
| WAS (web app scanning) | Medium | `assess_risk(scope="web")` |
| CertView (certificates) | Medium | `assess_risk(scope="certs")` |
| PM (patch management) | Medium | `plan_remediation` |
| EDR (endpoint detection) | Medium | `investigate(scope="edr")` |
| FIM (file integrity) | Medium | `investigate(scope="fim")` |
| PC (policy compliance) | Medium | `check_compliance` |
| CDR (cloud detection) | Medium | `assess_risk(scope="cloud")` |
| TotalAI (AI model security) | Medium | `investigate` |
| Policy Audit / PCAS | Medium | `check_compliance` |
| SaaS Detection & Response | Medium | `assess_risk` |
