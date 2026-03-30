#!/usr/bin/env python3
"""Qualys MCP Server — thin @mcp.tool wrappers over qualys.api + qualys.aggregators."""

from threading import Thread
from fastmcp import FastMCP
from qualys.api import BASE_URL, GATEWAY_URL, _resolved_pod, _log, _warmup_vmdr_cache
from qualys.aggregators import (
    _detect_gaps,
    weekly_priorities,
    investigate_cve_agg,
    investigate_agg,
    patch_status,
    search_vulns_agg,
    recommendations,
    eliminate_status,
    outstanding_patches,
    eliminate_coverage,
    scanner_health,
    etm_findings,
    morning_report,
    cve_details,
    qid_details,
    cloud_risk,
    cloud_account_summary,
    cloud_controls,
    asset_detail,
    tech_debt,
    image_vulns,
    image_vulns_list,
    container_vuln_summary,
    running_containers,
    expiring_certs,
    webapp_vulns,
    risk_by_tag,
    edr_events,
    fim_events,
    scan_status,
    asset_inventory,
    vuln_exceptions,
    compliance_posture,
    trurisk_score,
    reports_agg,
    summarize_investigation_agg,
    cache_status_agg,
)

mcp = FastMCP("qualys-mcp")


# ---------------------------------------------------------------------------
# Active tools — thin wrappers calling aggregators
# ---------------------------------------------------------------------------


@mcp.tool()
def get_weekly_priorities(limit: int = 10, sort_by: str = "trurisk", tag: str = "", asset_group: str = "", detail: str = "standard") -> dict:
    """[Risk Management] Weekly priorities — top high-risk assets ranked by TruRisk, risk distribution across severity tiers, and container risks. @slow

    USE WHEN: "what should I work on this week?", "top priorities", "what should we fix first?", sprint planning, or risk-ranked remediation lists.
    DO NOT USE WHEN: Asking about what happened today/overnight, drilling into a single asset, or checking cloud posture.
    PREFER INSTEAD: get_morning_report for daily briefing ("what happened overnight?"); get_asset for single-asset drill-down; get_cloud_risk for cloud posture; get_eliminate_status for patch deployment status.

    Parameters:
        limit: max top-risk assets to return (default 10)
        sort_by: ranking method — 'trurisk' (default, CSAM field truRisk DESC) or 'severity'
        tag: filter to assets with this tag (e.g. Production, PCI, cloud)
        asset_group: filter to assets in this Qualys asset group

    Returns: topRiskAssets (ranked list with assetId, hostname, ip, riskScore, os, criticality), priorities (actionable items with severity rank), summary (asset counts by risk tier, container risks).

    Performance: ~5s cold / ~3s warm (parallel CSAM queries)."""
    return weekly_priorities(limit=limit, sort_by=sort_by, tag=tag, asset_group=asset_group, detail=detail)


@mcp.tool()
def investigate_cve(cve: str, detail: str = "standard") -> dict:
    """[Vulnerability Intelligence] Single-CVE deep investigation — maps CVE to QIDs, retrieves KB details (severity, patches, threat intel, ransomware), and searches your asset inventory for affected software. @slow

    USE WHEN: Deep-diving a single CVE — "are we affected by CVE-2024-3400?", incident response triage, tracing a CVE to specific assets, or "what's the impact of CVE-X?"
    DO NOT USE WHEN: Looking up multiple CVEs at once (bulk metadata), searching KB by software/threat type, or checking confirmed detection status on assets.
    PREFER INSTEAD: get_cve_details when you need KB metadata for 2-20 CVEs without asset search; search_vulns when searching KB by software name or threat type; get_etm_findings with QQL `vulnerabilities.vulnerability.cveIds:CVE-...` when you need confirmed finding status.

    Parameters:
        cve: single CVE ID, e.g. 'CVE-2024-3400'

    Returns: qids (mapped QIDs), severity, qds, title, patchAvailable, solution, allKbDetails, threatIntel, ransomware flag, affectedAssets (CSAM software search with sample assets), summary.

    Performance: ~5s cold / ~3s warm (KB cached)."""
    return investigate_cve_agg(cve=cve, detail=detail)


@mcp.tool()
def investigate(topic: str, depth: str = "standard", prior_context: str = "", detail: str = "standard") -> dict:
    """[Investigation] Deep-dive investigation on any security topic. @slow

    USE WHEN: User wants a complete investigation — "tell me everything about Log4Shell",
    "investigate this asset", "why is our risk score so high", "deep dive on ransomware exposure".
    Also handles: multi-CVE analysis, compare these vulnerabilities, vulnerability backlog trend, cross-asset vulnerability analysis.
    DO NOT USE FOR: simple single-tool queries. Use specific tools for focused lookups.

    Automatically chains the right tools, correlates findings, and returns a unified report
    with specific follow-up actions ranked by priority.

    topic: CVE ID, asset hostname/IP, "risk spike", "ransomware", "compliance", or free-text
    depth: "quick" (2 tools, ~15s) | "standard" (4 tools, ~45s) | "deep" (6+ tools, ~90s)
    prior_context: summary from a previous investigate() call for chaining investigations"""
    return investigate_agg(topic=topic, depth=depth, prior_context=prior_context, detail=detail)


@mcp.tool()
def get_patch_status(limit: int = 20, tag: str = "", asset_group: str = "", detail: str = "standard") -> dict:
    """[Patch Posture] TruRisk-based patching coverage and gaps — risk distribution across severity tiers and top unpatched assets ranked by TruRisk score. This is a RISK POSTURE view from CSAM, NOT deployed/missing patch counts from the PM module.

    USE WHEN: "how is our patching going?" (risk posture), "how many assets are unpatched?", assessing patch posture by TruRisk tier, or identifying top unpatched assets by risk score.
    DO NOT USE WHEN: Asking about deployed vs missing patch counts, failed patch deployments, outstanding patches, or PM job status.
    PREFER INSTEAD: get_eliminate_status when "how many patches are deployed vs missing?", "what patches failed?", "what Windows patches are outstanding?", or any PM job/deployment question; get_asset for single-asset patch/vuln details.

    Parameters:
        limit: max high-risk assets to return (default 20)
        tag: filter to assets with this tag (e.g. Production, PCI, cloud)
        asset_group: filter to assets in this Qualys asset group

    Returns: coverage (% of assets with TruRisk < 100), assetsTotal, riskDistribution (critical_900plus, high_700plus, elevated_500plus, medium_100plus, low_under100), highRiskAssets (ranked list).

    Performance: ~5s cold / ~3s warm (parallel CSAM queries)."""
    return patch_status(limit=limit, tag=tag, asset_group=asset_group, detail=detail)


@mcp.tool()
def search_vulns(days: int = 7, threat_type: str = "", software: str = "", limit: int = 50, tag: str = "", asset_group: str = "", detail: str = "standard") -> dict:
    """[Vulnerability Intelligence] KB search — newly published vulns, threat intel (RTI) filtering, and software-specific vuln lookups from the Qualys Knowledge Base.

    USE WHEN: Searching for new vulns ("what was published this week?"), threat intel queries ("any ransomware vulns?", "CISA KEV additions?"), or software-specific lookups ("what vulns affect Apache?"). This searches the KB (published vulns), NOT your detections.
    DO NOT USE WHEN: Tracing a single CVE to affected assets in your environment, doing bulk CVE metadata lookup, or querying confirmed detections on your assets.
    PREFER INSTEAD: investigate_cve for single-CVE deep-dive with asset impact; get_cve_details for bulk CVE metadata; get_etm_findings for confirmed detections in YOUR environment.

    Parameters:
    days: how far back to search (default 7). Use days=1 for today, days=30 for last month.

    threat_type: RTI filter — one of the 12 Real-Time Threat Indicator tags:
      - Ransomware              — linked to ransomware campaigns
      - Malware                 — associated with known malware
      - Active_Attacks          — seen in active exploitation in the wild
      - Exploit_Public          — public exploit code available
      - Easy_Exploit            — low-skill exploitation possible
      - Wormable                — can spread without user interaction
      - Cisa_Known_Exploited_Vulns — on CISA KEV catalog
      - Denial_of_Service       — can cause service disruption
      - Privilege_Escalation    — enables privilege elevation
      - Remote_Code_Execution   — enables remote code execution
      - Predicted_High_Risk     — ML-predicted high risk
      - Unauthenticated_Exploitation — exploitable without authentication

    software: filter by product name in KB title/diagnosis. Fuzzy substring match — partial names work.
      Examples: 'Apache', 'OpenSSL', 'Microsoft Exchange', 'Chrome', 'nginx', 'Java', 'Log4j',
                'Cisco IOS', 'VMware', 'WordPress', 'PHP', 'PostgreSQL', 'Docker'

    tag: filter to assets with this tag (e.g. Production, PCI, cloud) — scopes affected-asset counts
    asset_group: filter to assets in this Qualys asset group — scopes affected-asset counts

    Filters combine: search_vulns(days=30, threat_type='Ransomware', software='Apache') returns Apache vulns with ransomware linkage from the last 30 days.

    Returns: totalVulns, severityBreakdown, withPatch, withThreatIntel, threatBreakdown (RTI tag counts), vulns (list with qid, title, severity, qds, cves, patchAvailable, threatIntel), summary.

    Performance: ~5s cold / ~3s warm (KB cached)."""
    return search_vulns_agg(days=days, threat_type=threat_type, software=software, limit=limit, tag=tag, asset_group=asset_group, detail=detail)


@mcp.tool()
def get_recommendations(detail: str = "standard") -> dict:
    """[Program Advisor] Security program recommendations — analyzes your environment and identifies coverage gaps across VMDR, TotalCloud, TotalAppSec, FIM, EDR, CertView, and Patch Management.

    USE WHEN: Gap analysis, program improvement, "what modules should we add?", "what should we invest in?", "what's missing from our security program?", or "how do we reduce our TruRisk score?"
    DO NOT USE WHEN: Responding to immediate threats, looking at asset-level vuln details, or checking patching status.
    PREFER INSTEAD: get_morning_report for immediate threat response; get_asset for asset-level details; get_eliminate_status for patching status.

    Returns: recommendations (prioritized list with priority, area, finding, qualysModule, riskAction=eliminate|mitigate), coverage (map of active vs missing capabilities), riskActions (eliminate/mitigate counts), summary.

    Performance: ~10s cold / ~5s warm (probes all data sources in parallel)."""
    return recommendations(detail=detail)


@mcp.tool()
def get_eliminate_status(status: str = "", detail: str = "standard") -> dict:
    """[TruRisk Eliminate] Patch deployment status — deployed/missing patch counts, PM jobs, MTG jobs, patch catalog, deployment success rates, mitigation technique breakdown, SLA compliance summary, and managed assets for Windows and Linux.

    USE WHEN: "how many patches are deployed vs missing?", "what patches failed to deploy?", "what's the success rate of our patch deployments?", "what mitigation techniques are being used?", "which assets are missing critical patches?", "what patches are deploying right now?", "are patches deploying?", "how many mitigation jobs are running?", "what's our patch catalog size?", or checking active risk elimination progress. Also handles: SLA compliance, patches within SLA, remediation deadlines, overdue patches, patch SLA rate, time to patch, remediation SLA, outstanding patches, missing patches, which patches need to be deployed, patches by severity.
    NOTE: For detailed outstanding patch lists (patch names, missing counts, severity breakdown), prefer get_outstanding_patches instead.
    DO NOT USE WHEN: Assessing overall risk posture by TruRisk tier (use get_patch_status), checking single-asset patch status (use get_asset), or checking mitigation coverage for specific QIDs/CVEs (use get_eliminate_coverage).
    PREFER INSTEAD: get_patch_status when "how is our patching going?" (TruRisk coverage/gaps); get_asset for per-asset details; get_eliminate_coverage when checking which vulns have mitigations available.

    Parameters:
        status: filter jobs by status (e.g. "Failed", "Completed", "Running"). "Running" returns in-progress jobs. Empty = all jobs. Status is passed to the API for server-side filtering.

    Returns: patchCounts (deployed/missing totals per platform), patchManagement (per-platform: totalJobs, activeJobs, byStatus, recentJobs, managedAssets), mitigations (per-platform: totalJobs, activeJobs, byStatus, recentJobs), patchCatalog (windows/linux totals and severity breakdown), deploymentSuccessRate (patch/mitigation/overall: succeeded, failed, total, rate%), techniqueBreakdown (byType with counts for REGISTRY, CONFIG, WORKAROUND, PATCH), slaSummary (within_30d, within_60d, overdue_30d, overdue_60d counts), summary.

    Performance: ~5s cold / ~3s warm (parallel PM+MTG+catalog queries)."""
    return eliminate_status(status=status, detail=detail)


@mcp.tool()
def get_outstanding_patches(platform: str = "", severity: str = "", top_n: int = 20, detail: str = "standard") -> dict:
    """[Patch Management] Outstanding patches — lists missing patches ranked by affected asset count, with security/reboot breakdowns and severity filtering.

    USE WHEN: "what patches are outstanding?", "which patches are missing?", "what Windows patches need to be deployed?", "which patches require a reboot?", "what security patches are missing?", "what critical patches are outstanding?", "patches by severity", "top missing patches", "how many patches are outstanding?", "which patches affect the most assets?".
    DO NOT USE WHEN: Checking deployment job status or success rates (use get_eliminate_status), checking overall patch posture by TruRisk (use get_patch_status), or investigating a specific CVE (use investigate_cve).
    PREFER INSTEAD: get_eliminate_status for deployment job status; get_patch_status for TruRisk patch posture; investigate_cve for single-CVE deep-dive.

    Parameters:
        platform: filter by platform — "Windows", "Linux", or "Mac". Empty = all platforms.
        severity: filter by vendor severity — "Critical", "Important", "Moderate". Empty = all severities.
        top_n: number of top patches to return, sorted by missingCount descending (default 20).

    Returns: totalOutstanding (patch count), totalMissingInstalls, securityPatches, nonSecurityPatches, rebootRequired, topPatches (list with title, missingCount, vendorSeverity, isSecurity, rebootRequired, cveCount, platform, category, kb), summary.

    Performance: ~3s cold / ~2s warm (parallel per-platform queries)."""
    return outstanding_patches(platform=platform, severity=severity, top_n=top_n, detail=detail)


@mcp.tool()
def get_eliminate_coverage(qids: list = None, cves: list = None, detail: str = "standard") -> dict:
    """[TruRisk Eliminate] Mitigation coverage check — given QIDs or CVEs, shows which have Eliminate mitigations available in the catalog and their technique types.

    USE WHEN: "which of our top vulns have Eliminate mitigations?", "what's our Eliminate catalog coverage for these CVEs?", "do we have mitigations for QID 12345?", "which vulnerabilities in our backlog have Eliminate mitigations available?", checking mitigation availability before deploying.
    DO NOT USE WHEN: Checking deployment job status (use get_eliminate_status), looking at overall patch counts, or investigating a single CVE (use investigate_cve).
    PREFER INSTEAD: get_eliminate_status for deployment job status and success rates; investigate_cve for single-CVE deep-dive.

    Parameters:
        qids: list of Qualys QID integers to check (e.g. [12345, 67890])
        cves: list of CVE IDs to check (e.g. ["CVE-2024-1234", "CVE-2024-5678"])

    Returns: coverage (list with hasMitigation, technique type, mitigation details per QID/CVE), summary (requested, covered, notCovered, coverageRate), catalogSize.

    Performance: ~5s cold / ~3s warm (parallel catalog + KB queries)."""
    return eliminate_coverage(qids=qids, cves=cves, detail=detail)


@mcp.tool()
def get_scanner_health(detail: str = "standard") -> dict:
    """[Infrastructure] Scanner appliance health — online/offline status, running/failed scans, capacity utilization, and vuln signature currency.

    USE WHEN: Scanners appear offline, coverage seems low, "why did my scan fail?", checking last scan times, or verifying scanner infrastructure health before a scan window.
    DO NOT USE WHEN: Checking scan job status/history, looking at vulnerability findings from scans, or checking patch deployment status.
    PREFER INSTEAD: get_scan_status for scan job status/history; get_etm_findings for vulnerability findings; get_eliminate_status for patch deployment status.

    Returns: scanners (list with name, status, runningScanCount, maxCapacity, heartbeatsMissed, vulnsigs currency), scanStatus (byState, errorScans, activeScans), summary.

    Performance: ~5s cold / ~3s warm (parallel scanner list + scan list queries)."""
    return scanner_health(detail=detail)


@mcp.tool()
def get_etm_findings(qql: str = "", report_id: str = "", detail: str = "standard") -> dict:
    """[Enterprise TruRisk] Confirmed vulnerability findings in YOUR environment from VMDR scans. Returns per-asset findings with QDS, CVSS, patch status, CVE mapping, vulnerability age metrics, and oldest unpatched vulnerabilities. @slow

    USE WHEN: User asks what vulns exist on their assets — "show me all critical vulns", "find Log4Shell across the environment", "what's confirmed in our scans?". Also handles: vulnerability age, average time to remediate, oldest unpatched vuln, vulnerability backlog, teams with most vulns, how long vulns have been open, mean time to remediate. Supports QQL-style filtering.
    DO NOT USE WHEN: Searching the KB for newly published vulns (not yet scanned), doing single-CVE investigation with asset software search, or checking cloud misconfigs.
    PREFER INSTEAD: search_vulns for KB-only search (published vulns, not your detections); investigate_cve for single-CVE deep-dive with asset impact; get_cloud_risk for cloud misconfigurations.

    Parameters:
    qql: Filter string (optional). Supports severity, CVE, and QID filters:
      - `vulnerabilities.vulnerability.severity:5` — critical findings only
      - `vulnerabilities.vulnerability.cveIds:CVE-2021-44228` — specific CVE
      - `vulnerabilities.vulnerability.qid:38580` — specific QID
      - `vulnerabilities.vulnerability.isPatchAvailable:true` — patchable only
    report_id: Ignored (kept for backward compatibility).

    Returns: findings (per-asset entries with cveId, qid, severity, qds, isPatchAvailable, firstFound), summary (totalFindings, uniqueAssets, uniqueCVEs, patchable, bySeverity), vulnAge (avgAgeDays, over30d, over60d, over90d, oldestUnpatched), topCVEs.

    Performance: ~2s warm (cached) / 1-3 min cold (VMDR API fetch + KB enrichment). Results cached for 1 hour."""
    return etm_findings(qql=qql, report_id=report_id, detail=detail)


@mcp.tool()
def get_morning_report(quick: bool = False, detail: str = "standard") -> dict:
    """[Daily Briefing] Morning security report or fast environment snapshot. @slow when quick=False

    USE WHEN: "what happened overnight?", "morning report", "give me a briefing", "what's new today?", "what does our environment look like?", environment overview, asset demographics, shift handover, or starting a session. This is the best first-call for daily situational awareness. Also handles: how has our posture changed, vulnerability trend, risk trend this month, security posture over time, are things getting better or worse.
    DO NOT USE WHEN: Planning the week's work, deep-diving a specific CVE, or investigating cloud-specific threats.
    PREFER INSTEAD: get_weekly_priorities when "what should I work on this week?" or "top priorities"; investigate_cve for single-CVE deep-dive; get_cloud_risk for cloud threat hunting.

    Parameters:
        quick: True for fast environment snapshot only (<3s) — asset counts by OS, cloud, EOL, criticality. False (default) for full daily briefing (~8s).

    Returns (quick=False): environment (healthScore, totalAssets, highRiskAssets, eolSystems), newVulns (24h counts by severity + criticalVulns list), threats (ransomwareLinked, activelyExploited, cisaKev), topRiskAssets, actionItems, truriskTrend.
    Returns (quick=True): totalAssets, byOS, byCloud, eolCounts, byCriticality, summary.

    Performance: ~8s cold / ~4s warm (quick=False). <3s (quick=True)."""
    return morning_report(quick=quick, detail=detail)


@mcp.tool()
def get_cve_details(cves: str, detail: str = "standard") -> dict:
    """[Vulnerability Intelligence] Bulk CVE lookup — severity, patches, threat intel, and remediation for 1-20 CVEs at once. KB data only (no asset search). @slow

    USE WHEN: Looking up multiple CVEs at once — "what's the severity of these CVEs?", comparing CVE risk, building a CVE summary table, or quick metadata check for a list of CVEs. Also handles: compare these CVEs, which CVE is most critical, CVE comparison table, rank these CVEs by severity or risk.
    DO NOT USE WHEN: Investigating a single CVE with asset impact analysis, looking up QIDs (not CVEs), or querying confirmed findings in your environment.
    PREFER INSTEAD: investigate_cve when you need a single CVE traced to affected assets in your environment; get_qid_details for QID-based lookup; get_etm_findings for confirmed detections.

    Parameters:
        cves: comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2024-3400'. Up to 20 per call; 10 recommended for best performance.

    Returns: per-CVE entries with severity, qds, cvss_v3, title, patchAvailable, has_exploit, solution, threatIntel, ransomware flag, and kbEntries (all mapped QIDs).

    Performance: ~5s cold / ~3s warm (KB cached). Scales linearly with CVE count."""
    return cve_details(cves=cves, detail=detail)


@mcp.tool()
def get_qid_details(qids: str, detail: str = "standard") -> dict:
    """[Vulnerability Intelligence] Direct QID lookup — KB details (severity, QDS, patches, threat intel, CVEs) for specific Qualys QIDs.

    USE WHEN: You have specific QID numbers from ETM findings, scan reports, or VMDR detections and need KB details. QIDs are Qualys-internal vulnerability identifiers.
    DO NOT USE WHEN: You have CVE IDs (not QIDs), searching KB by software/threat type, or querying confirmed findings across assets.
    PREFER INSTEAD: get_cve_details for CVE-based lookup; search_vulns for KB search by software or threat type; get_etm_findings for confirmed findings across assets.

    Parameters:
        qids: comma-separated QIDs, e.g. '38747,376418'. Up to 50 per call.

    Returns: per-QID entries with title, severity, qds, qds_factors, cvss_v3, cves, patchAvailable, has_exploit, solution, diagnosis, threatIntel, ransomware flag.

    Performance: ~3s cold / ~1s warm (KB cached)."""
    return qid_details(qids=qids, detail=detail)


@mcp.tool()
def get_cloud_risk(limit: int = 20, include_threats: bool = True, days: int = 7, per_account: bool = False, detail: str = "standard") -> dict:
    """[Cloud Security] Cloud security posture + CDR threat findings across AWS, Azure, and GCP — connected accounts, CIS benchmark control failures, and detailed CDR threats. @slow

    USE WHEN: "how are our cloud accounts doing?", cloud security posture overview, CIS benchmark compliance, cloud risk summary, investigating active cloud threats, lateral movement, suspicious network activity, or cloud incident response.
    DO NOT USE WHEN: Looking at host-based vulnerabilities or checking on-prem compliance.
    PREFER INSTEAD: get_cloud_account_summary for per-account breakdown; get_cloud_controls for service-level drill-down (S3, IAM, EC2); get_etm_findings for host-based vulnerabilities; get_compliance_posture for on-prem/Policy Compliance posture; get_edr_events for host-based endpoint threats.

    Parameters:
        limit: max failed controls and CDR threats to return (default 20)
        include_threats: include detailed CDR threat findings (default True). Set False for posture-only.
        days: CDR look-back window in days (default 7). Only used when include_threats=True.
        per_account: include per-account fail counts for ALL accounts (default False). Adds perAccount list ranked by failedEvaluations.

    Returns: accounts (list with id, provider, name), failedControls (CIS benchmark failures by controlId), threats (CDR findings with severity, category, resourceId, provider, account, region), stats (total accounts, critical threats). With per_account=True: perAccount (ranked list with failedEvaluations per account).

    Performance: ~6s cold / ~3s warm (parallel: 3 provider connectors + evaluations + CDR). With per_account=True: +2s for account counts."""
    return cloud_risk(limit=limit, include_threats=include_threats, days=days, per_account=per_account, detail=detail)


@mcp.tool()
def get_cloud_account_summary(provider: str = 'all', detail: str = "standard") -> dict:
    """[Cloud Security] Per-account evaluation counts across AWS, Azure, and GCP — ranked by total evaluations. @fast

    USE WHEN: "which cloud accounts have the most issues?", per-account cloud breakdown, multi-account visibility, or identifying which account needs attention.
    DO NOT USE WHEN: Looking at specific service controls (use get_cloud_controls) or overall posture overview (use get_cloud_risk).
    PREFER INSTEAD: get_cloud_risk for overall posture + CDR threats; get_cloud_controls for service-level drill-down (S3, IAM, EC2).

    Parameters:
        provider: 'all' (default), 'aws', 'azure', or 'gcp'

    Returns: accounts (ranked list with accountId, provider, name, totalEvaluations), totalAccounts.

    Performance: ~2s (pageSize=1 per account, parallel)."""
    return cloud_account_summary(provider=provider, detail=detail)


@mcp.tool()
def get_cloud_controls(provider: str = 'all', service: str = '', result: str = 'FAIL', account_id: str = '', limit: int = 50, detail: str = "standard") -> dict:
    """[Cloud Security] Service-level cloud control evaluations — filter by AWS/Azure/GCP service (S3, IAM, EC2, etc.) and result. @slow

    USE WHEN: "show me S3 misconfigurations", "which IAM controls are failing?", service-specific cloud security drill-down, investigating specific cloud service risks, or filtering cloud controls by pass/fail.
    DO NOT USE WHEN: Looking for overall cloud posture overview (use get_cloud_risk) or per-account summary (use get_cloud_account_summary).
    PREFER INSTEAD: get_cloud_risk for high-level posture + CDR threats; get_cloud_account_summary for per-account breakdown.

    Parameters:
        provider: 'all' (default), 'aws', 'azure', or 'gcp'
        service: filter by cloud service name — e.g. 'S3', 'IAM', 'EC2', 'Lambda', 'VPC', 'CloudTrail', 'RDS', 'KMS'. Leave empty for all services.
        result: filter by evaluation result — 'FAIL' (default), 'PASS', or '' for both
        account_id: filter to specific account ID. Leave empty for first account per provider.
        limit: max controls to return (default 50)

    Returns: controls (list ranked by failedResources with controlId, controlName, service, criticality, result, failedResources, passedResources, accountId, provider), byService (service distribution), passRate (overall resource pass rate %), failedControlCount, passedControlCount, totalResourcesFailed, totalResourcesPassed, filters.

    Performance: ~4s (parallel evaluation fetch per provider)."""
    return cloud_controls(provider=provider, service=service, result_filter=result, account_id=account_id, limit=limit, detail=detail)


@mcp.tool()
def get_asset(asset_id: str, detail: str = "summary") -> dict:
    """[Asset Risk] Single-asset risk profile — TruRisk score, OS, criticality, software, EOL flags, and vulnerability detections. @slow when detail='full'

    USE WHEN: Drilling into one specific asset — "what's the risk on this server?", "full profile", "complete profile", or "everything about this asset". Pass assetId from get_weekly_priorities, get_patch_status, get_etm_findings, or get_asset_inventory.
    DO NOT USE WHEN: Browsing multiple assets or viewing environment-wide risk.
    PREFER INSTEAD: get_weekly_priorities or get_asset_inventory for multi-asset browsing; get_risk_by_tag for aggregate risk by tag group.

    Parameters:
        asset_id: CSAM assetId (string) from any tool that returns asset lists
        detail: 'summary' (fast, CSAM+VMDR only, ~2s) or 'full' (complete, CSAM+ETM+VMDR parallel, ~6s)

    Returns: riskScore, hostname, ip, os, criticality, software, eolSoftware, vulns.
    With detail='full': also etmFindings, vmdrDetections, tags, and summary counts.

    Performance: ~3s cold / ~2s warm (detail='summary'). ~5-8s cold / ~2s warm (detail='full')."""
    return asset_detail(asset_id=asset_id, detail_level=detail)


@mcp.tool()
def get_tech_debt(limit: int = 100, days: int = 30, detail: str = "standard") -> dict:
    """[Asset Lifecycle] End-of-life and end-of-support systems — OS and hardware assets running unsupported software, sorted by criticality and risk score. @slow

    USE WHEN: "which systems are unsupported?", tech debt assessment, EOL/EOS exposure audit, or upgrade planning. Returns both OS EOL (e.g. Windows Server 2012) and hardware EOL assets.
    DO NOT USE WHEN: Checking EOL status for a single asset, browsing general asset inventory, or getting environment overview counts.
    PREFER INSTEAD: get_asset for single-asset EOL check; get_asset_inventory for general asset browsing; get_morning_report(quick=True) for quick environment counts.

    Parameters:
        limit: max assets per category (default 100). Use 500 for full inventory.
        days: recency window in days (default 30, use 0 for all-time). With days=30, typically ~4,229 assets vs ~6,645 all-time.

    Returns: os (list of OS EOL assets with assetId, hostname, os, riskScore, criticality, lifecycleStage), hardware (list of hardware EOL assets), summary (osEOL count, hardwareEOL count). truncated=True appears in meta when results are sliced.

    Performance: ~15s with days=30 / ~2min for days=0 (paginated CSAM API). Always paginates fully, then slices to limit."""
    return tech_debt(limit=limit, days=days, detail=detail)


@mcp.tool()
def get_container_vuln_summary(limit: int = 20, detail: str = "standard") -> dict:
    """[Container Security] Top container images ranked by critical vulnerability count — severity breakdown across all images with patch availability. @fast

    USE WHEN: "show me vulnerability counts by image", "which container images have the most critical vulns?", container security overview, image risk ranking, or container vulnerability audit.
    DO NOT USE WHEN: Investigating a single specific image (use get_image_vulns instead), looking at host-level vulnerabilities, or checking cloud posture.
    PREFER INSTEAD: get_image_vulns for single-image deep dive; get_running_containers for running container context; get_etm_findings for host-level vulnerabilities.

    Parameters:
        limit: max images to return (default 20). Use higher for full inventory.

    Returns: summary (critical/high/medium/low/total/patchable across all images), imageCount, images (list ranked by critical vulns with repo, tag, severity counts, patchable).

    Performance: ~3s (single paginated API call)."""
    return container_vuln_summary(limit=limit, detail=detail)


@mcp.tool()
def get_image_vulns(image_id: str = "", limit: int = 50, detail: str = "standard") -> dict:
    """[Container Security] Vulnerabilities for a specific container image — severity breakdown and individual vuln details with fix versions. Without image_id, lists top images by critical vuln count.

    USE WHEN: Investigating vulnerabilities in a specific container image, pre-deployment image scanning review, or container remediation planning. Also use without image_id to list top vulnerable images.
    DO NOT USE WHEN: Checking host-based vulnerabilities or viewing cloud posture.
    PREFER INSTEAD: get_container_vuln_summary for image ranking overview; get_asset for host-based vulnerabilities; get_cloud_risk for cloud posture overview.

    Parameters:
        image_id: TotalCloud imageId (from get_asset_inventory or get_weekly_priorities container risk section). Leave empty to list top images by critical vuln count.
        limit: max vulns/images to return (default 50)

    Returns: With image_id: imageId, repo, tag, created, stats (critical/high/medium/low/total), vulns (list with qid, cve, severity, title, fixVersion). Without image_id: ranked list of images with severity counts.

    Performance: ~3s (parallel image details + vulns API)."""
    if not image_id:
        return image_vulns_list(limit=limit, detail=detail)
    return image_vulns(image_id=image_id, limit=limit, detail=detail)


@mcp.tool()
def get_running_containers(limit: int = 50, detail: str = "standard") -> dict:
    """[Container Security] Running containers with image vulnerability context — identifies containers with unpatched critical vulns. @slow

    USE WHEN: "show me all running containers with unpatched critical vulns", "which containers are most at risk?", container runtime security audit, or finding containers that need immediate patching.
    DO NOT USE WHEN: Looking at container images without runtime context (use get_container_vuln_summary), investigating a single image (use get_image_vulns), or checking host-level vulns.
    PREFER INSTEAD: get_container_vuln_summary for image-level vuln ranking without runtime context; get_image_vulns for single-image deep dive.

    NOTE: Kubernetes namespace/pod-level data (namespaces, pods) is not available on all tenants. This tool returns container and image-level data. For K8s questions, it will indicate when namespace/pod data is unavailable.

    Parameters:
        limit: max containers to return (default 50)

    Returns: summary (totalRunning, withCriticalVulns, withUnpatchedCritical), containers (list sorted by critical vuln count with containerId, name, imageRepo, imageTag, host, critical/high/medium/patchable counts).

    Performance: ~5s (parallel containers + images API)."""
    return running_containers(limit=limit, detail=detail)


@mcp.tool()
def get_expiring_certs(days: int = 90, include_expired: bool = True, weak_only: bool = False,
                       protocol_filter: str = "", weak_ciphers: bool = False,
                       insecure_renegotiation: bool = False,
                       limit: int = 100, detail: str = "standard") -> dict:
    """[CertView] SSL/TLS certificate expiry monitoring and configuration issue detection — expiring/expired certs, weak keys, SHA-1, self-signed, and TLS 1.0/1.1 usage.

    USE WHEN: "which SSL certs expire soon?", certificate expiry audit, TLS version detection (TLS 1.0/1.1/SSLv3),
              weak cipher detection, insecure renegotiation, self-signed cert inventory, or outage prevention.
    DO NOT USE WHEN: Scanning for host vulnerabilities, checking cloud posture, or general security health overview.
    PREFER INSTEAD: get_etm_findings for vulnerability scanning; get_cloud_risk for cloud posture; get_morning_report or get_weekly_priorities for general security health.
                    get_cert_security_posture for TLS protocol/cipher/renegotiation queries (faster, server-side filtered).

    Parameters:
      - days: Look-ahead window for expiring certs (default 90)
      - include_expired: Include already-expired certs in results (default True)
      - weak_only: Only return certs that have at least one issue (default False)
      - protocol_filter: TLS/SSL protocol version to filter by (e.g. "TLSv1.0", "TLSv1.1", "SSLv3")
      - weak_ciphers: Return only certs using weak cipher suites (RC4, DES, 3DES)
      - insecure_renegotiation: Return only servers with insecure TLS renegotiation enabled
      - limit: Max certs to return (default 100)

    **Example questions:**
      - "Which SSL certs expire in the next 30 days?" → get_expiring_certs(days=30)
      - "Are any certificates already expired?" → get_expiring_certs(include_expired=True)
      - "Which servers are using weak cipher suites?" → get_expiring_certs(weak_only=True)
      - "Show me all self-signed certificates" → get_expiring_certs(weak_only=True)
      - "Are any servers still using TLS 1.0?" → get_expiring_certs(protocol_filter="TLSv1.0")
      - "Are any servers still using TLS 1.1?" → get_expiring_certs(protocol_filter="TLSv1.1")
      - "Which servers support insecure renegotiation?" → get_expiring_certs(insecure_renegotiation=True)
      - "Show servers with weak cipher suites" → get_expiring_certs(weak_ciphers=True)

    Returns: summary (total, expired, expiring30Days, expiring90Days, weakCiphers, selfSigned, weakKeySize, tls10or11), expiringSoon (list with subject, expiryDate, daysRemaining, host, grade, issues), issues (flat list with host, issue, severity).

    **Grades:** A = no issues, B = nearing expiry (<30 days), C = self-signed or weak key, F = expired or SHA-1.

    Performance: ~5s cold / ~3s warm. Protocol/cipher/renegotiation queries: ~3s (server-side filtered)."""
    # If security posture filters requested, delegate to efficient server-side filter
    if protocol_filter or weak_ciphers or insecure_renegotiation:
        from qualys.aggregators import cert_security_posture
        return cert_security_posture(
            protocol_filter=protocol_filter,
            weak_ciphers=weak_ciphers,
            insecure_renegotiation=insecure_renegotiation,
            limit=limit,
        )
    return expiring_certs(days=days, include_expired=include_expired, weak_only=weak_only, limit=limit, detail=detail)


@mcp.tool()
def get_cert_security_posture(protocol_filter: str = "", weak_ciphers: bool = False,
                               insecure_renegotiation: bool = False, limit: int = 100) -> dict:
    """[CertView] TLS protocol version detection, weak cipher audit, and insecure renegotiation scan — fast server-side filtered cert queries.

    USE WHEN: "are any servers using TLS 1.0 or 1.1?", TLS version compliance, "which servers support insecure renegotiation?",
              weak cipher detection, SSLv3 usage, or protocol-level security audits.
    DO NOT USE WHEN: Checking certificate expiry dates or general cert inventory — use get_expiring_certs instead.
    PREFER INSTEAD: get_expiring_certs for expiry-focused cert queries.

    Parameters:
      - protocol_filter: TLS/SSL protocol version to filter by (e.g. "TLSv1.0", "TLSv1.1", "SSLv3")
      - weak_ciphers: Return only certs using weak cipher suites (RC4, DES, 3DES)
      - insecure_renegotiation: Return only servers with insecure TLS renegotiation enabled
      - limit: Max certs to return (default 100)

    **Example questions:**
      - "Are any servers still using TLS 1.0?" → get_cert_security_posture(protocol_filter="TLSv1.0")
      - "Are any servers still using TLS 1.1?" → get_cert_security_posture(protocol_filter="TLSv1.1")
      - "Which servers support insecure renegotiation?" → get_cert_security_posture(insecure_renegotiation=True)
      - "Show servers with weak ciphers" → get_cert_security_posture(weak_ciphers=True)
      - "Are any servers using SSLv3?" → get_cert_security_posture(protocol_filter="SSLv3")

    Returns: total count, filter applied, certs list (subject, host, protocol, cipher, insecureRenegotiation, grade, expiryDate).

    Performance: ~3s (server-side filtered, no full scan needed)."""
    from qualys.aggregators import cert_security_posture
    return cert_security_posture(
        protocol_filter=protocol_filter,
        weak_ciphers=weak_ciphers,
        insecure_renegotiation=insecure_renegotiation,
        limit=limit,
    )


@mcp.tool()
def get_webapp_vulns(severity: int = 0, days: int = 0, app_name: str = "", owasp_category: str = "",
                     limit: int = 50, detail: str = "standard") -> dict:
    """[Web Application Security] Web application vulnerabilities from Qualys WAS / TotalAppSec — severity breakdown per app, OWASP Top 10 classification, and vuln categories.

    USE WHEN: "what web app vulns do we have?", OWASP Top 10 findings, XSS/SQLi/CSRF issues, per-app vulnerability posture, or web application security audit.
    DO NOT USE WHEN: Looking at host-based vulnerabilities, network-level findings, or SSL/TLS certificate issues.
    PREFER INSTEAD: get_etm_findings for host/network-level vulnerability findings; get_asset for host-based vuln details; get_expiring_certs for SSL/TLS certificate issues.

    Parameters:
        severity: Minimum severity filter (0=all, 1-5). 4=high+critical, 5=critical only.
        days: Only findings detected in the last N days (default 0 = all time). Use 7 for weekly review, 30 for monthly.
        app_name: Filter by web app name (substring match, e.g. "portal", "api").
        owasp_category: Filter results by OWASP Top 10 category keyword (e.g. "Injection", "XSS", "SSRF", "Access Control", "Cryptographic"). Case-insensitive substring match.
        limit: Max findings to return (default 50).

    Returns: stats (total, critical, high, medium, low, webApps), findings (list with id, qid, name, severity, url, webApp, owaspCategory), byWebApp (per-app severity counts), byCategory, owaspTop10 mapping.

    Performance: ~5s cold / ~3s warm (WAS API cached)."""
    return webapp_vulns(severity=severity, days=days, app_name=app_name, owasp_category=owasp_category, limit=limit, detail=detail)


@mcp.tool()
def get_risk_by_tag(tag: str, limit: int = 10, detail: str = "standard") -> dict:
    """[Asset Risk] Aggregate risk for a tag group — TruRisk tier distribution, top risky assets, and EOL counts scoped to a specific tag, business group, or department.

    USE WHEN: User asks about risk for a team, environment, or tag segment — "what's the risk for PCI assets?", "show me Production risk", "how is the DMZ doing?", or any business-unit/compliance-scope risk question. Also handles: business groups, department risk, which team has highest TruRisk, risk by business unit, team breakdown, org unit risk comparison.
    DO NOT USE WHEN: You need global risk overview (not scoped to a tag), single-asset details, or cloud posture.
    PREFER INSTEAD: get_weekly_priorities for global risk overview across all assets; get_asset for single-asset drill-down; get_cloud_risk for cloud-specific posture.

    Parameters:
        tag: tag name to filter by (e.g. 'PCI', 'Production', 'DMZ', 'AWS', 'HIPAA')
        limit: max top-risk assets to return (default 10)

    Returns: assets (total, critical, high, elevated counts), topRiskAssets (ranked list), eolCount, summary string.

    Performance: ~3s (parallel CSAM count queries)."""
    return risk_by_tag(tag=tag, limit=limit, detail=detail)


@mcp.tool()
def get_edr_events(days: int = 7, severity: str = "", category: str = "", host: str = "",
                   limit: int = 50, detail: str = "standard") -> dict:
    """[EDR] Endpoint Detection & Response events — malware, ransomware, C2 beaconing, process injection, lateral movement, and suspicious executions.

    USE WHEN: Investigating endpoint threats, malware detections, suspicious process executions, or host-level incident response. Filter by severity, category, or specific host.
    DO NOT USE WHEN: Monitoring file integrity changes, investigating cloud threats, or querying network-level vulnerability findings.
    PREFER INSTEAD: get_fim_events for file integrity changes; get_cloud_risk(include_threats=True) for cloud threats (CDR); get_etm_findings for network-level vulnerability findings.

    Parameters:
        days: look-back window in days (default 7)
        severity: filter by severity — CRITICAL, HIGH, MEDIUM, LOW (empty = all)
        category: filter by event category substring (e.g. 'Malware', 'C2', 'LateralMovement')
        host: filter by hostname substring
        limit: max events to return (default 50)

    Returns: summary (total, critical, high, medium, low, affectedHosts), byCategory, topHosts, events (list with id, severity, category, name, hostname, ip, user, process, timestamp).

    Performance: ~3s cold / ~2s warm."""
    return edr_events(days=days, severity=severity, category=category, host=host, limit=limit, detail=detail)


@mcp.tool()
def get_fim_events(days: int = 1, severity: str = "", host: str = "", path: str = "",
                   limit: int = 100, detail: str = "standard") -> dict:
    """[FIM] File Integrity Monitoring events — unauthorized file changes, critical system file modifications, and suspicious path activity.

    USE WHEN: Investigating file changes on hosts, "were any system files modified?", checking /etc/passwd or registry changes, reviewing off-hours activity, or auditing file integrity for compliance.
    DO NOT USE WHEN: Investigating process-level threats, malware detection, or cloud threat activity.
    PREFER INSTEAD: get_edr_events for process-level threats and malware detection; get_cloud_risk(include_threats=True) for cloud threat activity.

    Parameters:
        days: look-back window in days (default 1)
        severity: filter by severity — CRITICAL, HIGH, MEDIUM, LOW (empty = all)
        host: filter by hostname substring
        path: filter by file path prefix (e.g. '/etc/', 'C:\\Windows\\System32')
        limit: max events to return (default 100)

    Returns: summary (total, critical, high, affectedHosts, modified, created, deleted), topHosts, criticalChanges (with offHours flag), events (list with action, path, hostname, timestamp, severity, user, offHours).

    Performance: ~3s cold / ~2s warm."""
    return fim_events(days=days, severity=severity, host=host, path=path, limit=limit, detail=detail)


@mcp.tool()
def get_scan_status(state: str = "Running,Paused,Queued,Error", days: int = 7, limit: int = 50,
                    detail: str = "standard") -> dict:
    """[VM] Scan status — running, queued, and failed scans with duration and target info.

    USE WHEN: "are any scans running?", checking scan progress, troubleshooting failed scans, or reviewing scan history for the week.
    DO NOT USE WHEN: Checking scanner appliance health, looking at vulnerability findings from scans, or checking patch deployment status.
    PREFER INSTEAD: get_scanner_health for scanner appliance health (online/offline, capacity); get_etm_findings for vulnerability findings from scans; get_eliminate_status for patch deployment status.

    Parameters:
        state: comma-separated states to filter — Running, Paused, Queued, Error (default all four)
        days: look-back window in days for finished/history scans (default 7)
        limit: max results to return (default 50)

    Returns: stats (total, byState, running, queued, errors, completedToday), scans (list with ref, title, state, target, launched, duration, scanner), failedScans, summary.

    Performance: ~3s (parallel active + finished scan list queries)."""
    return scan_status(state=state, days=days, limit=limit, detail=detail)


@mcp.tool()
def get_asset_inventory(query: str = "", tag: str = "", os: str = "", days_since_seen: int = 0,
                        days_since_scan: int = 0, eol_only: bool = False, limit: int = 50,
                        list_tags: bool = False, list_groups: bool = False, detail: str = "standard") -> dict:
    """[CSAM] Asset inventory search — find assets by OS, tag, keyword, EOL status, staleness, or last scan date. Also lists tags and asset groups.

    USE WHEN: Searching for assets by name/OS/tag, finding stale assets, building asset lists for remediation, finding container image IDs for get_image_vulns, browsing available tags, or listing asset groups. Also handles: when was each asset last scanned, last scan date, assets not scanned in 30 days, stale assets, scan age, scan coverage gaps, days since last scan.
    DO NOT USE WHEN: Looking at single-asset risk details or wanting risk-ranked asset lists.
    PREFER INSTEAD: get_asset for single-asset risk details; get_weekly_priorities for risk-ranked asset lists; get_morning_report(quick=True) for quick environment counts.

    CSAM filter examples (applied automatically from parameters):
      - os="Windows Server 2019"      -> operatingSystem.osName CONTAINS 'Windows Server 2019'
      - tag="PCI"                      -> tags.name CONTAINS 'PCI'
      - eol_only=True                  -> operatingSystem.lifecycle.stage CONTAINS 'EOL'
      - days_since_seen=30             -> assets not seen in 30+ days (stale)
      - days_since_scan=30             -> assets not scanned in 30+ days

    Parameters:
        query: free-text search on hostname/name
        tag: filter by asset tag name (also replaces get_assets_by_tag)
        os: filter by OS (e.g. "Windows", "Linux", "Ubuntu", "CentOS")
        days_since_seen: only assets NOT seen in last N days (stale assets); 0 = no filter
        days_since_scan: only assets NOT scanned in last N days; 0 = no filter. Uses lastVmScannedDate from CSAM.
        eol_only: only return end-of-life assets
        limit: max results (default 50)
        list_tags: if True, return sorted list of all distinct tag names (replaces get_tags)
        list_groups: if True, return sorted list of all distinct asset group names (replaces get_asset_groups)

    Returns: summary (total, returned, byOS, byTag, eolCount), assets (list with id, name, ip, os, lastSeen, lastScanned, daysSinceScan, tags, truRiskScore, openVulns, eolStatus).
    With list_tags=True: adds tags (sorted list of distinct tag names).
    With list_groups=True: adds assetGroups (sorted list of distinct group names).

    Performance: ~3s (parallel CSAM search + count)."""
    return asset_inventory(query=query, tag=tag, os=os, days_since_seen=days_since_seen,
                           days_since_scan=days_since_scan, eol_only=eol_only, limit=limit,
                           list_tags=list_tags, list_groups=list_groups, detail=detail)


@mcp.tool()
def get_vuln_exceptions(status: str = "Active", vuln_type: str = "", days_to_expiry: int = 30,
                        limit: int = 50, detail: str = "standard") -> dict:
    """[VM] Vulnerability exceptions — approved risk acceptances, false positives, and compensating controls with expiry tracking.

    USE WHEN: Reviewing active risk acceptances/waivers, "which exceptions are expiring?", finding exceptions that need renewal, or auditing false positive classifications.
    DO NOT USE WHEN: Checking remediation/patching status, querying vulnerability findings, or reviewing compliance controls.
    PREFER INSTEAD: get_patch_status or get_eliminate_status for patching status; get_etm_findings for vulnerability findings; get_compliance_posture for compliance controls.

    Parameters:
        status: exception status filter — 'Active' (default), 'Expired', 'Pending'
        vuln_type: filter by exception type (e.g. 'False Positive', 'Compensating Control')
        days_to_expiry: only show exceptions expiring within N days (default 30). 0 = all.
        limit: max exceptions to return (default 50)

    Returns: stats (total, active, expiringSoon, expired, byType), exceptions (list with id, qid, title, type, status, reason, approvedBy, expiryDate, daysUntilExpiry).

    Performance: ~3s."""
    return vuln_exceptions(status=status, vuln_type=vuln_type, days_to_expiry=days_to_expiry, limit=limit, detail=detail)


@mcp.tool()
def get_compliance_posture(framework: str = "", platform: str = "", limit: int = 20,
                           detail: str = "standard") -> dict:
    """[PC] Qualys Policy Compliance posture — pass/fail rates, top failing controls, and per-framework breakdown (CIS, PCI-DSS, HIPAA, NIST, SOC2, ISO27001).

    USE WHEN: "are we passing CIS benchmarks?", compliance posture audit, audit readiness, or framework-specific control status. Covers on-prem and host-level compliance.
    DO NOT USE WHEN: Checking cloud-specific CIS compliance, querying vulnerability findings, or checking certificate compliance.
    PREFER INSTEAD: get_cloud_risk for cloud CIS compliance (TotalCloud); get_etm_findings for vulnerability findings; get_expiring_certs for certificate compliance.

    Parameters:
        framework: filter by framework name substring (e.g. 'CIS', 'PCI', 'HIPAA', 'NIST'). Empty = all.
        platform: filter by platform (e.g. 'Linux', 'Windows'). Empty = all.
        limit: max failing controls to return (default 20)

    Returns: summary (totalControls, passing, failing, passRate, affectedAssets, frameworks), topFailingControls (list with controlId, title, framework, failingAssets, severity), byFramework (pass rate per framework).

    Performance: ~5s cold. Falls back to cloud compliance if PC module not licensed."""
    return compliance_posture(framework=framework, platform=platform, limit=limit, detail=detail)


@mcp.tool()
def get_compliance_summary(framework: str = "") -> dict:
    """[PC] Quick compliance summary — pass/fail rates per framework without full control detail.

    USE WHEN: "what's our compliance score?", "how are we doing on CIS/PCI/HIPAA?", quick compliance overview, dashboard-style summary.
    DO NOT USE WHEN: Need full failing control details or remediation guidance.
    PREFER INSTEAD: get_compliance_posture for detailed failing controls and per-control breakdown.

    Parameters:
        framework: filter by framework name substring (e.g. 'CIS', 'PCI', 'HIPAA', 'NIST'). Empty = all.

    Returns: summary (totalControls, passing, failing, passRate, frameworks), byFramework (pass rate per framework).

    Performance: <5s (cached). Uses v4 instances summary endpoint."""
    result = compliance_posture(framework=framework, limit=5, detail="brief")
    if isinstance(result, dict):
        # Strip detailed control list for summary view
        result.pop('topFailingControls', None)
    return result


@mcp.tool()
def get_trurisk_score(days: int = 30, breakdown_by: str = "tag", detail: str = "standard") -> dict:
    """[Risk Management] Org-level TruRisk score with trending and breakdown — aggregate risk, trend direction, top assets, top QIDs, and tag breakdown.

    USE WHEN: "what's our org risk?", "is risk going up or down?", overall TruRisk score, risk trends, or risk breakdown by business unit/tag.
    DO NOT USE WHEN: Drilling into a single asset, planning weekly remediation, or investigating a specific vulnerability.
    PREFER INSTEAD: get_asset for single-asset risk; get_weekly_priorities for weekly remediation planning; investigate_cve for vulnerability investigation.

    Parameters:
        days: trend window in days (default 30). Compares current avg TruRisk vs N days ago.
        breakdown_by: 'tag' groups assets by their tags showing TruRisk per tag, 'none' skips breakdown.

    Returns: aggregate (totalAssets, risk tier counts), trend (avgTruRiskCurrent, avgTruRiskPrior, delta, direction=improving|stable|worsening), topAssets (top 10 by TruRisk with tags), topQIDs (top 10 by risk contribution), breakdown (per-tag avg/max TruRisk).

    Performance: ~5s cold / ~3s warm (parallel CSAM queries)."""
    return trurisk_score(days=days, breakdown_by=breakdown_by, detail=detail)


@mcp.tool()
def reports(action: str, report_id: str = "", template_id: str = "", asset_group_ids: str = "",
            template_name: str = "", report_title: str = "", output_format: str = "pdf") -> dict:
    """[Reporting] Unified report operations — list, templates, generate, status, download, delete.

    USE WHEN: Any report-related task — listing reports, finding templates, generating, checking status, downloading, or deleting reports.
    DO NOT USE WHEN: You need real-time security data — use analysis tools instead. Reports are pre-generated snapshots.

    Parameters:
        action: 'list' | 'templates' | 'generate' | 'status' | 'download' | 'delete'
        report_id: required for 'status', 'download', 'delete'
        template_id: required for 'generate' (from action='templates')
        asset_group_ids: optional comma-separated asset group IDs for 'generate'
        template_name: optional filter substring for 'templates'
        report_title: optional title for 'generate'
        output_format: pdf, html, mht, xml, csv, or docx (default 'pdf') for 'generate'

    Returns vary by action:
        list: total, reports (id, title, type, status, percentComplete, launchDatetime, outputFormat, size)
        templates: total, templates (id, title, type, isGlobal)
        generate: reportId, message
        status: id, title, status, percentComplete, outputFormat, size, launchDatetime
        download: reportId, contentType, encoding, data
        delete: reportId, message

    Performance: ~2-5s depending on action."""
    return reports_agg(action=action, report_id=report_id, template_id=template_id,
                       asset_group_ids=asset_group_ids, template_name=template_name,
                       report_title=report_title, output_format=output_format)


@mcp.tool()
def summarize_investigation(findings: str, audience: str = "technical") -> str:
    """[Reporting] Generate a narrative summary of an investigation for sharing with team or management.

    USE WHEN: User wants to share investigation results — "write up these findings for my manager", "summarize for the exec team", "create a report from this investigation".
    DO NOT USE WHEN: Running an actual investigation — use investigate() or other analysis tools first, then summarize.
    PREFER INSTEAD: investigate() for running the investigation; get_morning_report() for daily briefing.

    Parameters:
        findings: the investigation findings text (JSON or free-text from a prior tool call)
        audience: "technical" | "management" | "executive"
            - technical: full findings with QIDs, CVEs, asset names
            - management: risk score impact, affected systems count, remediation timeline
            - executive: business risk in plain English, cost of remediation vs cost of breach

    Returns: formatted narrative summary appropriate for the specified audience.

    Performance: <1s (local formatting only, no API calls)."""
    return summarize_investigation_agg(findings=findings, audience=audience)


@mcp.tool()
def cache_status(clear: bool = False) -> dict:
    """[Admin] Show cache stats or clear all caches.

    USE WHEN: Debugging stale data, checking cache freshness, or forcing a cache refresh before re-running a tool.
    DO NOT USE WHEN: Performing any security analysis — this is an administrative/diagnostic tool only.
    PREFER INSTEAD: Any security analysis tool (get_morning_report, get_weekly_priorities, etc.) for actual security work.

    Parameters:
        clear: set True to reset all caches (default False)

    Returns: kb_entries, detection_entries, qds_entries, was_keys, scanner_cached, etm_result_cached, cache ages in seconds.

    Performance: <1s."""
    return cache_status_agg(clear=clear)


# ---------------------------------------------------------------------------
# Deprecated stubs — kept for backward compatibility, no aggregator needed
# ---------------------------------------------------------------------------


@mcp.tool()
def get_cdr_findings(days: int = 7, limit: int = 50, severity: str = "", cloud_provider: str = "") -> dict:
    """DEPRECATED: Use get_cloud_risk(include_threats=True, days=N) instead. CDR findings are now included in get_cloud_risk."""
    return {'error': "get_cdr_findings has been removed. Use get_cloud_risk(include_threats=True, days=...) instead.", 'replacement': 'get_cloud_risk'}


@mcp.tool()
def get_asset_risk(asset_id: str, tag: str = "", asset_group: str = "") -> dict:
    """DEPRECATED: Use get_asset(asset_id, detail='summary') instead. This tool has been consolidated into get_asset()."""
    return {'error': "get_asset_risk has been removed. Use get_asset(asset_id='...', detail='summary') instead.", 'replacement': 'get_asset'}


@mcp.tool()
def get_asset_full_profile(asset_id: str) -> dict:
    """DEPRECATED: Use get_asset(asset_id, detail='full') instead. This tool has been consolidated into get_asset()."""
    return {'error': "get_asset_full_profile has been removed. Use get_asset(asset_id='...', detail='full') instead.", 'replacement': 'get_asset'}


@mcp.tool()
def get_environment_summary() -> dict:
    """DEPRECATED: Use get_morning_report(quick=True) instead. Environment snapshot is now part of get_morning_report."""
    result = {'error': "get_environment_summary has been removed. Use get_morning_report(quick=True) instead.", 'replacement': 'get_morning_report'}
    gaps = _detect_gaps(result)
    if gaps:
        result['_gaps'] = gaps
    return result


@mcp.tool()
def get_pm_status(platform: str = "Windows", days: int = 30, status: str = "", limit: int = 20) -> dict:
    """DEPRECATED: Use get_eliminate_status() instead. PM status is fully covered by get_eliminate_status."""
    return {'error': "get_pm_status has been removed. Use get_eliminate_status() instead — it covers PM+MTG combined.", 'replacement': 'get_eliminate_status'}


@mcp.tool()
def get_tags(limit: int = 500) -> dict:
    """DEPRECATED: Use get_asset_inventory(list_tags=True) instead."""
    return {'error': "get_tags has been removed. Use get_asset_inventory(list_tags=True) instead.", 'replacement': 'get_asset_inventory'}


@mcp.tool()
def get_asset_groups(limit: int = 500) -> dict:
    """DEPRECATED: Use get_asset_inventory(list_groups=True) instead."""
    return {'error': "get_asset_groups has been removed. Use get_asset_inventory(list_groups=True) instead.", 'replacement': 'get_asset_inventory'}


@mcp.tool()
def get_assets_by_tag(tag_name: str, limit: int = 50) -> dict:
    """DEPRECATED: Use get_asset_inventory(tag='...') instead."""
    return {'error': f"get_assets_by_tag has been removed. Use get_asset_inventory(tag='{tag_name}') instead.", 'replacement': 'get_asset_inventory'}


@mcp.tool()
def list_reports(limit: int = 50) -> dict:
    """DEPRECATED: Use reports(action='list') instead."""
    return {'error': "list_reports has been removed. Use reports(action='list') instead.", 'replacement': 'reports'}


@mcp.tool()
def list_report_templates(limit: int = 100) -> dict:
    """DEPRECATED: Use reports(action='templates') instead."""
    return {'error': "list_report_templates has been removed. Use reports(action='templates') instead.", 'replacement': 'reports'}


@mcp.tool()
def generate_report(template_id: str, report_title: str = "", output_format: str = "pdf",
                    asset_group_ids: str = "", ips: str = "", tags: str = "") -> dict:
    """DEPRECATED: Use reports(action='generate', template_id='...') instead."""
    return {'error': "generate_report has been removed. Use reports(action='generate', template_id='...') instead.", 'replacement': 'reports'}


@mcp.tool()
def get_report_status(report_id: str) -> dict:
    """DEPRECATED: Use reports(action='status', report_id='...') instead."""
    return {'error': "get_report_status has been removed. Use reports(action='status', report_id='...') instead.", 'replacement': 'reports'}


@mcp.tool()
def download_report(report_id: str) -> dict:
    """DEPRECATED: Use reports(action='download', report_id='...') instead."""
    return {'error': "download_report has been removed. Use reports(action='download', report_id='...') instead.", 'replacement': 'reports'}


@mcp.tool()
def delete_report(report_id: str) -> dict:
    """DEPRECATED: Use reports(action='delete', report_id='...') instead."""
    return {'error': "delete_report has been removed. Use reports(action='delete', report_id='...') instead.", 'replacement': 'reports'}


@mcp.tool()
def qualys_cache_clear(key: str = "") -> str:
    """Clear the qualys-mcp cache (both in-memory L1 and disk L2).
    key: optional specific cache key; if empty, clears everything."""
    from qualys.cache import disk_cache
    from qualys.api import clear_memory_cache
    clear_memory_cache(key if key else None)
    disk_cache.clear(key if key else None)
    if key:
        return f"Cache cleared for key: {key}"
    return "Cache cleared (all keys, both memory and disk)"


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def main():
    if not BASE_URL:
        raise EnvironmentError(
            "Qualys platform not configured. "
            "Set QUALYS_POD (e.g. QUALYS_POD=US2) or provide explicit "
            "QUALYS_BASE_URL and QUALYS_GATEWAY_URL environment variables."
        )
    # Log resolved platform at startup
    if _resolved_pod:
        _log(f"Platform: POD={_resolved_pod}  BASE_URL={BASE_URL}  GATEWAY_URL={GATEWAY_URL}")
    else:
        _log(f"Platform: explicit URLs  BASE_URL={BASE_URL}  GATEWAY_URL={GATEWAY_URL}")
    # Spawn background daemon thread to warm VMDR detection cache
    warmup = Thread(target=_warmup_vmdr_cache, daemon=True, name="vmdr-cache-warmup")
    warmup.start()
    mcp.run()


if __name__ == "__main__":
    main()
