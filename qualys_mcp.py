#!/usr/bin/env python3
"""Qualys MCP Server v3 — 5 analytical workflow tools + 2 utility tools."""

import asyncio
from threading import Thread
from fastmcp import FastMCP
from qualys.api import BASE_URL, GATEWAY_URL, _resolved_pod, _log, _warmup_vmdr_cache
from qualys.workflows.investigate import investigate as investigate_wf
from qualys.workflows.assess_risk import assess_risk as assess_risk_wf
from qualys.workflows.compliance import check_compliance as check_compliance_wf
from qualys.workflows.remediation import plan_remediation as plan_remediation_wf
from qualys.workflows.overview import security_overview as security_overview_wf
from qualys.aggregators import reports_agg, cache_status_agg

mcp = FastMCP("qualys-mcp")


@mcp.tool()
async def investigate(target: str, depth: str = "standard", scope: str = "all",
                tag: str = "", asset_group: str = "", threat_type: str = "",
                software: str = "", days: int = 7, limit: int = 20,
                detail: str = "standard", prior_context: str = "",
                audience: str = "technical") -> dict:
    """[Investigation] Deep-dive investigation on any security topic — CVEs, threat actors, assets, endpoint events, vulnerability intelligence. @slow

    USE WHEN: "tell me about CVE-2024-3400", "are we exposed to Lazarus Group?", "investigate this IP",
    "what ransomware vulns exist?", "deep dive on Log4Shell", "what's happening on 10.0.0.1?"

    Parameters:
        target: CVE ID, threat actor/nation, hostname, IP address, or free-text topic
        depth: "quick" (~10s, 2 sources) | "standard" (~20s, 4 sources) | "deep" (~45s, all sources + summary)
        scope: "all" | "vulns" | "threats" | "assets" | "edr" | "fim"
        tag: filter affected assets by tag
        asset_group: filter by asset group
        threat_type: RTI filter — Ransomware, Active_Attacks, Cisa_Known_Exploited_Vulns, etc.
        software: software name filter for KB search (e.g. "Apache", "OpenSSL")
        days: lookback window for events/vulns (default 7)
        limit: max results per data source (default 20)
        detail: "summary" | "standard" | "detailed" (includes raw aggregator output)
        prior_context: summary from a previous investigation for chaining
        audience: "technical" | "management" | "executive" (for deep investigation summaries)

    Returns: unified envelope with summary (headline, risk_level, key_findings), data (per-source results),
    correlations (cross-source insights), actions (prioritized next steps with tool_hints)."""
    return await asyncio.to_thread(investigate_wf, target=target, depth=depth, scope=scope, tag=tag,
                          asset_group=asset_group, threat_type=threat_type,
                          software=software, days=days, limit=limit,
                          detail=detail, prior_context=prior_context, audience=audience)


@mcp.tool()
async def assess_risk(scope: str = "all", tag: str = "", asset_group: str = "",
                asset_id: str = "", os: str = "", query: str = "",
                days_since_seen: int = 0, days_since_scan: int = 0, eol_only: bool = False,
                provider: str = "", service: str = "", account_id: str = "",
                per_account: bool = False, image_id: str = "",
                app_name: str = "", owasp_category: str = "",
                protocol_filter: str = "", weak_ciphers: bool = False,
                weak_only: bool = False, insecure_renegotiation: bool = False,
                include_expired: bool = True, days: int = 30, limit: int = 20,
                detail: str = "standard", sort_by: str = "trurisk",
                breakdown_by: str = "tag") -> dict:
    """[Risk Assessment] Cross-domain risk assessment — VMs, cloud, containers, web apps, certificates, assets. @slow

    USE WHEN: "what's our risk?", "show me cloud risk in AWS", "top risky assets", "container vulnerabilities",
    "expiring certificates", "EOL systems", "risk by business unit", "how's our security posture?"

    Parameters:
        scope: "all" | "cloud" | "containers" | "web" | "certs" | "assets"
        tag: filter by tag/business group
        asset_group: filter by asset group
        asset_id: single asset deep-dive (skips broad queries)
        os: OS filter
        query: hostname/asset name search
        days_since_seen: stale asset filter (days)
        days_since_scan: scan gap filter (days)
        eol_only: only end-of-life assets
        provider: "aws" | "azure" | "gcp" (cloud scope)
        service: cloud service filter (S3, IAM, EC2, Lambda, etc.)
        account_id: specific cloud account
        per_account: include per-account breakdown
        image_id: specific container image
        app_name: web application name filter
        owasp_category: OWASP Top 10 category (Injection, XSS, etc.)
        protocol_filter: TLS version filter (TLSv1.0, SSLv3, etc.)
        weak_ciphers: filter for weak cipher suites
        weak_only: only certificates with issues
        insecure_renegotiation: filter for insecure TLS renegotiation
        include_expired: include expired certificates
        days: time window (default 30)
        limit: max results per data source (default 20)
        detail: "summary" | "standard" | "detailed"
        sort_by: "trurisk" | "severity"
        breakdown_by: "tag" | "none"

    Returns: unified envelope with summary, data (per-domain results), correlations, actions."""
    return await asyncio.to_thread(assess_risk_wf, scope=scope, tag=tag, asset_group=asset_group,
                          asset_id=asset_id, os=os, query=query,
                          days_since_seen=days_since_seen, days_since_scan=days_since_scan,
                          eol_only=eol_only, provider=provider, service=service,
                          account_id=account_id, per_account=per_account, image_id=image_id,
                          app_name=app_name, owasp_category=owasp_category,
                          protocol_filter=protocol_filter, weak_ciphers=weak_ciphers,
                          weak_only=weak_only, insecure_renegotiation=insecure_renegotiation,
                          include_expired=include_expired, days=days, limit=limit,
                          detail=detail, sort_by=sort_by, breakdown_by=breakdown_by)


@mcp.tool()
async def check_compliance(framework: str = "", platform: str = "", tag: str = "",
                     asset_group: str = "", include_exceptions: bool = False,
                     exception_status: str = "Active", vuln_type: str = "",
                     days_to_expiry: int = 30, limit: int = 20,
                     detail: str = "standard") -> dict:
    """[Compliance] Compliance posture assessment — framework pass/fail rates, failing controls, risk acceptances. @slow

    USE WHEN: "are we PCI compliant?", "compliance gaps", "show failing controls", "risk acceptances expiring",
    "HIPAA posture", "CIS benchmark results", "what frameworks do we have?"

    Parameters:
        framework: "PCI" | "HIPAA" | "SOC2" | "CIS" | "NIST" | "" (all frameworks)
        platform: "windows" | "linux" (filter by platform)
        tag: filter by tag
        asset_group: filter by asset group
        include_exceptions: include vulnerability exceptions/risk acceptances
        exception_status: "Active" | "Expired" | "Pending"
        vuln_type: "False Positive" | "Compensating Control"
        days_to_expiry: show exceptions expiring within N days (default 30)
        limit: max results (default 20)
        detail: "summary" | "standard" | "detailed"

    Returns: unified envelope with summary, data (posture + exceptions), correlations, actions."""
    return await asyncio.to_thread(check_compliance_wf, framework=framework, platform=platform, tag=tag,
                               asset_group=asset_group, include_exceptions=include_exceptions,
                               exception_status=exception_status, vuln_type=vuln_type,
                               days_to_expiry=days_to_expiry, limit=limit, detail=detail)


@mcp.tool()
async def plan_remediation(scope: str = "all", tag: str = "", asset_group: str = "",
                     platform: str = "", severity: str = "", status: str = "",
                     qids: list = None, cves: list = None, limit: int = 20,
                     detail: str = "standard") -> dict:
    """[Remediation] Remediation planning — patch priorities, deployment status, mitigation coverage, program gaps. @slow

    USE WHEN: "what should we patch?", "outstanding patches", "patch deployment status", "mitigation coverage",
    "is there a mitigation for CVE-X?", "what's missing from our security program?", "how do we reduce risk?"

    Parameters:
        scope: "all" | "patches" | "mitigations" | "program"
        tag: filter by tag
        asset_group: filter by asset group
        platform: "windows" | "linux"
        severity: "critical" | "high" | "moderate"
        status: patch job status filter
        qids: check mitigation coverage for specific QIDs (list of ints)
        cves: check mitigation coverage for specific CVEs (list of strings)
        limit: max results (default 20)
        detail: "summary" | "standard" | "detailed"

    Returns: unified envelope with summary, data (patches + mitigations + program), correlations, actions."""
    return await asyncio.to_thread(plan_remediation_wf, scope=scope, tag=tag, asset_group=asset_group,
                               platform=platform, severity=severity, status=status,
                               qids=qids, cves=cves, limit=limit, detail=detail)


@mcp.tool()
async def security_overview(period: str = "today", scope: str = "all", quick: bool = False,
                      tag: str = "", asset_group: str = "", qql: str = "",
                      severity: str = "", scan_state: str = "Running,Paused,Queued,Error",
                      limit: int = 50, detail: str = "standard") -> dict:
    """[Overview] Security briefing — daily/weekly/monthly summary with scanner health, findings, and risk trends. @slow when quick=False

    USE WHEN: "morning briefing", "what happened this week?", "security overview", "any new critical vulns?",
    "scanner status", "what needs attention today?"

    Parameters:
        period: "today" | "week" | "month"
        scope: "all" | "infrastructure" | "findings" | "risk"
        quick: True for fast snapshot (~3s), False for full briefing (~10s)
        tag: filter by tag
        asset_group: filter by asset group
        qql: QQL query for ETM findings
        severity: finding severity filter
        scan_state: comma-separated scan states (default "Running,Paused,Queued,Error")
        limit: max results (default 50)
        detail: "summary" | "standard" | "detailed"

    Returns: unified envelope with summary, data (briefing + infrastructure + findings), correlations, actions."""
    return await asyncio.to_thread(security_overview_wf, period=period, scope=scope, quick=quick,
                                tag=tag, asset_group=asset_group, qql=qql,
                                severity=severity, scan_state=scan_state,
                                limit=limit, detail=detail)


@mcp.tool()
async def reports(action: str, report_id: str = "", template_id: str = "",
            asset_group_ids: str = "", template_name: str = "",
            report_title: str = "", output_format: str = "pdf") -> dict:
    """[Reporting] Unified report operations — list, templates, generate, status, download, delete.

    Parameters:
        action: "list" | "templates" | "generate" | "status" | "download" | "delete"
        report_id: report ID (for status/download/delete)
        template_id: template ID (for generate)
        asset_group_ids: comma-separated asset group IDs (for generate)
        template_name: filter templates by name substring
        report_title: custom title for generated report
        output_format: "pdf" | "html" | "mht" | "xml" | "csv" | "docx" (default pdf)"""
    return await asyncio.to_thread(reports_agg, action=action, report_id=report_id, template_id=template_id,
                       asset_group_ids=asset_group_ids, template_name=template_name,
                       report_title=report_title, output_format=output_format)


@mcp.tool()
async def cache_status(clear: bool = False) -> dict:
    """[Admin] Show cache stats or clear all caches.

    Parameters:
        clear: True to clear all caches, False to show stats only"""
    return await asyncio.to_thread(cache_status_agg, clear=clear)


def main():
    if not BASE_URL:
        raise EnvironmentError(
            "Qualys platform not configured. "
            "Set QUALYS_POD (e.g. QUALYS_POD=US2) or provide explicit "
            "QUALYS_BASE_URL and QUALYS_GATEWAY_URL environment variables."
        )
    if _resolved_pod:
        _log(f"qualys-mcp v0.1.9 — POD={_resolved_pod}  BASE_URL={BASE_URL}  GATEWAY_URL={GATEWAY_URL}")
    else:
        _log(f"qualys-mcp v0.1.9 — BASE_URL={BASE_URL}  GATEWAY_URL={GATEWAY_URL}")
    _log("7 tools: investigate, assess_risk, check_compliance, plan_remediation, security_overview, reports, cache_status")
    warmup = Thread(target=_warmup_vmdr_cache, daemon=True, name="vmdr-cache-warmup")
    warmup.start()
    mcp.run()


if __name__ == "__main__":
    main()
