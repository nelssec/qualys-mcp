"""Security overview workflow — orchestrates morning_report, scanner_health,
scan_status, and etm_findings into a single consolidated response.
"""

from qualys.aggregators import (
    etm_findings,
    morning_report,
    scan_status,
    scanner_health,
)
from qualys.workflows import _apply_detail, _build_envelope, _dispatch

# ---------------------------------------------------------------------------
# Period mapping
# ---------------------------------------------------------------------------

_PERIOD_DAYS = {
    "today": 1,
    "week": 7,
    "month": 30,
}


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def _build_plan(
    period: str,
    scope: str,
    quick: bool,
    qql: str,
    scan_state: str,
    limit: int,
    detail: str,
) -> dict:
    """Build dispatch plan dict based on dispatch rules."""
    days = _PERIOD_DAYS.get(period, 1)
    plan = {}

    plan["morning_report"] = lambda q=quick, d=detail: morning_report(quick=q, detail=d)

    if scope in ("all", "infrastructure"):
        plan["scanner_health"] = lambda d=detail: scanner_health(detail=d)
        plan["scan_status"] = lambda s=scan_state, dy=days, lm=limit, d=detail: scan_status(
            state=s, days=dy, limit=lm, detail=d
        )

    if scope in ("all", "findings") or qql:
        plan["etm_findings"] = lambda q=qql, d=detail: etm_findings(qql=q, detail=d)

    return plan


# ---------------------------------------------------------------------------
# Synthesis helpers
# ---------------------------------------------------------------------------

def _summarize(data):
    findings = []
    stats = {}

    mr = data.get("morning_report") or {}
    if isinstance(mr, dict) and "error" not in mr:
        env = mr.get("environment") or {}
        total_assets = env.get("totalAssets") or mr.get("totalAssets") or mr.get("assetsTotal") or 0
        health = env.get("healthScore") or mr.get("healthScore")
        if total_assets:
            stats["total_assets"] = total_assets
        if health is not None:
            stats["health_score"] = health
        mr_summary = mr.get("summary")
        if isinstance(mr_summary, str) and mr_summary:
            findings.append(mr_summary)
        elif isinstance(mr_summary, dict) and mr_summary.get("headline"):
            findings.append(mr_summary["headline"])

    sh = data.get("scanner_health") or {}
    if isinstance(sh, dict) and "error" not in sh:
        scanners = sh.get("scanners") or []
        online = sum(1 for s in scanners if isinstance(s, dict) and s.get("status", "").lower() == "online")
        offline = len(scanners) - online
        stats["scanners_online"] = online
        stats["scanners_offline"] = offline
        if offline:
            findings.append(f"{offline} scanners offline")

    ss = data.get("scan_status") or {}
    if isinstance(ss, dict) and "error" not in ss:
        ss_stats = ss.get("stats") or {}
        errors = ss_stats.get("errors", 0)
        if errors:
            stats["scan_errors"] = errors
            findings.append(f"{errors} scan errors")

    ef = data.get("etm_findings") or {}
    if isinstance(ef, dict) and "error" not in ef:
        ef_findings = ef.get("findings") or []
        count = ef.get("total", len(ef_findings))
        if count:
            stats["findings_count"] = count

    headline = "Security overview complete"
    if findings:
        headline = findings[0]

    risk = "unknown"
    if stats.get("scanners_offline", 0) > 0 or stats.get("scan_errors", 0) > 0:
        risk = "medium"
    if stats.get("findings_count", 0) > 50:
        risk = "high"

    return {
        "headline": headline,
        "risk_level": risk,
        "key_findings": findings[:5],
        "stats": {k: v for k, v in stats.items() if v is not None},
    }


def _correlate(data: dict) -> list[dict]:
    """Correlate offline scanners with scan errors to surface related issues."""
    correlations = []

    sh = data.get("scanner_health") or {}
    ss = data.get("scan_status") or {}

    if isinstance(sh, dict) and isinstance(ss, dict):
        offline_scanners = [
            s for s in (sh.get("scanners") or [])
            if s.get("status", "").lower() != "online"
        ]
        failed_scans = ss.get("failedScans") or []
        error_count = (ss.get("stats") or {}).get("errors", 0)

        if offline_scanners and error_count > 0:
            correlations.append({
                "type": "scanner_scan_correlation",
                "description": (
                    f"{len(offline_scanners)} offline scanner(s) may be contributing to "
                    f"{error_count} scan error(s)"
                ),
                "offline_scanners": [s.get("name", "unknown") for s in offline_scanners],
                "scan_errors": error_count,
                "recommendation": "Bring offline scanners online to resolve scan errors",
            })

    return correlations


def _build_actions(data: dict, correlations: list) -> list[dict]:
    """Build prioritized action items from data and correlations."""
    actions = []

    sh = data.get("scanner_health") or {}
    ss = data.get("scan_status") or {}
    mr = data.get("morning_report") or {}

    # Flag offline scanners
    if isinstance(sh, dict) and "error" not in sh:
        offline_scanners = [
            s for s in (sh.get("scanners") or [])
            if s.get("status", "").lower() != "online"
        ]
        for scanner in offline_scanners:
            actions.append({
                "priority": "high",
                "type": "offline_scanner",
                "title": f"Scanner offline: {scanner.get('name', 'unknown')}",
                "description": (
                    f"Scanner '{scanner.get('name', 'unknown')}' is not online "
                    f"(missed heartbeats: {scanner.get('heartbeatsMissed', 'unknown')})"
                ),
                "action": "Investigate scanner connectivity and restart if necessary",
            })

    # Flag scan issues (errors)
    if isinstance(ss, dict) and "error" not in ss:
        stats = ss.get("stats") or {}
        error_count = stats.get("errors", 0)
        if error_count > 0:
            failed_scans = ss.get("failedScans") or []
            actions.append({
                "priority": "high",
                "type": "scan_errors",
                "title": f"{error_count} scan(s) in error state",
                "description": f"{error_count} scans have encountered errors and require attention",
                "affected_scans": [s.get("title", s.get("name", "unknown")) for s in failed_scans[:5]],
                "action": "Review failed scans and re-launch or investigate root cause",
            })

    # Flag low health score
    if isinstance(mr, dict) and "error" not in mr:
        env = mr.get("environment") or {}
        health = env.get("healthScore") or mr.get("healthScore")
        if health is not None and health < 80:
            actions.append({
                "priority": "medium",
                "type": "low_health_score",
                "title": f"Security health score low: {health}",
                "description": f"Overall security health score is {health}/100, below the recommended threshold of 80",
                "action": "Review unscanned assets and address outstanding vulnerabilities",
            })

    # Surface correlation-driven actions
    for correlation in correlations:
        if correlation.get("type") == "scanner_scan_correlation":
            actions.append({
                "priority": "high",
                "type": "correlated_issue",
                "title": "Offline scanners causing scan failures",
                "description": correlation["description"],
                "action": correlation["recommendation"],
            })

    return actions


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def security_overview(
    period: str = "today",
    scope: str = "all",
    quick: bool = False,
    tag: str = "",
    asset_group: str = "",
    qql: str = "",
    severity: str = "",
    scan_state: str = "Running,Paused,Queued,Error",
    limit: int = 50,
    detail: str = "standard",
) -> dict:
    """Consolidated security overview across infrastructure, scans, and findings.

    Args:
        period: Time window — "today" (1 day), "week" (7 days), "month" (30 days).
        scope: Data scope — "all", "infrastructure", or "findings".
        quick: If True, use fast snapshot mode for morning_report.
        tag: Asset tag filter (passed through to underlying calls where supported).
        asset_group: Asset group filter (passed through where supported).
        qql: QQL query for ETM findings (triggers findings fetch even if scope != "findings").
        severity: Severity filter (informational, for downstream use).
        scan_state: Comma-separated scan states to include.
        limit: Maximum number of scans/findings to return.
        detail: Response verbosity — "summary", "standard", or "detailed".

    Returns:
        Consolidated envelope with summary, actions, correlations, and raw data.
    """
    plan = _build_plan(
        period=period,
        scope=scope,
        quick=quick,
        qql=qql,
        scan_state=scan_state,
        limit=limit,
        detail=detail,
    )

    overview_timeout = 30 if quick else 120
    results, elapsed_ms = _dispatch(plan, timeout=overview_timeout)

    envelope = _build_envelope(
        workflow="security_overview",
        aggregators_called=list(plan.keys()),
        results=results,
        execution_time_ms=elapsed_ms,
        summary_fn=_summarize,
        correlate_fn=_correlate,
        actions_fn=lambda data: _build_actions(data, _correlate(data)),
    )

    if detail == "detailed":
        envelope["_raw_results"] = results

    return _apply_detail(envelope, detail)
