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
) -> list[dict]:
    """Build the ordered list of workflow steps based on dispatch rules."""
    days = _PERIOD_DAYS.get(period, 1)
    plan = []

    # Always: morning report
    plan.append({
        "key": "morning_report",
        "fn": lambda q=quick, d=detail: morning_report(quick=q, detail=d),
    })

    # Infrastructure scope: scanner health + scan status
    if scope in ("all", "infrastructure"):
        plan.append({
            "key": "scanner_health",
            "fn": lambda d=detail: scanner_health(detail=d),
        })
        plan.append({
            "key": "scan_status",
            "fn": lambda s=scan_state, dy=days, lm=limit, d=detail: scan_status(
                state=s, days=dy, limit=lm, detail=d
            ),
        })

    # Findings scope or explicit QQL
    if scope in ("all", "findings") or qql:
        plan.append({
            "key": "etm_findings",
            "fn": lambda q=qql, d=detail: etm_findings(qql=q, detail=d),
        })

    return plan


# ---------------------------------------------------------------------------
# Synthesis helpers
# ---------------------------------------------------------------------------

def _summarize(data: dict) -> dict:
    """Extract high-level metrics from workflow results."""
    summary = {
        "total_assets": 0,
        "health_score": None,
        "scanners_online": 0,
        "scanners_offline": 0,
        "active_scans": 0,
        "scan_errors": 0,
        "findings_count": 0,
    }

    # morning_report data
    mr = data.get("morning_report") or {}
    if isinstance(mr, dict) and "error" not in mr:
        env = mr.get("environment") or {}
        summary["total_assets"] = (
            env.get("totalAssets")
            or mr.get("assetsTotal")
            or mr.get("totalAssets")
            or 0
        )
        summary["health_score"] = env.get("healthScore") or mr.get("healthScore")

    # scanner_health data
    sh = data.get("scanner_health") or {}
    if isinstance(sh, dict) and "error" not in sh:
        scan_status_info = sh.get("scanStatus") or {}
        scanners = sh.get("scanners") or []
        online = sum(1 for s in scanners if s.get("status", "").lower() == "online")
        offline = len(scanners) - online
        summary["scanners_online"] = online
        summary["scanners_offline"] = offline

    # scan_status data
    ss = data.get("scan_status") or {}
    if isinstance(ss, dict) and "error" not in ss:
        stats = ss.get("stats") or {}
        summary["active_scans"] = stats.get("running", 0) + stats.get("queued", 0)
        summary["scan_errors"] = stats.get("errors", 0)

    # etm_findings data
    ef = data.get("etm_findings") or {}
    if isinstance(ef, dict) and "error" not in ef:
        findings = ef.get("findings") or []
        summary["findings_count"] = ef.get("total", len(findings))

    return summary


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

    results, elapsed_ms = _dispatch(plan)

    summary = _summarize(results)
    correlations = _correlate(results)
    actions = _build_actions(results, correlations)

    envelope = _build_envelope(
        workflow="security_overview",
        period=period,
        scope=scope,
        elapsed_ms=elapsed_ms,
        summary=summary,
        actions=actions,
        correlations=correlations,
        data=results,
        detail=detail,
    )

    return _apply_detail(envelope, detail)
