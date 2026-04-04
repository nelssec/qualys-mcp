"""Compliance workflow orchestrator for qualys-mcp.

Consolidates compliance_posture, list_compliance_frameworks, and vuln_exceptions
into a single check_compliance entry point.
"""

from __future__ import annotations

from typing import Any

from qualys.aggregators import (
    compliance_posture,
    list_compliance_frameworks,
    vuln_exceptions,
)
from qualys.workflows import _apply_detail, _build_envelope, _dispatch

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TOOL_NAME = "check_compliance"


def _build_plan(
    framework: str,
    platform: str,
    include_exceptions: bool,
    exception_status: str,
    vuln_type: str,
    days_to_expiry: int,
    limit: int,
    detail: str,
) -> list[dict[str, Any]]:
    """Build the dispatch plan based on input parameters.

    Rules:
    - Always call compliance_posture (handles framework="" or "list" internally).
    - If framework is "" or "list", also call list_compliance_frameworks to
      surface available options.
    - If include_exceptions is True, also call vuln_exceptions.
    - If a specific framework is set (not "" and not "list"), skip
      list_compliance_frameworks.
    """
    plan: list[dict[str, Any]] = []

    # Always fetch posture data
    plan.append({
        "key": "posture",
        "fn": compliance_posture,
        "kwargs": {
            "framework": framework,
            "platform": platform,
            "limit": limit,
            "detail": detail,
        },
    })

    # List frameworks when no specific framework is requested
    if not framework or framework.lower() == "list":
        plan.append({
            "key": "frameworks",
            "fn": list_compliance_frameworks,
            "kwargs": {},
        })

    # Optionally include active exceptions
    if include_exceptions:
        plan.append({
            "key": "exceptions",
            "fn": vuln_exceptions,
            "kwargs": {
                "status": exception_status,
                "vuln_type": vuln_type,
                "days_to_expiry": days_to_expiry,
                "limit": limit,
                "detail": detail,
            },
        })

    return plan


def _summarize(data: dict[str, Any]) -> dict[str, Any]:
    """Extract high-level metrics from workflow results.

    Returns a summary dict with:
    - pass_rate: float percentage of passing controls (0.0–100.0)
    - failing_controls: int count of failing controls
    - exception_count: int total exceptions found (0 if not fetched)
    - frameworks: list of framework names seen
    - total_controls: int total controls evaluated
    """
    posture = data.get("posture", {})
    exceptions_data = data.get("exceptions", {})

    # Navigate into nested summary if present
    posture_summary = posture.get("summary", posture)

    total = posture_summary.get("controls", 0)
    passing = posture_summary.get("passing", 0)
    failing = posture_summary.get("failing", 0)

    if total > 0:
        pass_rate = round(passing / total * 100, 1)
    elif posture_summary.get("pass_pct") is not None:
        pass_rate = float(posture_summary["pass_pct"])
    else:
        pass_rate = 0.0

    exception_count = 0
    if isinstance(exceptions_data, dict):
        stats = exceptions_data.get("stats", {})
        exception_count = stats.get("total", 0) or len(exceptions_data.get("exceptions", []))

    frameworks = posture_summary.get("frameworks", [])
    if not frameworks:
        by_fw = posture.get("byFramework", {})
        frameworks = list(by_fw.keys()) if isinstance(by_fw, dict) else []

    return {
        "pass_rate": pass_rate,
        "failing_controls": failing,
        "total_controls": total,
        "exception_count": exception_count,
        "frameworks": frameworks,
    }


def _correlate(data: dict[str, Any]) -> dict[str, Any]:
    """Find exceptions expiring within 7 days that may impact compliance posture.

    Returns a correlations dict with:
    - expiring_soon: list of exception records with daysUntilExpiry <= 7
    - at_risk_count: int number of such exceptions
    """
    exceptions_data = data.get("exceptions", {})
    if not isinstance(exceptions_data, dict):
        return {"expiring_soon": [], "at_risk_count": 0}

    all_exceptions = exceptions_data.get("exceptions", [])
    expiring_soon = [
        exc for exc in all_exceptions
        if isinstance(exc, dict) and exc.get("daysUntilExpiry") is not None
        and exc["daysUntilExpiry"] <= 7
    ]

    return {
        "expiring_soon": expiring_soon,
        "at_risk_count": len(expiring_soon),
    }


def _build_actions(
    data: dict[str, Any],
    correlations: dict[str, Any],
) -> list[str]:
    """Build a prioritised list of remediation actions.

    Surfaces:
    1. Top failing controls as direct remediation items.
    2. Warnings about exceptions expiring within 7 days.
    """
    actions: list[str] = []

    posture = data.get("posture", {})
    top_failing = posture.get("topFailingControls", [])

    for ctrl in top_failing[:5]:
        ctrl_id = ctrl.get("controlId", "")
        title = ctrl.get("title", "")
        assets = ctrl.get("failingAssets", 0)
        severity = ctrl.get("severity", "")
        label = ctrl_id or title or "Unknown control"
        detail_parts = []
        if title and ctrl_id:
            detail_parts.append(title)
        if severity:
            detail_parts.append(severity)
        if assets:
            detail_parts.append(f"{assets} assets affected")
        action = f"Remediate failing control: {label}"
        if detail_parts:
            action += f" ({', '.join(detail_parts)})"
        actions.append(action)

    expiring_soon = correlations.get("expiring_soon", [])
    for exc in expiring_soon[:3]:
        exc_id = exc.get("id", "")
        title = exc.get("title", "")
        days = exc.get("daysUntilExpiry", "?")
        label = exc_id or title or "exception"
        actions.append(
            f"Review expiring exception {label} — expires in {days} day(s); "
            "compliance posture may degrade when it lapses."
        )

    if not actions:
        summary = _summarize(data)
        if summary["pass_rate"] == 0.0 and summary["total_controls"] == 0:
            actions.append(
                "No compliance data found. Verify that the Policy Compliance (PC) "
                "module is licensed and policies are configured."
            )
        elif summary["failing_controls"] == 0:
            actions.append("No failing controls detected. Maintain current configuration baselines.")

    return actions


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_compliance(
    framework: str = "",
    platform: str = "",
    tag: str = "",
    asset_group: str = "",
    include_exceptions: bool = False,
    exception_status: str = "Active",
    vuln_type: str = "",
    days_to_expiry: int = 30,
    limit: int = 20,
    detail: str = "standard",
) -> dict[str, Any]:
    """Check compliance posture across frameworks with optional exception correlation.

    Args:
        framework: Framework name to filter on (e.g. "CIS", "DISA STIG").
                   Use "" or "list" to discover available frameworks.
        platform:  Platform filter (e.g. "Windows", "Linux").
        tag:       Asset tag filter (passed through for future use).
        asset_group: Asset group filter (passed through for future use).
        include_exceptions: When True, also fetch active vuln exceptions.
        exception_status:   Exception status filter ("Active", "Expired", etc.).
        vuln_type:          Vulnerability exception type filter.
        days_to_expiry:     Window in days for "expiring soon" exceptions.
        limit:              Maximum records per result set.
        detail:             Response detail level: "minimal", "standard", or "full".

    Returns:
        A standard workflow envelope with summary, actions, and raw data.
    """
    plan = _build_plan(
        framework=framework,
        platform=platform,
        include_exceptions=include_exceptions,
        exception_status=exception_status,
        vuln_type=vuln_type,
        days_to_expiry=days_to_expiry,
        limit=limit,
        detail=detail,
    )

    raw_results, elapsed_ms = _dispatch(plan)

    summary = _summarize(raw_results)
    correlations = _correlate(raw_results)
    actions = _build_actions(raw_results, correlations)

    envelope = _build_envelope(
        tool=_TOOL_NAME,
        summary=summary,
        actions=actions,
        elapsed_ms=elapsed_ms,
        data={**raw_results, "correlations": correlations},
    )

    return _apply_detail(envelope, detail)
