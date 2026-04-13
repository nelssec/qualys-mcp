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
    policy_audit_agg,
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
    plan = {}

    def _get_compliance():
        result = compliance_posture(framework=framework, platform=platform, limit=limit, detail=detail)
        is_empty = (not result or
                    (isinstance(result, dict) and
                     not result.get("topFailingControls") and
                     (not result.get("summary") or
                      (isinstance(result.get("summary"), dict) and result["summary"].get("controls", 0) == 0))))
        if is_empty and framework:
            result = compliance_posture(framework="", platform=platform, limit=limit, detail=detail)
            if result and isinstance(result, dict):
                result["_note"] = f"Framework-specific query for '{framework}' returned no data. Showing overall compliance posture."
        return result
    plan["compliance_posture"] = _get_compliance

    if not framework or framework.lower() == "list":
        plan["list_compliance_frameworks"] = lambda: list_compliance_frameworks()

    if include_exceptions:
        plan["vuln_exceptions"] = lambda: vuln_exceptions(
            status=exception_status, vuln_type=vuln_type,
            days_to_expiry=days_to_expiry, limit=limit, detail=detail,
        )

    plan["policy_audit"] = lambda: policy_audit_agg(label=framework, limit=limit, detail=detail)

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
    posture = data.get("compliance_posture", {})
    exceptions_data = data.get("vuln_exceptions", {})

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

    findings = []
    headline = "Compliance posture assessed"
    if pass_rate > 0:
        headline = f"Compliance: {pass_rate}% pass rate"
        findings.append(f"Overall pass rate: {pass_rate}%")
    if failing:
        headline += f", {failing} failing controls"
        findings.append(f"{failing} failing controls identified")
    if exception_count:
        findings.append(f"{exception_count} active risk acceptances")
    if not findings:
        findings.append("No compliance data available. Policy Compliance may not be configured, or no compliance policies are assigned to assets in this environment.")

    return {
        "headline": headline,
        "risk_level": "low" if pass_rate >= 90 else "medium" if pass_rate >= 70 else "high" if pass_rate > 0 else "unknown",
        "key_findings": findings[:5],
        "stats": {
            "pass_rate": pass_rate,
            "failing_controls": failing,
            "total_controls": total,
            "exception_count": exception_count,
            "frameworks": frameworks,
        },
    }


def _correlate(data: dict[str, Any]) -> dict[str, Any]:
    """Find exceptions expiring within 7 days that may impact compliance posture.

    Returns a correlations dict with:
    - expiring_soon: list of exception records with daysUntilExpiry <= 7
    - at_risk_count: int number of such exceptions
    """
    correlations = []
    exceptions_data = data.get("vuln_exceptions", {})
    if not isinstance(exceptions_data, dict):
        return correlations

    all_exceptions = exceptions_data.get("exceptions", [])
    expiring_soon = [
        exc for exc in all_exceptions
        if isinstance(exc, dict) and exc.get("daysUntilExpiry") is not None
        and exc["daysUntilExpiry"] <= 7
    ]

    if expiring_soon:
        correlations.append({
            "finding": f"{len(expiring_soon)} risk acceptances expiring within 7 days — may impact compliance posture",
            "severity": "high",
            "sources": ["compliance_posture", "vuln_exceptions"],
        })

    return correlations


def _build_actions(data, correlations):
    actions = []
    priority = 1

    posture = data.get("compliance_posture", {})
    for ctrl in (posture.get("topFailingControls") or [])[:5]:
        if isinstance(ctrl, dict):
            actions.append({
                "priority": priority,
                "action": f"Remediate failing control: {ctrl.get('controlId', 'unknown')}",
                "scope": f"{ctrl.get('failingAssets', 'N/A')} assets",
                "tool_hint": "plan_remediation(scope='patches')",
            })
            priority += 1

    return actions[:10]


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

    results, elapsed_ms = _dispatch(plan, timeout=90)

    envelope = _build_envelope(
        workflow="check_compliance",
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
