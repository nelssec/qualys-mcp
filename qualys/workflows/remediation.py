"""Remediation workflow orchestrator.

Consolidates patch_status, eliminate_status, outstanding_patches,
eliminate_coverage, and recommendations into a single coordinated plan.
"""

from qualys.aggregators import (
    eliminate_coverage,
    eliminate_status,
    outstanding_patches,
    patch_status,
    recommendations,
)
from qualys.workflows import _apply_detail, _build_envelope, _dispatch


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def _build_plan(
    scope: str,
    tag: str,
    asset_group: str,
    platform: str,
    severity: str,
    status: str,
    qids: list | None,
    cves: list | None,
    limit: int,
    detail: str,
) -> list:
    """Return a list of (name, callable) pairs based on the requested scope."""

    # Mitigations / coverage scope — or when specific QIDs/CVEs are provided
    if scope == "mitigations" or qids or cves:
        return [
            (
                "eliminate_coverage",
                lambda: eliminate_coverage(
                    qids=qids or [],
                    cves=cves or [],
                    detail=detail,
                ),
            ),
        ]

    # Program gap analysis
    if scope == "program":
        return [
            ("recommendations", lambda: recommendations(detail=detail)),
        ]

    # Patches only
    if scope == "patches":
        return [
            (
                "patch_status",
                lambda: patch_status(
                    limit=limit,
                    tag=tag,
                    asset_group=asset_group,
                    detail=detail,
                ),
            ),
            (
                "outstanding_patches",
                lambda: outstanding_patches(
                    platform=platform,
                    severity=severity,
                    top_n=limit,
                    detail=detail,
                ),
            ),
        ]

    # "all" scope — or empty/unknown scope: patch_status + eliminate_status
    if scope in ("all",):
        return [
            (
                "patch_status",
                lambda: patch_status(
                    limit=limit,
                    tag=tag,
                    asset_group=asset_group,
                    detail=detail,
                ),
            ),
            (
                "eliminate_status",
                lambda: eliminate_status(detail=detail, status=status),
            ),
            (
                "outstanding_patches",
                lambda: outstanding_patches(
                    platform=platform,
                    severity=severity,
                    top_n=limit,
                    detail=detail,
                ),
            ),
        ]

    # Fallback (empty / unrecognised scope)
    return [
        (
            "patch_status",
            lambda: patch_status(
                limit=limit,
                tag=tag,
                asset_group=asset_group,
                detail=detail,
            ),
        ),
        (
            "eliminate_status",
            lambda: eliminate_status(detail=detail, status=status),
        ),
    ]


# ---------------------------------------------------------------------------
# Synthesis helpers
# ---------------------------------------------------------------------------

def _summarize(data: dict) -> dict:
    """Extract high-level metrics from the collected workflow data."""
    summary = {}

    # Patch coverage
    ps = data.get("patch_status") or {}
    if ps:
        summary["patch_coverage_pct"] = ps.get("coverage", 0)
        summary["assets_total"] = ps.get("assetsTotal", 0)
        risk_dist = ps.get("riskDistribution") or {}
        summary["critical_assets"] = risk_dist.get("critical_900plus", 0)
        summary["high_risk_assets"] = risk_dist.get("high_700plus", 0)

    # Outstanding patches count
    op = data.get("outstanding_patches") or {}
    if op:
        summary["outstanding_patches_total"] = op.get("totalOutstanding", 0)
        summary["outstanding_missing_installs"] = op.get("totalMissingInstalls", 0)
        summary["security_patches"] = op.get("securityPatches", 0)

    # Deployed / missing counts from eliminate_status
    es = data.get("eliminate_status") or {}
    if es:
        patch_counts = es.get("patchCounts") or {}
        missing = patch_counts.get("missing") or {}
        deployed = patch_counts.get("deployed") or {}
        summary["deployed_count"] = deployed.get("total", 0)
        summary["missing_count"] = missing.get("total", 0)

    # Eliminate coverage summary
    ec = data.get("eliminate_coverage") or {}
    if ec:
        ec_summary = ec.get("summary") or {}
        summary["coverage_requested"] = ec_summary.get("requested", 0)
        summary["coverage_covered"] = ec_summary.get("covered", 0)
        summary["coverage_rate"] = ec_summary.get("coverageRate", "N/A")

    # Recommendations count
    recs = data.get("recommendations") or {}
    if recs:
        rec_list = recs.get("recommendations") or []
        summary["recommendations_count"] = len(rec_list)

    return summary


def _correlate(data: dict) -> dict:
    """Cross-reference outstanding patches with eliminate coverage to find
    unmitigated QIDs."""
    correlations = {}

    op = data.get("outstanding_patches") or {}
    ec = data.get("eliminate_coverage") or {}

    top_patches = op.get("topPatches") or []
    coverage_list = ec.get("coverage") or []

    if not top_patches or not coverage_list:
        correlations["unmitigated_qids"] = []
        correlations["unmitigated_count"] = 0
        return correlations

    # Build set of QIDs that have a mitigation available
    mitigated_qids: set = set()
    for entry in coverage_list:
        if entry.get("hasMitigation"):
            qid = entry.get("qid")
            if qid is not None:
                mitigated_qids.add(qid)

    # Collect QIDs from outstanding patches that are NOT mitigated
    unmitigated = []
    for patch in top_patches:
        # Outstanding patches may carry associated QIDs
        patch_qids = patch.get("qids") or patch.get("qidList") or []
        if isinstance(patch_qids, int):
            patch_qids = [patch_qids]
        for q in patch_qids:
            if q not in mitigated_qids:
                unmitigated.append({
                    "qid": q,
                    "patch_title": patch.get("title", ""),
                    "missing_count": patch.get("missingCount", 0),
                    "platform": patch.get("platform", ""),
                })

    correlations["unmitigated_qids"] = unmitigated
    correlations["unmitigated_count"] = len(unmitigated)
    return correlations


def _build_actions(data: dict, correlations: dict) -> list:
    """Produce a prioritised action list from workflow results and correlations."""
    actions = []

    # Top outstanding patches
    op = data.get("outstanding_patches") or {}
    top_patches = op.get("topPatches") or []
    for patch in top_patches[:5]:
        title = patch.get("title", "Unknown patch")
        missing = patch.get("missingCount", 0)
        platform = patch.get("platform", "")
        severity = patch.get("vendorSeverity", "")
        actions.append({
            "type": "deploy_patch",
            "priority": "HIGH" if severity.lower() in ("critical", "important") else "MEDIUM",
            "title": title,
            "description": f"Deploy to {missing} affected {'asset' if missing == 1 else 'assets'}"
                           + (f" ({platform})" if platform else ""),
            "missing_count": missing,
        })

    # Unmitigated QIDs from correlation
    unmitigated = correlations.get("unmitigated_qids") or []
    for item in unmitigated[:5]:
        actions.append({
            "type": "apply_mitigation",
            "priority": "MEDIUM",
            "title": f"No mitigation for QID {item['qid']}",
            "description": (
                f"Patch '{item['patch_title']}' affects {item['missing_count']} assets "
                f"with no compensating control available."
            ),
            "qid": item["qid"],
        })

    # Program recommendations
    recs = data.get("recommendations") or {}
    rec_list = recs.get("recommendations") or []
    for rec in rec_list[:3]:
        actions.append({
            "type": "program_action",
            "priority": rec.get("priority", "MEDIUM"),
            "title": rec.get("area", ""),
            "description": rec.get("finding", ""),
        })

    return actions


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def plan_remediation(
    scope: str = "all",
    tag: str = "",
    asset_group: str = "",
    platform: str = "",
    severity: str = "",
    status: str = "",
    qids: list | None = None,
    cves: list | None = None,
    limit: int = 20,
    detail: str = "standard",
) -> dict:
    """Orchestrate remediation data collection and synthesis.

    Parameters
    ----------
    scope:
        One of "all", "patches", "mitigations", "program", or "" (fallback).
    tag:
        Qualys tag name to filter assets.
    asset_group:
        Asset group name to filter assets.
    platform:
        Platform filter for outstanding patches (Windows/Linux/Mac).
    severity:
        Severity filter for outstanding patches.
    status:
        Deployment status filter for eliminate_status.
    qids:
        List of QIDs for eliminate_coverage lookup.
    cves:
        List of CVE IDs for eliminate_coverage lookup.
    limit:
        Maximum number of items to return per aggregator.
    detail:
        Detail level: "summary", "standard", or "detailed".

    Returns
    -------
    dict
        Envelope containing raw aggregator data, a high-level summary,
        cross-reference correlations, and a prioritised action list.
    """
    plan = _build_plan(
        scope=scope,
        tag=tag,
        asset_group=asset_group,
        platform=platform,
        severity=severity,
        status=status,
        qids=qids,
        cves=cves,
        limit=limit,
        detail=detail,
    )

    results, elapsed_ms = _dispatch(plan)

    envelope = _build_envelope(scope=scope, results=results, elapsed_ms=elapsed_ms)

    data = envelope.get("data") or {}
    summary = _summarize(data)
    correlations = _correlate(data)
    actions = _build_actions(data, correlations)

    envelope["summary"] = summary
    envelope["correlations"] = correlations
    envelope["actions"] = actions

    return _apply_detail(envelope, detail)
