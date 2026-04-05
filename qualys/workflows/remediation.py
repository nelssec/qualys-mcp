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

def _build_plan(scope, tag, asset_group, platform, severity, status,
                qids, cves, limit, detail):
    """Return a dict of {name: callable} based on the requested scope."""
    plan = {}

    if scope == "mitigations" or qids or cves:
        plan["eliminate_coverage"] = lambda: eliminate_coverage(qids=qids or [], cves=cves or [], detail=detail)
        return plan

    if scope == "program":
        plan["recommendations"] = lambda: recommendations(detail=detail)
        return plan

    if scope in ("all", "patches"):
        plan["patch_status"] = lambda: patch_status(limit=limit, tag=tag, asset_group=asset_group, detail=detail)
        plan["outstanding_patches"] = lambda: outstanding_patches(platform=platform, severity=severity, top_n=limit, detail=detail)

    if scope == "all":
        plan["eliminate_status"] = lambda: eliminate_status(detail=detail, status=status)

    if not plan:
        plan["patch_status"] = lambda: patch_status(limit=limit, tag=tag, asset_group=asset_group, detail=detail)
        plan["eliminate_status"] = lambda: eliminate_status(detail=detail, status=status)

    return plan


# ---------------------------------------------------------------------------
# Synthesis helpers
# ---------------------------------------------------------------------------

def _summarize(data):
    findings = []
    stats = {}

    ps = data.get("patch_status") or {}
    if ps:
        coverage = ps.get("coverage")
        if coverage is not None:
            stats["patch_coverage"] = coverage
            findings.append(f"Patch coverage: {coverage}%")

    op = data.get("outstanding_patches") or {}
    if op:
        total = op.get("totalOutstanding") or len(op.get("patches", []))
        if total:
            stats["outstanding_patches"] = total
            findings.append(f"{total} outstanding patches")

    es = data.get("eliminate_status") or {}
    if es:
        patch_counts = es.get("patchCounts") or {}
        deployed = (patch_counts.get("deployed") or {}).get("total", es.get("deployed", 0))
        missing = (patch_counts.get("missing") or {}).get("total", es.get("missing", 0))
        if deployed:
            stats["patches_deployed"] = deployed
        if missing:
            stats["patches_missing"] = missing
            findings.append(f"{missing} patches missing across managed assets")

    if not findings:
        findings.append("No outstanding patches or remediation actions found. Patch management data may not be available — verify TruRisk Eliminate is configured.")

    headline = "Remediation plan assessed"
    if stats.get("patch_coverage") is not None:
        headline = f"Patch coverage: {stats['patch_coverage']}%"
        if stats.get("outstanding_patches"):
            headline += f", {stats['outstanding_patches']} patches outstanding"

    return {
        "headline": headline,
        "risk_level": "high" if stats.get("outstanding_patches", 0) > 20 else "medium" if stats.get("outstanding_patches", 0) > 0 else "low",
        "key_findings": findings[:5],
        "stats": stats,
    }


def _correlate(data: dict) -> dict:
    """Cross-reference outstanding patches with eliminate coverage to find
    unmitigated QIDs."""
    correlations = []

    op = data.get("outstanding_patches") or {}
    ec = data.get("eliminate_coverage") or {}

    top_patches = op.get("topPatches") or op.get("patches") or []
    coverage_list = ec.get("coverage") or ec.get("mitigations") or []

    if not top_patches or not coverage_list:
        return correlations

    mitigated_qids = set()
    for entry in coverage_list:
        if isinstance(entry, dict) and entry.get("hasMitigation"):
            qid = entry.get("qid")
            if qid is not None:
                mitigated_qids.add(qid)

    unmitigated_count = 0
    for patch in top_patches:
        patch_qids = patch.get("qids") or patch.get("qidList") or []
        if isinstance(patch_qids, int):
            patch_qids = [patch_qids]
        for q in patch_qids:
            if q not in mitigated_qids:
                unmitigated_count += 1

    if unmitigated_count:
        correlations.append({
            "finding": f"{unmitigated_count} outstanding QIDs have no TruRisk Eliminate mitigation available",
            "severity": "medium",
            "sources": ["outstanding_patches", "eliminate_coverage"],
        })

    return correlations


def _build_actions(data, correlations):
    actions = []
    priority = 1

    op = data.get("outstanding_patches") or {}
    for patch in (op.get("topPatches") or op.get("patches") or [])[:5]:
        if isinstance(patch, dict):
            actions.append({
                "priority": priority,
                "action": f"Deploy patch: {patch.get('title', patch.get('patchId', 'unknown'))}",
                "scope": f"{patch.get('missingCount', patch.get('affectedAssets', 'N/A'))} assets",
                "tool_hint": "plan_remediation(scope='patches')",
            })
            priority += 1

    recs = data.get("recommendations") or {}
    for rec in (recs.get("recommendations") or [])[:3]:
        if isinstance(rec, dict):
            actions.append({
                "priority": priority,
                "action": rec.get("finding", "Address program gap"),
                "scope": rec.get("area", ""),
                "tool_hint": "plan_remediation(scope='program')",
            })
            priority += 1

    return actions[:10]


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

    envelope = _build_envelope(
        workflow="plan_remediation",
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
