"""Workflow: investigate — unified threat and vulnerability investigation.

Composes aggregator calls based on target type detection, returning a
structured envelope with findings, correlations, and recommended actions.
"""

import re
from typing import Any

from qualys.workflows import (
    _dispatch,
    _build_envelope,
    _apply_detail,
    _determine_risk_level,
)

# ---------------------------------------------------------------------------
# Threat actor / industry maps
# ---------------------------------------------------------------------------

APT_MAP: dict[str, list[str]] = {
    "iran": ["APT33", "APT34", "APT35", "OilRig", "Charming Kitten", "Elfin"],
    "iranian": ["APT33", "APT34", "APT35", "OilRig", "Charming Kitten", "Elfin"],
    "north korea": ["Lazarus", "APT38", "Kimsuky", "HIDDEN COBRA"],
    "north korean": ["Lazarus", "APT38", "Kimsuky", "HIDDEN COBRA"],
    "dprk": ["Lazarus", "APT38", "Kimsuky", "HIDDEN COBRA"],
    "lazarus": ["Lazarus", "APT38"],
    "russia": ["APT28", "APT29", "Sandworm", "Cozy Bear", "Fancy Bear"],
    "russian": ["APT28", "APT29", "Sandworm", "Cozy Bear", "Fancy Bear"],
    "china": ["APT41", "APT10", "Volt Typhoon", "Salt Typhoon"],
    "chinese": ["APT41", "APT10", "Volt Typhoon", "Salt Typhoon"],
    "ransomware": ["LockBit", "ALPHV", "BlackCat", "Cl0p", "RansomHub"],
    "apt33": ["APT33"],
    "apt34": ["APT34"],
    "apt35": ["APT35"],
    "apt28": ["APT28"],
    "apt29": ["APT29"],
    "apt38": ["APT38"],
    "apt41": ["APT41"],
    "apt10": ["APT10"],
    "sandworm": ["Sandworm"],
    "cozy bear": ["APT29", "Cozy Bear"],
    "fancy bear": ["APT28", "Fancy Bear"],
    "volt typhoon": ["Volt Typhoon"],
    "salt typhoon": ["Salt Typhoon"],
    "kimsuky": ["Kimsuky"],
    "oilrig": ["OilRig"],
    "charming kitten": ["Charming Kitten"],
    "lockbit": ["LockBit"],
    "alphv": ["ALPHV"],
    "blackcat": ["BlackCat"],
    "cl0p": ["Cl0p"],
    "ransomhub": ["RansomHub"],
}

INDUSTRY_MAP: dict[str, list[str]] = {
    "healthcare": ["healthcare", "medical", "hospital", "HIPAA"],
    "health": ["healthcare", "medical", "hospital", "HIPAA"],
    "finance": ["financial", "banking", "SWIFT"],
    "financial": ["financial", "banking", "SWIFT"],
    "banking": ["financial", "banking", "SWIFT"],
    "energy": ["energy", "ICS", "SCADA", "OT"],
    "government": ["government", "federal", "public sector"],
    "federal": ["government", "federal", "public sector"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_actor_tags(key: str) -> list[str] | None:
    """Return actor tag list for key, checking APT_MAP then INDUSTRY_MAP.

    Exact match first, then case-insensitive substring fallback.
    Returns None if no match found.
    """
    key_lower = key.lower().strip()

    # Exact match in APT_MAP
    if key_lower in APT_MAP:
        return APT_MAP[key_lower]

    # Exact match in INDUSTRY_MAP
    if key_lower in INDUSTRY_MAP:
        return INDUSTRY_MAP[key_lower]

    # Substring fallback: APT_MAP
    for map_key, tags in APT_MAP.items():
        if map_key in key_lower or key_lower in map_key:
            return tags

    # Substring fallback: INDUSTRY_MAP
    for map_key, tags in INDUSTRY_MAP.items():
        if map_key in key_lower or key_lower in map_key:
            return tags

    return None


_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _detect_target_type(target: str) -> str:
    """Return one of: 'cve', 'ip', 'hostname', 'threat_actor', 'general'."""
    t = target.strip()

    # CVE pattern — must be CVE-YYYY-NNNNN with numeric year and ID
    if re.match(r"^CVE-", t, re.IGNORECASE):
        if _CVE_PATTERN.match(t):
            return "cve"
        # Malformed CVE (e.g., CVE-invalid) → treat as general
        return "general"

    # IP address
    if _IP_PATTERN.match(t):
        return "ip"

    # Explicit asset/hostname prefix
    if t.lower().startswith("asset:"):
        return "hostname"

    # Threat actor / nation / industry
    if _resolve_actor_tags(t) is not None:
        return "threat_actor"

    return "general"


_VALID_DEPTHS = {"quick", "standard", "deep"}


def _build_plan(
    target: str,
    target_type: str,
    depth: str,
    scope: list[str],
    tag: str,
    asset_group: str,
    threat_type: str,
    software: str,
    days: int,
    limit: int,
    detail: str,
    prior_context: str,
) -> dict[str, Any]:
    """Build a dispatch plan dict mapping keys to callables.

    Returns a dict suitable for passing to _dispatch().
    """
    from qualys.aggregators import (
        investigate_cve_agg,
        investigate_agg,
        search_vulns_agg,
        cve_details,
        threat_actor_exposure_agg,
        edr_events,
        fim_events,
    )

    plan: dict[str, Any] = {}
    has_investigate_agg = False

    if target_type == "cve":
        plan["cve_deep"] = lambda: investigate_cve_agg(target, detail=detail)
        plan["cve_meta"] = lambda: cve_details(target, detail=detail)

    elif target_type == "threat_actor":
        actor_tags = _resolve_actor_tags(target) or []
        plan["threat_actor"] = lambda: threat_actor_exposure_agg(
            threat_actor=target,
            actor_tags=actor_tags,
            limit=limit,
            detail=detail,
        )

    elif target_type in ("ip", "hostname"):
        # Use a quick depth for host-based investigate_agg
        host_depth = "quick" if depth == "standard" else depth
        plan["investigate"] = lambda: investigate_agg(
            topic=target,
            depth=host_depth,
            prior_context=prior_context,
            detail=detail,
        )
        has_investigate_agg = True
        plan["edr"] = lambda: edr_events(
            days=days,
            host=target,
            limit=limit,
            detail=detail,
        )
        plan["fim"] = lambda: fim_events(
            days=days,
            host=target,
            limit=limit,
            detail=detail,
        )

    # Scope-based additions (can layer on top of host/general)
    if "edr" in scope and "edr" not in plan:
        plan["edr"] = lambda: edr_events(
            days=days,
            limit=limit,
            detail=detail,
        )

    if "fim" in scope and "fim" not in plan:
        plan["fim"] = lambda: fim_events(
            days=days,
            limit=limit,
            detail=detail,
        )

    if "vulns" in scope or software or threat_type:
        if "vulns" not in plan:
            plan["vulns"] = lambda: search_vulns_agg(
                days=days,
                threat_type=threat_type,
                software=software,
                limit=limit,
                tag=tag,
                asset_group=asset_group,
                detail=detail,
            )

    # General target or scope=="all" without investigate_agg yet
    scope_all = "all" in scope or scope == []
    needs_general = target_type == "general" or (scope_all and not has_investigate_agg and "investigate" not in plan)
    if needs_general and "investigate" not in plan:
        plan["investigate"] = lambda: investigate_agg(
            topic=target,
            depth=depth,
            prior_context=prior_context,
            detail=detail,
        )
        has_investigate_agg = True

    return plan


# ---------------------------------------------------------------------------
# Synthesis functions
# ---------------------------------------------------------------------------

def _summarize(data: dict) -> str:
    """Build a narrative summary string from aggregated results."""
    parts: list[str] = []

    cve_deep = data.get("cve_deep") or {}
    if cve_deep:
        cve_id = cve_deep.get("cve", "")
        title = cve_deep.get("title", "")
        qds = cve_deep.get("qds", 0)
        severity = cve_deep.get("severity", 0)
        ransomware = cve_deep.get("ransomware", False)
        patch = cve_deep.get("patchAvailable", False)
        summary_inner = cve_deep.get("summary", {})
        asset_count = summary_inner.get("assetsWithSoftware", 0) if isinstance(summary_inner, dict) else 0

        desc = f"{cve_id}"
        if title:
            desc += f" ({title})"
        desc += f" — severity {severity}, QDS {qds}"
        if ransomware:
            desc += ", linked to ransomware"
        if patch:
            desc += ", patch available"
        if asset_count:
            desc += f", {asset_count} potentially affected assets"
        parts.append(desc)

    threat_actor = data.get("threat_actor") or {}
    if threat_actor:
        actor = threat_actor.get("threatActor", "")
        active = threat_actor.get("activeInEnvironment", 0)
        total_kb = threat_actor.get("totalInKB", 0)
        summary_inner = threat_actor.get("summary", "")
        if summary_inner:
            parts.append(summary_inner)
        elif actor:
            parts.append(f"{actor}: {total_kb} KB vulns, {active} active in environment")

    investigate = data.get("investigate") or {}
    if investigate and isinstance(investigate, dict):
        inv_summary = investigate.get("summary", "")
        if inv_summary and isinstance(inv_summary, str):
            parts.append(inv_summary)

    edr = data.get("edr") or {}
    if edr and isinstance(edr, dict):
        edr_summary = edr.get("summary", "")
        if edr_summary and isinstance(edr_summary, str):
            parts.append(f"EDR: {edr_summary}")

    fim = data.get("fim") or {}
    if fim and isinstance(fim, dict):
        fim_summary = fim.get("summary", "")
        if fim_summary and isinstance(fim_summary, str):
            parts.append(f"FIM: {fim_summary}")

    vulns = data.get("vulns") or {}
    if vulns and isinstance(vulns, dict):
        vulns_summary = vulns.get("summary", "")
        if vulns_summary and isinstance(vulns_summary, str):
            parts.append(f"Vuln search: {vulns_summary}")

    return " | ".join(parts) if parts else "Investigation complete."


def _correlate(data: dict) -> dict:
    """Cross-reference results to surface correlated findings."""
    correlations: dict = {}

    cve_deep = data.get("cve_deep") or {}
    cve_meta = data.get("cve_meta") or {}

    # Merge CVE identity info
    if cve_deep or cve_meta:
        cve_id = cve_deep.get("cve") or cve_meta.get("cve", "")
        qids_deep = set(cve_deep.get("qids") or [])
        qids_meta = set(cve_meta.get("qids") or []) if isinstance(cve_meta, dict) else set()
        all_qids = list(qids_deep | qids_meta)
        correlations["cve_qids"] = {"cve": cve_id, "qids": all_qids, "count": len(all_qids)}

    # Correlate host-level findings
    edr = data.get("edr") or {}
    fim = data.get("fim") or {}
    investigate = data.get("investigate") or {}

    if edr or fim:
        affected_hosts: set[str] = set()
        edr_hosts = (edr.get("affectedHosts") or []) if isinstance(edr, dict) else []
        fim_hosts = (fim.get("affectedHosts") or []) if isinstance(fim, dict) else []
        affected_hosts.update(edr_hosts)
        affected_hosts.update(fim_hosts)
        if affected_hosts:
            correlations["affected_hosts"] = sorted(affected_hosts)

    # Risk level
    risk = _determine_risk_level(data)
    correlations["risk_level"] = risk

    return correlations


def _build_actions(data: dict, correlations: dict) -> list[dict]:
    """Generate prioritized recommended actions from findings."""
    actions: list[dict] = []

    risk = correlations.get("risk_level", "UNKNOWN")

    cve_deep = data.get("cve_deep") or {}
    if cve_deep:
        cve_id = cve_deep.get("cve", "CVE")
        patch = cve_deep.get("patchAvailable", False)
        ransomware = cve_deep.get("ransomware", False)
        qids = (correlations.get("cve_qids") or {}).get("qids") or []

        if ransomware:
            actions.append({
                "priority": "CRITICAL",
                "action": f"Immediately patch or mitigate {cve_id} — ransomware exploitation confirmed",
                "qids": qids[:5],
            })
        elif patch and risk in ("CRITICAL", "HIGH"):
            actions.append({
                "priority": "HIGH",
                "action": f"Apply available patch for {cve_id}",
                "qids": qids[:5],
            })
        elif not patch:
            actions.append({
                "priority": "MEDIUM",
                "action": f"Implement compensating controls for {cve_id} — no patch available",
                "qids": qids[:5],
            })

    threat_actor = data.get("threat_actor") or {}
    if threat_actor:
        active = threat_actor.get("activeInEnvironment", 0)
        actor = threat_actor.get("threatActor", "threat actor")
        if active > 0:
            actions.append({
                "priority": "HIGH",
                "action": f"Remediate {active} active vulnerabilities exploited by {actor}",
            })

    edr = data.get("edr") or {}
    if isinstance(edr, dict):
        critical_count = (edr.get("severityCounts") or {}).get("CRITICAL", 0)
        if critical_count > 0:
            actions.append({
                "priority": "CRITICAL",
                "action": f"Investigate {critical_count} critical EDR detections immediately",
            })

    fim = data.get("fim") or {}
    if isinstance(fim, dict):
        critical_paths = fim.get("criticalPathEvents", 0)
        if critical_paths > 0:
            actions.append({
                "priority": "HIGH",
                "action": f"Review {critical_paths} FIM events on critical system paths",
            })

    # Sort by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    actions.sort(key=lambda a: priority_order.get(a.get("priority", "LOW"), 3))

    return actions


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def investigate(
    target: str,
    depth: str = "standard",
    scope: list[str] | None = None,
    tag: str = "",
    asset_group: str = "",
    threat_type: str = "",
    software: str = "",
    days: int = 7,
    limit: int = 50,
    detail: str = "standard",
    prior_context: str = "",
    audience: str = "technical",
) -> dict:
    """Unified investigation workflow.

    Detects target type, dispatches appropriate aggregators concurrently,
    and returns an enriched envelope with findings, correlations, and actions.

    Args:
        target: CVE ID, IP address, hostname (prefix "asset:"), threat actor
                name/nation, industry sector, or general topic.
        depth: "quick", "standard", or "deep". Invalid values default to "standard".
        scope: List of additional data sources to include: "edr", "fim", "vulns",
               "all". Defaults to [] (auto-detected based on target type).
        tag: Qualys asset tag filter for vuln searches.
        asset_group: Qualys asset group filter.
        threat_type: Filter vuln searches by threat type keyword.
        software: Filter vuln searches by software name.
        days: Lookback window in days for time-based queries.
        limit: Maximum number of items to return per aggregator.
        detail: "summary", "standard", or "detailed".
        prior_context: Prior investigation context to pass to investigate_agg.
        audience: "technical" or "executive" for summarize_investigation_agg.

    Returns:
        Workflow envelope dict with keys: workflow, aggregators_called,
        execution_time_ms, results, correlations, actions, summary.
        On validation error returns {"error": ..., "summary": {...}}.
    """
    # --- Input validation ---

    # Empty/whitespace target
    if not target or not target.strip():
        return {
            "error": "target is required",
            "summary": {
                "workflow": "investigate",
                "message": "A non-empty target is required. Provide a CVE ID, IP address, hostname, threat actor, or topic.",
            },
        }

    target = target.strip()

    # Normalize depth
    if depth not in _VALID_DEPTHS:
        depth = "standard"

    # Normalize scope
    if scope is None:
        scope = []
    scope = [s.lower().strip() for s in scope if s]

    # --- Target type detection ---
    target_type = _detect_target_type(target)

    # --- Build dispatch plan ---
    plan = _build_plan(
        target=target,
        target_type=target_type,
        depth=depth,
        scope=scope,
        tag=tag,
        asset_group=asset_group,
        threat_type=threat_type,
        software=software,
        days=days,
        limit=limit,
        detail=detail,
        prior_context=prior_context,
    )

    aggregators_called = list(plan.keys())

    # --- Dispatch ---
    results, elapsed_ms = _dispatch(plan)

    # --- Deep mode: add narrative summary via summarize_investigation_agg ---
    if depth == "deep":
        try:
            import json as _json
            from qualys.aggregators import summarize_investigation_agg
            findings_text = _json.dumps(results, default=str)[:8000]
            narrative = summarize_investigation_agg(findings=findings_text, audience=audience)
            results["narrative_summary"] = narrative
            aggregators_called.append("summarize_investigation_agg")
        except Exception:
            pass

    # --- Build envelope ---
    envelope = _build_envelope(
        workflow="investigate",
        aggregators_called=aggregators_called,
        results=results,
        execution_time_ms=elapsed_ms,
        summary_fn=_summarize,
        correlate_fn=_correlate,
        actions_fn=_build_actions,
    )

    # --- Apply detail level ---
    return _apply_detail(envelope, detail)
