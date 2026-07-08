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
_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
# Qualys QID: "QID 38906", "qid:38906", or a bare 4-8 digit number
_QID_PATTERN = re.compile(r"^(?:qid[\s:#-]*)?(\d{4,8})$", re.IGNORECASE)


def _extract_qid(target: str) -> str:
    m = _QID_PATTERN.match(target.strip())
    return m.group(1) if m else ""

# Vulnerability-listing intent: queries like "list exploitable vulnerabilities",
# "top sev 5 QIDs", "what's actively exploited" want a vulnerability LIST, not a
# software/host lookup. Map intent → Qualys threat-intel filter.
_VULN_THREAT_KEYWORDS = {
    "Active_Attacks": ("exploit", "active attack", "actively exploited", "in the wild", "weaponized"),
    "Ransomware": ("ransomware", "ransom"),
    "Cisa_Known_Exploited_Vulns": ("cisa", "kev", "known exploited"),
}
_VULN_LISTING_KEYWORDS = (
    "vulnerabilit", "sev 5", "severity 5", "sev5", "critical vuln", "qid",
    "unpatched", "zero-day", "zero day", "0-day", "cve", "cves",
    "recent vuln", "new vuln", "top vuln", "list vuln", "show vuln",
)


def _vuln_listing_intent(target: str) -> tuple[str, bool]:
    """Return (threat_type, is_listing) for vulnerability-listing queries.

    threat_type is a Qualys RTI filter ("" if none); is_listing is True when the
    query asks for a vulnerability list rather than a specific software/host.
    """
    t = target.lower()
    threat = ""
    for tt, kws in _VULN_THREAT_KEYWORDS.items():
        if any(k in t for k in kws):
            threat = tt
            break
    is_listing = bool(threat) or any(k in t for k in _VULN_LISTING_KEYWORDS)
    return threat, is_listing


def _detect_target_type(target: str) -> str:
    """Return one of: 'cve', 'ip', 'hostname', 'threat_actor', 'cs_vuln_uuid', 'general'."""
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

    # Container security vulnerability UUID (e.g., from get_cs_vulnerabilities output)
    if _UUID_PATTERN.match(t):
        return "cs_vuln_uuid"

    # Qualys QID ("QID 38906" or a bare numeric id)
    if _QID_PATTERN.match(t):
        return "qid"

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
        totalai_summary,
        cs_vulnerability_detail_agg,
        assess_exposure,
        qid_details,
        get_threats,
        cloud_resources_v1_agg,
    )
    from qualys.api import module_available, prewarm_modules

    AI_KEYWORDS = {"ai", "llm", "gpt", "totalai", "jailbreak", "owasp llm", "model detection", "ai security", "ai risk", "ai vulnerability"}
    WORKSPACE_KEYWORDS = {"workspace", "workspaces", "aws workspace"}
    VMSS_KEYWORDS = {"vmss", "scale set", "scale sets", "azure vmss"}

    plan: dict[str, Any] = {}
    has_investigate_agg = False

    # Pre-warm module availability concurrently (host investigations probe
    # both EDR and FIM; serial cold probes would add ~20s).
    if target_type in ("ip", "hostname") or "edr" in scope or "fim" in scope:
        prewarm_modules(["edr", "fim"])

    if any(kw in target.lower() for kw in AI_KEYWORDS) and module_available("totalai"):
        plan["totalai"] = lambda: totalai_summary(detail=detail)

    # TotalCloud 2.24 inventory types — workspace/scale-set questions get the
    # v1 resource listing directly.
    if module_available("totalcloud"):
        if any(kw in target.lower() for kw in WORKSPACE_KEYWORDS):
            plan["cloud_resources"] = lambda: cloud_resources_v1_agg(
                provider="aws", resource_type="WORKSPACE", limit=limit, detail=detail,
            )
        elif any(kw in target.lower() for kw in VMSS_KEYWORDS):
            plan["cloud_resources"] = lambda: cloud_resources_v1_agg(
                provider="azure", resource_type="VIRTUAL_MACHINE_SCALE_SET", limit=limit, detail=detail,
            )

    if target_type == "cve":
        plan["cve_deep"] = lambda: investigate_cve_agg(target, detail=detail)
        plan["exposure"] = lambda: assess_exposure(cve=target, detail=detail)

    elif target_type == "qid":
        qid_num = _extract_qid(target)
        plan["qid_detail"] = lambda q=qid_num: qid_details(qids=q, detail=detail)
        plan["exposure"] = lambda q=qid_num: assess_exposure(qid=int(q), detail=detail)

    elif target_type == "cs_vuln_uuid":
        plan["cs_vuln_detail"] = lambda: cs_vulnerability_detail_agg(target, detail=detail)

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
        if module_available("edr"):
            plan["edr"] = lambda: edr_events(
                days=days,
                host=target,
                limit=limit,
                detail=detail,
            )
        if module_available("fim"):
            plan["fim"] = lambda: fim_events(
                days=days,
                host=target,
                limit=limit,
                detail=detail,
            )

    if "edr" in scope and "edr" not in plan and module_available("edr"):
        plan["edr"] = lambda: edr_events(
            days=days,
            limit=limit,
            detail=detail,
        )

    if "fim" in scope and "fim" not in plan and module_available("fim"):
        plan["fim"] = lambda: fim_events(
            days=days,
            limit=limit,
            detail=detail,
        )

    # scope="threats" — combined FIM + EDR + CDR threat view (documented in the
    # tool docstring; previously promised but never dispatched).
    if "threats" in scope and "threats" not in plan:
        plan["threats"] = lambda: get_threats(days=days, limit=limit)

    if ("vulns" in scope or software or threat_type) and target_type != "cve":
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

    # For general/unknown targets: detect vulnerability-listing intent and route to
    # the KB search with the right RTI filter (fast). Otherwise treat the target as
    # a software name. This avoids using the literal question as a bogus software
    # filter (e.g. "list exploitable vulnerabilities") which returns no data.
    is_vuln_listing = False
    if target_type == "general" and not software and "vulns" not in plan:
        v_threat, is_vuln_listing = _vuln_listing_intent(target)
        if is_vuln_listing:
            plan["vulns"] = lambda tt=v_threat: search_vulns_agg(
                days=7, threat_type=tt, limit=limit, detail=detail, enrich_qds=False,
            )
        else:
            plan["vulns"] = lambda: search_vulns_agg(
                days=7, software=target, limit=limit, detail=detail, enrich_qds=False,
            )

    # General target or scope=="all" without investigate_agg yet. Skip the generic
    # environment snapshot for pure vulnerability-listing queries — the KB vuln
    # search above is the answer, and skipping the snapshot keeps it fast.
    scope_all = "all" in scope or scope == []
    needs_general = target_type == "general" or (scope_all and not has_investigate_agg and "investigate" not in plan and target_type not in ("cve", "threat_actor", "qid", "cs_vuln_uuid"))
    if needs_general and "investigate" not in plan and not is_vuln_listing:
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
    stats: dict[str, Any] = {}

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

    qid_detail = data.get("qid_detail") or {}
    if isinstance(qid_detail, dict) and qid_detail.get("qids"):
        q = qid_detail["qids"][0]
        desc = (f"QID {q.get('qid')}: {q.get('title', '')} — severity {q.get('severity')}/5, "
                f"QDS {q.get('qds')}")
        if q.get("cves"):
            desc += f", CVEs: {', '.join(q['cves'][:4])}"
        if q.get("patchAvailable"):
            desc += ", patch available"
        if q.get("has_exploit"):
            desc += ", known exploit"
        parts.insert(0, desc)
        stats["qid"] = q.get("qid")

    threats = data.get("threats") or {}
    if isinstance(threats, dict) and threats.get("stats"):
        ts = threats["stats"]
        parts.append(
            f"Threat view ({threats.get('days', 7)}d): {ts.get('fim', 0)} FIM, "
            f"{ts.get('edr', 0)} EDR, {ts.get('cdr', 0)} CDR events "
            f"({ts.get('critical', 0)} critical, {ts.get('high', 0)} high)"
        )
        stats["threatEvents"] = ts.get("fim", 0) + ts.get("edr", 0) + ts.get("cdr", 0)

    cloud_res = data.get("cloud_resources") or {}
    if isinstance(cloud_res, dict) and cloud_res.get("summary"):
        parts.append(str(cloud_res["summary"]))
        if cloud_res.get("totalResources"):
            stats["cloudResources"] = cloud_res["totalResources"]

    exposure = data.get("exposure")
    if isinstance(exposure, dict):
        exp = exposure.get("exposure", {})
        potential = exp.get("potentialAssets", 0)
        if potential > 0:
            sw_matches = exp.get("softwareMatches", [])
            sw_names = ", ".join(m.get("software", "") for m in sw_matches[:3])
            parts.append(f"{potential} assets potentially exposed (running {sw_names})")
            stats["potentiallyExposed"] = potential
        risk_ctx = exp.get("riskContext", {})
        if risk_ctx.get("hasExploit"):
            parts.append("Active exploit exists — prioritize scanning")
        if risk_ctx.get("ransomware"):
            parts.append("Linked to ransomware campaigns")

    threat_actor = data.get("threat_actor") or {}
    if threat_actor:
        actor = threat_actor.get("threatActor", "")
        active = threat_actor.get("activeInEnvironment", 0)
        total_kb = threat_actor.get("totalInKB", 0)
        summary_inner = threat_actor.get("summary", "")
        if total_kb > 0 and summary_inner and "no vulnerabilities found" not in summary_inner.lower():
            parts.append(summary_inner)
        elif total_kb > 0 and actor:
            parts.append(f"{actor}: {total_kb} KB vulns, {active} active in environment")
        elif total_kb == 0 and actor:
            parts.append(f"No known CVEs attributed to {actor} in the Qualys KB (last year). They may use zero-days or unattributed techniques.")

    investigate = data.get("investigate") or {}
    if investigate and isinstance(investigate, dict):
        inv_summary = investigate.get("summary", "")
        if inv_summary and isinstance(inv_summary, str):
            parts.append(inv_summary)
        # Propagate the aggregator's key facts — for per-asset investigations
        # these carry the actual detection data (QID/severity/CVE); dropping
        # them left the rendered output with no detections (issue #229).
        for fact in (investigate.get("key_facts") or []):
            if isinstance(fact, str) and fact and fact not in parts:
                parts.append(fact)

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

    totalai = data.get("totalai") or {}
    if totalai and isinstance(totalai, dict):
        ai_summary = totalai.get("summary", "")
        if ai_summary and isinstance(ai_summary, str):
            parts.append(f"AI Security: {ai_summary}")

    vulns = data.get("vulns") or {}
    if vulns and isinstance(vulns, dict):
        vulns_summary = vulns.get("summary", "")
        if vulns_summary and isinstance(vulns_summary, str):
            parts.append(f"Vuln search: {vulns_summary}")

    if not parts:
        parts.append(f"No results found for '{data.get('_target', 'unknown')}' in the Qualys Knowledge Base or detection data. "
                     "For threat actor attribution (e.g., CrackArmor, APT groups), check Qualys TruLens at ETM > TruLens > Threat Actors in the Qualys UI. "
                     "Try a more specific target: exact CVE ID, hostname, IP address, or software name.")
    headline = parts[0]

    risk = "unknown"
    cve_deep = data.get("cve_deep") or {}
    qid_first = (data.get("qid_detail") or {}).get("qids") or [{}]
    sev_src = cve_deep if isinstance(cve_deep, dict) and cve_deep else qid_first[0]
    if isinstance(sev_src, dict):
        sev = sev_src.get("severity", 0)
        ransomware = sev_src.get("ransomware", False)
        if ransomware or sev >= 5:
            risk = "critical"
        elif sev >= 4:
            risk = "high"
        elif sev >= 3:
            risk = "medium"
        elif sev >= 1:
            risk = "low"

    threat_actor = data.get("threat_actor") or {}
    if isinstance(threat_actor, dict):
        if threat_actor.get("activeInEnvironment", 0) > 0:
            risk = "high" if risk == "unknown" else risk
        elif threat_actor.get("totalInKB", -1) == 0:
            risk = "low" if risk == "unknown" else risk

    # Adopt the investigate aggregator's computed risk (e.g. per-asset TruRisk)
    # when nothing more specific set one — a TruRisk-1000 asset must not
    # surface as "low"/"unknown" (issue #229 follow-on).
    investigate = data.get("investigate") or {}
    if isinstance(investigate, dict) and risk == "unknown":
        inv_risk = investigate.get("risk_level", "")
        if inv_risk in ("critical", "high", "medium", "low"):
            risk = inv_risk

    totalai = data.get("totalai") or {}
    if isinstance(totalai, dict) and totalai.get("totalDetections", 0) > 0:
        jailbreaks = totalai.get("jailbreakCount", 0)
        if jailbreaks > 10:
            risk = "high" if risk == "unknown" else risk
        elif totalai.get("totalDetections", 0) > 0:
            risk = "medium" if risk == "unknown" else risk

    if risk == "unknown" and len(parts) > 1:
        risk = "low"

    return {
        "headline": headline,
        "risk_level": risk,
        "key_findings": parts[:5],
        "stats": stats,
    }


def _correlate(data):
    correlations = []

    cve_deep = data.get("cve_deep") or {}
    cve_meta = data.get("cve_meta") or {}

    if cve_deep or cve_meta:
        cve_id = cve_deep.get("cve") or cve_meta.get("cve", "")
        qids_deep = set(cve_deep.get("qids") or [])
        qids_meta = set(cve_meta.get("qids") or []) if isinstance(cve_meta, dict) else set()
        all_qids = list(qids_deep | qids_meta)
        if cve_id and all_qids:
            correlations.append({
                "finding": f"{cve_id} maps to {len(all_qids)} QID(s): {all_qids[:5]}",
                "severity": "high",
                "sources": ["cve_deep", "cve_meta"],
            })

    edr = data.get("edr") or {}
    fim = data.get("fim") or {}
    if edr or fim:
        affected_hosts = set()
        for src in (edr, fim):
            if isinstance(src, dict):
                for h in (src.get("affectedHosts") or []):
                    affected_hosts.add(h if isinstance(h, str) else str(h))
        if affected_hosts:
            correlations.append({
                "finding": f"{len(affected_hosts)} hosts with endpoint events",
                "severity": "medium",
                "sources": ["edr", "fim"],
            })

    return correlations


def _build_actions(data, correlations):
    actions = []
    priority = 1

    cve_deep = data.get("cve_deep") or {}
    if cve_deep:
        cve_id = cve_deep.get("cve", "CVE")
        patch = cve_deep.get("patchAvailable", False)
        ransomware = cve_deep.get("ransomware", False)

        if ransomware:
            actions.append({
                "priority": priority,
                "action": f"Immediately patch or mitigate {cve_id} — ransomware exploitation confirmed",
                "scope": cve_id,
                "tool_hint": f"plan_remediation(cves=['{cve_id}'])",
            })
            priority += 1
        elif patch:
            actions.append({
                "priority": priority,
                "action": f"Apply available patch for {cve_id}",
                "scope": cve_id,
                "tool_hint": f"plan_remediation(cves=['{cve_id}'])",
            })
            priority += 1
        elif not patch:
            actions.append({
                "priority": priority,
                "action": f"Implement compensating controls for {cve_id} — no patch available",
                "scope": cve_id,
                "tool_hint": f"investigate(target='{cve_id}')",
            })
            priority += 1

    threat_actor = data.get("threat_actor") or {}
    if threat_actor:
        active = threat_actor.get("activeInEnvironment", 0)
        actor = threat_actor.get("threatActor", "threat actor")
        if active > 0:
            actions.append({
                "priority": priority,
                "action": f"Remediate {active} active vulnerabilities exploited by {actor}",
                "scope": f"{active} vulns",
                "tool_hint": f"plan_remediation(scope='patches')",
            })
            priority += 1

    edr = data.get("edr") or {}
    if isinstance(edr, dict):
        critical_count = (edr.get("severityCounts") or {}).get("CRITICAL", 0)
        if critical_count > 0:
            actions.append({
                "priority": priority,
                "action": f"Investigate {critical_count} critical EDR detections immediately",
                "scope": "EDR",
                "tool_hint": "investigate(target='edr', scope='edr')",
            })

    fim = data.get("fim") or {}
    if isinstance(fim, dict):
        critical_paths = fim.get("criticalPathEvents", 0)
        if critical_paths > 0:
            priority += 1
            actions.append({
                "priority": priority,
                "action": f"Review {critical_paths} FIM events on critical system paths",
                "scope": "FIM",
                "tool_hint": "investigate(target='fim', scope='fim')",
            })

    return actions[:10]


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

    # Normalize scope — the MCP tool passes a string ("all" or "edr,fim");
    # iterating a string directly would yield characters and silently break
    # every scope check ("all" -> ['a','l','l']).
    if scope is None:
        scope = []
    if isinstance(scope, str):
        scope = [p for p in re.split(r"[,\s]+", scope) if p]
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
    # Deep budget must cover a cold per-host VMDR detection fetch (~60-90s on
    # large subscriptions) plus KB enrichment; 120s was routinely exceeded,
    # dropping every per-asset finding (issue #229).
    inv_timeout = 30 if depth == "quick" else 60 if depth == "standard" else 240
    results, elapsed_ms = _dispatch(plan, timeout=inv_timeout)
    results["_target"] = target

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
        actions_fn=lambda data: _build_actions(data, _correlate(data)),
    )

    # --- Apply detail level ---
    return _apply_detail(envelope, detail)
