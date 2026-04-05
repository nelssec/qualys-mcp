"""Workflow: assess_risk — consolidated risk assessment across all Qualys modules.

Dispatches aggregators based on scope and parameter context, then correlates
findings into a unified risk envelope.
"""

from qualys.aggregators import (
    weekly_priorities,
    trurisk_score,
    risk_by_tag,
    cloud_risk as cloud_risk_agg,
    cloud_account_summary,
    cloud_controls,
    container_vuln_summary,
    image_vulns,
    running_containers,
    webapp_vulns,
    expiring_certs,
    cert_security_posture,
    tech_debt,
    asset_inventory,
    asset_detail,
)
from qualys.workflows import _dispatch, _build_envelope, _apply_detail


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------


def _summarize(data):
    """Produce a headline summary dict from aggregator results.

    Extracts the highest-level risk signal available across all returned data
    sources and surfaces key findings as a flat list.
    """
    findings = []
    stats = {}
    risk_level = "unknown"
    headline_parts = []

    # Asset detail (single-asset path)
    ad = data.get("asset_detail")
    if ad:
        hostname = (
            ad.get("hostname")
            or ad.get("name")
            or ad.get("asset", {}).get("hostname", "")
            if isinstance(ad, dict)
            else ""
        )
        score = (
            ad.get("truriskScore")
            or ad.get("riskScore")
            or (ad.get("asset") or {}).get("truriskScore")
            if isinstance(ad, dict)
            else None
        )
        if score is not None:
            try:
                s = float(score)
                if s >= 900:
                    risk_level = "critical"
                elif s >= 700:
                    risk_level = "high"
                elif s >= 300:
                    risk_level = "medium"
                else:
                    risk_level = "low"
                stats["truriskScore"] = int(s)
            except (TypeError, ValueError):
                pass
        label = hostname or "asset"
        findings.append(f"Asset detail retrieved for {label}")
        headline_parts.append(f"Single-asset risk assessment for {label}")

    # TruRisk score (org-level)
    trs = data.get("trurisk_score")
    if isinstance(trs, dict):
        score = trs.get("score") or trs.get("truriskScore")
        agg = trs.get("aggregate") or {}
        if score is not None:
            try:
                s = float(score)
                stats["orgTruRisk"] = int(s)
                if risk_level == "unknown":
                    if s >= 900:
                        risk_level = "critical"
                    elif s >= 700:
                        risk_level = "high"
                    elif s >= 300:
                        risk_level = "medium"
                    else:
                        risk_level = "low"
                headline_parts.append(f"Org TruRisk: {int(s)}")
            except (TypeError, ValueError):
                pass
        elif isinstance(agg, dict) and agg.get("totalAssets"):
            total = agg.get("totalAssets", 1)
            crit = agg.get("criticalRisk_900plus", 0)
            high = agg.get("highRisk_700plus", 0)
            stats["totalAssets"] = total
            stats["criticalRiskAssets"] = crit
            stats["highRiskAssets"] = high
            if risk_level == "unknown":
                crit_pct = (crit / total * 100) if total else 0
                high_pct = (high / total * 100) if total else 0
                if crit_pct > 5:
                    risk_level = "critical"
                elif high_pct > 10:
                    risk_level = "high"
                elif high_pct > 2:
                    risk_level = "medium"
                else:
                    risk_level = "low"
            findings.append(f"{crit} critical-risk assets ({crit/total*100:.1f}%), {high} high-risk ({high/total*100:.1f}%) out of {total} total")
            headline_parts.append(f"{total} assets, {crit} critical-risk, {high} high-risk")
        trend = trs.get("trend") or trs.get("truriskTrend") or {}
        if isinstance(trend, dict):
            direction = trend.get("direction", "stable")
            if direction == "worsening":
                findings.append("Org risk score is trending upward — investigate new vulnerabilities")
            stats["trend"] = direction

    # Weekly priorities
    wp = data.get("weekly_priorities")
    if isinstance(wp, dict):
        top = wp.get("topVulns") or wp.get("vulnerabilities") or []
        if top:
            stats["topVulnsCount"] = len(top)
            findings.append(f"{len(top)} prioritized vulnerabilities identified this week")

    # Risk by tag
    rbt = data.get("risk_by_tag")
    if isinstance(rbt, dict):
        tag_risk = rbt.get("score") or rbt.get("truriskScore")
        if tag_risk is not None:
            findings.append(f"Tag-scoped risk score: {tag_risk}")

    # Cloud risk
    cr = data.get("cloud_risk")
    if isinstance(cr, dict):
        accts_list = cr.get("accounts", [])
        acct_count = len(accts_list) if isinstance(accts_list, list) else (accts_list if isinstance(accts_list, int) else 0)
        failed_ctrls = len(cr.get("failedControls", []))
        threats = len(cr.get("threats", []))
        pass_rate = cr.get("overallPassRate")
        if acct_count:
            stats["cloudAccounts"] = acct_count
        if pass_rate is not None:
            stats["cloudPassRate"] = pass_rate
        if threats:
            findings.append(f"{threats} CDR threat findings across {acct_count} cloud accounts")
        if failed_ctrls:
            findings.append(f"{failed_ctrls} failing cloud controls ({pass_rate}% pass rate)" if pass_rate else f"{failed_ctrls} failing cloud controls")
        elif acct_count:
            findings.append(f"{acct_count} cloud accounts assessed — {pass_rate}% pass rate" if pass_rate else f"{acct_count} cloud accounts connected")

    # Cloud account summary
    cas = data.get("cloud_account_summary")
    if isinstance(cas, dict):
        total = cas.get("total") or cas.get("totalAccounts") or 0
        if total:
            stats["cloudAccountsTotal"] = total

    # Cloud controls
    cc = data.get("cloud_controls")
    if isinstance(cc, dict):
        failed = cc.get("failed") or cc.get("failCount") or 0
        if failed:
            findings.append(f"{failed} cloud control checks failed")

    # Container vuln summary
    cvs = data.get("container_vuln_summary")
    if isinstance(cvs, dict):
        total_images = cvs.get("totalImages", 0)
        total_vuln_images = cvs.get("totalVulnerableImages", 0)
        cvs_summary = cvs.get("summary", {}) if isinstance(cvs.get("summary"), dict) else {}
        total_vulns = cvs_summary.get("total", 0) or cvs.get("totalVulns", 0)
        critical_vulns = cvs_summary.get("critical", 0) or cvs.get("critical", 0)
        if total_images:
            stats["totalContainerImages"] = total_images
        if critical_vulns:
            findings.append(f"{critical_vulns} critical container vulnerabilities across {total_vuln_images} of {total_images} images")
        elif total_vulns:
            findings.append(f"{total_vulns} container vulnerabilities across {total_images} images")
        elif total_images:
            findings.append(f"{total_images} container images scanned — no critical vulnerabilities found")

    # Image vulns
    iv = data.get("image_vulns")
    if isinstance(iv, dict):
        img_vulns = iv.get("totalVulns") or iv.get("total") or 0
        if img_vulns:
            findings.append(f"{img_vulns} vulnerabilities found in container image")

    # Running containers
    rc = data.get("running_containers")
    if isinstance(rc, dict):
        rc_summary = rc.get("summary", {})
        running = rc_summary.get("totalRunning", 0) if isinstance(rc_summary, dict) else 0
        with_crit = rc_summary.get("withCriticalVulns", 0) if isinstance(rc_summary, dict) else 0
        is_estimated = rc_summary.get("withCriticalVulnsEstimated", False) if isinstance(rc_summary, dict) else False
        if running:
            stats["runningContainers"] = running
            if with_crit:
                approx = "~" if is_estimated else ""
                findings.append(f"{approx}{with_crit} of {running} running containers have critical vulnerabilities")
            else:
                findings.append(f"{running} running containers — none with critical vulnerabilities")

    # Web app vulns
    wv = data.get("webapp_vulns")
    if isinstance(wv, dict):
        wv_stats = wv.get("stats", {}) if isinstance(wv.get("stats"), dict) else {}
        total_web = wv_stats.get("total", 0) or wv.get("total", 0) or wv.get("totalFindings", 0)
        critical_web = wv_stats.get("critical", 0) or wv.get("critical", 0)
        web_apps = wv_stats.get("webApps", 0)
        if critical_web:
            findings.append(f"{critical_web} critical web application vulnerabilities across {web_apps} apps ({total_web} total findings)")
        elif total_web:
            findings.append(f"{total_web} web application findings across {web_apps} apps (none critical)")
        else:
            findings.append("No web application vulnerabilities found — WAS scan results are clean or no apps have been scanned")

    # Expiring certs
    ec = data.get("expiring_certs")
    if isinstance(ec, dict):
        expiring = ec.get("expiringSoon") or ec.get("total") or 0
        expired = ec.get("expired") or 0
        if expired:
            findings.append(f"{expired} SSL/TLS certificates have already expired")
        elif expiring:
            findings.append(f"{expiring} SSL/TLS certificates expiring soon")
        else:
            findings.append("No expiring or expired certificates found")

    # Cert security posture
    csp = data.get("cert_security_posture")
    if isinstance(csp, dict):
        weak = csp.get("weakCerts") or csp.get("weak") or 0
        if weak:
            findings.append(f"{weak} certificates with weak ciphers or protocols")

    # Tech debt
    td = data.get("tech_debt")
    if isinstance(td, dict):
        eol = td.get("eolSystems") or td.get("eol") or 0
        if eol:
            findings.append(f"{eol} end-of-life systems contributing to technical debt")
            stats["eolSystems"] = eol

    # Asset inventory
    ai = data.get("asset_inventory")
    if isinstance(ai, dict):
        total_assets = ai.get("total") or ai.get("totalAssets") or 0
        if total_assets:
            stats["assetsInScope"] = total_assets

    if not headline_parts:
        scope_parts = []
        if "trurisk_score" in data or "weekly_priorities" in data:
            scope_parts.append("asset risk")
        if "cloud_risk" in data or "cloud_account_summary" in data:
            scope_parts.append("cloud")
        if "container_vuln_summary" in data:
            scope_parts.append("containers")
        if "webapp_vulns" in data:
            scope_parts.append("web apps")
        if "expiring_certs" in data:
            scope_parts.append("certificates")
        if "tech_debt" in data:
            scope_parts.append("tech debt")
        if scope_parts:
            headline_parts.append(f"Risk assessment covering {', '.join(scope_parts)}")
        else:
            headline_parts.append("Risk assessment complete")

    return {
        "headline": "; ".join(headline_parts),
        "risk_level": risk_level,
        "key_findings": findings[:10],
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Correlation helper
# ---------------------------------------------------------------------------


def _correlate(data):
    """Cross-reference findings from multiple aggregators to surface compounding risks.

    Returns a list of correlation dicts with keys: type, finding, severity, sources.
    """
    correlations = []

    # Cloud risk + cloud controls failures = compounding cloud exposure
    cr = data.get("cloud_risk")
    cc = data.get("cloud_controls")
    if cr and cc:
        cr_critical = (cr.get("criticalFindings") or cr.get("critical") or 0) if isinstance(cr, dict) else 0
        cc_failed = (cc.get("failed") or cc.get("failCount") or 0) if isinstance(cc, dict) else 0
        if cr_critical > 0 and cc_failed > 0:
            correlations.append({
                "type": "compounding_cloud_risk",
                "finding": (
                    f"{cr_critical} critical cloud risk findings combined with "
                    f"{cc_failed} failed control checks — elevated cloud exposure"
                ),
                "severity": "critical",
                "sources": ["cloud_risk", "cloud_controls"],
            })

    # Container vulns + running containers = active exposure
    cvs = data.get("container_vuln_summary")
    rc = data.get("running_containers")
    if cvs and rc:
        crit_container = (cvs.get("critical") or 0) if isinstance(cvs, dict) else 0
        running = (rc.get("total") or rc.get("totalContainers") or 0) if isinstance(rc, dict) else 0
        if crit_container > 0 and running > 0:
            correlations.append({
                "type": "active_container_exposure",
                "finding": (
                    f"{crit_container} critical vulnerabilities in images with "
                    f"{running} containers currently running"
                ),
                "severity": "critical",
                "sources": ["container_vuln_summary", "running_containers"],
            })

    # EOL systems + high vuln count = unpatched legacy risk
    td = data.get("tech_debt")
    wp = data.get("weekly_priorities")
    if td and wp:
        eol = (td.get("eolSystems") or td.get("eol") or 0) if isinstance(td, dict) else 0
        top_vulns = (wp.get("topVulns") or wp.get("vulnerabilities") or []) if isinstance(wp, dict) else []
        if eol > 0 and len(top_vulns) > 0:
            correlations.append({
                "type": "eol_vulnerability_risk",
                "finding": (
                    f"{eol} EOL systems may be affected by {len(top_vulns)} "
                    "prioritized vulnerabilities — patches may not be available"
                ),
                "severity": "high",
                "sources": ["tech_debt", "weekly_priorities"],
            })

    # Expired certs + web app vulns = web layer weakness
    ec = data.get("expiring_certs")
    wv = data.get("webapp_vulns")
    if ec and wv:
        expired = (ec.get("expired") or 0) if isinstance(ec, dict) else 0
        web_critical = (wv.get("critical") or 0) if isinstance(wv, dict) else 0
        if expired > 0 and web_critical > 0:
            correlations.append({
                "type": "web_layer_weakness",
                "finding": (
                    f"{expired} expired certificates alongside {web_critical} "
                    "critical web vulnerabilities — web tier requires immediate attention"
                ),
                "severity": "critical",
                "sources": ["expiring_certs", "webapp_vulns"],
            })

    # Org TruRisk worsening trend + weekly priorities = risk spike
    trs = data.get("trurisk_score")
    if trs and wp:
        trend = (trs.get("trend") or trs.get("truriskTrend") or {}) if isinstance(trs, dict) else {}
        top_vulns = (wp.get("topVulns") or wp.get("vulnerabilities") or []) if isinstance(wp, dict) else []
        if isinstance(trend, dict) and trend.get("direction") == "worsening" and top_vulns:
            correlations.append({
                "type": "risk_score_spike",
                "finding": (
                    f"Org risk score trending upward with {len(top_vulns)} "
                    "new high-priority vulnerabilities this week"
                ),
                "severity": "high",
                "sources": ["trurisk_score", "weekly_priorities"],
            })

    return correlations


# ---------------------------------------------------------------------------
# Actions helper
# ---------------------------------------------------------------------------


def _build_actions(data, correlations):
    """Derive prioritized remediation actions from aggregator results and correlations.

    Returns a list of action dicts with keys: priority, action, module, rationale.
    """
    actions = []

    # Correlation-derived actions (highest priority)
    for corr in correlations:
        if corr.get("severity") == "critical":
            sources = corr.get("sources", [])
            action_map = {
                "compounding_cloud_risk": {
                    "action": "Remediate critical cloud misconfigurations and failing controls",
                    "module": "Qualys TotalCloud",
                },
                "active_container_exposure": {
                    "action": "Patch or replace vulnerable container images with running instances",
                    "module": "Qualys Container Security",
                },
                "web_layer_weakness": {
                    "action": "Renew expired certificates and remediate critical web vulnerabilities",
                    "module": "Qualys TotalAppSec / CertView",
                },
            }
            for ctype, act in action_map.items():
                if corr.get("type") == ctype:
                    actions.append({
                        "priority": 1,
                        "action": act["action"],
                        "module": act["module"],
                        "rationale": corr["finding"],
                    })

    # Weekly priorities — patch top vulns
    wp = data.get("weekly_priorities")
    if isinstance(wp, dict):
        top = wp.get("topVulns") or wp.get("vulnerabilities") or []
        if top:
            actions.append({
                "priority": 1,
                "action": f"Address {len(top)} prioritized vulnerabilities identified this week",
                "module": "Qualys VMDR / Patch Management",
                "rationale": "Weekly priority list based on TruRisk scoring",
            })

    # Critical cloud findings
    cr = data.get("cloud_risk")
    if isinstance(cr, dict):
        critical = cr.get("criticalFindings") or cr.get("critical") or 0
        if critical:
            actions.append({
                "priority": 1,
                "action": f"Investigate and remediate {critical} critical cloud security findings",
                "module": "Qualys TotalCloud",
                "rationale": "Critical cloud posture issues require immediate action",
            })

    # Expired certs
    ec = data.get("expiring_certs")
    if isinstance(ec, dict):
        expired = ec.get("expired") or 0
        expiring = ec.get("expiringSoon") or ec.get("total") or 0
        if expired:
            actions.append({
                "priority": 1,
                "action": f"Immediately renew {expired} already-expired SSL/TLS certificates",
                "module": "Qualys CertView",
                "rationale": "Expired certificates may cause service outages and security failures",
            })
        elif expiring:
            actions.append({
                "priority": 2,
                "action": f"Schedule renewal for {expiring} certificates expiring soon",
                "module": "Qualys CertView",
                "rationale": "Proactive renewal prevents unplanned outages",
            })

    # Critical container vulns
    cvs = data.get("container_vuln_summary")
    if isinstance(cvs, dict):
        crit = cvs.get("critical") or 0
        if crit:
            actions.append({
                "priority": 1,
                "action": f"Rebuild or patch {crit} critically vulnerable container images",
                "module": "Qualys Container Security",
                "rationale": "Critical container vulnerabilities in active workloads pose immediate risk",
            })

    # Critical web app vulns
    wv = data.get("webapp_vulns")
    if isinstance(wv, dict):
        crit_web = wv.get("critical") or 0
        if crit_web:
            actions.append({
                "priority": 1,
                "action": f"Remediate {crit_web} critical web application vulnerabilities",
                "module": "Qualys TotalAppSec",
                "rationale": "Critical web vulnerabilities are directly exploitable",
            })

    # EOL systems
    td = data.get("tech_debt")
    if isinstance(td, dict):
        eol = td.get("eolSystems") or td.get("eol") or 0
        if eol:
            actions.append({
                "priority": 2,
                "action": f"Create upgrade plan for {eol} end-of-life systems",
                "module": "Qualys CSAM",
                "rationale": "EOL systems receive no security patches — persistent vulnerability risk",
            })

    # Failed cloud controls
    cc = data.get("cloud_controls")
    if isinstance(cc, dict):
        failed = cc.get("failed") or cc.get("failCount") or 0
        if failed:
            actions.append({
                "priority": 2,
                "action": f"Remediate {failed} failing cloud security control checks",
                "module": "Qualys TotalCloud",
                "rationale": "Control failures indicate misconfigurations that may be exploited",
            })

    # Weak cert configurations
    csp = data.get("cert_security_posture")
    if isinstance(csp, dict):
        weak = csp.get("weakCerts") or csp.get("weak") or 0
        if weak:
            actions.append({
                "priority": 2,
                "action": f"Update {weak} certificates using weak ciphers or deprecated protocols",
                "module": "Qualys CertView",
                "rationale": "Weak cryptographic configurations are exploitable by downgrade attacks",
            })

    # Deduplicate and sort by priority
    seen = set()
    unique_actions = []
    for act in sorted(actions, key=lambda x: x.get("priority", 9)):
        key = act["action"]
        if key not in seen:
            seen.add(key)
            unique_actions.append(act)

    return unique_actions[:10]


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------


def assess_risk(
    scope="all",
    tag="",
    asset_group="",
    asset_id="",
    os="",
    query="",
    days_since_seen=0,
    days_since_scan=0,
    eol_only=False,
    provider="",
    service="",
    account_id="",
    per_account=False,
    image_id="",
    app_name="",
    owasp_category="",
    protocol_filter="",
    weak_ciphers=False,
    weak_only=False,
    insecure_renegotiation=False,
    include_expired=True,
    days=30,
    limit=20,
    detail="standard",
    sort_by="trurisk",
    breakdown_by="tag",
):
    """Consolidated risk assessment across all Qualys modules.

    Dispatches aggregators based on scope and parameter context, correlates
    cross-domain findings, and returns a unified risk envelope.

    Scope values: "all", "assets", "cloud", "containers", "web", "certs"
    """
    plan = {}

    # ------------------------------------------------------------------
    # Single-asset fast path: skip all broad queries
    # ------------------------------------------------------------------
    if asset_id:
        plan["asset_detail"] = lambda: asset_detail(
            asset_id=asset_id,
            detail_level="full",
            detail=detail,
        )
        results, elapsed_ms = _dispatch(plan)
        envelope = _build_envelope(
            workflow="assess_risk",
            aggregators_called=list(plan.keys()),
            results=results,
            execution_time_ms=elapsed_ms,
            summary_fn=_summarize,
            correlate_fn=_correlate,
            actions_fn=lambda data: _build_actions(data, _correlate(data)),
        )
        return _apply_detail(envelope, detail)

    # ------------------------------------------------------------------
    # Derive boolean flags for scope checks
    # ------------------------------------------------------------------
    cert_params_set = bool(protocol_filter or weak_ciphers or weak_only or insecure_renegotiation)
    staleness_params_set = bool(days_since_seen or days_since_scan)
    cloud_params_set = bool(provider or service or account_id)
    web_params_set = bool(app_name or owasp_category)

    scope_all = scope == "all"

    # ------------------------------------------------------------------
    # Assets / trurisk (scope "all" or "assets")
    # ------------------------------------------------------------------
    if scope_all or scope == "assets":
        plan["trurisk_score"] = lambda: trurisk_score(
            days=days,
            breakdown_by=breakdown_by,
            detail=detail,
        )
        plan["weekly_priorities"] = lambda: weekly_priorities(
            limit=limit,
            sort_by=sort_by,
            tag=tag,
            asset_group=asset_group,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Tag-scoped risk (tag set, without asset_id)
    # ------------------------------------------------------------------
    if tag and not asset_id:
        plan["risk_by_tag"] = lambda: risk_by_tag(
            tag=tag,
            limit=limit,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Cloud (scope "all" or "cloud", or cloud params set)
    # ------------------------------------------------------------------
    if scope_all or scope == "cloud" or cloud_params_set:
        plan["cloud_risk"] = lambda: cloud_risk_agg(
            limit=limit,
            include_threats=True,
            days=days,
            per_account=per_account,
            detail=detail,
        )
        plan["cloud_account_summary"] = lambda: cloud_account_summary(
            provider=provider or "all",
            detail=detail,
        )
        plan["cloud_controls"] = lambda: cloud_controls(
            provider=provider or "all",
            service=service,
            result_filter="FAIL",
            account_id=account_id,
            limit=limit,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Containers (scope "all" or "containers", or image_id set)
    # ------------------------------------------------------------------
    if scope_all or scope == "containers" or image_id:
        plan["container_vuln_summary"] = lambda: container_vuln_summary(
            limit=limit,
            detail=detail,
        )
        plan["running_containers"] = lambda: running_containers(
            limit=limit,
            detail=detail,
        )
        if image_id:
            plan["image_vulns"] = lambda: image_vulns(
                image_id=image_id,
                limit=limit,
                detail=detail,
            )

    # ------------------------------------------------------------------
    # Web apps (scope "all" or "web", or web params set)
    # ------------------------------------------------------------------
    if scope_all or scope == "web" or web_params_set:
        plan["webapp_vulns"] = lambda: webapp_vulns(
            severity=0,
            days=0,
            app_name=app_name,
            owasp_category=owasp_category,
            limit=limit,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Certificates (scope "all" or "certs", or cert params set)
    # ------------------------------------------------------------------
    if scope_all or scope == "certs" or cert_params_set:
        plan["expiring_certs"] = lambda: expiring_certs(
            days=days,
            include_expired=include_expired,
            weak_only=weak_only,
            limit=limit,
        )
        plan["cert_security_posture"] = lambda: cert_security_posture(
            protocol_filter=protocol_filter,
            weak_ciphers=weak_ciphers,
            insecure_renegotiation=insecure_renegotiation,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Tech debt / asset inventory (eol_only or staleness params set)
    # ------------------------------------------------------------------
    if eol_only or staleness_params_set:
        plan["tech_debt"] = lambda: tech_debt(
            limit=limit,
            days=days,
            detail=detail,
        )
        plan["asset_inventory"] = lambda: asset_inventory(
            query=query,
            tag=tag,
            os=os,
            days_since_seen=days_since_seen,
            days_since_scan=days_since_scan,
            eol_only=eol_only,
            limit=limit,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Dispatch and build envelope
    # ------------------------------------------------------------------
    risk_timeout = 30 if scope != "all" else 60
    results, elapsed_ms = _dispatch(plan, timeout=risk_timeout)

    # Compute correlations once for reuse in actions_fn
    def _actions_with_correlations(data):
        corrs = _correlate(data)
        return _build_actions(data, corrs)

    envelope = _build_envelope(
        workflow="assess_risk",
        aggregators_called=list(plan.keys()),
        results=results,
        execution_time_ms=elapsed_ms,
        summary_fn=_summarize,
        correlate_fn=_correlate,
        actions_fn=_actions_with_correlations,
    )

    return _apply_detail(envelope, detail)
