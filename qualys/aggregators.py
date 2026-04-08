"""Qualys aggregation/enrichment business logic.

Each function here corresponds to an @mcp.tool in qualys_mcp.py.
The tool functions become thin wrappers that call these aggregators.
"""

from qualys.api import *
# Underscore-prefixed helpers not exported by import *
from qualys.api import (
    _fetch_edr_events_raw,
    _fetch_fim_events_raw,
    _get_was_count,
    _get_was_severity_counts,
    _get_was_webapp_count,
    _log,
    _open,
    _parse_duration,
    _run_concurrent,
    _scope_filters,
    _with_meta,
)


# ---------------------------------------------------------------------------
# Detail-level post-processing helper
# ---------------------------------------------------------------------------

def _apply_detail_level(result, detail, list_keys=None):
    """Post-process result based on detail level."""
    if detail == "standard":
        return result
    if detail == "summary":
        if list_keys:
            for key in list_keys:
                if key in result and isinstance(result[key], list):
                    result[key] = result[key][:5]
        # Remove _followups, _gaps, _next for summary
        result.pop('_followups', None)
        result.pop('_gaps', None)
        result.pop('_next', None)
        return result
    # "detailed" — return everything (no truncation was applied)
    return result


# ---------------------------------------------------------------------------
# Internal helpers (non-tool functions)
# ---------------------------------------------------------------------------

def _detect_gaps(data: dict) -> list[dict]:
    """Detect coverage gaps from data already returned by existing API calls."""
    if not data:
        return []

    gaps = []

    _summary = data.get('summary') if isinstance(data.get('summary'), dict) else {}

    # 1. Assets unscanned >7 days
    total_assets = (data.get('environment') or {}).get('totalAssets', 0) or \
                   _summary.get('totalAssets', 0) or \
                   data.get('assetsTotal', 0) or data.get('totalAssets', 0)
    health = (data.get('environment') or {}).get('healthScore', 100)
    if total_assets > 0 and health < 80:
        estimated_unscanned = max(1, int(total_assets * (100 - health) / 200))
        gaps.append({
            'gap': 'Scan coverage',
            'impact': f'Estimated {estimated_unscanned} assets may not have recent scans (health score: {health})',
            'unprotected': estimated_unscanned,
            'module': 'Qualys VMDR',
            'action': 'Run vulnerability scans on unscanned assets',
            'unlock': {
                'module': 'Qualys VMDR',
                'value': 'Continuous vulnerability detection across your entire attack surface',
                'quickstart': 'Schedule a scan \u2192 ask me: get_scanner_status() to check scanner availability',
            },
        })

    # 2. EDR coverage <80% of endpoints
    edr_events = data.get('edr') or data.get('edr_events')
    edr_active = bool(edr_events)
    coverage = data.get('coverage') or {}
    if isinstance(coverage, dict) and coverage.get('endpointDetection') is False:
        edr_active = False
    if not edr_active and total_assets > 0:
        unmonitored = total_assets
        gaps.append({
            'gap': 'EDR coverage',
            'impact': f'Endpoints not monitored for active threats (EDR not active)',
            'unprotected': unmonitored,
            'module': 'Qualys Multi-Vector EDR',
            'action': 'Enable EDR on unmonitored endpoints',
            'unlock': {
                'module': 'Qualys Multi-Vector EDR',
                'value': 'Real-time threat detection, behavioral analysis, and automated response',
                'quickstart': 'Check EDR status \u2192 ask me: get_edr_events() to review detections',
            },
        })

    # 3. Cloud assets with no posture check
    cloud_accounts = (data.get('environment') or {}).get('cloudAccounts', 0) or \
                     (data.get('cloud') or {}).get('accounts', 0)
    cloud_active = bool(coverage.get('totalCloud')) if isinstance(coverage, dict) else cloud_accounts > 0
    cloud_assets = data.get('byCloud') or {}
    cloud_count = sum(v for k, v in cloud_assets.items() if k != 'OnPrem') if cloud_assets else 0
    if cloud_count > 0 and not cloud_active:
        gaps.append({
            'gap': 'Cloud posture',
            'impact': f'{cloud_count} cloud assets with no posture assessment',
            'unprotected': cloud_count,
            'module': 'Qualys TotalCloud',
            'action': 'Enable cloud security posture management for cloud assets',
            'unlock': {
                'module': 'Qualys TotalCloud',
                'value': 'Unified cloud security: CSPM, CWPP, CIEM, and container security',
                'quickstart': 'Connect your cloud \u2192 ask me: get_cloud_risk() to assess posture',
            },
        })

    # 4. Web apps discovered but not WAS-scanned
    was_active = bool(coverage.get('totalAppSec')) if isinstance(coverage, dict) else False
    if not was_active and total_assets > 0:
        gaps.append({
            'gap': 'Web app scanning',
            'impact': 'Web applications not scanned for OWASP Top 10 vulnerabilities',
            'unprotected': 0,
            'module': 'Qualys TotalAppSec',
            'action': 'Scan web applications for SQLi, XSS, and other web vulnerabilities',
            'unlock': {
                'module': 'Qualys TotalAppSec',
                'value': 'Automated DAST scanning for web apps and APIs with OWASP coverage',
                'quickstart': 'Start scanning \u2192 ask me: get_was_findings() to review web app security',
            },
        })

    # 5. Certs discovered but CertView not deployed
    cert_active = bool(coverage.get('certificateView')) if isinstance(coverage, dict) else False
    if not cert_active and total_assets > 0:
        gaps.append({
            'gap': 'Certificate monitoring',
            'impact': 'SSL/TLS certificates not monitored for expiration or weakness',
            'unprotected': 0,
            'module': 'Qualys CertView',
            'action': 'Deploy CertView to monitor certificate health and expiration',
            'unlock': {
                'module': 'Qualys CertView',
                'value': 'Discover and monitor all SSL/TLS certificates, prevent outages from expiration',
                'quickstart': 'Check certificates \u2192 ask me: get_expiring_certs() to find at-risk certs',
            },
        })

    # 6. Patches available but no active patch job
    risk_900 = _summary.get('criticalRisk', 0) or \
               (data.get('riskDistribution') or {}).get('critical_900plus', 0)
    risk_high = _summary.get('highRisk', 0) or \
                (data.get('riskDistribution') or {}).get('high_700plus', 0)
    patch_available = data.get('patchAvailable', False)
    has_vulns = (risk_900 or 0) + (risk_high or 0) > 0
    if has_vulns and patch_available is not False:
        vuln_count = (risk_900 or 0) + (risk_high or 0)
        gaps.append({
            'gap': 'Patch automation',
            'impact': f'{vuln_count} high-risk assets with available patches, no automated remediation confirmed',
            'unprotected': vuln_count,
            'module': 'Qualys Patch Management',
            'action': 'Enable automated patch deployment for critical assets',
            'unlock': {
                'module': 'Qualys Patch Management',
                'value': 'Auto-remediate vulns with one-click patch deployment',
                'quickstart': 'Launch your first patch job \u2192 ask me: get_eliminate_status() to check patch deployment',
            },
        })

    # 7. No compliance framework configured
    compliance = data.get('compliance') or {}
    comp_summary = compliance.get('summary') or {}
    frameworks = comp_summary.get('frameworks', [])
    comp_error = compliance.get('error', '')
    if (not frameworks and not comp_error) or 'not licensed' in str(comp_error).lower():
        gaps.append({
            'gap': 'Compliance frameworks',
            'impact': 'No compliance framework configured \u2014 regulatory risk unassessed',
            'unprotected': total_assets,
            'module': 'Qualys Policy Compliance',
            'action': 'Configure compliance frameworks (CIS, PCI DSS, HIPAA, SOC 2)',
            'unlock': {
                'module': 'Qualys Policy Compliance',
                'value': 'Continuous compliance monitoring against CIS, PCI, HIPAA, NIST frameworks',
                'quickstart': 'Check compliance \u2192 ask me: get_compliance_posture() to assess current state',
            },
        })

    # 8. Critical servers without FIM monitoring
    fim_active = bool(coverage.get('fileIntegrityMonitoring')) if isinstance(coverage, dict) else False
    if not fim_active and total_assets > 0:
        gaps.append({
            'gap': 'File integrity monitoring',
            'impact': 'Critical file changes not monitored \u2014 unauthorized modifications may go undetected',
            'unprotected': 0,
            'module': 'Qualys FIM',
            'action': 'Enable FIM on critical servers to detect unauthorized file changes',
            'unlock': {
                'module': 'Qualys FIM',
                'value': 'Real-time detection of unauthorized file and registry changes on critical systems',
                'quickstart': 'Monitor file changes \u2192 ask me: get_fim_events() to review activity',
            },
        })

    return gaps


def _build_next(data: dict, tool_name: str) -> dict:
    """Build contextual _next block based on actual findings data."""
    investigate = []
    actions = []

    if not data:
        return {'investigate_deeper': investigate, 'take_action': actions}

    _summary = data.get('summary') if isinstance(data.get('summary'), dict) else {}

    # --- CVE-related suggestions ---
    cve = data.get('cve', '')
    if cve:
        if data.get('patchAvailable'):
            investigate.append({
                'question': f'What is the patch deployment status for {cve}?',
                'tool': 'get_patch_status',
                'params': {},
            })
            actions.append({'action': f'Deploy patches for {cve}', 'module': 'Qualys Patch Management'})
        if data.get('ransomware'):
            investigate.append({
                'question': f'What is our full ransomware exposure beyond {cve}?',
                'tool': 'get_etm_findings',
                'params': {'qql': 'threatName:ransomware'},
            })
            actions.append({'action': 'Review ransomware defense posture', 'module': 'Qualys Multi-Vector EDR'})
        if data.get('has_exploit'):
            investigate.append({
                'question': f'Which assets have confirmed {cve} findings?',
                'tool': 'get_etm_findings',
                'params': {'qql': f'vulnerabilities.vulnerability.cveIds:{cve}'},
            })
        asset_count = _summary.get('assetsWithSoftware', 0)
        if asset_count:
            investigate.append({
                'question': f'What are the top affected assets for {cve}?',
                'tool': 'investigate',
                'params': {'topic': cve, 'depth': 'deep'},
            })

    # --- Risk / environment suggestions ---
    top_assets = data.get('topRiskAssets') or []
    if top_assets:
        worst = top_assets[0]
        aid = worst.get('assetId', '')
        hostname = worst.get('hostname', '?')
        investigate.append({
            'question': f'What vulns are on the highest-risk asset ({hostname})?',
            'tool': 'get_asset',
            'params': {'asset_id': aid, 'detail': 'full'},
        })

    # Threat-related
    threats = data.get('threats') or {}
    if threats.get('ransomwareLinked', 0) > 0:
        investigate.append({
            'question': 'Deep-dive on ransomware exposure',
            'tool': 'investigate',
            'params': {'topic': 'ransomware', 'depth': 'standard'},
        })
        actions.append({'action': 'Investigate ransomware-linked vulnerabilities', 'module': 'Qualys VMDR'})
    if threats.get('activelyExploited', 0) > 0:
        investigate.append({
            'question': 'Which actively exploited vulns affect us?',
            'tool': 'search_vulns',
            'params': {'threat_type': 'Active_Attacks'},
        })

    # TruRisk trend
    trend = data.get('truriskTrend') or {}
    if trend.get('direction') == 'worsening':
        investigate.append({
            'question': 'Why is our risk score increasing?',
            'tool': 'investigate',
            'params': {'topic': 'risk spike', 'depth': 'standard'},
        })

    # New critical vulns
    new_vulns = data.get('newVulns') or {}
    if new_vulns.get('critical', 0) > 0:
        crit_vulns = new_vulns.get('criticalVulns') or []
        if crit_vulns:
            first_cve = (crit_vulns[0].get('cves') or [''])[0] if crit_vulns[0].get('cves') else ''
            if first_cve:
                investigate.append({
                    'question': f'Investigate new critical vuln {first_cve}',
                    'tool': 'investigate_cve',
                    'params': {'cve': first_cve},
                })

    # EOL systems
    eol = (data.get('environment') or {}).get('eolSystems', 0) or \
          _summary.get('eolSystems', 0)
    if eol:
        actions.append({'action': f'Plan upgrades for {eol} EOL systems', 'module': 'Qualys CSAM'})

    # ETM findings
    if _summary.get('totalFindings', 0) > 0:
        patchable = _summary.get('patchable', 0)
        if patchable:
            actions.append({'action': f'Patch {patchable} remediable findings', 'module': 'Qualys Patch Management'})

    # Investigation-level suggestions
    if tool_name == 'investigate':
        actions.append({'action': 'Generate a summary for management', 'module': 'summarize_investigation'})

    # Deduplicate
    seen_q = set()
    deduped_investigate = []
    for item in investigate[:5]:
        q = item['question']
        if q not in seen_q:
            seen_q.add(q)
            deduped_investigate.append(item)

    seen_a = set()
    deduped_actions = []
    for item in actions[:5]:
        a = item['action']
        if a not in seen_a:
            seen_a.add(a)
            deduped_actions.append(item)

    return {'investigate_deeper': deduped_investigate, 'take_action': deduped_actions}


def _track_usage(tool_name: str, params: dict, result_summary: dict):
    """Write usage log line to ~/.qualys-mcp/usage.jsonl."""
    if os.environ.get('QUALYS_MCP_NO_TRACKING') == '1':
        return
    try:
        log_dir = os.path.expanduser('~/.qualys-mcp')
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, 'usage.jsonl')
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'tool': tool_name,
            'params': {k: v for k, v in params.items() if v} if params else {},
            'gaps_found': result_summary.get('gaps_found', 0),
            'next_suggestions': result_summary.get('next_suggestions', 0),
        }
        with open(log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass


def _extract_software_keywords(title):
    """Extract software name keywords from KB title for CSAM software search."""
    if not title:
        return []
    import re
    keywords = []
    parens = re.findall(r'\(([^)]+)\)', title)
    for p in parens:
        p = p.strip()
        if len(p) >= 3 and not any(w in p.lower() for w in ['cve-', 'formerly', 'aka']):
            keywords.append(p)
    stop_words = {
        'remote', 'code', 'execution', 'vulnerability', 'vulnerabilities',
        'multiple', 'security', 'update', 'patch', 'advisory', 'detected',
        'denial', 'of', 'service', 'privilege', 'escalation', 'information',
        'disclosure', 'buffer', 'overflow', 'injection', 'cross-site',
        'scripting', 'authentication', 'bypass', 'insecure', 'configuration',
        'arbitrary', 'command', 'rce', 'dos', 'xss', 'sqli', 'point', 'and',
    }
    parts = title.split()
    product_words = []
    for word in parts:
        clean = word.strip('()').lower()
        if clean in stop_words:
            break
        if word.startswith('(') and word.endswith(')'):
            continue
        product_words.append(word.strip('()'))
    if len(product_words) >= 2:
        full = ' '.join(product_words)
        keywords.append(full)
        if len(product_words) >= 3:
            keywords.append(' '.join(product_words[-2:]))
        if len(product_words) >= 4:
            keywords.append(' '.join(product_words[1:3]))
    return keywords


def get_security_posture(tag: str = "", asset_group: str = "") -> dict:
    """Internal helper -- overall security health score (0-100). Called by morning_report."""
    health = 100
    result = {'healthScore': 0, 'assets': {'total': 0, 'highRisk': 0},
              'vulns': {'critical': 0, 'high': 0}, 'containers': {'total': 0, 'atRisk': 0},
              'cloud': {'accounts': 0, 'failedControls': 0}, 'warnings': []}

    base = _scope_filters(None, tag, asset_group)
    concurrent = _run_concurrent(
        asset_count=lambda: csam_count(base),
        risk_900=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}], tag, asset_group)),
        risk_700=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}], tag, asset_group)),
        risk_500=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}], tag, asset_group)),
        eol_os=lambda: csam_count(_scope_filters([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}], tag, asset_group)),
        images=lambda: get_images(50),
        vuln_images=lambda: get_images(30, 5),
        containers=lambda: get_containers(50),
    )

    total = concurrent.get('asset_count') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol_count = concurrent.get('eol_os') or 0
    result['assets']['total'] = total
    result['assets']['highRisk'] = risk_700
    if total > 0:
        health -= min(50, int(risk_700 / total * 100))

    result['vulns']['critical'] = risk_900
    result['vulns']['high'] = risk_500
    result['vulns']['eolSystems'] = eol_count
    if risk_900 > 50:
        health -= 20
    elif risk_900 > 10:
        health -= 10

    images = concurrent.get('images') or []
    vuln_images = concurrent.get('vuln_images') or []
    containers = concurrent.get('containers') or []
    result['containers']['total'] = len(images)
    vuln_ids = {i.get('imageId') for i in vuln_images}
    result['containers']['atRisk'] = len([c for c in containers if c.get('imageId') in vuln_ids])

    try:
        cloud_conns = _run_concurrent(
            aws=lambda: get_connectors('aws', 5),
            azure=lambda: get_connectors('azure', 5),
            gcp=lambda: get_connectors('gcp', 5),
            oci=lambda: get_connectors('oci', 5),
        )
        acc_key_map = {'aws': 'awsAccountId', 'azure': 'azureSubscriptionId', 'gcp': 'gcpProjectId', 'oci': 'ociTenancyId'}
        eval_tasks = {}
        for p, conns in cloud_conns.items():
            if conns:
                result['cloud']['accounts'] += len(conns)
                acc = conns[0].get(acc_key_map[p])
                if acc:
                    eval_tasks[f'evals_{p}'] = (lambda a=acc, pv=p: get_evaluations(a, pv, 50))
        if eval_tasks:
            eval_results = _run_concurrent(**eval_tasks)
            for key, evals in eval_results.items():
                result['cloud']['failedControls'] += len([e for e in (evals or []) if e.get('result') in ['FAIL', 'FAILED']])
    except Exception:
        result['warnings'].append('cloud data unavailable')

    if not result['warnings']:
        del result['warnings']
    result['healthScore'] = max(0, health)
    return result


def _get_first_cloud_evals():
    """Get evaluations from the first available cloud connector."""
    connector_results = _run_concurrent(
        aws=lambda: get_connectors('aws', 1),
        azure=lambda: get_connectors('azure', 1),
        gcp=lambda: get_connectors('gcp', 1),
        oci=lambda: get_connectors('oci', 1),
    )
    for provider, acc_key in [('aws', 'awsAccountId'), ('azure', 'azureSubscriptionId'), ('gcp', 'gcpProjectId'), ('oci', 'ociTenancyId')]:
        conns = connector_results.get(provider) or []
        if conns:
            acc = conns[0].get(acc_key)
            if acc:
                return get_evaluations(acc, provider, 100)
    return []


def _format_vmdr_as_etm_findings(det_tuples):
    """Format VMDR detections (enriched with KB data) into the ETM findings response format."""
    by_severity = {}
    by_cve = {}
    assets_seen = set()
    patchable = 0
    findings = []

    for d, kb, cves, is_patchable in det_tuples:
        sev = d.get('severity', 0)
        by_severity[sev] = by_severity.get(sev, 0) + 1

        hostname = d.get('hostname', '') or d.get('ip', '')
        if hostname:
            assets_seen.add(hostname)

        if is_patchable:
            patchable += 1

        qid = d.get('qid', 0)
        title = kb.get('title', '')
        qds = d.get('qds', 0) or kb.get('qds', 0)
        cvss_v3 = kb.get('cvss_v3')

        cve_list = cves if cves else ['']
        for cve in cve_list:
            if cve:
                if cve not in by_cve:
                    by_cve[cve] = {'count': 0, 'severity': sev, 'title': title, 'qid': str(qid)}
                by_cve[cve]['count'] += 1

            findings.append({
                'cveId': cve,
                'qid': str(qid),
                'title': title[:80],
                'severity': sev,
                'qds': qds,
                'status': d.get('status', 'Active'),
                'category': 'VULNERABILITY',
                'assetName': short_host(hostname) or '',
                'isPatchAvailable': is_patchable,
                'cvss': {'v3_base': cvss_v3} if cvss_v3 else {},
                'source': 'Qualys VMDR',
                'firstFound': short_date(d.get('first_found', '')),
                'has_exploit': kb.get('has_exploit', False),
                'ransomware': kb.get('ransomware', False),
            })

    findings.sort(key=lambda x: (-x['severity'], -x.get('qds', 0)))
    capped_findings = findings[:200]
    top_cves = sorted(by_cve.items(), key=lambda x: (-x[1]['count'], -x[1]['severity']))[:20]

    # -- Vulnerability age metrics --
    now = datetime.now(timezone.utc)
    ages = []
    oldest_unpatched = None
    oldest_age = 0
    over_30 = over_60 = over_90 = 0
    for d, kb, cves_list, is_patchable in det_tuples:
        ff = d.get('first_found', '')
        if not ff:
            continue
        try:
            found_dt = datetime.fromisoformat(str(ff).replace('Z', '+00:00'))
            age_days = (now - found_dt).days
        except (ValueError, TypeError):
            continue
        ages.append(age_days)
        if age_days > 30:
            over_30 += 1
        if age_days > 60:
            over_60 += 1
        if age_days > 90:
            over_90 += 1
        if not is_patchable and age_days > oldest_age:
            oldest_age = age_days
            oldest_unpatched = {'title': (kb.get('title', '') or '')[:80], 'ageDays': age_days,
                                'qid': d.get('qid', 0)}

    vuln_age = {
        'avgAgeDays': round(sum(ages) / len(ages)) if ages else 0,
        'over30d': over_30,
        'over60d': over_60,
        'over90d': over_90,
    }
    if oldest_unpatched:
        vuln_age['oldestUnpatched'] = oldest_unpatched

    result = {
        'reportStatus': 'COMPLETED',
        'findings': capped_findings,
        'totalFindings': len(findings),
        'summary': {
            'totalFindings': len(findings),
            'uniqueAssets': len(assets_seen),
            'uniqueCVEs': len(by_cve),
            'patchable': patchable,
            'bySeverity': {f'sev{k}': v for k, v in sorted(by_severity.items(), reverse=True)},
        },
        'vulnAge': vuln_age,
        'topCVEs': [{'cve': cve, 'qid': info.get('qid', ''), 'assets': info['count'], 'severity': info['severity'], 'title': info['title'][:80]} for cve, info in top_cves],
    }

    result['_next'] = _build_next(result, 'get_etm_findings')
    _track_usage('get_etm_findings', {},
                 {'gaps_found': 0, 'next_suggestions': len(result['_next'].get('investigate_deeper', []))})

    return result


def get_compliance_gaps(limit: int = 20) -> dict:
    """Get top failing compliance controls that could fail audits."""
    result = {'pass_pct': 0, 'failingControls': 0, 'topFailing': []}

    fails = {}
    passes = 0
    for p in ['aws', 'azure', 'gcp']:
        conns = get_connectors(p, 10)
        if conns:
            acc = conns[0].get('awsAccountId') or conns[0].get('azureSubscriptionId') or conns[0].get('gcpProjectId')
            if acc:
                for e in get_evaluations(acc, p, 500):
                    if e.get('result') in ['FAIL', 'FAILED']:
                        cid = e.get('controlId', '')
                        fails[cid] = fails.get(cid, 0) + 1
                    elif e.get('result') in ['PASS', 'PASSED']:
                        passes += 1

    result['failingControls'] = len(fails)
    result['topFailing'] = [{'controlId': c, 'failCount': n} for c, n in sorted(fails.items(), key=lambda x: x[1], reverse=True)[:limit]]

    total = sum(fails.values()) + passes
    result['pass_pct'] = round(passes / total * 100, 1) if total else 0
    return result


def get_threats(days: int = 7, limit: int = 50) -> dict:
    """Get combined threat view from FIM, EDR, and CDR."""
    result = {
        'days': days,
        'stats': {'fim': 0, 'edr': 0, 'cdr': 0, 'critical': 0, 'high': 0},
        'fim': [], 'edr': [], 'cdr': []
    }

    concurrent = _run_concurrent(
        fim=lambda: _fetch_fim_events_raw(limit, days),
        edr_crit=lambda: _fetch_edr_events_raw(limit, 'Critical'),
        edr_high=lambda: _fetch_edr_events_raw(limit, 'High'),
        cdr=lambda: get_cdr(days, limit),
    )

    fim_events = concurrent.get('fim') or []
    for e in fim_events:
        sev = e.get('severity', '')
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        elif sev in ['HIGH', '4']:
            result['stats']['high'] += 1
        result['fim'].append({
            'action': e.get('action', ''), 'path': e.get('filePath', ''),
            'hostname': e.get('hostname', ''), 'dateTime': e.get('dateTime', ''),
            'severity': sev
        })
    result['stats']['fim'] = len(fim_events)

    edr_events = (concurrent.get('edr_crit') or []) + (concurrent.get('edr_high') or [])
    for e in edr_events[:limit]:
        sev = e.get('severity', '')
        if sev == 'Critical':
            result['stats']['critical'] += 1
        elif sev == 'High':
            result['stats']['high'] += 1
        result['edr'].append({
            'type': e.get('eventType', ''), 'process': e.get('processName', ''),
            'hostname': e.get('hostname', ''), 'dateTime': e.get('dateTime', ''),
            'severity': sev
        })
    result['stats']['edr'] = len(edr_events)

    cdr_findings = concurrent.get('cdr') or []
    for f in cdr_findings:
        sev = str(f.get('severity', ''))
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        elif sev in ['HIGH', '4']:
            result['stats']['high'] += 1
        result['cdr'].append({
            'category': f.get('category', ''), 'resource': f.get('resourceId', ''),
            'provider': f.get('cloudProvider', ''), 'dateTime': f.get('createdAt', ''),
            'severity': sev
        })
    result['stats']['cdr'] = len(cdr_findings)

    return result


# ---------------------------------------------------------------------------
# Aggregator functions — one per @mcp.tool
# ---------------------------------------------------------------------------

def weekly_priorities(limit: int = 10, sort_by: str = "trurisk", tag: str = "", asset_group: str = "", detail: str = "standard") -> dict:
    result = {'summary': {}, 'priorities': [], 'topRiskAssets': []}

    concurrent = _run_concurrent(
        total=lambda: csam_count(_scope_filters(None, tag, asset_group)),
        risk_900=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}], tag, asset_group)),
        risk_700=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}], tag, asset_group)),
        risk_500=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}], tag, asset_group)),
        eol_count=lambda: csam_count(_scope_filters([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}], tag, asset_group)),
        assets_900=lambda: csam_search(
            _scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}], tag, asset_group),
            limit=limit
        ),
        assets_700=lambda: csam_search(
            _scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}], tag, asset_group),
            limit=limit
        ),
        vuln_imgs=lambda: get_images(50, 5),
        containers=lambda: get_containers(100),
    )

    total = concurrent.get('total') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol_count = concurrent.get('eol_count') or 0

    result['summary'] = {
        'totalAssets': total,
        'criticalRisk': risk_900,
        'highRisk': risk_700,
        'elevatedRisk': risk_500,
        'eolSystems': eol_count,
    }

    seen = set()
    high_risk = []
    for asset in (concurrent.get('assets_900') or []) + (concurrent.get('assets_700') or []):
        aid = asset.get('assetId')
        if aid and aid not in seen:
            seen.add(aid)
            high_risk.append(asset)
    high_risk.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for i, asset in enumerate(high_risk[:limit]):
        result['topRiskAssets'].append({
            'rank': i + 1,
            'assetId': str(asset.get('assetId', '')),
            'hostId': str(asset.get('hostId') or ''),
            'hostname': short_host(asset.get('dnsHostName', '') or asset.get('dnsName', '')),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
            'criticality': get_criticality(asset),
        })

    rank = 1
    if risk_900 > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 5,
            'title': f"Remediate {risk_900} critical-risk assets (TruRisk > 900)",
            'action': 'Use get_asset(assetId) for specific vulnerabilities per asset',
        })
        rank += 1

    if risk_700 > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 4,
            'title': f"Address {risk_700} high-risk assets (TruRisk > 700)",
            'action': 'Focus on highest TruRisk scores first',
        })
        rank += 1

    if eol_count > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 4,
            'title': f"Plan upgrades for {eol_count} EOL/EOS systems",
            'action': 'Use get_tech_debt() for full EOL inventory',
        })
        rank += 1

    vuln_imgs = concurrent.get('vuln_imgs') or []
    containers = concurrent.get('containers') or []
    vuln_img_ids = {img.get('imageId') for img in vuln_imgs}
    at_risk = [c for c in containers if c.get('imageId') in vuln_img_ids]
    if at_risk:
        result['priorities'].append({
            'rank': rank, 'severity': 5,
            'title': f"Update {len(at_risk)} vulnerable containers",
            'action': 'Rebuild container images with patched base images',
        })
        result['summary']['containersAtRisk'] = len(at_risk)

    followups = []
    top = result.get('topRiskAssets') or []
    if top:
        worst = top[0]
        followups.append(f"Asset {worst.get('hostname', worst.get('assetId', '?'))} has TruRisk {worst.get('riskScore', '?')} \u2014 get_asset('{worst.get('assetId', '')}', detail='full') for full profile?")
    crit_count = result.get('summary', {}).get('criticalRisk', 0) or result.get('summary', {}).get('highRisk', 0)
    if crit_count:
        followups.append(f"{crit_count} assets in critical/high risk tier \u2014 investigate top CVEs with investigate_cve()?")
    containers_at_risk = result.get('summary', {}).get('containersAtRisk', 0)
    if containers_at_risk:
        followups.append(f"{containers_at_risk} containers running vulnerable images \u2014 get_image_vulns() for details?")
    eol_priority = [p for p in result.get('priorities', []) if 'EOL' in p.get('title', '')]
    if eol_priority:
        followups.append("EOL/EOS systems detected \u2014 get_tech_debt() for full inventory?")
    result['_followups'] = followups

    gaps = _detect_gaps(result)
    if gaps:
        result['_gaps'] = gaps
    result['_next'] = _build_next(result, 'get_weekly_priorities')
    _track_usage('get_weekly_priorities', {'limit': limit, 'tag': tag, 'asset_group': asset_group},
                 {'gaps_found': len(gaps), 'next_suggestions': len(result['_next'].get('investigate_deeper', []))})

    result = _with_meta(result, 'topRiskAssets')
    return _apply_detail_level(result, detail, list_keys=['topRiskAssets', 'priorities'])


def investigate_cve_agg(cve: str, detail: str = "standard") -> dict:
    result = {'cve': cve, 'qids': [], 'severity': 0, 'qds': 0,
              'qds_factors': '',
              'title': '', 'patchAvailable': False, 'solution': '',
              'allKbDetails': [], 'threatIntel': [],
              'ransomware': False,
              'summary': {'qidCount': 0, 'patchAvailable': False,
                          'assetsWithSoftware': 0}}

    qids = get_cve_qids(cve)
    result['qids'] = qids
    result['summary']['qidCount'] = len(qids)

    if qids:
        concurrent = _run_concurrent(
            kb=lambda: get_kb_batch(qids[:20]),
            qds=lambda: get_qds_for_qids(qids[:20]),
        )
        kb_data = concurrent.get('kb') or {}
        qds_scores = concurrent.get('qds') or {}

        max_sev = 0
        all_threat_intel = set()
        software_keywords = set()
        for qid in qids:
            kb = kb_data.get(qid)
            if kb:
                real_qds = qds_scores.get(qid, 0)
                if kb.get('severity', 0) > max_sev:
                    max_sev = kb['severity']
                    result['title'] = kb.get('title', '')
                    result['severity'] = kb['severity']
                    result['qds'] = real_qds or kb.get('qds', 0)
                    result['qds_factors'] = kb.get('qds_factors', '')
                    result['patchAvailable'] = kb.get('patch_available', False)
                    result['has_exploit'] = kb.get('has_exploit', False)
                    result['cvss_v3'] = kb.get('cvss_v3')
                    result['cvss_v3_vector'] = kb.get('cvss_v3_vector', '')
                    if detail == "detailed":
                        result['solution'] = kb.get('solution', '')
                        result['diagnosis'] = kb.get('diagnosis', '')
                    else:
                        result['solution'] = kb.get('solution', '')[:500]
                        result['diagnosis'] = kb.get('diagnosis', '')[:300]
                    result['summary']['patchAvailable'] = kb.get('patch_available', False)
                ti = kb.get('threat_intel', [])
                all_threat_intel.update(ti)
                if kb.get('ransomware'):
                    result['ransomware'] = True
                kb_title = kb.get('title', '')
                if detail == "detailed":
                    kb_title_display = kb_title
                else:
                    kb_title_display = kb_title[:80]
                result['allKbDetails'].append({
                    'qid': qid,
                    'title': kb_title_display,
                    'severity': kb.get('severity', 0),
                    'qds': real_qds or kb.get('qds', 0),
                    'cvss_v3': kb.get('cvss_v3'),
                    'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                    'patchAvailable': kb.get('patch_available', False),
                    'has_exploit': kb.get('has_exploit', False),
                    'cves': kb.get('cves', []),
                    'threatIntel': ti,
                    'ransomware': kb.get('ransomware', False),
                })
                for kw in _extract_software_keywords(kb.get('title', '')):
                    software_keywords.add(kw)

        result['threatIntel'] = sorted(all_threat_intel)
        result['allKbDetails'].sort(key=lambda x: x['severity'], reverse=True)

        # Step 2: Search CSAM for assets running the affected software
        title_lower = result['title'].lower()
        os_filter = None
        if 'windows' in title_lower or 'microsoft' in title_lower:
            os_filter = {'field': 'operatingSystem.name', 'operator': 'CONTAINS', 'value': 'Windows'}
        elif 'linux' in title_lower or 'ubuntu' in title_lower or 'centos' in title_lower or 'rhel' in title_lower:
            os_filter = {'field': 'operatingSystem.name', 'operator': 'CONTAINS', 'value': 'Linux'}

        if software_keywords:
            software_searches = {}
            for kw in list(software_keywords)[:4]:
                filters = [{'field': 'software.name', 'operator': 'CONTAINS', 'value': kw}]
                if os_filter:
                    filters.append(os_filter)
                software_searches[kw] = lambda f=filters: (
                    csam_count(f),
                    csam_search(f, limit=5)
                )
            sw_results = _run_concurrent(**software_searches)
            best_count = 0
            best_keyword = ''
            best_assets = []
            for kw, val in sw_results.items():
                if val and isinstance(val, tuple):
                    count, assets = val
                    if count and count > best_count:
                        best_count = count
                        best_keyword = kw
                        best_assets = assets or []

            if best_count == 0 and os_filter:
                os_count = csam_count([os_filter])
                os_assets = csam_search([os_filter], limit=5)
                result['assets'] = {
                    'searchedSoftware': ', '.join(list(software_keywords)[:2]),
                    'assetCount': 0,
                    'osExposure': {
                        'os': os_filter['value'],
                        'totalAssets': os_count,
                    },
                    'sampleAssets': [{
                        'assetId': str(a.get('assetId', '')),
                        'name': a.get('assetName', ''),
                        'riskScore': a.get('riskScore', 0),
                        'os': (a.get('operatingSystem') or {}).get('osName', ''),
                    } for a in (os_assets or [])[:5]],
                    'note': f'No specific software match but {os_count} {os_filter["value"]} assets could be affected. Use get_asset(assetId) to confirm.',
                }
                result['summary']['assetsWithSoftware'] = 0
                result['summary']['osExposedAssets'] = os_count
            else:
                result['assets'] = {
                    'searchedSoftware': best_keyword,
                    'assetCount': best_count,
                    'sampleAssets': [{
                        'assetId': str(a.get('assetId', '')),
                        'name': a.get('assetName', ''),
                        'riskScore': a.get('riskScore', 0),
                        'os': (a.get('operatingSystem') or {}).get('osName', ''),
                    } for a in best_assets[:5]],
                    'note': 'Assets running the affected software (potential exposure). Use get_asset(assetId) for confirmed vulnerability details.',
                }
                result['summary']['assetsWithSoftware'] = best_count

    followups = []
    asset_count = result.get('summary', {}).get('assetsWithSoftware', 0)
    if asset_count:
        followups.append(f"You have {asset_count} assets potentially affected by {cve} \u2014 investigate patch status with get_patch_status()?")
    if result.get('ransomware'):
        followups.append(f"{cve} is linked to ransomware \u2014 get_etm_findings(qql='threatName:ransomware') for full ransomware exposure?")
    if result.get('patchAvailable'):
        followups.append(f"Patch available for {cve} \u2014 get_patch_status() to see deployment coverage?")
    elif result.get('qids'):
        followups.append(f"No patch available for {cve} \u2014 get_vuln_exceptions() to check for compensating controls?")
    if result.get('has_exploit'):
        followups.append(f"{cve} has a known exploit \u2014 get_etm_findings(qql='vulnerabilities.vulnerability.cveIds:{cve}') for confirmed findings?")
    result['_followups'] = followups

    result['_next'] = _build_next(result, 'investigate_cve')
    _track_usage('investigate_cve', {'cve': cve},
                 {'gaps_found': 0, 'next_suggestions': len(result['_next'].get('investigate_deeper', []))})

    result = _with_meta(result, 'allKbDetails')
    return _apply_detail_level(result, detail, list_keys=['allKbDetails'])


def investigate_agg(topic: str, depth: str = "standard", prior_context: str = "", detail: str = "standard") -> dict:
    import re

    depth = depth.lower() if depth else "standard"
    if depth not in ("quick", "standard", "deep"):
        depth = "standard"

    findings = {}
    tools_called = []

    if prior_context:
        findings['prior_investigation'] = prior_context

    topic_lower = topic.lower().strip()

    def _detect_type():
        if re.match(r'CVE-\d{4}-\d{4,}', topic.strip(), re.IGNORECASE):
            return 'cve'
        if topic_lower.startswith('asset:') or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', topic.strip()):
            return 'asset'
        if any(kw in topic_lower for kw in ('risk', 'score', 'trurisk', 'why')):
            return 'risk_spike'
        if any(kw in topic_lower for kw in ('ransomware', 'ransom')):
            return 'ransomware'
        if any(kw in topic_lower for kw in ('compliance', 'audit', 'posture')):
            return 'compliance'
        if '.' in topic.strip() or topic_lower.startswith('asset:'):
            return 'asset'
        return 'general'

    inv_type = _detect_type()

    def _safe_call(name, fn):
        try:
            result = fn()
            tools_called.append(name)
            return compact(result) if result else None
        except Exception as e:
            _log(f"investigate({topic}): {name} failed: {e}")
            tools_called.append(f"{name}(failed)")
            return None

    if inv_type == 'cve':
        cve_id = re.search(r'(CVE-\d{4}-\d{4,})', topic, re.IGNORECASE).group(1).upper()

        tasks = {
            'cve_details': lambda: _safe_call('get_cve_details', lambda: cve_details(cve_id)),
            'cve_investigation': lambda: _safe_call('investigate_cve', lambda: investigate_cve_agg(cve_id)),
        }
        results = _run_concurrent(**tasks)
        findings['cve_details'] = results.get('cve_details')
        findings['cve_investigation'] = results.get('cve_investigation')

        if depth in ('standard', 'deep'):
            std_tasks = {
                'patch_status': lambda: _safe_call('get_patch_status', lambda: patch_status()),
                'vuln_exceptions': lambda: _safe_call('get_vuln_exceptions', lambda: vuln_exceptions()),
            }
            std_results = _run_concurrent(**std_tasks)
            findings['patch_status'] = std_results.get('patch_status')
            findings['vuln_exceptions'] = std_results.get('vuln_exceptions')

        if depth == 'deep':
            deep_tasks = {
                'etm_findings': lambda: _safe_call('get_etm_findings',
                    lambda: etm_findings(qql=f'vulnerabilities.vulnerability.cveIds:{cve_id}')),
                'weekly_priorities': lambda: _safe_call('get_weekly_priorities', lambda: weekly_priorities()),
            }
            deep_results = _run_concurrent(**deep_tasks)
            findings['etm_findings'] = deep_results.get('etm_findings')
            findings['weekly_priorities'] = deep_results.get('weekly_priorities')

    elif inv_type == 'asset':
        asset_query = topic_lower.replace('asset:', '').strip()
        findings['asset'] = _safe_call('get_asset', lambda: asset_detail(asset_query, detail_level='full'))

        if depth in ('standard', 'deep'):
            findings['etm_findings'] = _safe_call('get_etm_findings', lambda: etm_findings())

        if depth == 'deep':
            deep_tasks = {
                'patch_status': lambda: _safe_call('get_patch_status', lambda: patch_status()),
                'vuln_exceptions': lambda: _safe_call('get_vuln_exceptions', lambda: vuln_exceptions()),
            }
            deep_results = _run_concurrent(**deep_tasks)
            findings['patch_status'] = deep_results.get('patch_status')
            findings['vuln_exceptions'] = deep_results.get('vuln_exceptions')

    elif inv_type == 'risk_spike':
        tasks = {
            'trurisk': lambda: _safe_call('get_trurisk_score', lambda: trurisk_score()),
            'weekly_priorities': lambda: _safe_call('get_weekly_priorities', lambda: weekly_priorities()),
        }
        results = _run_concurrent(**tasks)
        findings['trurisk'] = results.get('trurisk')
        findings['weekly_priorities'] = results.get('weekly_priorities')

        if depth in ('standard', 'deep'):
            std_tasks = {
                'search_vulns': lambda: _safe_call('search_vulns', lambda: search_vulns_agg()),
                'morning_report': lambda: _safe_call('get_morning_report', lambda: morning_report()),
            }
            std_results = _run_concurrent(**std_tasks)
            findings['search_vulns'] = std_results.get('search_vulns')
            findings['morning_report'] = std_results.get('morning_report')

        if depth == 'deep':
            priorities = findings.get('weekly_priorities') or {}
            top_assets = (priorities.get('topRiskAssets') or [])[:3]
            for i, asset in enumerate(top_assets):
                asset_id = str(asset.get('assetId', ''))
                if asset_id:
                    findings[f'top_asset_{i}'] = _safe_call(
                        f'get_asset({asset_id})',
                        lambda aid=asset_id: asset_detail(aid, detail_level='full'))

    elif inv_type == 'ransomware':
        if depth == 'quick':
            tasks = {
                'ransomware_vulns': lambda: _safe_call('search_vulns',
                    lambda: search_vulns_agg(days=30, threat_type='Ransomware', limit=20)),
                'risk_summary': lambda: _safe_call('trurisk',
                    lambda: trurisk_score(days=30)),
            }
            results = _run_concurrent(**tasks)
            findings['ransomware_vulns'] = results.get('ransomware_vulns')
            findings['risk_summary'] = results.get('risk_summary')
        else:
            tasks = {
                'etm_findings': lambda: _safe_call('get_etm_findings',
                    lambda: etm_findings(qql='threatName:ransomware')),
                'weekly_priorities': lambda: _safe_call('get_weekly_priorities', lambda: weekly_priorities()),
            }
            results = _run_concurrent(**tasks)
            findings['etm_findings'] = results.get('etm_findings')
            findings['weekly_priorities'] = results.get('weekly_priorities')

        if depth in ('standard', 'deep'):
            std_tasks = {
                'edr_events': lambda: _safe_call('get_edr_events', lambda: edr_events()),
                'patch_status': lambda: _safe_call('get_patch_status', lambda: patch_status()),
            }
            std_results = _run_concurrent(**std_tasks)
            findings['edr_events'] = std_results.get('edr_events')
            findings['patch_status'] = std_results.get('patch_status')

        if depth == 'deep':
            etm = findings.get('etm_findings') or {}
            etm_list = etm.get('findings') or []
            seen_cves = set()
            for f in etm_list[:5]:
                for cve_id in (f.get('cves') or []):
                    if cve_id not in seen_cves and len(seen_cves) < 3:
                        seen_cves.add(cve_id)
                        findings[f'cve_{cve_id}'] = _safe_call(
                            f'investigate_cve({cve_id})',
                            lambda c=cve_id: investigate_cve_agg(c))

    elif inv_type == 'compliance':
        tasks = {
            'compliance': lambda: _safe_call('get_compliance_posture', lambda: compliance_posture()),
            'morning_report': lambda: _safe_call('get_morning_report', lambda: morning_report(quick=True)),
        }
        results = _run_concurrent(**tasks)
        findings['compliance'] = results.get('compliance')
        findings['morning_report'] = results.get('morning_report')

        if depth in ('standard', 'deep'):
            std_tasks = {
                'etm_findings': lambda: _safe_call('get_etm_findings', lambda: etm_findings()),
                'vuln_exceptions': lambda: _safe_call('get_vuln_exceptions', lambda: vuln_exceptions()),
            }
            std_results = _run_concurrent(**std_tasks)
            findings['etm_findings'] = std_results.get('etm_findings')
            findings['vuln_exceptions'] = std_results.get('vuln_exceptions')

        if depth == 'deep':
            deep_tasks = {
                'cloud_risk': lambda: _safe_call('get_cloud_risk', lambda: cloud_risk()),
                'expiring_certs': lambda: _safe_call('get_expiring_certs', lambda: expiring_certs()),
            }
            deep_results = _run_concurrent(**deep_tasks)
            findings['cloud_risk'] = deep_results.get('cloud_risk')
            findings['expiring_certs'] = deep_results.get('expiring_certs')

    else:
        if depth == 'quick':
            tasks = {
                'morning_report': lambda: _safe_call('get_morning_report', lambda: morning_report(quick=True)),
                'risk_summary': lambda: _safe_call('trurisk', lambda: trurisk_score(days=30)),
            }
        else:
            tasks = {
                'morning_report': lambda: _safe_call('get_morning_report', lambda: morning_report()),
                'weekly_priorities': lambda: _safe_call('get_weekly_priorities', lambda: weekly_priorities()),
            }
        results = _run_concurrent(**tasks)
        for k, v in results.items():
            findings[k] = v

        if depth in ('standard', 'deep'):
            findings['search_vulns'] = _safe_call('search_vulns', lambda: search_vulns_agg())

        if depth == 'deep':
            deep_tasks = {
                'cloud_risk': lambda: _safe_call('get_cloud_risk', lambda: cloud_risk()),
                'compliance': lambda: _safe_call('get_compliance_posture', lambda: compliance_posture()),
            }
            deep_results = _run_concurrent(**deep_tasks)
            findings['cloud_risk'] = deep_results.get('cloud_risk')
            findings['compliance'] = deep_results.get('compliance')

    # --- Build summary and risk level ---
    risk_level = 'low'
    key_facts = []
    recommended_actions = []
    followups = []

    if inv_type == 'cve':
        cve_inv = findings.get('cve_investigation') or {}
        sev = cve_inv.get('severity', 0)
        qds = cve_inv.get('qds', 0)
        asset_count = (cve_inv.get('summary') or {}).get('assetsWithSoftware', 0)
        is_ransomware = cve_inv.get('ransomware', False)
        has_patch = cve_inv.get('patchAvailable', False)

        if sev >= 5 or qds >= 90 or is_ransomware:
            risk_level = 'critical'
        elif sev >= 4 or qds >= 70:
            risk_level = 'high'
        elif sev >= 3:
            risk_level = 'medium'

        title = cve_inv.get('title', topic)
        key_facts.append(f"{topic}: {title}")
        key_facts.append(f"Severity {sev}/5, QDS {qds}/100")
        if asset_count:
            key_facts.append(f"{asset_count} assets potentially affected")
        if is_ransomware:
            key_facts.append("Linked to ransomware campaigns")
        if has_patch:
            key_facts.append("Patch available")
            recommended_actions.append("Deploy patch to affected assets immediately")
        else:
            recommended_actions.append("Apply compensating controls \u2014 no vendor patch available")
        if asset_count:
            recommended_actions.append(f"Review {asset_count} affected assets for exposure")
        followups.append(f"investigate('{topic}', depth='deep') for full ETM findings" if depth != 'deep' else f"get_asset() on top affected assets for detailed profiles")

    elif inv_type == 'risk_spike':
        trurisk_data = findings.get('trurisk') or {}
        trend = trurisk_data.get('trend') or {}
        direction = trend.get('direction', 'stable')
        delta = trend.get('delta', 0)
        if direction == 'worsening' and abs(delta) > 10:
            risk_level = 'high'
        elif direction == 'worsening':
            risk_level = 'medium'
        key_facts.append(f"TruRisk trend: {direction} (delta {delta:+d})")
        priorities = findings.get('weekly_priorities') or {}
        top = (priorities.get('topRiskAssets') or [])[:3]
        for a in top:
            key_facts.append(f"Top risk: {a.get('hostname', '?')} (TruRisk {a.get('riskScore', '?')})")
        recommended_actions.append("Focus remediation on top risk assets")
        if direction == 'worsening':
            recommended_actions.append("Investigate new vulnerability introductions this week")
        followups.append("get_asset() on top risk assets for detailed breakdown")

    elif inv_type == 'ransomware':
        etm = findings.get('etm_findings') or {}
        finding_count = len(etm.get('findings') or [])
        risk_level = 'critical' if finding_count > 0 else 'medium'
        key_facts.append(f"{finding_count} ransomware-linked findings in environment")
        patch = findings.get('patch_status') or {}
        if patch:
            key_facts.append(f"Patch coverage: {patch.get('summary', {}).get('patchedPct', '?')}%")
        recommended_actions.append("Prioritize patching ransomware-linked CVEs")
        recommended_actions.append("Verify EDR coverage on high-risk assets")
        followups.append("investigate_cve() on each ransomware CVE for asset-level impact")

    elif inv_type == 'asset':
        asset = findings.get('asset') or {}
        risk_score_val = asset.get('riskScore', 0)
        if risk_score_val >= 900:
            risk_level = 'critical'
        elif risk_score_val >= 700:
            risk_level = 'high'
        elif risk_score_val >= 400:
            risk_level = 'medium'
        key_facts.append(f"Asset TruRisk: {risk_score_val}")
        key_facts.append(f"Hostname: {asset.get('hostname', '?')}, OS: {asset.get('os', '?')}")
        vuln_count = len(asset.get('vulns', []))
        if vuln_count:
            key_facts.append(f"{vuln_count} vulnerabilities detected")
        recommended_actions.append("Patch critical vulnerabilities on this asset")
        followups.append("investigate_cve() on top CVEs affecting this asset")

    elif inv_type == 'compliance':
        comp = findings.get('compliance') or {}
        summary = comp.get('summary') or {}
        pass_pct = summary.get('pass_pct', 0)
        failing = summary.get('failing', 0)
        if pass_pct < 70:
            risk_level = 'high'
        elif pass_pct < 85:
            risk_level = 'medium'
        key_facts.append(f"Compliance pass rate: {pass_pct}%")
        key_facts.append(f"{failing} controls failing")
        frameworks_list = summary.get('frameworks', [])
        if frameworks_list:
            key_facts.append(f"Frameworks: {', '.join(frameworks_list[:5])}")
        recommended_actions.append("Address top failing controls by asset impact")
        if failing:
            recommended_actions.append("Review vulnerability exceptions expiring soon")
        followups.append("get_cloud_risk() for cloud-specific compliance")

    else:
        report = findings.get('morning_report') or {}
        env = report.get('environment') or {}
        high_risk_count = env.get('highRiskAssets', 0)
        if high_risk_count > 50:
            risk_level = 'high'
        elif high_risk_count > 10:
            risk_level = 'medium'
        total_a = env.get('totalAssets') or mr.get('totalAssets') or ''
        if total_a:
            key_facts.append(f"{total_a} total assets, {high_risk_count} high-risk")
        threats_data = report.get('threats') or {}
        if threats_data.get('ransomwareLinked'):
            key_facts.append(f"{threats_data['ransomwareLinked']} ransomware-linked vulns")
        recommended_actions.append("Review morning report action items")
        followups.append("investigate('ransomware') for ransomware deep-dive")
        followups.append("investigate('compliance') for compliance posture")

    summary_parts = [f"{inv_type.replace('_', ' ').title()} investigation on '{topic}' ({depth} depth)."]
    if key_facts:
        summary_parts.append(key_facts[0] + '.')
    summary_parts.append(f"Risk level: {risk_level}.")
    executive_summary = ' '.join(summary_parts)

    if len(followups) < 3:
        if inv_type != 'cve':
            followups.append(f"investigate('{topic}', depth='deep') for deeper analysis" if depth != 'deep' else "Review findings and prioritize actions")
        followups.append("get_morning_report() for current daily briefing")
        followups.append("get_weekly_priorities() for prioritized remediation list")
    followups = followups[:5]

    total_items = sum(1 for v in findings.values() if v is not None)
    result = {
        'topic': topic,
        'depth': depth,
        'investigation_type': inv_type,
        'summary': executive_summary,
        'findings': compact(findings),
        'risk_level': risk_level,
        'key_facts': key_facts[:5],
        'recommended_actions': recommended_actions[:5],
        '_followups': followups,
        '_meta': {
            'returned': total_items,
            'total': total_items,
            'truncated': False,
            'tools_called': tools_called,
            'depth': depth,
        },
    }

    result['_next'] = _build_next(result, 'investigate')
    _track_usage('investigate', {'topic': topic, 'depth': depth},
                 {'gaps_found': 0, 'next_suggestions': len(result['_next'].get('investigate_deeper', []))})

    result = compact(result)
    return _apply_detail_level(result, detail, list_keys=['key_facts', 'recommended_actions'])


def patch_status(limit: int = 20, tag: str = "", asset_group: str = "", detail: str = "standard") -> dict:
    result = {'coverage': 0, 'assetsTotal': 0, 'riskDistribution': {},
              'highRiskAssets': []}

    concurrent = _run_concurrent(
        total=lambda: csam_count(_scope_filters(None, tag, asset_group)),
        risk_900=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}], tag, asset_group)),
        risk_700=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}], tag, asset_group)),
        risk_500=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}], tag, asset_group)),
        risk_100=lambda: csam_count(_scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "100"}], tag, asset_group)),
        assets_900=lambda: csam_search(
            _scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}], tag, asset_group),
            limit=limit
        ),
        assets_700=lambda: csam_search(
            _scope_filters([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}], tag, asset_group),
            limit=limit
        ),
    )

    total = concurrent.get('total') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    risk_100 = concurrent.get('risk_100') or 0
    result['assetsTotal'] = total
    result['riskDistribution'] = {
        'critical_900plus': risk_900,
        'high_700plus': risk_700,
        'elevated_500plus': risk_500,
        'medium_100plus': risk_100,
        'low_under100': total - risk_100,
    }

    seen = set()
    top_risk = []
    for asset in (concurrent.get('assets_900') or []) + (concurrent.get('assets_700') or []):
        aid = asset.get('assetId')
        if aid and aid not in seen:
            seen.add(aid)
            top_risk.append(asset)
    top_risk.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for asset in top_risk[:limit]:
        result['highRiskAssets'].append({
            'assetId': str(asset.get('assetId', '')),
            'hostId': str(asset.get('hostId') or ''),
            'hostname': short_host(asset.get('dnsHostName', '') or asset.get('dnsName', '')),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
        })

    if total > 0:
        result['coverage'] = round((total - risk_100) / total * 100, 1)

    result = _with_meta(result, 'highRiskAssets', total)
    return _apply_detail_level(result, detail, list_keys=['highRiskAssets'])


def search_vulns_agg(days: int = 7, threat_type: str = "", software: str = "", limit: int = 50, tag: str = "", asset_group: str = "", detail: str = "standard") -> dict:
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    result = {'days': days, 'publishedAfter': after, 'totalVulns': 0,
              'severityBreakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
              'withPatch': 0, 'withThreatIntel': 0,
              'threatFilter': threat_type or 'all',
              'softwareFilter': software or 'all',
              'threatBreakdown': {}, 'vulns': [], 'summary': ''}

    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=120
    )
    if data == 'KB_BUSY':
        result['summary'] = KB_BUSY_MSG
        return _with_meta(result, 'vulns')
    if not data:
        result['summary'] = 'Failed to fetch KB data'
        return _with_meta(result, 'vulns')

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['summary'] = 'Failed to parse KB data'
        return _with_meta(result, 'vulns')

    all_vulns_xml = root.findall('.//VULN')
    result['totalVulns'] = len(all_vulns_xml)
    matching = []
    threat_counts = {}
    ti_count = 0
    search_lower = software.lower() if software else ''

    for v in all_vulns_xml:
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        ti = parsed.get('threat_intel', [])
        if ti:
            ti_count += 1
        for tag_item in ti:
            threat_counts[tag_item] = threat_counts.get(tag_item, 0) + 1

        if threat_type:
            if not any(threat_type.lower() in t.lower() for t in ti):
                continue
        if search_lower:
            title = parsed.get('title', '').lower()
            diagnosis = parsed.get('diagnosis', '').lower()
            if search_lower not in title and search_lower not in diagnosis:
                continue

        matching.append(parsed)

    result['withThreatIntel'] = ti_count
    result['threatBreakdown'] = dict(sorted(threat_counts.items(), key=lambda x: -x[1]))

    for v in matching:
        sev = v['severity']
        if sev >= 5:
            result['severityBreakdown']['critical'] += 1
        elif sev >= 4:
            result['severityBreakdown']['high'] += 1
        elif sev >= 3:
            result['severityBreakdown']['medium'] += 1
        else:
            result['severityBreakdown']['low'] += 1
        if v.get('patch_available'):
            result['withPatch'] += 1

    matching.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))

    top_qids = [v['qid'] for v in matching[:20] if v.get('qid')]
    qds_scores = get_qds_for_qids(top_qids) if top_qids else {}

    for v in matching[:limit]:
        real_qds = qds_scores.get(v['qid'], 0)
        vuln_title = v['title']
        if detail != "detailed":
            vuln_title = vuln_title[:80]
        result['vulns'].append({
            'qid': v['qid'],
            'title': vuln_title,
            'severity': v['severity'],
            'qds': real_qds or v.get('qds', 0),
            'cvss_v3': v.get('cvss_v3'),
            'cvss_v3_vector': v.get('cvss_v3_vector', ''),
            'cves': v.get('cves', []),
            'patchAvailable': v.get('patch_available', False),
            'has_exploit': v.get('has_exploit', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    result['totalMatching'] = len(matching)
    filters = []
    if threat_type:
        filters.append(f"threat_type='{threat_type}'")
    if software:
        filters.append(f"software='{software}'")
    filter_label = ', '.join(filters) if filters else 'no filters'
    patched = sum(1 for v in matching if v.get('patch_available'))
    result['summary'] = (
        f"{len(matching)} matching vulns ({filter_label}) out of {len(all_vulns_xml)} "
        f"published in last {days} days. {patched} have patches available."
    )
    result = _with_meta(result, 'vulns', result.get('totalMatching', len(matching)))
    return _apply_detail_level(result, detail, list_keys=['vulns'])


def threat_actor_exposure_agg(threat_actor: str, actor_tags: list[str], limit: int = 20, detail: str = "standard") -> dict:
    """Search KB for vulns attributed to threat actor tags, then cross-reference with active VMDR detections."""
    result = {
        'threatActor': threat_actor,
        'tagsSearched': actor_tags,
        'totalInKB': 0,
        'activeInEnvironment': 0,
        'severityBreakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'vulns': [],
        'affectedHosts': [],
        'summary': '',
    }

    # Step 1: Search KB for vulns matching threat actor tags
    # Fetch recent KB entries with threat intel info
    kb_after = (datetime.now(timezone.utc) - timedelta(days=90)).strftime('%Y-%m-%d')
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&show_supported_modules_info=0&published_after={kb_after}",
        timeout=120
    )
    if data == 'KB_BUSY':
        result['summary'] = KB_BUSY_MSG
        return _with_meta(result, 'vulns')
    if not data:
        result['summary'] = 'Failed to fetch KB data'
        return _with_meta(result, 'vulns')

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['summary'] = 'Failed to parse KB data'
        return _with_meta(result, 'vulns')

    # Find vulns whose threat_intel tags or title/diagnosis match actor tags
    tag_lower = [t.lower() for t in actor_tags]
    matching_vulns = []

    for v in root.findall('.//VULN'):
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed

        # Match on threat_intel tags
        ti_lower = [t.lower() for t in parsed.get('threat_intel', [])]
        matched = any(tag in ti_text for tag in tag_lower for ti_text in ti_lower)

        # Also match on title/diagnosis for industry/actor keywords
        if not matched:
            title_diag = (parsed.get('title', '') + ' ' + parsed.get('diagnosis', '')).lower()
            matched = any(tag in title_diag for tag in tag_lower)

        if matched:
            matching_vulns.append(parsed)

    result['totalInKB'] = len(matching_vulns)

    if not matching_vulns:
        result['summary'] = f"No vulnerabilities found in Qualys KB matching {threat_actor} (tags searched: {', '.join(actor_tags)}). This actor may use zero-days or vulns not yet attributed in the KB."
        return _with_meta(result, 'vulns')

    # Sort by severity desc, then by QDS desc
    matching_vulns.sort(key=lambda x: (-x['severity'], -x.get('qds', 0)))

    # Step 2: Cross-reference with active VMDR detections
    matching_qids = {v['qid'] for v in matching_vulns}

    # Fetch critical detections only (sev 5) for cross-reference
    concurrent = _run_concurrent(
        det_sev5=lambda: get_detections(severity=5),
    )
    all_detections = []
    dets = concurrent.get('det_sev5')
    if dets:
        all_detections.extend(dets)

    # Filter detections to only those matching our QIDs
    active_dets = [d for d in all_detections if d.get('qid') in matching_qids]
    active_qids = {d['qid'] for d in active_dets}
    result['activeInEnvironment'] = len(active_qids)

    # Build host impact summary
    host_map = {}  # hostname -> {qids, severity_max}
    for d in active_dets:
        host = d.get('hostname') or d.get('ip') or d.get('host_id', 'unknown')
        if host not in host_map:
            host_map[host] = {'hostname': host, 'ip': d.get('ip', ''), 'qidCount': 0, 'maxSeverity': 0}
        host_map[host]['qidCount'] += 1
        host_map[host]['maxSeverity'] = max(host_map[host]['maxSeverity'], d.get('severity', 0))

    # Top affected hosts
    sorted_hosts = sorted(host_map.values(), key=lambda x: (-x['maxSeverity'], -x['qidCount']))
    result['affectedHosts'] = sorted_hosts[:10]

    # Get real QDS scores for top vulns
    top_qids = [v['qid'] for v in matching_vulns[:30] if v.get('qid')]
    qds_scores = get_qds_for_qids(top_qids) if top_qids else {}

    # Build severity breakdown and vuln list
    for v in matching_vulns:
        sev = v['severity']
        if sev >= 5:
            result['severityBreakdown']['critical'] += 1
        elif sev >= 4:
            result['severityBreakdown']['high'] += 1
        elif sev >= 3:
            result['severityBreakdown']['medium'] += 1
        else:
            result['severityBreakdown']['low'] += 1

    for v in matching_vulns[:limit]:
        real_qds = qds_scores.get(v['qid'], 0)
        vuln_entry = {
            'qid': v['qid'],
            'title': v['title'][:100] if detail != "detailed" else v['title'],
            'severity': v['severity'],
            'qds': real_qds or v.get('qds', 0),
            'cvss_v3': v.get('cvss_v3'),
            'cves': v.get('cves', []),
            'patchAvailable': v.get('patch_available', False),
            'has_exploit': v.get('has_exploit', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
            'activeInEnv': v['qid'] in active_qids,
        }
        result['vulns'].append(vuln_entry)

    active_count = sum(1 for v in result['vulns'] if v['activeInEnv'])
    patched = sum(1 for v in matching_vulns if v.get('patch_available'))
    host_count = len(host_map)
    sev = result['severityBreakdown']
    result['summary'] = (
        f"{len(matching_vulns)} KB vulns attributed to {threat_actor} "
        f"({sev['critical']} critical, {sev['high']} high). "
        f"{len(active_qids)} actively detected in your environment across {host_count} hosts. "
        f"{patched} have patches available."
    )

    result = _with_meta(result, 'vulns', result['totalInKB'])
    return _apply_detail_level(result, detail, list_keys=['vulns', 'affectedHosts'])


def recommendations(detail: str = "standard") -> dict:
    result = {'recommendations': [], 'coverage': {}, 'summary': ''}
    recs = []

    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        eol_count=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        images=lambda: get_images(10),
        vuln_images=lambda: get_images(10, 5),
        containers=lambda: get_containers(10),
        cloud_aws=lambda: get_connectors('aws', 5),
        cloud_azure=lambda: get_connectors('azure', 5),
        cloud_gcp=lambda: get_connectors('gcp', 5),
        cloud_oci=lambda: get_connectors('oci', 5),
        cloud_evals=lambda: _get_first_cloud_evals(),
        was=lambda: get_was_findings(5, 4),
        fim=lambda: _fetch_fim_events_raw(5, 7),
        edr=lambda: _fetch_edr_events_raw(5),
        certs=lambda: get_certificates(5, 30),
        ransomware_vulns=lambda: search_vulns_agg(days=7, threat_type='Ransomware', limit=10),
    )

    total = concurrent.get('total') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol_count = concurrent.get('eol_count') or 0
    images = concurrent.get('images') or []
    vuln_images = concurrent.get('vuln_images') or []
    containers = concurrent.get('containers') or []
    cloud_aws = concurrent.get('cloud_aws') or []
    cloud_azure = concurrent.get('cloud_azure') or []
    cloud_gcp = concurrent.get('cloud_gcp') or []
    was = concurrent.get('was') or []
    fim = concurrent.get('fim') or []
    edr = concurrent.get('edr') or []
    certs = concurrent.get('certs') or []
    ransomware = concurrent.get('ransomware_vulns') or {}

    coverage = {
        'vmdr': True,
        'totalCloud': len(images) > 0 or len(cloud_aws) + len(cloud_azure) + len(cloud_gcp) > 0,
        'totalAppSec': len(was) > 0,
        'fileIntegrityMonitoring': len(fim) > 0,
        'endpointDetection': len(edr) > 0,
        'certificateView': len(certs) > 0,
    }
    result['coverage'] = coverage

    rank = 1

    if risk_900 > 0:
        recs.append({
            'rank': rank, 'priority': 'CRITICAL',
            'area': 'Risk Elimination',
            'finding': f'{risk_900} assets have TruRisk scores above 900 (maximum risk)',
            'qualysModule': 'Patch Management + VMDR',
            'riskAction': 'eliminate',
        })
        rank += 1

    if eol_count > 0:
        pct = round(eol_count / total * 100, 1) if total else 0
        recs.append({
            'rank': rank, 'priority': 'HIGH',
            'area': 'Asset Lifecycle',
            'finding': f'{eol_count} systems ({pct}% of environment) are running EOL/EOS operating systems that no longer receive security patches',
            'qualysModule': 'CSAM + Patch Management',
            'riskAction': 'eliminate',
        })
        rank += 1

    if not images:
        recs.append({
            'rank': rank, 'priority': 'HIGH',
            'area': 'Container & Cloud Security',
            'finding': 'No container images detected \u2014 container workloads may be running unscanned',
            'qualysModule': 'TotalCloud',
            'riskAction': 'eliminate',
        })
        rank += 1
    elif vuln_images:
        vuln_img_ids = {img.get('imageId') for img in vuln_images}
        at_risk = [c for c in containers if c.get('imageId') in vuln_img_ids]
        if at_risk:
            recs.append({
                'rank': rank, 'priority': 'HIGH',
                'area': 'Container & Cloud Security',
                'finding': f'{len(at_risk)} running containers are based on images with critical vulnerabilities',
                'qualysModule': 'TotalCloud',
                'riskAction': 'eliminate',
            })
            rank += 1

    cloud_total = len(cloud_aws) + len(cloud_azure) + len(cloud_gcp)
    cloud_evals = concurrent.get('cloud_evals') or []
    if not cloud_total:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Cloud Security Posture',
            'finding': 'No cloud connectors configured \u2014 cloud assets may have unmonitored misconfigurations',
            'qualysModule': 'TotalCloud',
            'riskAction': 'mitigate',
        })
        rank += 1
    else:
        fails = [e for e in cloud_evals if e.get('result') in ['FAIL', 'FAILED']]
        if fails:
            recs.append({
                'rank': rank, 'priority': 'MEDIUM',
                'area': 'Cloud Security Posture',
                'finding': f'{len(fails)} cloud security control failures detected across {cloud_total} connected accounts',
                'qualysModule': 'TotalCloud + Policy Compliance',
                'riskAction': 'eliminate',
            })
            rank += 1

    if not was:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Application Security',
            'finding': 'No application scan findings detected \u2014 web apps and APIs may not be scanned for vulnerabilities like SQLi, XSS, and OWASP Top 10',
            'qualysModule': 'TotalAppSec (TAS)',
            'riskAction': 'eliminate',
        })
        rank += 1

    if not fim:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'File Integrity Monitoring',
            'finding': 'No file integrity monitoring events detected \u2014 unauthorized changes to critical files may go undetected',
            'qualysModule': 'File Integrity Monitoring (FIM)',
            'riskAction': 'mitigate',
        })
        rank += 1

    if not edr:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Endpoint Detection & Response',
            'finding': 'No endpoint detection events \u2014 active threats and malicious behaviors may not be detected in real time',
            'qualysModule': 'Multi-Vector EDR',
            'riskAction': 'mitigate',
        })
        rank += 1

    if not certs:
        recs.append({
            'rank': rank, 'priority': 'LOW',
            'area': 'Certificate Management',
            'finding': 'No certificate data available \u2014 expired or weak SSL/TLS certificates may cause outages or security gaps',
            'qualysModule': 'CertView',
            'riskAction': 'mitigate',
        })
        rank += 1

    ransomware_count = ransomware.get('totalMatching', 0)
    if ransomware_count > 0:
        recs.append({
            'rank': rank, 'priority': 'HIGH',
            'area': 'Ransomware Defense',
            'finding': f'{ransomware_count} vulnerabilities with ransomware linkage published in last 30 days',
            'qualysModule': 'Patch Management + VMDR + EDR',
            'riskAction': 'eliminate',
        })
        rank += 1

    if total > 0 and risk_500 > 0:
        risk_pct = round(risk_500 / total * 100, 1)
        if risk_pct > 10:
            recs.append({
                'rank': rank, 'priority': 'HIGH',
                'area': 'Patch Coverage',
                'finding': f'{risk_500} assets ({risk_pct}%) have elevated risk (TruRisk > 500) indicating significant unpatched vulnerabilities',
                'qualysModule': 'Patch Management + VMDR',
                'riskAction': 'eliminate',
            })
            rank += 1

    result['recommendations'] = recs

    eliminate_count = sum(1 for r in recs if r.get('riskAction') == 'eliminate')
    mitigate_count = sum(1 for r in recs if r.get('riskAction') == 'mitigate')
    active = sum(1 for v in coverage.values() if v)
    total_modules = len(coverage)
    result['riskActions'] = {
        'eliminate': eliminate_count,
        'mitigate': mitigate_count,
    }
    result['summary'] = (
        f'{len(recs)} recommendations across {total} assets. '
        f'{eliminate_count} actions to eliminate risk, {mitigate_count} to mitigate. '
        f'Module coverage: {active}/{total_modules} security capabilities active. '
        f'Top priorities: {"critical risk remediation, " if risk_900 else ""}'
        f'{"EOL migration, " if eol_count else ""}'
        f'{"container scanning, " if not images else ""}'
        f'{"cloud posture, " if not cloud_total else ""}'
        f'{"app scanning, " if not was else ""}'
        f'patch acceleration'
    )

    gaps = _detect_gaps(result)
    if gaps:
        result['_gaps'] = gaps
    _track_usage('get_recommendations', {},
                 {'gaps_found': len(gaps), 'next_suggestions': 0})

    result = _with_meta(result, 'recommendations')
    return _apply_detail_level(result, detail, list_keys=['recommendations'])


def outstanding_patches(platform: str = "", severity: str = "", top_n: int = 20, detail: str = "standard") -> dict:
    """Fetch outstanding (missing) patches from /pm/v1/patches and return a ranked summary."""
    platforms = []
    if platform:
        platforms = [platform.strip().capitalize()]
    else:
        platforms = ['Windows', 'Linux']

    sev_filter = severity.strip().capitalize() if severity else ""

    # Fetch patches for each platform in parallel
    tasks = {}
    for p in platforms:
        tasks[p.lower()] = lambda _p=p: get_pm_patches(_p, status='Missing', page_size=50)
    concurrent = _run_concurrent(**tasks)

    all_patches = []
    for p in platforms:
        patches = concurrent.get(p.lower()) or []
        if isinstance(patches, dict):
            # API may return {data: [...]} or flat list
            patches = patches.get('data', patches.get('patches', []))
        if isinstance(patches, list):
            for patch in patches:
                patch['_platform'] = p
                all_patches.append(patch)

    if not all_patches:
        return _with_meta({
            'totalOutstanding': 0,
            'patches': [],
            'summary': f'No outstanding (missing) patches found{" for " + platform if platform else ""}.',
        })

    # Apply severity filter
    if sev_filter:
        all_patches = [p for p in all_patches if (p.get('vendorSeverity') or '').capitalize() == sev_filter]

    # Sort by missingCount descending
    all_patches.sort(key=lambda p: p.get('missingCount', 0), reverse=True)

    # Compute breakdowns
    security_count = sum(1 for p in all_patches if p.get('isSecurity'))
    non_security_count = len(all_patches) - security_count
    reboot_required_count = sum(1 for p in all_patches if p.get('rebootRequired'))

    # Take top N
    top_patches = all_patches[:top_n]
    formatted = []
    for p in top_patches:
        cves = p.get('cve') or p.get('cves') or []
        formatted.append({
            'title': p.get('title', ''),
            'missingCount': p.get('missingCount', 0),
            'vendorSeverity': p.get('vendorSeverity', ''),
            'isSecurity': p.get('isSecurity', False),
            'rebootRequired': p.get('rebootRequired', False),
            'cveCount': len(cves) if isinstance(cves, list) else 0,
            'platform': p.get('_platform', ''),
            'category': p.get('category', ''),
            'kb': p.get('kb', ''),
        })

    total = len(all_patches)
    total_missing = sum(p.get('missingCount', 0) for p in all_patches)
    lines = [
        f"{total} outstanding patches ({total_missing} total missing installations)",
        f"Security: {security_count} | Non-security: {non_security_count}",
        f"Reboot required: {reboot_required_count}",
    ]
    if sev_filter:
        lines.append(f"Filtered by severity: {sev_filter}")
    if platform:
        lines.append(f"Platform: {platform}")
    lines.append(f"Showing top {len(formatted)} by missing count")

    result = {
        'totalOutstanding': total,
        'totalMissingInstalls': total_missing,
        'securityPatches': security_count,
        'nonSecurityPatches': non_security_count,
        'rebootRequired': reboot_required_count,
        'topPatches': formatted,
        'summary': '. '.join(lines) + '.',
    }
    return _with_meta(_apply_detail_level(result, detail, list_keys=['topPatches']))


def eliminate_status(detail: str = "standard", status: str = "") -> dict:
    result = {
        'patchManagement': {'windows': {}, 'linux': {}},
        'mitigations': {'windows': {}, 'linux': {}},
        'patchCatalog': {},
        'patchCounts': {},
        'deploymentSuccessRate': {},
        'techniqueBreakdown': {},
        'summary': '',
    }

    status_filter = status.strip().capitalize() if status else ""
    # Pass status to API so the server filters instead of fetching all
    pm_status = status_filter or None
    mtg_status = status_filter or None

    concurrent = _run_concurrent(
        windows_pm_jobs=lambda: get_pm_jobs('Windows', 20, status=pm_status),
        linux_pm_jobs=lambda: get_pm_jobs('Linux', 20, status=pm_status),
        windows_mtg_jobs=lambda: get_mtg_jobs('Windows', 20, status=mtg_status),
        linux_mtg_jobs=lambda: get_mtg_jobs('Linux', 20, status=mtg_status),
        windows_patches=lambda: get_pm_patches_count('Windows', 'vendorSeverity'),
        linux_patches=lambda: get_pm_patches_count('Linux'),
        windows_assets=lambda: get_pm_assets('Windows', 5),
        linux_assets=lambda: get_pm_assets('Linux', 5),
        windows_missing=lambda: get_pm_patches_count('Windows', status='Missing'),
        linux_missing=lambda: get_pm_patches_count('Linux', status='Missing'),
        windows_deployed=lambda: get_pm_patches_count('Windows', status='Installed'),
        linux_deployed=lambda: get_pm_patches_count('Linux', status='Installed'),
        # Success rate: fetch succeeded and failed job counts from API
        win_pm_succeeded=lambda: get_pm_jobs('Windows', 100, status='Completed'),
        win_pm_failed=lambda: get_pm_jobs('Windows', 100, status='Failed'),
        lin_pm_succeeded=lambda: get_pm_jobs('Linux', 100, status='Completed'),
        lin_pm_failed=lambda: get_pm_jobs('Linux', 100, status='Failed'),
        win_mtg_succeeded=lambda: get_mtg_jobs('Windows', 100, status='Completed'),
        win_mtg_failed=lambda: get_mtg_jobs('Windows', 100, status='Failed'),
        lin_mtg_succeeded=lambda: get_mtg_jobs('Linux', 100, status='Completed'),
        lin_mtg_failed=lambda: get_mtg_jobs('Linux', 100, status='Failed'),
        # Mitigation catalog for technique breakdown
        etm_mitigations=lambda: get_etm_mitigations(100),
    )

    all_empty = all(
        not concurrent.get(k)
        for k in ('windows_pm_jobs', 'linux_pm_jobs', 'windows_mtg_jobs', 'linux_mtg_jobs',
                  'windows_patches', 'linux_patches', 'windows_assets', 'linux_assets',
                  'windows_missing', 'linux_missing', 'windows_deployed', 'linux_deployed')
    )
    if all_empty:
        return _with_meta({
            'message': (
                'Patch Management (PM) and TruRisk Mitigate (MTG) modules are not enabled '
                'on this Qualys subscription, or no deployment jobs have been configured yet. '
                'Contact your Qualys administrator to enable these modules.'
            ),
            'patchManagement': {'windows': {}, 'linux': {}},
            'mitigations': {'windows': {}, 'linux': {}},
            'patchCatalog': {},
            'summary': 'TruRisk Eliminate modules not available on this subscription.',
        })

    total_patch_jobs = 0
    total_mtg_jobs = 0
    active_patch_jobs = 0
    active_mtg_jobs = 0

    for platform in ['windows', 'linux']:
        pm_jobs = concurrent.get(f'{platform}_pm_jobs') or []
        patch_jobs = [j for j in pm_jobs if j.get('subCategory') == 'Patch']
        total_patch_jobs += len(patch_jobs)

        active = [j for j in patch_jobs if j.get('status') not in ('Disabled', 'Deleted')]
        active_patch_jobs += len(active)

        by_status = {}
        for j in patch_jobs:
            s = j.get('status', 'Unknown')
            by_status[s] = by_status.get(s, 0) + 1

        recent_jobs = []
        for j in patch_jobs[:10]:
            job_info = {
                'name': j.get('name', ''),
                'status': j.get('status', ''),
                'schedule': j.get('scheduleType', ''),
                'assets': j.get('applicableAssetCount') or j.get('assetCount') or 0,
                'completion': j.get('completionPercent'),
            }
            if j.get('subCategory') == 'Patch':
                job_info['patches'] = j.get('patchCount', 0)
            recent_jobs.append(job_info)

        pm_assets = concurrent.get(f'{platform}_assets') or []
        result['patchManagement'][platform] = {
            'total': len(patch_jobs),
            'active': len(active),
            'byStatus': by_status,
            'recentJobs': recent_jobs,
            'managedAssets': len(pm_assets),
        }

        mtg_jobs = concurrent.get(f'{platform}_mtg_jobs') or []
        total_mtg_jobs += len(mtg_jobs)

        mtg_active = [j for j in mtg_jobs if j.get('status') not in ('Disabled', 'Deleted')]
        active_mtg_jobs += len(mtg_active)

        mtg_by_status = {}
        for j in mtg_jobs:
            s = j.get('status', 'Unknown')
            mtg_by_status[s] = mtg_by_status.get(s, 0) + 1

        mtg_recent = []
        for j in mtg_jobs[:10]:
            mtg_recent.append({
                'name': j.get('name', ''),
                'status': j.get('status', ''),
                'schedule': j.get('scheduleType', ''),
                'assets': j.get('applicableAssetCount') or j.get('assetCount') or 0,
                'mitigationActions': j.get('mitigationActionCount', 0),
                'completion': j.get('completionPercent'),
            })

        result['mitigations'][platform] = {
            'total': len(mtg_jobs),
            'active': len(mtg_active),
            'byStatus': mtg_by_status,
            'recentJobs': mtg_recent,
        }

    # -- Patch catalog --
    win_patches = concurrent.get('windows_patches') or {}
    linux_patches = concurrent.get('linux_patches') or {}
    win_sev = win_patches.get('vendorSeverity', {})
    linux_count = linux_patches.get('patches', {}).get('count', 0)
    result['patchCatalog'] = {
        'windows': {
            'total': sum(win_sev.values()) if win_sev else win_patches.get('patches', {}).get('count', 0),
            'bySeverity': win_sev,
        },
        'linux': {'total': linux_count},
    }

    total_catalog = result['patchCatalog']['windows']['total'] + result['patchCatalog']['linux']['total']

    def _extract_count(data):
        if isinstance(data, dict):
            return data.get('patches', {}).get('count', 0) if 'patches' in data else 0
        return 0

    win_missing = _extract_count(concurrent.get('windows_missing') or {})
    lin_missing = _extract_count(concurrent.get('linux_missing') or {})
    win_deployed = _extract_count(concurrent.get('windows_deployed') or {})
    lin_deployed = _extract_count(concurrent.get('linux_deployed') or {})

    result['patchCounts'] = {
        'missing': {'windows': win_missing, 'linux': lin_missing, 'total': win_missing + lin_missing},
        'deployed': {'windows': win_deployed, 'linux': lin_deployed, 'total': win_deployed + lin_deployed},
    }

    total_missing = win_missing + lin_missing
    total_deployed = win_deployed + lin_deployed

    # -- Pre-calculated deployment success rate --
    pm_succeeded = len(concurrent.get('win_pm_succeeded') or []) + len(concurrent.get('lin_pm_succeeded') or [])
    pm_failed = len(concurrent.get('win_pm_failed') or []) + len(concurrent.get('lin_pm_failed') or [])
    mtg_succeeded = len(concurrent.get('win_mtg_succeeded') or []) + len(concurrent.get('lin_mtg_succeeded') or [])
    mtg_failed = len(concurrent.get('win_mtg_failed') or []) + len(concurrent.get('lin_mtg_failed') or [])

    pm_total_completed = pm_succeeded + pm_failed
    mtg_total_completed = mtg_succeeded + mtg_failed
    all_completed = pm_total_completed + mtg_total_completed
    all_succeeded = pm_succeeded + mtg_succeeded

    result['deploymentSuccessRate'] = {
        'patch': {
            'succeeded': pm_succeeded,
            'failed': pm_failed,
            'total': pm_total_completed,
            'rate': f"{(pm_succeeded / pm_total_completed * 100):.1f}%" if pm_total_completed else 'N/A',
        },
        'mitigation': {
            'succeeded': mtg_succeeded,
            'failed': mtg_failed,
            'total': mtg_total_completed,
            'rate': f"{(mtg_succeeded / mtg_total_completed * 100):.1f}%" if mtg_total_completed else 'N/A',
        },
        'overall': {
            'succeeded': all_succeeded,
            'failed': pm_failed + mtg_failed,
            'total': all_completed,
            'rate': f"{(all_succeeded / all_completed * 100):.1f}%" if all_completed else 'N/A',
        },
    }

    # -- Technique breakdown from mitigation catalog --
    etm_mits = concurrent.get('etm_mitigations') or []
    technique_counts = {}
    for m in etm_mits:
        technique = m.get('techniqueType') or m.get('technique_type') or m.get('type') or 'UNKNOWN'
        technique = technique.upper()
        technique_counts[technique] = technique_counts.get(technique, 0) + 1
    result['techniqueBreakdown'] = {
        'byType': technique_counts,
        'total': len(etm_mits),
    }

    # -- SLA summary: how many completed jobs finished within 30d / 60d of creation --
    sla_within_30 = sla_within_60 = sla_over_30 = sla_over_60 = 0
    for platform in ['windows', 'linux']:
        for job_key in (f'{platform}_pm_jobs', f'{platform}_mtg_jobs'):
            for j in (concurrent.get(job_key) or []):
                status = (j.get('status') or '').lower()
                if status not in ('completed', 'failed'):
                    continue
                created = j.get('createdDate') or j.get('created') or ''
                completed = j.get('completedDate') or j.get('lastExecutedDate') or j.get('updatedDate') or ''
                if not created or not completed:
                    continue
                try:
                    c_dt = datetime.fromisoformat(str(created).replace('Z', '+00:00'))
                    d_dt = datetime.fromisoformat(str(completed).replace('Z', '+00:00'))
                    elapsed = (d_dt - c_dt).days
                except (ValueError, TypeError):
                    continue
                if elapsed <= 30:
                    sla_within_30 += 1
                elif elapsed <= 60:
                    sla_within_60 += 1
                if elapsed > 30:
                    sla_over_30 += 1
                if elapsed > 60:
                    sla_over_60 += 1

    result['slaSummary'] = {
        'within_30d': sla_within_30,
        'within_60d': sla_within_30 + sla_within_60,
        'overdue_30d': sla_over_30,
        'overdue_60d': sla_over_60,
    }

    # -- Summary --
    success_str = result['deploymentSuccessRate']['overall']['rate']
    technique_str = ', '.join(f'{t}: {c}' for t, c in sorted(technique_counts.items())) if technique_counts else 'none loaded'

    result['summary'] = (
        f'TruRisk Eliminate: {total_patch_jobs} patch jobs ({active_patch_jobs} active), '
        f'{total_mtg_jobs} mitigation jobs ({active_mtg_jobs} active). '
        f'Deployment success rate: {success_str} ({all_succeeded}/{all_completed} completed jobs). '
        f'Patch catalog: {total_catalog:,} patches available. '
        f'Patches deployed: {total_deployed:,}, missing: {total_missing:,}. '
        f'Mitigation catalog: {len(etm_mits)} techniques ({technique_str}). '
        f'SLA: {sla_within_30} jobs within 30d, {sla_over_30} overdue >30d, {sla_over_60} overdue >60d. '
        f'Use Patch to eliminate risk by deploying fixes. '
        f'Use Mitigate to apply compensating controls when no patch exists.'
    )

    result = _with_meta(result)
    return _apply_detail_level(result, detail)


def eliminate_coverage(qids: list = None, cves: list = None, detail: str = "standard") -> dict:
    """Check which QIDs or CVEs have Eliminate mitigations available in the catalog."""
    if not qids and not cves:
        return _with_meta({'error': 'Provide at least one QID or CVE.', 'coverage': []})

    # Fetch mitigation catalog and KB data concurrently
    tasks = {'etm_mitigations': lambda: get_etm_mitigations(200)}
    lookup_qids = list(qids or [])

    # If CVEs provided, resolve them to QIDs via KB
    if cves:
        # Get recent detections to find QIDs for these CVEs
        tasks['detections'] = lambda: get_detections(severity=3, days=90)

    concurrent = _run_concurrent(**tasks)
    etm_mits = concurrent.get('etm_mitigations') or []

    # Build mitigation lookup by QID and CVE
    mit_by_qid = {}
    mit_by_cve = {}
    for m in etm_mits:
        m_qids = m.get('qids') or m.get('qidList') or []
        if isinstance(m_qids, int):
            m_qids = [m_qids]
        m_cves = m.get('cves') or m.get('cveList') or []
        if isinstance(m_cves, str):
            m_cves = [m_cves]
        technique = (m.get('techniqueType') or m.get('technique_type') or m.get('type') or 'UNKNOWN').upper()
        entry = {
            'name': m.get('name') or m.get('title') or '',
            'technique': technique,
            'qids': m_qids,
            'cves': m_cves,
        }
        for q in m_qids:
            mit_by_qid.setdefault(q, []).append(entry)
        for c in m_cves:
            mit_by_cve.setdefault(c.upper(), []).append(entry)

    # If CVEs given, resolve to QIDs from detection data
    cve_to_qid = {}
    if cves:
        dets = concurrent.get('detections') or []
        all_det_qids = list({d.get('qid') for d in dets if d.get('qid')})
        kb_data = get_kb_batch(all_det_qids[:300]) if all_det_qids else {}
        for qid, kb in kb_data.items():
            for c in kb.get('cves', []):
                cve_to_qid.setdefault(c.upper(), set()).add(qid)

    coverage = []
    covered_count = 0

    # Check QIDs
    for q in (qids or []):
        mits = mit_by_qid.get(q, [])
        entry = {'qid': q, 'hasMitigation': bool(mits), 'mitigations': mits}
        if mits:
            covered_count += 1
        coverage.append(entry)

    # Check CVEs
    for c in (cves or []):
        c_upper = c.upper()
        mits = mit_by_cve.get(c_upper, [])
        resolved_qids = list(cve_to_qid.get(c_upper, set()))
        # Also check QID-based mitigations for resolved QIDs
        if not mits and resolved_qids:
            for rq in resolved_qids:
                mits.extend(mit_by_qid.get(rq, []))
        entry = {'cve': c_upper, 'hasMitigation': bool(mits), 'resolvedQids': resolved_qids, 'mitigations': mits}
        if mits:
            covered_count += 1
        coverage.append(entry)

    total_requested = len(qids or []) + len(cves or [])
    result = {
        'coverage': coverage,
        'summary': {
            'requested': total_requested,
            'covered': covered_count,
            'notCovered': total_requested - covered_count,
            'coverageRate': f"{(covered_count / total_requested * 100):.1f}%" if total_requested else 'N/A',
        },
        'catalogSize': len(etm_mits),
    }

    result = _with_meta(result, 'coverage', total_requested)
    return _apply_detail_level(result, detail, list_keys=['coverage'])


def scanner_health(detail: str = "standard") -> dict:
    result = {
        'scanners': [],
        'scanStatus': {},
        'summary': '',
    }

    concurrent = _run_concurrent(
        scanners=lambda: get_scanner_list(),
        active_scans=lambda: get_scan_list('Running,Paused,Queued', 100),
        error_scans=lambda: get_scan_list('Error', 50),
    )

    scanners = concurrent.get('scanners') or []
    active_scans = concurrent.get('active_scans') or []
    error_scans = concurrent.get('error_scans') or []

    online = 0
    offline = 0
    outdated_sigs = 0
    total_capacity = 0
    total_running = 0

    for s in scanners:
        status = s.get('status', '').lower()
        if status == 'online':
            online += 1
        else:
            offline += 1

        running = s.get('runningScanCount', 0)
        capacity = s.get('maxCapacity', 0)
        total_running += running
        total_capacity += capacity

        sigs_outdated = (s.get('vulnsigsVersion', '') != s.get('vulnsigsLatest', '') and s.get('vulnsigsLatest', ''))

        if sigs_outdated:
            outdated_sigs += 1

        scanner_info = {
            'name': s.get('name', ''),
            'status': s.get('status', ''),
            'runningScanCount': running,
            'maxCapacity': capacity,
            'heartbeatsMissed': s.get('heartbeatsMissed', 0),
            'lastUpdated': short_date(s.get('lastUpdated', '')),
        }
        if sigs_outdated:
            scanner_info['vulnsigsOutdated'] = True
            scanner_info['vulnsigsVersion'] = s.get('vulnsigsVersion', '')
            scanner_info['vulnsigsLatest'] = s.get('vulnsigsLatest', '')
        result['scanners'].append(scanner_info)

    result['scanners'].sort(key=lambda x: (x['status'] != 'Online', -x['runningScanCount']))

    scan_states = {}
    for s in active_scans + error_scans:
        state = s.get('state', 'Unknown')
        scan_states[state] = scan_states.get(state, 0) + 1

    result['scanStatus'] = {
        'byState': scan_states,
        'errorScans': [{
            'title': s.get('title', ''),
            'launched': short_date(s.get('launched', '')),
            'scanner': s.get('scannerName', ''),
        } for s in error_scans[:10]],
        'activeScans': [{
            'title': s.get('title', ''),
            'state': s.get('state', ''),
            'scanner': s.get('scannerName', ''),
        } for s in active_scans[:10]],
    }

    utilization = round(total_running / total_capacity * 100, 1) if total_capacity > 0 else 0

    error_count = scan_states.get('Error', 0)
    running_count = scan_states.get('Running', 0)
    queued_count = scan_states.get('Queued', 0)

    warnings = []
    if offline > 0:
        warnings.append(f'{offline} scanner(s) offline')
    if outdated_sigs > 0:
        warnings.append(f'{outdated_sigs} scanner(s) with outdated vulnerability signatures')
    if error_count > 10:
        warnings.append(f'{error_count} failed scans')
    if utilization > 80:
        warnings.append(f'scanner utilization at {utilization}%')

    result['summary'] = (
        f'{online} scanner(s) online, {offline} offline. '
        f'{running_count} scans running, {queued_count} queued, {error_count} errors. '
        f'Capacity utilization: {utilization}%. '
        + (f'Warnings: {"; ".join(warnings)}.' if warnings else 'No warnings.')
    )

    result = _with_meta(result, 'scanners')
    return _apply_detail_level(result, detail, list_keys=['scanners'])


def etm_findings(qql: str = "", report_id: str = "", detail: str = "standard") -> dict:
    global ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    now = datetime.now(timezone.utc)
    import re

    severities = [3, 4, 5]
    cve_filter = None
    qid_filter = None
    patch_filter = None

    if qql:
        sev_match = re.search(r'vulnerabilities\.vulnerability\.severity[:\s]*(\d)', qql)
        if sev_match:
            severities = [int(sev_match.group(1))]
        cve_match = re.search(r'vulnerabilities\.vulnerability\.cveIds[:\s]*(CVE-[\d-]+)', qql, re.IGNORECASE)
        if cve_match:
            cve_filter = cve_match.group(1).upper()
        qid_match = re.search(r'vulnerabilities\.vulnerability\.qid[:\s]*(\d+)', qql)
        if qid_match:
            qid_filter = int(qid_match.group(1))
        if 'ispatchavailable:true' in qql.lower().replace(' ', ''):
            patch_filter = True

    if not qql and ETM_RESULT_CACHE is not None and ETM_RESULT_CACHE_TIME:
        age = (now - ETM_RESULT_CACHE_TIME).total_seconds()
        if age < 3600:
            _log(f"ETM result cache hit (age {int(age)}s)")
            cached = dict(ETM_RESULT_CACHE)
            cached['cacheAge'] = int(age)
            return compact(cached)

    # L2 disk cache check for ETM (no qql filter only)
    if not qql:
        from qualys.cache import disk_cache, TTL_ETM as DISK_TTL_ETM
        _ETM_DISK_KEY = "etm_result"
        disk_hit = disk_cache.get(_ETM_DISK_KEY)
        if disk_hit is not None:
            ETM_RESULT_CACHE = disk_hit
            ETM_RESULT_CACHE_TIME = now
            _log("Disk cache hit for etm_result")
            cached = dict(disk_hit)
            cached['cacheAge'] = 0
            return compact(cached)

    all_dets = []
    for sev in severities:
        dets = get_detections(severity=sev, days=30)
        all_dets.extend(dets)

    if not all_dets:
        result = {
            'findings': [],
            'reportStatus': 'COMPLETED',
            'summary': {'totalFindings': 0, 'uniqueAssets': 0, 'uniqueCVEs': 0, 'patchable': 0, 'bySeverity': {}},
            'topCVEs': [],
        }
        return _with_meta(result, 'findings')

    if qid_filter:
        all_dets = [d for d in all_dets if d.get('qid') == qid_filter]

    unique_qids = list({d.get('qid', 0) for d in all_dets if d.get('qid')})
    kb_data = get_kb_batch(unique_qids[:200]) if unique_qids else {}

    filtered_dets = []
    for d in all_dets:
        kb = kb_data.get(d.get('qid', 0)) or {}
        cves = kb.get('cves', [])
        is_patchable = kb.get('patch_available', False)
        if cve_filter and cve_filter not in cves:
            continue
        if patch_filter and not is_patchable:
            continue
        filtered_dets.append((d, kb, cves, is_patchable))

    formatted = _format_vmdr_as_etm_findings(filtered_dets)

    if not qql:
        ETM_RESULT_CACHE = formatted
        ETM_RESULT_CACHE_TIME = now
        from qualys.cache import disk_cache, TTL_ETM as DISK_TTL_ETM
        disk_cache.set("etm_result", formatted, DISK_TTL_ETM)

    result = _with_meta(formatted, 'findings', formatted.get('totalFindings', len(formatted.get('findings', []))))
    return _apply_detail_level(result, detail, list_keys=['findings', 'topCVEs'])


def morning_report(quick: bool = False, detail: str = "standard") -> dict:
    if quick:
        concurrent = _run_concurrent(
            total=lambda: csam_count(),
            windows=lambda: csam_count([{"field": "operatingSystem.name", "operator": "CONTAINS", "value": "Windows"}]),
            linux=lambda: csam_count([{"field": "operatingSystem.name", "operator": "CONTAINS", "value": "Linux"}]),
            macos=lambda: csam_count([{"field": "operatingSystem.name", "operator": "CONTAINS", "value": "Mac"}]),
            cloud_aws=lambda: csam_count([{"field": "cloud.provider", "operator": "EQUALS", "value": "AWS"}]),
            cloud_azure=lambda: csam_count([{"field": "cloud.provider", "operator": "EQUALS", "value": "AZURE"}]),
            cloud_gcp=lambda: csam_count([{"field": "cloud.provider", "operator": "EQUALS", "value": "GCP"}]),
            eol_os=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
            eol_hw=lambda: csam_count([{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
            crit_high=lambda: csam_count([{"field": "asset.criticalityScore", "operator": "GREATER", "value": "7"}]),
            crit_med=lambda: csam_count([{"field": "asset.criticalityScore", "operator": "GREATER", "value": "4"}]),
        )
        total = concurrent.get('total') or 0
        windows = concurrent.get('windows') or 0
        linux = concurrent.get('linux') or 0
        macos = concurrent.get('macos') or 0
        aws = concurrent.get('cloud_aws') or 0
        azure = concurrent.get('cloud_azure') or 0
        gcp = concurrent.get('cloud_gcp') or 0
        cloud_total = aws + azure + gcp
        crit_high = concurrent.get('crit_high') or 0
        crit_med = concurrent.get('crit_med') or 0
        snap = {
            'report': 'Environment Snapshot',
            'totalAssets': total,
            'byOS': {'Windows': windows, 'Linux': linux, 'macOS': macos, 'Other': max(0, total - windows - linux - macos)},
            'byCloud': {'AWS': aws, 'Azure': azure, 'GCP': gcp, 'OnPrem': max(0, total - cloud_total)},
            'eolCounts': {'eolOS': concurrent.get('eol_os') or 0, 'eolHardware': concurrent.get('eol_hw') or 0},
            'byCriticality': {'high_8to10': crit_high, 'medium_5to7': max(0, crit_med - crit_high), 'low_1to4': max(0, total - crit_med)},
            'summary': (
                f"{total} total assets. "
                f"OS: {windows} Windows, {linux} Linux, {macos} macOS. "
                f"Cloud: {aws} AWS, {azure} Azure, {gcp} GCP, {max(0, total - cloud_total)} on-prem. "
                f"EOL: {concurrent.get('eol_os') or 0} OS, {concurrent.get('eol_hw') or 0} hardware. "
                f"Criticality: {crit_high} high-criticality assets."
            ),
            '_meta': {'returned': 1, 'total': 1, 'truncated': False},
        }
        gaps = _detect_gaps(snap)
        if gaps:
            snap['_gaps'] = gaps
        _track_usage('get_morning_report', {'quick': True},
                     {'gaps_found': len(gaps), 'next_suggestions': 0})
        return _apply_detail_level(compact(snap), detail)

    result = {'report': 'Daily Security Briefing', 'environment': {},
              'newVulns': {}, 'threats': {}, 'topRiskAssets': [],
              'actionItems': [], 'truriskTrend': {}}

    concurrent = _run_concurrent(
        posture=lambda: get_security_posture(),
        priorities=lambda: weekly_priorities(),
        new_vulns=lambda: search_vulns_agg(days=1),
        trurisk_now=lambda: csam_search(limit=100, fields="truRisk"),
    )

    posture = concurrent.get('posture') or {}
    result['environment'] = {
        'healthScore': posture.get('healthScore', 0),
        'totalAssets': (posture.get('assets') or {}).get('total', 0),
        'highRiskAssets': (posture.get('assets') or {}).get('highRisk', 0),
        'eolSystems': (posture.get('vulns') or {}).get('eolSystems', 0),
        'containersAtRisk': (posture.get('containers') or {}).get('atRisk', 0),
        'cloudAccounts': (posture.get('cloud') or {}).get('accounts', 0),
    }

    new = concurrent.get('new_vulns') or {}
    sb = new.get('severityBreakdown') or {}
    result['newVulns'] = {
        'total': new.get('totalVulns', 0),
        'critical': sb.get('critical', 0),
        'high': sb.get('high', 0),
        'medium': sb.get('medium', 0),
        'withPatch': new.get('withPatch', 0),
        'withThreatIntel': new.get('withThreatIntel', 0),
    }

    all_new_vulns = new.get('vulns') or []
    def _count_threat(vulns, tag):
        tag_lower = tag.lower()
        return sum(1 for v in vulns if any(tag_lower in t.lower() for t in v.get('threat_intel', [])))
    result['threats'] = {
        'ransomwareLinked': _count_threat(all_new_vulns, 'Ransomware'),
        'activelyExploited': _count_threat(all_new_vulns, 'Active_Attacks'),
        'cisaKev': _count_threat(all_new_vulns, 'Cisa_Known_Exploited_Vulns'),
    }

    critical_new = []
    for v in (new.get('vulns') or []):
        if v['severity'] >= 5 and len(critical_new) < 10:
            critical_new.append({
                'qid': v['qid'],
                'title': v['title'],
                'qds': v.get('qds', 0),
                'cvss_v3': v.get('cvss_v3'),
                'cvss_v3_vector': v.get('cvss_v3_vector', ''),
                'cves': v.get('cves', []),
                'patchAvailable': v.get('patchAvailable', False),
                'has_exploit': v.get('has_exploit', False),
                'threatIntel': v.get('threatIntel', []),
                'ransomware': v.get('ransomware', False),
            })
    result['newVulns']['criticalVulns'] = critical_new

    priorities_data = concurrent.get('priorities') or {}
    result['topRiskAssets'] = (priorities_data.get('topRiskAssets') or [])[:5]
    result['actionItems'] = priorities_data.get('priorities') or []

    now_assets = concurrent.get('trurisk_now') or []
    if now_assets:
        avg_now = sum(int(a.get('riskScore') or 0) for a in now_assets) / len(now_assets)
        delta = 0
        if delta < -5:
            direction = 'improving'
            arrow = '\u2193'
        elif delta > 5:
            direction = 'worsening'
            arrow = '\u2191'
        else:
            direction = 'stable'
            arrow = '\u2192'
        result['truriskTrend'] = {
            'current': round(avg_now),
            'direction': direction,
            'display': f"TruRisk: {round(avg_now)} {arrow} {direction}",
            'delta': round(delta),
        }

    followups = []
    new_total = result.get('newVulns', {}).get('total', 0)
    new_crit = result.get('newVulns', {}).get('critical', 0)
    if new_crit:
        followups.append(f"{new_crit} new critical vulnerabilities in last 24h \u2014 investigate top CVEs with investigate_cve()?")
    ransomware_count = result.get('threats', {}).get('ransomwareLinked', 0)
    if ransomware_count:
        followups.append(f"{ransomware_count} ransomware-linked vulnerabilities detected \u2014 investigate('ransomware') for full exposure?")
    trend = result.get('truriskTrend', {})
    if trend.get('direction') == 'worsening':
        delta_val = trend.get('delta', 0)
        followups.append(f"TruRisk score changed {delta_val:+d} vs last week \u2014 investigate('risk spike') for drivers?")
    eol = result.get('environment', {}).get('eolSystems', 0)
    if eol:
        followups.append(f"{eol} EOL systems in environment \u2014 get_tech_debt() for full inventory?")
    top_assets = result.get('topRiskAssets', [])
    if top_assets:
        worst = top_assets[0]
        followups.append(f"Top risk asset: {worst.get('hostname', '?')} (TruRisk {worst.get('riskScore', '?')}) \u2014 get_asset('{worst.get('assetId', '')}', detail='full')?")
    result['_followups'] = followups

    gaps = _detect_gaps(result)
    if gaps:
        result['_gaps'] = gaps
    result['_next'] = _build_next(result, 'get_morning_report')
    _track_usage('get_morning_report', {'quick': False},
                 {'gaps_found': len(gaps), 'next_suggestions': len(result['_next'].get('investigate_deeper', []))})

    result = _with_meta(result, 'topRiskAssets')
    return _apply_detail_level(result, detail, list_keys=['topRiskAssets', 'actionItems'])


def cve_details(cves: str, detail: str = "standard") -> dict:
    cve_list = [c.strip() for c in cves.split(',') if c.strip()]
    result = {'requested': len(cve_list), 'found': 0, 'cves': []}

    def fetch_cve(cve):
        qids = get_cve_qids(cve)
        if not qids:
            return {'cve': cve, 'found': False}
        kb_data = get_kb_batch(qids[:20])
        qds_scores = get_qds_for_qids(qids[:20])
        max_sev = 0
        best = None
        best_qid = None
        all_threat_intel = set()
        is_ransomware = False
        all_kb = []
        for qid in qids:
            kb = kb_data.get(qid)
            if kb:
                real_qds = qds_scores.get(qid, 0)
                if kb.get('severity', 0) > max_sev:
                    max_sev = kb['severity']
                    best = kb
                    best_qid = qid
                all_threat_intel.update(kb.get('threat_intel', []))
                if kb.get('ransomware'):
                    is_ransomware = True
                kb_title = kb.get('title', '')
                if detail != "detailed":
                    kb_title = kb_title[:80]
                all_kb.append({
                    'qid': qid,
                    'title': kb_title,
                    'severity': kb.get('severity', 0),
                    'qds': real_qds or kb.get('qds', 0),
                    'cvss_v3': kb.get('cvss_v3'),
                    'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                    'patchAvailable': kb.get('patch_available', False),
                    'has_exploit': kb.get('has_exploit', False),
                })
        best_qds = qds_scores.get(best_qid, 0) if best_qid else 0
        if detail == "detailed":
            sol = best.get('solution', '') if best else ''
            diag = best.get('diagnosis', '') if best else ''
        else:
            sol = (best.get('solution', '') if best else '')[:120]
            diag = (best.get('diagnosis', '') if best else '')[:120]
        entry = {
            'cve': cve, 'found': True, 'qids': qids,
            'severity': max_sev,
            'qds': best_qds or (best.get('qds', 0) if best else 0),
            'qds_factors': best.get('qds_factors', '') if best else '',
            'cvss_v3': best.get('cvss_v3') if best else None,
            'cvss_v3_temporal': best.get('cvss_v3_temporal') if best else None,
            'cvss_v3_vector': (best.get('cvss_v3_vector', '') if best else ''),
            'title': best.get('title', '') if best else '',
            'patchAvailable': best.get('patch_available', False) if best else False,
            'has_exploit': best.get('has_exploit', False) if best else False,
            'solution': sol,
            'diagnosis': diag,
            'threatIntel': sorted(all_threat_intel),
            'ransomware': is_ransomware,
            'kbEntries': all_kb,
        }
        return entry

    tasks = {cve: (lambda c=cve: fetch_cve(c)) for cve in cve_list[:20]}
    fetched = _run_concurrent(**tasks)

    for cve in cve_list[:20]:
        entry = fetched.get(cve)
        if entry:
            if entry.get('found'):
                result['found'] += 1
            result['cves'].append(entry)

    result['cves'].sort(key=lambda x: (-x.get('severity', 0), x['cve']))
    result = _with_meta(result, 'cves')
    return _apply_detail_level(result, detail, list_keys=['cves'])


def qid_details(qids: str, detail: str = "standard") -> dict:
    qid_list = []
    for q in qids.split(','):
        q = q.strip()
        if q.isdigit():
            qid_list.append(int(q))
    if not qid_list:
        return compact({'error': 'No valid QIDs provided', 'requested': 0, 'found': 0, 'qids': []})

    result = {'requested': len(qid_list), 'found': 0, 'qids': []}

    concurrent = _run_concurrent(
        kb=lambda: get_kb_batch(qid_list[:50]),
        qds=lambda: get_qds_for_qids(qid_list[:50]),
    )
    kb_data = concurrent.get('kb') or {}
    qds_scores = concurrent.get('qds') or {}

    for qid in qid_list[:50]:
        kb = kb_data.get(qid)
        if kb:
            real_qds = qds_scores.get(qid, 0)
            result['found'] += 1
            if detail == "detailed":
                title_display = kb.get('title', '')
                sol_display = kb.get('solution', '')
                diag_display = kb.get('diagnosis', '')
            else:
                title_display = kb.get('title', '')[:80]
                sol_display = kb.get('solution', '')[:120]
                diag_display = kb.get('diagnosis', '')[:120]
            result['qids'].append({
                'qid': qid,
                'title': title_display,
                'severity': kb.get('severity', 0),
                'qds': real_qds or kb.get('qds', 0),
                'qds_factors': kb.get('qds_factors', ''),
                'cvss_v3': kb.get('cvss_v3'),
                'cvss_v3_temporal': kb.get('cvss_v3_temporal'),
                'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                'cves': kb.get('cves', []),
                'patchAvailable': kb.get('patch_available', False),
                'has_exploit': kb.get('has_exploit', False),
                'solution': sol_display,
                'diagnosis': diag_display,
                'threatIntel': kb.get('threat_intel', []),
                'ransomware': kb.get('ransomware', False),
            })
        else:
            result['qids'].append({'qid': qid, 'found': False})

    result['qids'].sort(key=lambda x: (-x.get('severity', 0), -x.get('qds', 0)))
    result = _with_meta(result, 'qids')
    return _apply_detail_level(result, detail, list_keys=['qids'])


def cloud_account_summary(provider: str = 'all', detail: str = "standard") -> dict:
    """Per-account evaluation counts across all cloud providers. Fast (pageSize=1 per account)."""
    from qualys.cache import disk_cache, TTL_CLOUD
    cache_key = f"cloud_account_summary_{provider}"
    cached = disk_cache.get(cache_key)
    if cached is not None:
        _log("cloud_account_summary: disk cache hit")
        cached = dict(cached)
        cached['cacheAge'] = disk_cache.age(cache_key) or 0
        return compact(cached)

    providers = ['aws', 'azure', 'gcp', 'oci'] if provider == 'all' else [provider.lower()]
    acc_key_map = {'aws': 'awsAccountId', 'azure': 'azureSubscriptionId', 'gcp': 'gcpProjectId', 'oci': 'ociTenancyId'}

    # Fetch connectors + OCI asset count (OCI has no connector API)
    conn_tasks = {p: (lambda p=p: get_connectors(p, 50)) for p in providers if p != 'oci'}
    if 'oci' in providers:
        conn_tasks['oci_assets'] = lambda: csam_count([{"field": "cloud.provider", "operator": "EQUALS", "value": "OCI"}])
    conn_results = _run_concurrent(**conn_tasks)

    # Build account list
    accounts = []
    for p in providers:
        if p == 'oci':
            oci_count = conn_results.get('oci_assets') or 0
            if oci_count > 0:
                accounts.append({'id': 'oci-tenant', 'provider': 'OCI', 'name': f'OCI ({oci_count} assets)'})
            continue
        conns = conn_results.get(p) or []
        acc_key = acc_key_map.get(p, 'awsAccountId')
        for c in conns:
            acc_id = c.get(acc_key, '')
            if acc_id:
                accounts.append({'id': acc_id, 'provider': p, 'name': c.get('name', '')})

    if not accounts:
        return compact({'accounts': [], 'message': 'No cloud connectors configured.', '_meta': {'returned': 0, 'total': 0, 'truncated': False}})

    # Fetch total and failed eval counts concurrently (pageSize=1 for speed)
    count_tasks = {}
    for a in accounts:
        key_total = f"{a['provider']}_{a['id']}_total"
        key_fail = f"{a['provider']}_{a['id']}_fail"
        count_tasks[key_total] = (lambda a=a: get_evaluation_count(a['id'], a['provider'], filter_str=''))
        count_tasks[key_fail] = (lambda a=a: get_evaluation_count(a['id'], a['provider'], filter_str='result:FAIL'))
    count_results = _run_concurrent(**count_tasks)

    ranked = []
    for a in accounts:
        key_total = f"{a['provider']}_{a['id']}_total"
        key_fail = f"{a['provider']}_{a['id']}_fail"
        total_counts = count_results.get(key_total)
        fail_counts = count_results.get(key_fail)
        total = total_counts.get('total', 0) if total_counts else 0
        failed = fail_counts.get('total', 0) if fail_counts else 0
        fail_rate = round(failed / total, 3) if total > 0 else 0.0
        ranked.append({
            'accountId': a['id'],
            'provider': a['provider'].upper(),
            'name': a['name'],
            'totalEvaluations': total,
            'failedEvaluations': failed,
            'failRate': fail_rate,
        })

    ranked.sort(key=lambda x: -x['failedEvaluations'])

    # For top 5 accounts by failedEvaluations, fetch top failed controls
    top5 = [a for a in ranked if a['failedEvaluations'] > 0][:5]
    if top5:
        # Find provider info for top accounts
        acct_provider = {a['id']: a['provider'].lower() for a in accounts}
        ctrl_tasks = {
            f"ctrls_{r['accountId']}": (lambda r=r: get_evaluations_filtered(
                r['accountId'], acct_provider.get(r['accountId'], 'aws'),
                limit=10, filter_str='result:FAIL'))
            for r in top5
        }
        ctrl_results = _run_concurrent(**ctrl_tasks)
        top5_ids = {r['accountId'] for r in top5}
        for r in ranked:
            if r['accountId'] not in top5_ids:
                continue
            evals = ctrl_results.get(f"ctrls_{r['accountId']}") or []
            # Sort by failedResources desc and extract top 3 unique control names
            evals.sort(key=lambda e: -(e.get('failedResources', 0) or 0))
            seen = set()
            top_controls = []
            for e in evals:
                name = e.get('controlName', '')
                if name and name not in seen:
                    seen.add(name)
                    top_controls.append(name)
                if len(top_controls) >= 3:
                    break
            r['topFailedControls'] = top_controls

    result = {
        'accounts': ranked,
        'totalAccounts': len(ranked),
        '_meta': {'returned': len(ranked), 'total': len(ranked), 'truncated': False},
        '_followups': [
            f"{len(ranked)} cloud accounts found — ranked by failed evaluations (fail rates included). Use get_cloud_controls(provider, service, account_id) to drill into specific services.",
        ],
    }
    result = compact(result)
    disk_cache.set(cache_key, result, TTL_CLOUD)
    return _apply_detail_level(result, detail, list_keys=['accounts'])


def cloud_controls(provider: str = 'all', service: str = '', result_filter: str = 'FAIL',
                   account_id: str = '', limit: int = 50, detail: str = "standard") -> dict:
    """Service-level cloud control evaluations with filtering (S3, IAM, EC2, etc.)."""
    from qualys.cache import disk_cache, TTL_CLOUD
    cache_key = f"cloud_controls_{provider}_{service}_{result_filter}_{account_id}_{limit}"
    cached = disk_cache.get(cache_key)
    if cached is not None:
        _log("cloud_controls: disk cache hit")
        cached = dict(cached)
        cached['cacheAge'] = disk_cache.age(cache_key) or 0
        return compact(cached)

    providers = ['aws', 'azure', 'gcp', 'oci'] if provider == 'all' else [provider.lower()]
    acc_key_map = {'aws': 'awsAccountId', 'azure': 'azureSubscriptionId', 'gcp': 'gcpProjectId', 'oci': 'ociTenancyId'}

    # If account_id given, use it directly; otherwise discover accounts
    if account_id:
        target_accounts = [{'id': account_id, 'provider': providers[0]}]
    else:
        conn_tasks = {p: (lambda p=p: get_connectors(p, 50)) for p in providers}
        conn_results = _run_concurrent(**conn_tasks)
        target_accounts = []
        for p in providers:
            conns = conn_results.get(p) or []
            acc_key = acc_key_map.get(p, 'awsAccountId')
            for c in conns:
                acc = c.get(acc_key, '')
                if acc:
                    target_accounts.append({'id': acc, 'provider': p})

    if not target_accounts:
        return compact({'controls': [], 'message': 'No cloud accounts found.', '_meta': {'returned': 0, 'total': 0, 'truncated': False}})

    # Build filter string
    filter_str = ''
    if service:
        filter_str = f"service:{service}"

    # Fetch evaluations (use first account per provider if no account_id, to stay fast)
    seen_providers = set()
    fetch_accounts = []
    for a in target_accounts:
        if account_id or a['provider'] not in seen_providers:
            fetch_accounts.append(a)
            seen_providers.add(a['provider'])

    eval_tasks = {
        f"evals_{a['provider']}_{a['id']}": (lambda a=a, fs=filter_str: get_evaluations_filtered(a['id'], a['provider'], limit=limit * 2, filter_str=fs))
        for a in fetch_accounts
    }
    eval_results = _run_concurrent(**eval_tasks)

    controls = []
    for a in fetch_accounts:
        key = f"evals_{a['provider']}_{a['id']}"
        evals = eval_results.get(key) or []
        for e in evals:
            r = (e.get('result') or '').upper()
            if result_filter and r != result_filter.upper():
                continue
            controls.append({
                'controlId': e.get('controlId', ''),
                'controlName': (e.get('controlName', '') or '')[:120],
                'service': e.get('service', ''),
                'criticality': e.get('criticality', ''),
                'result': r,
                'failedResources': e.get('failedResources', 0),
                'passedResources': e.get('passedResources', 0),
                'accountId': a['id'],
                'provider': a['provider'].upper(),
            })

    controls.sort(key=lambda x: (-x.get('failedResources', 0), x.get('controlName', '')))
    controls = controls[:limit]

    # Service filter note
    note = ''
    if service and not controls:
        note = f"No evaluations found for service '{service}' with result={result_filter}. Try without service filter or with result_filter='PASS'."

    by_service = {}
    for c in controls:
        svc = c.get('service', 'Unknown')
        by_service[svc] = by_service.get(svc, 0) + 1
    by_service = dict(sorted(by_service.items(), key=lambda x: -x[1]))

    # Compute overall pass rate stats across returned controls
    total_failed_res = sum(c.get('failedResources', 0) for c in controls)
    total_passed_res = sum(c.get('passedResources', 0) for c in controls)
    total_res = total_failed_res + total_passed_res
    pass_rate = round(total_passed_res / total_res * 100, 1) if total_res > 0 else None
    failed_control_count = sum(1 for c in controls if c.get('result') == 'FAIL')
    passed_control_count = sum(1 for c in controls if c.get('result') == 'PASS')

    res = {
        'controls': controls,
        'byService': by_service,
        'totalReturned': len(controls),
        'passRate': pass_rate,
        'failedControlCount': failed_control_count,
        'passedControlCount': passed_control_count,
        'totalResourcesFailed': total_failed_res,
        'totalResourcesPassed': total_passed_res,
        'filters': {'provider': provider, 'service': service or 'all', 'result': result_filter, 'accountId': account_id or 'all'},
        '_meta': {'returned': len(controls), 'total': len(controls), 'truncated': False},
    }
    if note:
        res['note'] = note
    followups = []
    if controls:
        top_svc = list(by_service.keys())[:3]
        followups.append(f"Top failing services: {', '.join(top_svc)}. Drill into a specific service with get_cloud_controls(service='...').")
    res['_followups'] = followups

    res = compact(res)
    disk_cache.set(cache_key, res, TTL_CLOUD)
    return _apply_detail_level(res, detail, list_keys=['controls'])


def cloud_risk(limit: int = 20, include_threats: bool = True, days: int = 7, per_account: bool = False, detail: str = "standard") -> dict:
    result = {'accounts': [], 'failedControls': [], 'threats': [], 'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}}

    connector_results = _run_concurrent(
        aws=lambda: get_connectors('aws', 50),
        azure=lambda: get_connectors('azure', 50),
        gcp=lambda: get_connectors('gcp', 50),
        oci_assets=lambda: csam_count([{"field": "cloud.provider", "operator": "EQUALS", "value": "OCI"}]),
    )

    all_accounts = []
    first_accounts = {}

    oci_count = connector_results.pop('oci_assets', 0) or 0
    if oci_count > 0:
        result['accounts'].append({'id': 'oci-tenant', 'provider': 'OCI', 'name': f'OCI ({oci_count} assets)'})

    for provider, conns in connector_results.items():
        if not conns:
            continue
        acc_key = {'aws': 'awsAccountId', 'azure': 'azureSubscriptionId', 'gcp': 'gcpProjectId'}.get(provider, 'accountId')
        for c in conns:
            acc = c.get(acc_key, '')
            result['accounts'].append({'id': acc, 'provider': provider.upper(), 'name': c.get('name', '')})
            if acc:
                all_accounts.append({'id': acc, 'provider': provider})
        first_acc = conns[0].get(acc_key, '')
        if first_acc:
            first_accounts[provider] = first_acc

    result['stats']['total'] = len(result['accounts'])

    if not result['accounts']:
        result['message'] = 'No cloud connectors configured. Connect AWS, Azure, GCP, or OCI accounts in Qualys TotalCloud to see cloud risk data.'
        return compact(result)

    # Per-account summary: fast counts via pageSize=1 for ALL accounts
    if per_account and all_accounts:
        count_tasks = {
            f"count_{a['provider']}_{a['id']}": (lambda a=a: get_evaluation_count(a['id'], a['provider'], 'result:FAIL'))
            for a in all_accounts
        }
        count_results = _run_concurrent(**count_tasks)
        per_acct = []
        for a in all_accounts:
            key = f"count_{a['provider']}_{a['id']}"
            counts = count_results.get(key)
            total_fails = counts.get('total', 0) if counts else 0
            name = ''
            for ra in result['accounts']:
                if ra['id'] == a['id']:
                    name = ra.get('name', '')
                    break
            per_acct.append({
                'accountId': a['id'],
                'provider': a['provider'].upper(),
                'name': name,
                'failedEvaluations': total_fails,
            })
        per_acct.sort(key=lambda x: -x['failedEvaluations'])
        result['perAccount'] = per_acct

    eval_tasks = {
        f'evals_{p}': (lambda p=p, a=a: get_evaluations(a, p, min(limit * 5, 200)))
        for p, a in first_accounts.items()
    }
    if include_threats:
        eval_tasks['cdr'] = lambda: get_cdr(days, min(limit, 50))
        eval_tasks['cdr_count'] = lambda: get_cdr_count(days)
    eval_results = _run_concurrent(**eval_tasks)

    fails = {}  # {controlId: {controlName, service, count}}
    total_failed_res = 0
    total_passed_res = 0
    for p in first_accounts:
        evals = eval_results.get(f'evals_{p}') or []
        for e in evals:
            total_failed_res += e.get('failedResources', 0) or 0
            total_passed_res += e.get('passedResources', 0) or 0
            if e.get('result') in ['FAIL', 'FAILED']:
                cid = e.get('controlId', '')
                if cid not in fails:
                    fails[cid] = {
                        'controlName': e.get('controlName', '') or '',
                        'service': e.get('service', '') or '',
                        'count': 0,
                    }
                fails[cid]['count'] += 1
    result['failedControls'] = [
        {'controlId': cid, 'controlName': info['controlName'], 'service': info['service'], 'count': info['count']}
        for cid, info in sorted(fails.items(), key=lambda x: x[1]['count'], reverse=True)[:limit]
    ]
    total_res = total_failed_res + total_passed_res
    result['overallPassRate'] = round(total_passed_res / total_res * 100, 1) if total_res > 0 else None
    result['totalResourcesFailed'] = total_failed_res
    result['totalResourcesPassed'] = total_passed_res

    if include_threats:
        cdr_result = eval_results.get('cdr')
        if cdr_result == 'CDR_UNAVAILABLE':
            result['cdr_status'] = CDR_UNAVAILABLE_MSG
            findings_list = []
        else:
            findings_list = cdr_result or []
        sev_map = {'1': 'LOW', '2': 'MEDIUM', '3': 'HIGH', '4': 'CRITICAL'}
        by_provider = {}
        by_category = {}

        for f in findings_list:
            sev = str(f.get('severity', '')).upper()
            sev_label = sev_map.get(sev, sev)

            if sev_label == 'CRITICAL':
                result['stats']['critical'] += 1
            elif sev_label == 'HIGH':
                result['stats']['high'] += 1
            elif sev_label == 'MEDIUM':
                result['stats']['medium'] += 1
            elif sev_label == 'LOW':
                result['stats']['low'] += 1

            provider = f.get('cloudType', '') or f.get('cloudProvider', '') or 'Unknown'
            by_provider[provider] = by_provider.get(provider, 0) + 1

            cat = f.get('threatCategory', '') or f.get('category', '') or f.get('alertClass', '') or 'Unknown'
            by_category[cat] = by_category.get(cat, 0) + 1

            remote = f.get('remoteIpDetails', {}) or {}
            entry = {
                'severity': sev_label,
                'category': cat,
                'eventMessage': (f.get('eventMessage', '') or '')[:200],
                'resourceId': f.get('resourceId', '') or f.get('affectedResource', ''),
                'resourceType': f.get('resourceType', ''),
                'provider': provider,
                'account': f.get('cspAccount', '') or f.get('cloudAccount', ''),
                'region': f.get('cspRegion', '') or f.get('region', ''),
                'timestamp': f.get('timestamp', '') or f.get('createdAt', ''),
            }
            if remote and (remote.get('ipAddressV4') or remote.get('ip')):
                entry['remoteIp'] = {
                    'ip': remote.get('ipAddressV4', '') or remote.get('ip', ''),
                    'country': remote.get('country', ''),
                    'city': remote.get('city', ''),
                }
            result['threats'].append(entry)

        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        result['threats'].sort(key=lambda x: sev_order.get(x.get('severity', ''), 4))
        result['byProvider'] = dict(sorted(by_provider.items(), key=lambda x: -x[1]))
        result['byCategory'] = dict(sorted(by_category.items(), key=lambda x: -x[1]))

        cdr_total = eval_results.get('cdr_count') or len(findings_list)
        result['totalThreats'] = cdr_total
        crit = result['stats']['critical']
        high = result['stats']['high']
        total_threats = cdr_total
        providers_str = ', '.join(result['byProvider'].keys()) or 'none'
        top_cats = ', '.join(list(result['byCategory'].keys())[:3]) or 'none'
        result['threatSummary'] = (
            f"{total_threats} cloud threat findings in last {days} days. "
            f"{crit} critical, {high} high severity. "
            f"Providers: {providers_str}. Top categories: {top_cats}."
        )

    total_threats = len(result['threats'])
    total_controls = len(result['failedControls'])
    result['_meta'] = {
        'returned': total_threats + total_controls,
        'total': total_threats + total_controls,
        'truncated': False,
    }

    followups = []
    crit_threats = result['stats'].get('critical', 0)
    high_threats = result['stats'].get('high', 0)
    if crit_threats:
        followups.append(f"{crit_threats} critical cloud threat detections \u2014 review threats list for immediate action?")
    if high_threats:
        followups.append(f"{high_threats} high-severity cloud findings \u2014 investigate affected resources?")
    failed_controls = len(result.get('failedControls', []))
    if failed_controls:
        followups.append(f"{failed_controls} CIS benchmark controls failing \u2014 get_cloud_controls(service='S3') to drill into specific services.")
    total_accounts = result['stats'].get('total', 0)
    if total_accounts == 0:
        followups.append("No cloud accounts connected \u2014 configure cloud connectors in Qualys TotalCloud?")
    if total_accounts > 1:
        followups.append(f"{total_accounts} cloud accounts \u2014 get_cloud_account_summary() for per-account fail breakdown.")
    result['_followups'] = followups

    result = compact(result)
    return _apply_detail_level(result, detail, list_keys=['threats', 'failedControls', 'accounts', 'perAccount'])


def asset_detail(asset_id: str, detail_level: str = "summary", detail: str = "standard") -> dict:
    result = {
        'assetId': asset_id, 'riskScore': 0, 'truriskScore': 0,
        'software': [], 'eolSoftware': [],
        '_meta': {'returned': 1, 'total': 1, 'truncated': False},
    }

    if detail_level == 'full':
        asset = get_asset_by_id(asset_id)
        if not asset:
            result['_meta'] = {'returned': 0, 'total': 0, 'truncated': False}
            result['error'] = f'Asset {asset_id} not found in CSAM'
            return compact(result)

        host_id = str(asset.get('hostId') or '')
        hostname = asset.get('dnsHostName', '') or asset.get('dnsName', '') or asset.get('address', '')
        os_name = (asset.get('operatingSystem') or {}).get('osName', '')

        sw_list = asset.get('softwareListData', {}) or {}
        software = []
        eol_software = []
        for sw in (sw_list.get('software') or [])[:30]:
            name = sw.get('fullName') or sw.get('productName') or sw.get('name') or ''
            sw_info = {'name': name.strip()[:60], 'version': sw.get('version', '')}
            lifecycle = (sw.get('lifecycle') or {})
            if lifecycle.get('stage') and lifecycle['stage'] not in ('Unknown', 'Not Applicable', 'OS Dependent'):
                sw_info['lifecycleStage'] = lifecycle['stage']
                if is_eol_stage(lifecycle['stage']):
                    eol_software.append(sw_info)
            software.append(sw_info)

        result['csam'] = {
            'hostname': hostname,
            'ip': asset.get('address', ''),
            'os': os_name,
            'hostId': host_id,
            'riskScore': int(asset.get('riskScore') or 0),
            'criticality': get_criticality(asset),
            'lastSeen': short_date(asset.get('lastModifiedDate', '')),
            'software': software[:20],
            'eolSoftware': eol_software,
            'tags': [t.get('name', '') for t in (asset.get('tags') or {}).get('tag', [])[:10]],
        }
        result['riskScore'] = result['csam']['riskScore']
        result['truriskScore'] = result['csam']['riskScore']

        def _fetch_etm():
            if ETM_RESULT_CACHE:
                all_findings = ETM_RESULT_CACHE.get('findings', [])
                hn_lower = hostname.lower() if hostname else ''
                return [f for f in all_findings if
                        f.get('assetName', '').lower() == hn_lower][:50]
            return []

        def _fetch_vmdr():
            if not host_id:
                return []
            return get_host_detections(host_id, severity=4, days=30)

        parallel = _run_concurrent(etm=_fetch_etm, vmdr=_fetch_vmdr)

        etm_raw = parallel.get('etm') or []
        vmdr_raw = parallel.get('vmdr') or []

        etm_findings_list = []
        for f in etm_raw:
            etm_findings_list.append({
                'title': f.get('title', '')[:100],
                'cveId': f.get('cveId', ''),
                'severity': f.get('severity', 0),
                'qds': f.get('qds', 0),
                'isPatchAvailable': f.get('isPatchAvailable', False),
                'status': f.get('status', ''),
                'category': f.get('category', ''),
            })
        etm_findings_list.sort(key=lambda x: (-x['severity'], -x.get('qds', 0)))
        result['etmFindings'] = etm_findings_list[:30]

        vmdr_qids = list({d.get('qid', 0) for d in vmdr_raw if d.get('qid')})
        vmdr_kb = get_kb_batch(vmdr_qids[:50]) if vmdr_qids else {}
        vmdr_dets = []
        for d in vmdr_raw:
            kb = vmdr_kb.get(d.get('qid', 0)) or {}
            kb_title = kb.get('title', '')
            if detail != "detailed":
                kb_title = kb_title[:80]
            vmdr_dets.append({
                'qid': d.get('qid', 0),
                'title': kb_title,
                'severity': d.get('severity', 0),
                'qds': d.get('qds', 0) or kb.get('qds', 0),
                'cvss_v3': kb.get('cvss_v3'),
                'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                'cves': kb.get('cves', []),
                'patchAvailable': kb.get('patch_available', False),
                'has_exploit': kb.get('has_exploit', False),
                'ransomware': kb.get('ransomware', False),
                'status': d.get('status', ''),
                'firstFound': short_date(d.get('first_found', '')),
            })
        vmdr_dets.sort(key=lambda x: (-x['severity'], -x['qds']))
        result['vmdrDetections'] = vmdr_dets[:30]

        crit_etm = sum(1 for f in etm_findings_list if f['severity'] >= 5)
        high_etm = sum(1 for f in etm_findings_list if f['severity'] == 4)
        patchable_etm = sum(1 for f in etm_findings_list if f['isPatchAvailable'])
        result['summary'] = {
            'riskScore': result['csam']['riskScore'],
            'criticality': result['csam']['criticality'],
            'etmFindings': len(etm_findings_list),
            'etmCritical': crit_etm,
            'etmHigh': high_etm,
            'etmPatchable': patchable_etm,
            'vmdrDetections': len(vmdr_dets),
            'eolSoftware': len(eol_software),
        }

        result = compact(result)
        return _apply_detail_level(result, detail, list_keys=['etmFindings', 'vmdrDetections'])

    # detail_level='summary'
    filters = [{"field": "asset.id", "operator": "EQUALS", "value": str(asset_id)}]
    asset = csam_search(filters=filters, limit=1)
    asset = asset[0] if asset else None
    if asset:
        result['ip'] = asset.get('address', '')
        result['hostname'] = asset.get('dnsHostName', '') or asset.get('dnsName', '')
        trurisk_val = int(asset.get('riskScore') or 0)
        result['riskScore'] = trurisk_val
        result['truriskScore'] = trurisk_val
        result['os'] = (asset.get('operatingSystem') or {}).get('osName', '')
        result['criticality'] = get_criticality(asset)
        result['hostId'] = str(asset.get('hostId') or '')
        result['lastUpdated'] = asset.get('lastModifiedDate', '')
        result['provider'] = (asset.get('cloudProvider') or {}).get('aws', {}).get('ec2', {}).get('region', {}).get('name', '') if asset.get('cloudProvider') else ''

        sw_list = asset.get('softwareListData', {})
        if sw_list and isinstance(sw_list, dict):
            for sw in (sw_list.get('software') or [])[:30]:
                name = sw.get('fullName') or sw.get('productName') or sw.get('name') or ''
                sw_info = {
                    'name': name.strip()[:60],
                    'version': sw.get('version', ''),
                    'category': sw.get('category', ''),
                }
                lifecycle = (sw.get('lifecycle') or {})
                if lifecycle.get('stage') and lifecycle['stage'] not in ('Unknown', 'Not Applicable', 'OS Dependent'):
                    sw_info['lifecycleStage'] = lifecycle['stage']
                    if is_eol_stage(lifecycle['stage']):
                        result['eolSoftware'].append(sw_info)
                result['software'].append(sw_info)

        os_info = asset.get('operatingSystem') or {}
        os_lifecycle = (os_info.get('lifecycle') or {})
        if os_lifecycle.get('stage'):
            result['osLifecycle'] = os_lifecycle['stage']

        host_id = result.get('hostId', '')
        if host_id:
            dets = get_host_detections(host_id, severity=3, days=90)
            if dets:
                det_qids = list({d['qid'] for d in dets if d.get('qid')})
                kb_data = get_kb_batch(det_qids[:50]) if det_qids else {}
                vulns = []
                for d in sorted(dets, key=lambda x: (-x.get('severity', 0), -x.get('qds', 0))):
                    kb = kb_data.get(d['qid']) or {}
                    kb_title = kb.get('title', '')
                    if detail != "detailed":
                        kb_title = kb_title[:80]
                    vulns.append({
                        'qid': d['qid'],
                        'title': kb_title,
                        'severity': d.get('severity', 0),
                        'qds': d.get('qds', 0) or kb.get('qds', 0),
                        'cvss_v3': kb.get('cvss_v3'),
                        'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                        'cves': kb.get('cves', []),
                        'patchAvailable': kb.get('patch_available', False),
                        'has_exploit': kb.get('has_exploit', False),
                        'ransomware': kb.get('ransomware', False),
                        'first_found': short_date(d.get('first_found', '')),
                    })
                result['vulns'] = vulns[:50]
                result['vulnCount'] = len(dets)
    else:
        result['_meta'] = {'returned': 0, 'total': 0, 'truncated': False}

    return compact(result)


# ---------------------------------------------------------------------------
# tech_debt
# ---------------------------------------------------------------------------

def tech_debt(limit: int = 100, days: int = 30, detail: str = "standard") -> dict:
    """End-of-life and end-of-support systems — OS and hardware assets running unsupported software."""
    cutoff = None
    if days > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    concurrent = _run_concurrent(
        os_eol=lambda: fetch_all_eol('os', cutoff_date=cutoff),
        hw_eol=lambda: fetch_all_eol('hardware', cutoff_date=cutoff),
    )

    result = {
        'os': concurrent.get('os_eol') or [],
        'hardware': concurrent.get('hw_eol') or [],
    }

    result['os'].sort(key=lambda x: (-x['criticality'], -x['riskScore']))
    result['hardware'].sort(key=lambda x: (-x['criticality'], -x['riskScore']))
    result['summary'] = {'osEOL': len(result['os']), 'hardwareEOL': len(result['hardware'])}

    truncated = False
    if limit > 0:
        if len(result['os']) > limit:
            result['os'] = result['os'][:limit]
            truncated = True
        if len(result['hardware']) > limit:
            result['hardware'] = result['hardware'][:limit]
            truncated = True

    meta = _with_meta(result, 'os', len(result['os']) + len(result['hardware']))
    if truncated:
        meta.get('_meta', {})['truncated'] = True

    return _apply_detail_level(meta, detail, list_keys=['os', 'hardware'])


# ---------------------------------------------------------------------------
# image_vulns
# ---------------------------------------------------------------------------

def image_vulns(image_id: str, limit: int = 50, detail: str = "standard") -> dict:
    """Vulnerabilities for a specific container image."""
    result = {
        'imageId': image_id, 'repo': '', 'tag': '',
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
        'vulns': []
    }

    concurrent = _run_concurrent(
        img=lambda: get_image_details(image_id),
        vulns=lambda: get_image_vulns_api(image_id),
    )

    img = concurrent.get('img')
    vulns = concurrent.get('vulns') or []

    if not img and not vulns:
        empty = _container_empty_response('image data')
        empty['imageId'] = image_id
        return empty

    if img:
        result['repo'] = img.get('repo', '')
        result['tag'] = img.get('tag', '')
        result['created'] = img.get('created', '')
    for v in vulns[:limit]:
        sev = v.get('severity', 0)
        if sev == 5:
            result['stats']['critical'] += 1
        elif sev == 4:
            result['stats']['high'] += 1
        elif sev == 3:
            result['stats']['medium'] += 1
        else:
            result['stats']['low'] += 1

        title = v.get('title', '')
        if detail != "detailed":
            title = title[:80]
        result['vulns'].append({
            'qid': v.get('qid'), 'cve': v.get('cveId', ''),
            'severity': sev, 'title': title,
            'fixVersion': v.get('fixedVersion', '')
        })

    result['stats']['total'] = len(vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    out = _with_meta(result, 'vulns', len(vulns))
    return _apply_detail_level(out, detail, list_keys=['vulns'])


# ---------------------------------------------------------------------------
# _container_empty_response — graceful fallback when no container data exists
# ---------------------------------------------------------------------------

def _container_empty_response(context: str) -> dict:
    """Build a descriptive empty response with vuln fallback context.

    When containers/images return empty, this provides a useful response instead
    of a bare empty dict. It attempts to fetch aggregate container vuln data from
    /csapi/v1.3/vuln as fallback context.
    """
    result = {
        'message': (
            f'No {context} found. Container Security module is licensed but '
            'no container agents are reporting data for this resource type.'
        ),
        'available_tools': [
            'get_container_vuln_summary — image vulnerability ranking',
            'get_image_vulns — deep dive into a specific image',
            'get_running_containers — running container inventory',
        ],
    }

    # Try vuln endpoint as fallback context
    try:
        vuln_ctx = get_container_vulns_summary()
        if vuln_ctx and vuln_ctx.get('totalVulns'):
            result['vulnContext'] = {
                'note': 'Container vulnerability data IS available via the vuln database even though no live runtime data was returned.',
                'totalContainerVulns': vuln_ctx['totalVulns'],
                'severityBreakdown': vuln_ctx.get('severity', {}),
            }
    except Exception:
        pass  # Best-effort fallback

    return compact(result)


# ---------------------------------------------------------------------------
# container_vuln_summary
# ---------------------------------------------------------------------------

def container_vuln_summary(limit: int = 20, detail: str = "standard") -> dict:
    """Top container images ranked by critical vulnerability count with severity breakdown."""
    concurrent = _run_concurrent(
        images=lambda: get_images_by_vulns(limit=limit),
        total_images=lambda: get_images(1, count_only=True),
        total_vuln_images=lambda: get_images(1, severity=5, count_only=True),
    )
    images = concurrent.get('images') or []
    total_images = concurrent.get('total_images') or 0
    total_vuln_images = concurrent.get('total_vuln_images') or 0
    if not images:
        return _container_empty_response('container images')

    ranked = []
    totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0, 'patchable': 0}

    for img in images:
        vulns = img.get('vulnerabilities', {}) or {}
        sev = vulns.get('severity', {}) or {}
        crit = sev.get('5', 0) or sev.get(5, 0) or vulns.get('severity5Count', 0)
        high = sev.get('4', 0) or sev.get(4, 0) or vulns.get('severity4Count', 0)
        med = sev.get('3', 0) or sev.get(3, 0) or vulns.get('severity3Count', 0)
        low = (sev.get('2', 0) or sev.get(2, 0) or vulns.get('severity2Count', 0)) + \
              (sev.get('1', 0) or sev.get(1, 0) or vulns.get('severity1Count', 0))
        img_total = crit + high + med + low
        patchable = vulns.get('patchAvailable', 0) or vulns.get('patchAvailableCount', 0)
        totals['critical'] += crit
        totals['high'] += high
        totals['medium'] += med
        totals['low'] += low
        totals['total'] += img_total
        totals['patchable'] += patchable

        ranked.append(compact({
            'imageId': img.get('imageId', ''),
            'repo': img.get('repo', ''),
            'tag': img.get('tag', ''),
            'created': short_date(img.get('created', '')),
            'critical': crit, 'high': high, 'medium': med, 'low': low,
            'total': img_total, 'patchable': patchable,
        }))

    result = {
        'summary': totals,
        'totalImages': total_images,
        'totalVulnerableImages': total_vuln_images,
        'imageCount': len(ranked),
        'images': ranked,
    }
    out = _with_meta(result, 'images', total_images)
    return _apply_detail_level(out, detail, list_keys=['images'])


# ---------------------------------------------------------------------------
# image_vulns_list  (list mode — no image_id)
# ---------------------------------------------------------------------------

def image_vulns_list(limit: int = 20, detail: str = "standard") -> dict:
    """List container images ranked by critical vuln count (no specific image_id needed)."""
    return container_vuln_summary(limit=limit, detail=detail)


# ---------------------------------------------------------------------------
# running_containers
# ---------------------------------------------------------------------------

def running_containers(limit: int = 50, detail: str = "standard") -> dict:
    """Running containers with image vulnerability context."""
    sample_size = min(max(limit, 100), 500)
    concurrent = _run_concurrent(
        containers=lambda: get_containers(limit=sample_size),
        total_containers=lambda: get_containers(1, count_only=True),
        images=lambda: get_images_by_vulns(limit=200),
    )

    containers = concurrent.get('containers') or []
    total_containers = concurrent.get('total_containers') or len(containers)
    images_list = concurrent.get('images') or []

    if not containers and not images_list:
        return _container_empty_response('running containers')

    # Build image vuln lookup by imageId
    img_vulns = {}
    for img in images_list:
        iid = img.get('imageId', '')
        if iid:
            vulns = img.get('vulnerabilities', {}) or {}
            sev = vulns.get('severity', {}) or {}
            img_vulns[iid] = {
                'critical': sev.get('5', 0) or sev.get(5, 0) or vulns.get('severity5Count', 0),
                'high': sev.get('4', 0) or sev.get(4, 0) or vulns.get('severity4Count', 0),
                'medium': sev.get('3', 0) or sev.get(3, 0) or vulns.get('severity3Count', 0),
                'patchable': vulns.get('patchAvailable', 0) or vulns.get('patchAvailableCount', 0),
            }

    rows = []
    for c in containers:
        iid = c.get('imageId', '')
        vuln_info = img_vulns.get(iid, {})
        if not vuln_info.get('critical') and not vuln_info.get('high'):
            c_vulns = c.get('vulnerabilities', {}) or {}
            vuln_info = {
                'critical': c_vulns.get('severity5Count', 0) or (c_vulns.get('severity', {}) or {}).get('5', 0),
                'high': c_vulns.get('severity4Count', 0) or (c_vulns.get('severity', {}) or {}).get('4', 0),
                'medium': c_vulns.get('severity3Count', 0) or (c_vulns.get('severity', {}) or {}).get('3', 0),
                'patchable': c_vulns.get('patchAvailableCount', 0) or c_vulns.get('patchAvailable', 0),
            }
        rows.append(compact({
            'containerId': c.get('containerId', ''),
            'name': c.get('name', ''),
            'imageId': iid,
            'imageRepo': c.get('imageRepo', '') or c.get('repo', ''),
            'imageTag': c.get('imageTag', '') or c.get('tag', ''),
            'state': c.get('state', ''),
            'host': c.get('hostName', '') or c.get('hostname', ''),
            'critical': vuln_info.get('critical', 0),
            'high': vuln_info.get('high', 0),
            'medium': vuln_info.get('medium', 0),
            'patchable': vuln_info.get('patchable', 0),
        }))

    # Sort by critical desc, then high desc
    rows.sort(key=lambda r: (-r.get('critical', 0), -r.get('high', 0)))

    unpatched_critical = [r for r in rows if r.get('critical', 0) > 0 and r.get('patchable', 0) > 0]

    local_crit_count = sum(1 for r in rows if r.get('critical', 0) > 0)
    if len(rows) > 0 and total_containers > len(rows):
        crit_ratio = local_crit_count / len(rows)
        estimated_crit = int(crit_ratio * total_containers)
        crit_is_estimated = True
    else:
        estimated_crit = local_crit_count
        crit_is_estimated = False

    result = {
        'summary': {
            'totalRunning': total_containers,
            'returned': len(rows),
            'sampled': len(rows),
            'withCriticalVulns': estimated_crit,
            'withCriticalVulnsEstimated': crit_is_estimated,
            'withUnpatchedCritical': len(unpatched_critical),
        },
        'containers': rows[:limit],
        '_k8sNote': 'Kubernetes namespace/pod data is not available on this tenant. '
                    'Showing container and image-level data instead.',
    }
    out = _with_meta(result, 'containers', total_containers)
    return _apply_detail_level(out, detail, list_keys=['containers'])


# ---------------------------------------------------------------------------
# cert_security_posture
# ---------------------------------------------------------------------------

def cert_security_posture(protocol_filter: str = "", weak_ciphers: bool = False,
                           insecure_renegotiation: bool = False, limit: int = 100) -> dict:
    """Filtered certificate security posture — TLS protocol, cipher, renegotiation."""
    from qualys.api import get_certificates_filtered

    # Build filter string
    filters = []
    if protocol_filter:
        proto = protocol_filter.strip()
        mapping = {
            "tls1.0": "TLSv1.0", "tls 1.0": "TLSv1.0", "tlsv1.0": "TLSv1.0",
            "tls1.1": "TLSv1.1", "tls 1.1": "TLSv1.1", "tlsv1.1": "TLSv1.1",
            "ssl3": "SSLv3", "sslv3": "SSLv3", "ssl 3": "SSLv3",
        }
        proto_key = mapping.get(proto.lower(), proto)
        filters.append(f"protocol:{proto_key}")
    if weak_ciphers:
        filters.append("weakCiphers:true")
    if insecure_renegotiation:
        filters.append("insecureRenegotiation:true")

    if not filters:
        return {"error": "No filter specified. Provide protocol_filter, weak_ciphers=True, or insecure_renegotiation=True."}

    filter_str = " AND ".join(filters)
    certs = get_certificates_filtered(filter_str, limit)

    if certs is None:
        return {"error": "CertView API unavailable or not licensed.", "total": 0}
    if not certs:
        return {"total": 0, "message": f"No certificates found matching filter: {filter_str}", "certs": []}

    result_certs = []
    for c in certs:
        result_certs.append({
            "subject": c.get("certhash", c.get("subject", "")),
            "host": c.get("host", c.get("hostname", "")),
            "protocol": c.get("protocol", ""),
            "cipher": c.get("cipher", ""),
            "insecureRenegotiation": c.get("insecureRenegotiation", False),
            "grade": c.get("grade", c.get("sslGrade", "")),
            "expiryDate": c.get("validTo", ""),
        })

    return {
        "total": len(result_certs),
        "filter": filter_str,
        "certs": result_certs,
    }


# ---------------------------------------------------------------------------
# expiring_certs
# ---------------------------------------------------------------------------

def expiring_certs(days: int = 90, include_expired: bool = True, weak_only: bool = False,
                   limit: int = 100, detail: str = "standard") -> dict:
    """SSL/TLS certificate expiry monitoring and configuration issue detection."""
    result = {
        'days': days,
        'summary': {
            'total': 0, 'expired': 0, 'expiring30Days': 0, 'expiring90Days': 0,
            'weakCiphers': 0, 'selfSigned': 0, 'weakKeySize': 0, 'tls10or11': 0,
        },
        'expiringSoon': [],
        'issues': [],
    }

    today = datetime.now(timezone.utc)

    certs = get_certificates(limit * 3, days)
    if certs is None:
        return {
            "error": "Certificate management (CertView) is not enabled on this Qualys subscription. "
                     "Contact your Qualys administrator to enable the CertView module.",
            "total": 0,
            "certs": [],
        }
    if not certs:
        return {"error": "No certificates found in CertView for this tenant.", "total": 0, "certs": []}
    all_certs = []

    for c in certs:
        subject_obj = c.get('subject', {}) or {}
        issuer_obj = c.get('issuer', {}) or {}
        subject_cn = subject_obj.get('commonName', '')
        issuer_cn = issuer_obj.get('commonName', '')
        sig_algo = (c.get('signatureAlgorithm', '') or issuer_obj.get('signatureAlgorithm', '') or '').lower()
        hosts_raw = c.get('hosts', []) or []
        first_host = hosts_raw[0].get('hostname', '') if hosts_raw else ''
        host_list = [h.get('hostname', '') for h in hosts_raw[:5]]

        cert_issues = []

        if 'sha1' in sig_algo:
            cert_issues.append({'issue': 'SHA-1 signature algorithm', 'severity': 'CRITICAL'})
        elif 'md5' in sig_algo:
            cert_issues.append({'issue': 'MD5 signature algorithm', 'severity': 'CRITICAL'})

        key_size = c.get('keySize') or (c.get('publicKey') or {}).get('bitSize') or 0
        key_algo = (c.get('keyAlgorithm', '') or (c.get('publicKey') or {}).get('algorithm', '') or '').upper()
        try:
            key_size = int(key_size)
        except (ValueError, TypeError):
            key_size = 0
        if key_size > 0:
            if 'RSA' in key_algo and key_size < 2048:
                cert_issues.append({'issue': f'Weak RSA key ({key_size}-bit, minimum 2048)', 'severity': 'HIGH'})
            elif 'EC' in key_algo and key_size < 256:
                cert_issues.append({'issue': f'Weak EC key ({key_size}-bit, minimum 256)', 'severity': 'HIGH'})

        is_self_signed = False
        if subject_cn and issuer_cn and subject_cn.strip().lower() == issuer_cn.strip().lower():
            is_self_signed = True
            cert_issues.append({'issue': 'Self-signed certificate', 'severity': 'MEDIUM'})

        for h in hosts_raw[:5]:
            tls_version = h.get('protocol', '') or h.get('tlsVersion', '') or h.get('sslProtocol', '') or ''
            tls_version_lower = tls_version.lower()
            if 'tls1.0' in tls_version_lower or 'tlsv1.0' in tls_version_lower or tls_version_lower == 'tls 1.0' or 'ssl' in tls_version_lower:
                cert_issues.append({'issue': f'TLS 1.0 enabled on {h.get("hostname", "unknown")}', 'severity': 'HIGH'})
                break
            elif 'tls1.1' in tls_version_lower or 'tlsv1.1' in tls_version_lower or tls_version_lower == 'tls 1.1':
                cert_issues.append({'issue': f'TLS 1.1 enabled on {h.get("hostname", "unknown")}', 'severity': 'HIGH'})
                break

        certview_grade = c.get('grade', '') or c.get('sslGrade', '') or ''

        valid_to = c.get('validTo', '')
        days_left = None
        is_expired = False
        if valid_to:
            try:
                exp_date = datetime.strptime(valid_to[:10], '%Y-%m-%d')
                days_left = (exp_date - today).days
                if days_left < 0:
                    is_expired = True
                    cert_issues.append({'issue': f'Certificate expired {abs(days_left)} days ago', 'severity': 'CRITICAL'})
            except ValueError:
                pass

        has_critical = any(i['severity'] == 'CRITICAL' for i in cert_issues)
        has_high = any(i['severity'] == 'HIGH' for i in cert_issues)

        if is_expired or has_critical:
            grade = 'F'
        elif has_high or is_self_signed:
            grade = 'C'
        elif days_left is not None and 0 <= days_left <= 30:
            grade = 'B'
        else:
            grade = certview_grade.upper() if certview_grade else 'A'

        result['summary']['total'] += 1
        if is_expired:
            result['summary']['expired'] += 1
        if days_left is not None and 0 <= days_left <= 30:
            result['summary']['expiring30Days'] += 1
        if days_left is not None and 0 <= days_left <= 90:
            result['summary']['expiring90Days'] += 1
        if 'sha1' in sig_algo or 'md5' in sig_algo:
            result['summary']['weakCiphers'] += 1
        if is_self_signed:
            result['summary']['selfSigned'] += 1
        if key_size > 0 and (('RSA' in key_algo and key_size < 2048) or ('EC' in key_algo and key_size < 256)):
            result['summary']['weakKeySize'] += 1
        if any('TLS 1.0' in i['issue'] or 'TLS 1.1' in i['issue'] for i in cert_issues):
            result['summary']['tls10or11'] += 1

        cert_entry = {
            'subject': subject_cn,
            'expiryDate': valid_to[:10] if valid_to else '',
            'daysRemaining': days_left,
            'host': first_host,
            'hosts': host_list,
            'grade': grade,
            'issues': cert_issues,
        }

        for ci in cert_issues:
            result['issues'].append({
                'host': first_host or subject_cn,
                'issue': ci['issue'],
                'severity': ci['severity'],
            })

        if weak_only and not cert_issues:
            continue

        if is_expired:
            if include_expired:
                all_certs.append(cert_entry)
        elif days_left is not None and days_left <= days:
            all_certs.append(cert_entry)
        elif days_left is None or days_left > days:
            if weak_only and cert_issues:
                all_certs.append(cert_entry)

    all_certs.sort(key=lambda x: x.get('daysRemaining') if x.get('daysRemaining') is not None else 9999)
    result['expiringSoon'] = all_certs[:limit]

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    result['issues'].sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))

    out = _with_meta(result, 'expiringSoon', result.get('summary', {}).get('total', len(result.get('expiringSoon', []))))
    return _apply_detail_level(out, detail, list_keys=['expiringSoon', 'issues'])


# ---------------------------------------------------------------------------
# webapp_vulns
# ---------------------------------------------------------------------------

def webapp_vulns(severity: int = 0, days: int = 0, app_name: str = "", owasp_category: str = "",
                 limit: int = 50, detail: str = "standard") -> dict:
    """Web application vulnerabilities from Qualys WAS / TotalAppSec."""

    owasp_map = {
        'SQL Injection': 'A03:Injection',
        'Cross-Site Scripting': 'A03:Injection',
        'XSS': 'A03:Injection',
        'Command Injection': 'A03:Injection',
        'Code Injection': 'A03:Injection',
        'LDAP Injection': 'A03:Injection',
        'XPath Injection': 'A03:Injection',
        'Header Injection': 'A03:Injection',
        'CRLF Injection': 'A03:Injection',
        'Template Injection': 'A03:Injection',
        'Expression Language': 'A03:Injection',
        'SSRF': 'A10:Server-Side Request Forgery',
        'Server-Side Request Forgery': 'A10:Server-Side Request Forgery',
        'CSRF': 'A01:Broken Access Control',
        'Cross-Site Request Forgery': 'A01:Broken Access Control',
        'Insecure Direct Object': 'A01:Broken Access Control',
        'IDOR': 'A01:Broken Access Control',
        'Path Traversal': 'A01:Broken Access Control',
        'Directory Traversal': 'A01:Broken Access Control',
        'Authorization': 'A01:Broken Access Control',
        'Access Control': 'A01:Broken Access Control',
        'Privilege': 'A01:Broken Access Control',
        'Cryptographic': 'A02:Cryptographic Failures',
        'Sensitive Data': 'A02:Cryptographic Failures',
        'Clear-Text': 'A02:Cryptographic Failures',
        'Cleartext': 'A02:Cryptographic Failures',
        'Weak Cipher': 'A02:Cryptographic Failures',
        'SSL': 'A02:Cryptographic Failures',
        'TLS': 'A02:Cryptographic Failures',
        'XXE': 'A05:Security Misconfiguration',
        'XML External Entity': 'A05:Security Misconfiguration',
        'Misconfiguration': 'A05:Security Misconfiguration',
        'Default Credential': 'A05:Security Misconfiguration',
        'Information Disclosure': 'A05:Security Misconfiguration',
        'Server Version': 'A05:Security Misconfiguration',
        'Directory Listing': 'A05:Security Misconfiguration',
        'Error Message': 'A05:Security Misconfiguration',
        'Stack Trace': 'A05:Security Misconfiguration',
        'Authentication': 'A07:Identification and Authentication Failures',
        'Session': 'A07:Identification and Authentication Failures',
        'Brute Force': 'A07:Identification and Authentication Failures',
        'Password': 'A07:Identification and Authentication Failures',
        'Cookie': 'A07:Identification and Authentication Failures',
        'Deserialization': 'A08:Software and Data Integrity Failures',
        'Insecure Deserialization': 'A08:Software and Data Integrity Failures',
        'Log4j': 'A06:Vulnerable and Outdated Components',
        'Outdated': 'A06:Vulnerable and Outdated Components',
        'Component': 'A06:Vulnerable and Outdated Components',
        'Library': 'A06:Vulnerable and Outdated Components',
        'Open Redirect': 'A01:Broken Access Control',
        'Clickjacking': 'A05:Security Misconfiguration',
    }

    result = {
        'minSeverity': severity, 'days': days,
        'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'webApps': 0},
        'findings': [], 'byWebApp': [], 'byCategory': {}, 'owaspTop10': {},
    }

    sev_arg = severity if severity > 0 else None
    days_arg = days if days > 0 else None
    app_arg = app_name if app_name else None

    was_concurrent = _run_concurrent(
        findings=lambda: get_was_findings(limit * 3, severity=sev_arg, days=days_arg, app_name=app_arg),
        total_count=lambda: _get_was_count(),
        webapp_count=lambda: _get_was_webapp_count(),
        sev_counts=lambda: _get_was_severity_counts(),
    )
    findings = was_concurrent.get('findings') or []
    was_total = was_concurrent.get('total_count') or len(findings)
    was_apps = was_concurrent.get('webapp_count') or 0
    sev_counts = was_concurrent.get('sev_counts') or {}

    webapp_vulns_map = {}

    for f in findings:
        sev = f.get('severity', 0)
        name = f.get('name', '')

        owasp_cat = ''
        vuln_category = 'Other'
        for keyword, owasp in owasp_map.items():
            if keyword.lower() in name.lower():
                owasp_cat = owasp
                vuln_category = keyword
                break

        if owasp_category:
            match = owasp_category.lower()
            if match not in owasp_cat.lower() and match not in vuln_category.lower() and match not in name.lower():
                continue

        if sev >= 5:
            result['stats']['critical'] += 1
        elif sev >= 4:
            result['stats']['high'] += 1
        elif sev >= 3:
            result['stats']['medium'] += 1
        else:
            result['stats']['low'] += 1

        if owasp_cat:
            result['owaspTop10'][owasp_cat] = result['owaspTop10'].get(owasp_cat, 0) + 1

        result['byCategory'][vuln_category] = result['byCategory'].get(vuln_category, 0) + 1

        webapp_name = f.get('webAppName', '')
        webapp_id = f.get('webAppId', '')
        if webapp_id:
            if webapp_id not in webapp_vulns_map:
                webapp_vulns_map[webapp_id] = {
                    'id': webapp_id, 'appName': webapp_name,
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0
                }
            webapp_vulns_map[webapp_id]['total'] += 1
            if sev >= 5:
                webapp_vulns_map[webapp_id]['critical'] += 1
            elif sev >= 4:
                webapp_vulns_map[webapp_id]['high'] += 1
            elif sev >= 3:
                webapp_vulns_map[webapp_id]['medium'] += 1
            else:
                webapp_vulns_map[webapp_id]['low'] += 1

        result['findings'].append({
            'id': f.get('id', ''),
            'qid': f.get('qid'),
            'name': name,
            'severity': sev,
            'url': f.get('url', ''),
            'webApp': webapp_name,
            'detectedDate': short_date(f.get('detectedDate', '')),
            'type': f.get('type', ''),
            'owaspCategory': owasp_cat,
        })

    if sev_counts:
        result['stats']['critical'] = sev_counts.get(5, 0)
        result['stats']['high'] = sev_counts.get(4, 0)
        result['stats']['medium'] = sev_counts.get(3, 0)
        result['stats']['low'] = sev_counts.get(2, 0) + sev_counts.get(1, 0)
    result['stats']['total'] = was_total if was_total > len(result['findings']) else len(result['findings'])
    result['stats']['webApps'] = was_apps if was_apps > len(webapp_vulns_map) else len(webapp_vulns_map)
    result['findings'] = sorted(result['findings'], key=lambda x: x['severity'], reverse=True)[:limit]
    result['byWebApp'] = sorted(
        webapp_vulns_map.values(),
        key=lambda x: (x['critical'], x['high'], x['total']),
        reverse=True
    )[:20]
    result['byCategory'] = dict(sorted(result['byCategory'].items(), key=lambda x: x[1], reverse=True))
    result['owaspTop10'] = dict(sorted(result['owaspTop10'].items(), key=lambda x: x[1], reverse=True))
    out = _with_meta(result, 'findings', result['stats']['total'])
    return _apply_detail_level(out, detail, list_keys=['findings', 'byWebApp'])


# ---------------------------------------------------------------------------
# risk_by_tag
# ---------------------------------------------------------------------------

def risk_by_tag(tag: str, limit: int = 10, detail: str = "standard") -> dict:
    """Aggregate risk for a tag group — TruRisk tier distribution, top risky assets, and EOL counts."""
    result = {
        'tag': tag,
        'assets': {'total': 0, 'critical': 0, 'high': 0, 'elevated': 0},
        'topRiskAssets': [],
        'eolCount': 0,
        'summary': '',
    }

    tag_filter = [{"field": "asset.tag.name", "operator": "EQUALS", "value": tag}]

    concurrent = _run_concurrent(
        total=lambda: csam_count(tag_filter),
        risk_900=lambda: csam_count(tag_filter + [{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count(tag_filter + [{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count(tag_filter + [{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        eol=lambda: csam_count(tag_filter + [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        top_assets=lambda: csam_search(
            tag_filter + [{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}],
            limit=limit
        ),
    )

    total = concurrent.get('total') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol = concurrent.get('eol') or 0

    result['assets'] = {
        'total': total,
        'critical': risk_900,
        'high': risk_700,
        'elevated': risk_500,
    }
    result['eolCount'] = eol

    top = sorted(concurrent.get('top_assets') or [], key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for i, a in enumerate(top[:limit]):
        result['topRiskAssets'].append({
            'rank': i + 1,
            'assetId': str(a.get('assetId', '')),
            'hostname': short_host(a.get('dnsHostName', '') or a.get('dnsName', '')),
            'ip': a.get('address', ''),
            'riskScore': int(a.get('riskScore') or 0),
            'os': (a.get('operatingSystem') or {}).get('osName', ''),
            'criticality': get_criticality(a),
        })

    pct_crit = round(risk_900 / total * 100, 1) if total else 0
    result['summary'] = (
        f"Tag '{tag}': {total} assets total. "
        f"{risk_900} critical (TruRisk >900, {pct_crit}%), "
        f"{risk_700} high (>700), {risk_500} elevated (>500). "
        f"{eol} EOL/EOS systems."
    )

    out = _with_meta(result, 'topRiskAssets', total)
    return _apply_detail_level(out, detail, list_keys=['topRiskAssets'])


# ---------------------------------------------------------------------------
# edr_events
# ---------------------------------------------------------------------------

def edr_events(days: int = 7, severity: str = "", category: str = "", host: str = "",
               limit: int = 50, detail: str = "standard") -> dict:
    """Endpoint Detection & Response events."""

    SEV_NORM = {
        '1': 'LOW', 'low': 'LOW',
        '2': 'MEDIUM', 'medium': 'MEDIUM',
        '3': 'HIGH', 'high': 'HIGH',
        '4': 'CRITICAL', 'critical': 'CRITICAL',
        '5': 'CRITICAL',
    }

    sev_filter = severity if severity else None
    raw_events = _fetch_edr_events_raw(limit * 4, sev_filter)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    host_counts: dict = {}
    affected_hosts: set = set()
    by_category: dict = {}
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    events_out: list = []

    for e in raw_events:
        dt = e.get('dateTime', '') or e.get('timestamp', '') or ''
        if dt:
            try:
                event_time = datetime.strptime(dt[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                if event_time < cutoff:
                    continue
            except ValueError:
                pass

        evt_category = e.get('eventType', '') or e.get('category', '') or e.get('type', '') or 'Unknown'
        hostname = e.get('hostname', '') or e.get('asset', {}).get('hostname', '') or ''
        ip = e.get('ip', '') or e.get('asset', {}).get('address', '') or ''
        user = e.get('user', '') or e.get('actor', {}).get('user', '') or ''
        process = e.get('processName', '') or e.get('process', {}).get('name', '') or ''
        event_id = e.get('id', '') or e.get('eventId', '') or ''

        raw_sev = str(e.get('severity', '') or '').strip()
        sev = SEV_NORM.get(raw_sev.lower(), raw_sev.upper() or 'UNKNOWN')

        if severity and severity.upper() != sev:
            continue
        if category and category.lower() not in evt_category.lower():
            continue
        if host and host.lower() not in hostname.lower():
            continue

        if sev in sev_counts:
            sev_counts[sev] += 1
        by_category[evt_category] = by_category.get(evt_category, 0) + 1
        if hostname:
            affected_hosts.add(hostname)
            host_counts[hostname] = host_counts.get(hostname, 0) + 1

        if len(events_out) < limit:
            events_out.append({
                'id': event_id,
                'severity': sev,
                'category': evt_category,
                'name': e.get('name', '') or e.get('eventName', '') or evt_category,
                'hostname': hostname,
                'ip': ip,
                'user': user,
                'process': process,
                'timestamp': dt,
            })

    total = sum(sev_counts.values())
    top_hosts = sorted(
        [{'hostname': h, 'eventCount': c} for h, c in host_counts.items()],
        key=lambda x: x['eventCount'],
        reverse=True,
    )[:10]

    _r = {
        'summary': {
            'total': total,
            'critical': sev_counts['CRITICAL'],
            'high': sev_counts['HIGH'],
            'medium': sev_counts['MEDIUM'],
            'low': sev_counts['LOW'],
            'affectedHosts': len(affected_hosts),
        },
        'byCategory': by_category,
        'topHosts': top_hosts,
        'events': events_out,
    }
    out = _with_meta(_r, 'events', total)
    return _apply_detail_level(out, detail, list_keys=['events', 'topHosts'])


# ---------------------------------------------------------------------------
# fim_events
# ---------------------------------------------------------------------------

def fim_events(days: int = 1, severity: str = "", host: str = "", path: str = "",
               limit: int = 100, detail: str = "standard") -> dict:
    """File Integrity Monitoring events."""
    CRITICAL_PATHS = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/hosts',
        '/etc/cron', '/boot/',
        'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
        'HKLM\\SYSTEM', 'HKLM\\SAM',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    ]

    SEV_NORM = {
        '1': 'LOW', 'low': 'LOW',
        '2': 'MEDIUM', 'medium': 'MEDIUM',
        '3': 'HIGH', 'high': 'HIGH',
        '4': 'CRITICAL', 'critical': 'CRITICAL',
        '5': 'CRITICAL',
    }

    raw_events = _fetch_fim_events_raw(limit * 4, days, host)

    host_counts: dict = {}
    affected_hosts: set = set()
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    action_counts = {'modified': 0, 'created': 0, 'deleted': 0}
    critical_changes: list = []
    events_out: list = []

    for e in raw_events:
        file_path = e.get('filePath', '') or e.get('fullPath', '') or ''
        hostname = e.get('hostname', '') or e.get('asset', {}).get('hostname', '') or ''
        user = e.get('user', '') or e.get('actor', {}).get('user', '') or ''
        action = (e.get('action', '') or '').upper()
        dt = e.get('dateTime', '') or e.get('timestamp', '') or ''

        raw_sev = str(e.get('severity', '') or '').strip()
        sev = SEV_NORM.get(raw_sev.lower(), raw_sev.upper() or 'UNKNOWN')

        if severity and severity.upper() != sev:
            continue
        if host and host.lower() not in hostname.lower():
            continue
        if path and not file_path.lower().startswith(path.lower()):
            continue

        if sev in sev_counts:
            sev_counts[sev] += 1

        action_key = action.lower()
        if 'modif' in action_key:
            action_counts['modified'] += 1
        elif 'creat' in action_key or 'add' in action_key:
            action_counts['created'] += 1
        elif 'delet' in action_key or 'remov' in action_key:
            action_counts['deleted'] += 1

        if hostname:
            affected_hosts.add(hostname)
            host_counts[hostname] = host_counts.get(hostname, 0) + 1

        off_hours = False
        if dt:
            try:
                event_time = datetime.strptime(dt[:19], '%Y-%m-%dT%H:%M:%S')
                if event_time.hour < 8 or event_time.hour >= 18:
                    off_hours = True
            except ValueError:
                pass

        is_critical = any(file_path.lower().startswith(cp.lower()) for cp in CRITICAL_PATHS if file_path)
        if is_critical:
            critical_changes.append({
                'hostname': hostname,
                'path': file_path,
                'action': action or 'UNKNOWN',
                'timestamp': dt,
                'user': user,
                'offHours': off_hours,
            })

        if len(events_out) < limit:
            event_info = {
                'action': action, 'path': file_path,
                'hostname': hostname, 'timestamp': dt,
                'severity': sev, 'user': user,
                'offHours': off_hours,
            }
            events_out.append(event_info)

    total = sum(sev_counts.values())
    top_hosts = sorted(
        [{'hostname': h, 'eventCount': c} for h, c in host_counts.items()],
        key=lambda x: x['eventCount'],
        reverse=True,
    )[:10]

    _r = {
        'summary': {
            'total': total,
            'critical': sev_counts['CRITICAL'],
            'high': sev_counts['HIGH'],
            'affectedHosts': len(affected_hosts),
            'modified': action_counts['modified'],
            'created': action_counts['created'],
            'deleted': action_counts['deleted'],
        },
        'topHosts': top_hosts,
        'criticalChanges': critical_changes,
        'events': events_out,
    }
    out = _with_meta(_r, 'events', total)
    return _apply_detail_level(out, detail, list_keys=['events', 'topHosts', 'criticalChanges'])


# ---------------------------------------------------------------------------
# scan_status
# ---------------------------------------------------------------------------

def scan_status(state: str = "Running,Paused,Queued,Error", days: int = 7, limit: int = 50,
                detail: str = "standard") -> dict:
    """Scan status — running, queued, and failed scans with duration and target info."""
    result = {
        'states': state,
        'stats': {'total': 0, 'byState': {}, 'running': 0, 'queued': 0, 'errors': 0, 'completedToday': 0},
        'scans': [],
        'failedScans': [],
        'summary': '',
    }

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    concurrent = _run_concurrent(
        active=lambda: get_scan_list(state, limit),
        finished=lambda: get_scan_list('Finished', limit),
    )

    active_scans = concurrent.get('active') or []
    finished_scans = concurrent.get('finished') or []

    def _parse_launch_time(launched):
        if not launched:
            return None
        try:
            return datetime.strptime(launched[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _process_scan(s):
        scan_state = s.get('state', '')
        launched = s.get('launched', '')
        launch_time = _parse_launch_time(launched)

        if launch_time and launch_time < cutoff:
            return

        result['stats']['byState'][scan_state] = result['stats']['byState'].get(scan_state, 0) + 1

        scan_entry = {
            'ref': s.get('ref', ''), 'title': s.get('title', ''),
            'state': scan_state, 'type': s.get('type', ''),
            'target': s.get('target', ''), 'launched': short_date(launched),
            'duration': _parse_duration(s.get('duration', '')),
            'scanner': s.get('scannerName', ''),
        }

        if len(result['scans']) < limit:
            result['scans'].append(scan_entry)

        if scan_state == 'Error':
            result['failedScans'].append({
                'ref': scan_entry['ref'], 'title': scan_entry['title'],
                'scanner': scan_entry['scanner'], 'target': scan_entry['target'],
                'launched': short_date(launched),
            })

    for s in active_scans:
        _process_scan(s)

    for s in finished_scans:
        launched = s.get('launched', '')
        launch_time = _parse_launch_time(launched)
        if launch_time and launch_time >= cutoff:
            _process_scan(s)
            if launch_time >= today_start:
                result['stats']['completedToday'] += 1

    by_state = result['stats']['byState']
    result['stats']['running'] = by_state.get('Running', 0)
    result['stats']['queued'] = by_state.get('Queued', 0)
    result['stats']['errors'] = by_state.get('Error', 0)
    result['stats']['total'] = sum(by_state.values())

    parts = []
    total = result['stats']['total']
    parts.append(f"{total} scan(s) found")
    if result['stats']['running']:
        parts.append(f"{result['stats']['running']} running")
    if result['stats']['queued']:
        parts.append(f"{result['stats']['queued']} queued")
    if result['stats']['errors']:
        parts.append(f"{result['stats']['errors']} error(s)")
    if result['stats']['completedToday']:
        parts.append(f"{result['stats']['completedToday']} completed today")
    result['summary'] = ' \u00b7 '.join(parts)

    if result['failedScans']:
        result['summary'] += ' \u26a0 Use get_scanner_health() to check scanner appliance status for failed scans.'

    out = _with_meta(result, 'scans', total)
    return _apply_detail_level(out, detail, list_keys=['scans', 'failedScans'])


# ---------------------------------------------------------------------------
# asset_inventory
# ---------------------------------------------------------------------------

def asset_inventory(query: str = "", tag: str = "", os: str = "", days_since_seen: int = 0,
                    days_since_scan: int = 0, eol_only: bool = False, limit: int = 50,
                    list_tags: bool = False, list_groups: bool = False,
                    detail: str = "standard") -> dict:
    """Asset inventory search — find assets by OS, tag, keyword, EOL status, or staleness."""
    # Handle list_tags and list_groups metadata queries
    if list_tags or list_groups:
        result = {}
        if list_tags:
            tag_set = set()
            tag_url = f"{BASE_URL}/qps/rest/2.0/search/am/tag"
            tag_req_body = b'<ServiceRequest></ServiceRequest>'
            try:
                from urllib.request import Request as _Req
                req = _Req(tag_url, data=tag_req_body, method='POST')
                req.add_header('Authorization', f'Basic {BASIC_AUTH}')
                req.add_header('Content-Type', 'text/xml')
                req.add_header('X-Requested-With', 'qualys-mcp')
                with _open(req, timeout=30) as resp:
                    tag_root = ET.fromstring(resp.read())
                    for tag_el in tag_root.findall('.//Tag'):
                        name = tag_el.findtext('name', '')
                        if name:
                            tag_set.add(name)
            except Exception as e:
                _log(f"Tag API error: {e}")
                assets_raw = csam_search(limit=limit or 500, fields='tagList', fetch_all=False)
                for a in assets_raw:
                    for t in a.get('tagList', []) or a.get('tags', []) or []:
                        name = t.get('name', '') if isinstance(t, dict) else str(t)
                        if name:
                            tag_set.add(name)
            tags_sorted = sorted(tag_set)
            result['totalTags'] = len(tags_sorted)
            result['tags'] = tags_sorted
        if list_groups:
            group_set = set()
            groups_raw = csam_search(limit=limit or 500, fields='assetGroups', fetch_all=False)
            for a in groups_raw:
                for g in a.get('assetGroups', []) or []:
                    name = g.get('name', '') if isinstance(g, dict) else str(g)
                    if name:
                        group_set.add(name)
            groups_sorted = sorted(group_set)
            result['totalGroups'] = len(groups_sorted)
            result['assetGroups'] = groups_sorted
        total_items = result.get('totalTags', 0) + result.get('totalGroups', 0)
        result['_meta'] = {'returned': total_items, 'total': total_items, 'truncated': False}
        return compact(result)

    filters = []
    if os:
        filters.append({"field": "operatingSystem.name", "operator": "CONTAINS", "value": os})
    if tag:
        filters.append({"field": "asset.tag.name", "operator": "CONTAINS", "value": tag})
    if query:
        filters.append({"field": "asset.name", "operator": "CONTAINS", "value": query})
    if days_since_seen > 0:
        pass
    if eol_only:
        filters.append({"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"})

    f = filters if filters else None
    data = _run_concurrent(
        assets=lambda: csam_search(filters=f, limit=limit if not days_since_scan else limit * 3, fetch_all=False,
                                   fields="assetName,dnsName,netbiosName,address,lastModifiedDate,lastVmScannedDate,operatingSystem,hardware,tags,vulnerabilities,tagList,riskScore,criticality"),
        total=lambda: csam_count(filters=f),
    )
    assets = data.get('assets', [])
    total_count = data.get('total', len(assets))

    now = datetime.now(timezone.utc)
    scan_cutoff = (now - timedelta(days=days_since_scan)) if days_since_scan > 0 else None

    summary = {'total': total_count, 'returned': len(assets), 'byOS': {}, 'byTag': {}, 'eolCount': 0}
    result_assets = []

    for a in assets:
        os_info = a.get('operatingSystem', {}) or {}
        os_name = os_info.get('osName', '') or 'Unknown'
        lifecycle = (os_info.get('lifecycle', {}) or {}).get('stage', '')
        is_eol = is_eol_stage(lifecycle)

        # Extract last scan date
        last_scanned_raw = a.get('lastVmScannedDate', '') or ''
        last_scanned = short_date(last_scanned_raw)
        days_since = None
        if last_scanned_raw:
            try:
                scan_dt = datetime.fromisoformat(last_scanned_raw.replace('Z', '+00:00'))
                days_since = (now - scan_dt).days
            except (ValueError, TypeError):
                pass

        # Apply days_since_scan filter: skip assets scanned recently enough
        if scan_cutoff:
            if days_since is not None and days_since < days_since_scan:
                continue
            # Also skip if no scan date and filter is active (can't confirm staleness)
            if days_since is None and last_scanned_raw:
                continue

        if is_eol:
            summary['eolCount'] += 1

        summary['byOS'][os_name] = summary['byOS'].get(os_name, 0) + 1

        asset_tags = []
        raw_tags = (a.get('tagList') or {})
        tag_list = raw_tags.get('tag', []) if isinstance(raw_tags, dict) else raw_tags
        for t in tag_list or a.get('tags', []) or []:
            tag_name = t.get('tagName', '') or t.get('name', '') if isinstance(t, dict) else str(t)
            if tag_name:
                asset_tags.append(tag_name)
                summary['byTag'][tag_name] = summary['byTag'].get(tag_name, 0) + 1

        vulns_info = a.get('vulnerabilities', {}) or {}
        open_vulns = vulns_info.get('count', 0) or 0

        asset_entry = {
            'id': a.get('assetId', ''),
            'name': a.get('assetName', '') or a.get('dnsName', '') or a.get('netbiosName', ''),
            'ip': a.get('address', '') or a.get('ipAddress', ''),
            'os': os_name,
            'lastSeen': short_date(a.get('lastModifiedDate', '') or a.get('sensorLastUpdatedDate', '')),
            'lastScanned': last_scanned or 'Never',
            'tags': asset_tags,
            'truRiskScore': a.get('riskScore', 0) or a.get('truRiskScore', 0) or 0,
            'openVulns': open_vulns,
            'eolStatus': lifecycle if lifecycle else 'Active',
        }
        if days_since is not None:
            asset_entry['daysSinceScan'] = days_since
        result_assets.append(asset_entry)

    result_assets.sort(key=lambda x: -x['truRiskScore'])
    result_assets = result_assets[:limit]
    summary['returned'] = len(result_assets)
    out = compact({
        'summary': summary, 'assets': result_assets,
        '_meta': {'returned': len(result_assets), 'total': total_count, 'truncated': len(result_assets) < total_count},
    })
    return _apply_detail_level(out, detail, list_keys=['assets'])


# ---------------------------------------------------------------------------
# vuln_exceptions
# ---------------------------------------------------------------------------

def vuln_exceptions(status: str = "Active", vuln_type: str = "", days_to_expiry: int = 30,
                    limit: int = 50, detail: str = "standard") -> dict:
    """Vulnerability exceptions — approved risk acceptances, false positives, and compensating controls."""
    result = {
        'status': status,
        'stats': {'total': 0, 'active': 0, 'expiringSoon': 0, 'expired': 0, 'byType': {}},
        'exceptions': []
    }

    url = f"{BASE_URL}/api/2.0/fo/exception/vuln/?action=list&status={status}"
    if vuln_type:
        url += f"&exception_type={quote(vuln_type)}"
    data = api_get(url, timeout=30)
    if not data:
        result['note'] = 'Exceptions API not available — may require additional Qualys subscription'
        return _with_meta(result, 'exceptions')

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['note'] = 'Exceptions API returned invalid response'
        return _with_meta(result, 'exceptions')

    today = datetime.now(timezone.utc)
    expiry_cutoff = today + timedelta(days=days_to_expiry) if days_to_expiry > 0 else None

    for exc in root.findall('.//EXCEPTION')[:limit * 2]:
        exc_type = exc.findtext('EXCEPTION_TYPE', '') or exc.findtext('TYPE', '')
        if vuln_type and vuln_type.lower() not in exc_type.lower():
            continue

        exc_status = exc.findtext('STATUS', status)
        expiry = exc.findtext('EXPIRY_DATE', '') or exc.findtext('EXPIRATION_DATE', '')
        days_left = None
        if expiry:
            try:
                exp_date = datetime.strptime(expiry[:10], '%Y-%m-%d').replace(tzinfo=timezone.utc)
                days_left = (exp_date - today).days
                if days_left < 0:
                    result['stats']['expired'] += 1
                elif days_left <= days_to_expiry:
                    result['stats']['expiringSoon'] += 1
                if expiry_cutoff and exp_date > expiry_cutoff:
                    continue
            except ValueError:
                pass

        if exc_status.lower() == 'active':
            result['stats']['active'] += 1

        result['stats']['byType'][exc_type] = result['stats']['byType'].get(exc_type, 0) + 1

        if len(result['exceptions']) < limit:
            entry = {
                'id': exc.findtext('EXCEPTION_NUMBER', '') or exc.findtext('ID', ''),
                'qid': exc.findtext('QID', ''),
                'title': exc.findtext('VULN_TITLE', '') or exc.findtext('TITLE', ''),
                'type': exc_type,
                'status': exc_status,
                'reason': exc.findtext('COMMENTS', '') or exc.findtext('REASON', ''),
                'approvedBy': exc.findtext('APPROVED_BY', '') or exc.findtext('ASSIGNEE', ''),
                'hostIp': exc.findtext('HOST_IP', '') or exc.findtext('IP', ''),
                'assetCount': exc.findtext('ASSET_COUNT', '') or exc.findtext('HOST_COUNT', ''),
                'expiryDate': expiry,
            }
            if days_left is not None:
                entry['daysUntilExpiry'] = days_left
            result['exceptions'].append(entry)

    result['stats']['total'] = sum(result['stats']['byType'].values())
    out = _with_meta(result, 'exceptions', result['stats']['total'])
    return _apply_detail_level(out, detail, list_keys=['exceptions'])


# ---------------------------------------------------------------------------
# compliance_posture
# ---------------------------------------------------------------------------

def _get_available_policy_titles() -> list[str]:
    """Fetch policy titles from the compliance API and return a list of title strings (cached)."""
    from qualys.cache import disk_cache, TTL_COMPLIANCE
    _cache_key = "policy_titles_all"
    cached = disk_cache.get(_cache_key)
    if cached is not None:
        return cached

    titles: list[str] = []
    policy_data = api_get(f"{BASE_URL}/api/4.0/fo/compliance/policy/?action=list", timeout=120)
    if policy_data:
        try:
            root = ET.fromstring(policy_data if isinstance(policy_data, (str, bytes)) else policy_data)
            for policy in (root.findall('.//POLICY') or root.findall('.//COMPLIANCE_POLICY') or []):
                ptitle = policy.findtext('TITLE', '') or policy.findtext('NAME', '') or ''
                if ptitle:
                    titles.append(ptitle)
        except ET.ParseError:
            _log("Available frameworks: policy list returned non-XML")

    if titles:
        disk_cache.set(_cache_key, titles, TTL_COMPLIANCE)
    return titles


def _detect_framework_families(titles: list[str]) -> list[str]:
    """Detect framework families (CIS Benchmark, DISA STIG, etc.) from policy titles."""
    families: set[str] = set()
    for title in titles:
        t = title.upper()
        if 'CIS' in t:
            families.add('CIS Benchmark')
        if 'DISA' in t or 'STIG' in t:
            families.add('DISA STIG')
        if 'PCI' in t and 'DSS' in t:
            families.add('PCI-DSS')
        if 'HIPAA' in t:
            families.add('HIPAA')
        if 'NIST' in t:
            families.add('NIST')
        if 'ISO' in t and '27001' in t:
            families.add('ISO 27001')
        if 'SOC' in t and '2' in t:
            families.add('SOC 2')
    return sorted(families)


def list_compliance_frameworks() -> dict:
    """List available compliance frameworks/policies on this tenant."""
    titles = _get_available_policy_titles()
    families = _detect_framework_families(titles)
    return compact({
        'policies': titles,
        'frameworkFamilies': families,
        'count': len(titles),
        'hint': 'Use get_compliance_posture(framework="<name>") to query a specific framework.',
    })


def compliance_posture(framework: str = "", platform: str = "", limit: int = 20,
                       detail: str = "standard") -> dict:
    """Qualys Policy Compliance posture — pass/fail rates, top failing controls, and per-framework breakdown."""

    # --- Handle framework="list" shortcut ---
    if framework.lower() == "list":
        result = list_compliance_frameworks()
        if not result.get('policies'):
            result['error'] = 'No compliance policies found. The Policy Compliance (PC) module may not be licensed.'
            result['suggestion'] = 'Use get_cloud_risk() for cloud CIS compliance.'
        return result

    def _empty_result():
        return compact({
            'summary': {
                'controls': 0, 'passing': 0, 'failing': 0,
                'pass_pct': 0.0, 'assets': 0, 'frameworks': [],
            },
            'topFailingControls': [],
            'byFramework': {},
        })

    def _parse_controls(root):
        infos = root.findall('.//INFO')
        controls = (infos if infos else
                    root.findall('.//CONTROL') or root.findall('.//POSTURE')
                    or root.findall('.//COMPLIANCE_CONTROL'))
        if not controls:
            return None

        ctrl_lookup = {}
        for gc in root.findall('.//CONTROL'):
            cid = gc.findtext('ID', '')
            if cid:
                ctrl_lookup[cid] = {
                    'statement': gc.findtext('STATEMENT', ''),
                    'criticality': (gc.findtext('CRITICALITY', '') or '').strip(),
                }

        passed = 0
        failed = 0
        failing = []
        frameworks_seen = set()
        affected_hosts = set()
        by_fw = {}

        for c in controls:
            ctrl_status = (c.findtext('STATUS', '') or c.findtext('RESULT', '')).upper()
            ctrl_fw = (c.findtext('FRAMEWORK', '') or c.findtext('TECHNOLOGY', '')
                       or c.findtext('POLICY', ''))
            ctrl_id = c.findtext('CONTROL_ID', '') or c.findtext('CID', '') or c.findtext('ID', '')
            glossary = ctrl_lookup.get(ctrl_id, {})
            ctrl_name = (c.findtext('CONTROL_NAME', '') or c.findtext('TITLE', '')
                         or c.findtext('STATEMENT', '') or glossary.get('statement', ''))
            ctrl_sev = (c.findtext('SEVERITY', '') or c.findtext('CRITICALITY', '')
                        or glossary.get('criticality', '')).strip().upper()
            ctrl_platform = c.findtext('PLATFORM', '') or c.findtext('TECHNOLOGY', '') or ''
            host_count_text = c.findtext('HOST_COUNT', '') or c.findtext('ASSET_COUNT', '')

            if framework and framework.lower() not in ctrl_fw.lower():
                continue
            if platform and platform.lower() not in ctrl_platform.lower():
                continue

            if 'PASS' in ctrl_status:
                passed += 1
            elif 'FAIL' in ctrl_status or 'ERROR' in ctrl_status:
                failed += 1
                host_count = 0
                if host_count_text:
                    try:
                        host_count = int(host_count_text)
                    except ValueError:
                        pass
                failing.append({
                    'controlId': ctrl_id,
                    'title': ctrl_name,
                    'framework': ctrl_fw,
                    'failingAssets': host_count,
                    'severity': ctrl_sev or 'MEDIUM',
                })
                if host_count:
                    affected_hosts.add(host_count)

            if ctrl_fw:
                frameworks_seen.add(ctrl_fw.split()[0].upper().rstrip(','))
                if ctrl_fw not in by_fw:
                    by_fw[ctrl_fw] = {'pass': 0, 'fail': 0}
                if 'PASS' in ctrl_status:
                    by_fw[ctrl_fw]['pass'] += 1
                elif 'FAIL' in ctrl_status or 'ERROR' in ctrl_status:
                    by_fw[ctrl_fw]['fail'] += 1

        total_ctrl = passed + failed
        if total_ctrl == 0:
            return None

        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'URGENT': 1, 'MEDIUM': 2, 'LOW': 3}
        failing.sort(key=lambda x: (-x['failingAssets'], sev_order.get(x['severity'], 9)))

        res = _empty_result()
        res['summary']['controls'] = total_ctrl
        res['summary']['passing'] = passed
        res['summary']['failing'] = failed
        res['summary']['pass_pct'] = round(passed / total_ctrl * 100, 1)
        res['summary']['assets'] = max(affected_hosts) if affected_hosts else 0
        res['summary']['frameworks'] = sorted(frameworks_seen)
        res['topFailingControls'] = failing[:limit]

        for fw_name, counts in by_fw.items():
            fw_total = counts['pass'] + counts['fail']
            res['byFramework'][fw_name] = {
                'pass_pct': round(counts['pass'] / fw_total * 100, 1) if fw_total else 0,
                'failing': counts['fail'],
            }

        return compact(res)

    def _parse_controls_from_instances(data, fw_filter, plat_filter, lim):
        """Parse JSON from /rest/4.0/compliance/posture/instances into standard result."""
        # The instances endpoint may return various JSON shapes; try common ones
        records = []
        if isinstance(data, dict):
            records = data.get('data', data.get('instances', data.get('controls', [])))
        if isinstance(data, list):
            records = data
        if not records or not isinstance(records, list):
            return None

        passed = 0
        failed = 0
        failing = []
        frameworks_seen = set()
        by_fw = {}

        for rec in records:
            status = str(rec.get('status', rec.get('result', ''))).upper()
            ctrl_fw = rec.get('framework', rec.get('policy', ''))
            ctrl_id = str(rec.get('controlId', rec.get('id', rec.get('cid', ''))))
            ctrl_name = rec.get('title', rec.get('controlName', rec.get('statement', '')))
            ctrl_sev = str(rec.get('severity', rec.get('criticality', 'MEDIUM'))).upper()
            ctrl_plat = rec.get('platform', rec.get('technology', ''))
            host_count = int(rec.get('failingAssets', rec.get('hostCount', rec.get('assetCount', 0))) or 0)

            if fw_filter and fw_filter.lower() not in str(ctrl_fw).lower():
                continue
            if plat_filter and plat_filter.lower() not in str(ctrl_plat).lower():
                continue

            if 'PASS' in status:
                passed += 1
            elif 'FAIL' in status or 'ERROR' in status:
                failed += 1
                failing.append({
                    'controlId': ctrl_id,
                    'title': ctrl_name,
                    'framework': ctrl_fw,
                    'failingAssets': host_count,
                    'severity': ctrl_sev or 'MEDIUM',
                })

            if ctrl_fw:
                frameworks_seen.add(str(ctrl_fw).split()[0].upper().rstrip(','))
                if ctrl_fw not in by_fw:
                    by_fw[ctrl_fw] = {'pass': 0, 'fail': 0}
                if 'PASS' in status:
                    by_fw[ctrl_fw]['pass'] += 1
                elif 'FAIL' in status or 'ERROR' in status:
                    by_fw[ctrl_fw]['fail'] += 1

        total_ctrl = passed + failed
        if total_ctrl == 0:
            return None

        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'URGENT': 1, 'MEDIUM': 2, 'LOW': 3}
        failing.sort(key=lambda x: (-x['failingAssets'], sev_order.get(x['severity'], 9)))

        res = _empty_result()
        res['summary']['controls'] = total_ctrl
        res['summary']['passing'] = passed
        res['summary']['failing'] = failed
        res['summary']['pass_pct'] = round(passed / total_ctrl * 100, 1)
        res['summary']['frameworks'] = sorted(frameworks_seen)
        res['topFailingControls'] = failing[:lim]
        for fw_name, counts in by_fw.items():
            fw_total = counts['pass'] + counts['fail']
            res['byFramework'][fw_name] = {
                'pass_pct': round(counts['pass'] / fw_total * 100, 1) if fw_total else 0,
                'failing': counts['fail'],
            }
        return compact(res)

    def _add_compliance_followups(res):
        followups = []
        summary = res.get('summary', {})
        failing = summary.get('failing', 0)
        pass_pct = summary.get('pass_pct', 0)
        if failing:
            crit_fails = [c for c in res.get('topFailingControls', []) if c.get('severity') in ('CRITICAL', 'HIGH', 'URGENT')]
            if crit_fails:
                followups.append(f"{len(crit_fails)} critical/high severity controls failing — prioritize remediation?")
            followups.append(f"{failing} controls failing ({pass_pct}% pass rate) — get_etm_findings() for related vulnerabilities?")
        if pass_pct < 80 and pass_pct > 0:
            followups.append(f"Pass rate {pass_pct}% is below 80% threshold — review topFailingControls for quick wins?")
        frameworks = summary.get('frameworks', [])
        if frameworks:
            followups.append(f"Frameworks assessed: {', '.join(frameworks[:5])} — filter by framework for detailed view?")
        res['_followups'] = followups
        return res

    # --- Disk cache check ---
    from qualys.cache import disk_cache, TTL_COMPLIANCE
    _cache_key = f"compliance_posture_{framework or 'all'}_{platform or 'all'}"
    disk_hit = disk_cache.get(_cache_key)
    if disk_hit is not None:
        _log("Compliance posture: disk cache hit")
        cached = dict(disk_hit)
        cached['cacheAge'] = disk_cache.age(_cache_key) or 0
        return compact(cached)

    # --- Framework availability check (early exit) ---
    # When a specific framework is requested, check if it exists before trying
    # all strategies. This prevents silent fallback to wrong-framework data.
    if framework:
        available_titles = _get_available_policy_titles()
        if available_titles and not any(framework.lower() in t.lower() for t in available_titles):
            families = _detect_framework_families(available_titles)
            cat_str = ', '.join(families) if families else 'none detected'
            return compact({
                'error': 'not_configured',
                'message': (
                    f"{framework} compliance framework is not configured on this tenant. "
                    f"Available frameworks: {cat_str}. "
                    f"Use get_compliance_posture() without a framework filter to see all "
                    f"configured policies."
                ),
                'availableFrameworks': available_titles,
                'suggestion': (
                    f"Use get_compliance_posture() without framework filter to see all "
                    f"configured policies, or ask about {' or '.join(families[:2]) if families else 'available'} compliance."
                ),
            })

    # --- Strategy 0: PC v4 posture instances summary (fast) ---
    _log("Compliance posture: trying v4 posture instances summary...")
    instances_url = f"{BASE_URL}/rest/4.0/compliance/posture/instances"
    if framework:
        instances_url += f"?filter=framework:{framework}"
    instances_data = api_get(instances_url, timeout=60)
    if instances_data:
        try:
            import json as _json
            instances_json = _json.loads(instances_data if isinstance(instances_data, str) else instances_data.decode())
            parsed = _parse_controls_from_instances(instances_json, framework, platform, limit)
            if parsed:
                parsed['source'] = 'pc_instances_v4'
                out = _add_compliance_followups(parsed)
                result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                return result
        except Exception:
            _log("Compliance posture: instances endpoint did not return usable JSON")

    # --- Strategy 1: PC v4 — list policies, then get posture per policy ---
    _log("Compliance posture: listing policies via v4 API...")
    policy_list_url = f"{BASE_URL}/api/4.0/fo/compliance/policy/?action=list"
    if framework:
        policy_list_url += f"&search_keyword={framework}"
    policy_data = api_get(policy_list_url, timeout=120)
    policy_ids = []
    if policy_data:
        try:
            policy_root = ET.fromstring(policy_data if isinstance(policy_data, (str, bytes)) else policy_data)
            for policy in (policy_root.findall('.//POLICY') or policy_root.findall('.//COMPLIANCE_POLICY') or []):
                pid = policy.findtext('ID', '') or policy.findtext('POLICY_ID', '')
                ptitle = policy.findtext('TITLE', '') or policy.findtext('NAME', '') or ''
                if pid:
                    if framework and framework.lower() not in ptitle.lower():
                        continue
                    policy_ids.append(pid)
        except ET.ParseError:
            _log("Compliance posture: policy list returned non-XML")

    if policy_ids:
        _log(f"Compliance posture: found {len(policy_ids)} policies, fetching posture (max 5) in parallel...")
        policy_tasks = {
            f"policy_{pid}": (lambda p=pid: api_get(
                f"{BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list&policy_id={p}",
                timeout=120
            ))
            for pid in policy_ids[:5]
        }
        policy_results = _run_concurrent(**policy_tasks)
        for pid in policy_ids[:5]:
            posture_data = policy_results.get(f"policy_{pid}")
            if posture_data:
                try:
                    root = ET.fromstring(posture_data if isinstance(posture_data, (str, bytes)) else posture_data)
                    parsed = _parse_controls(root)
                    if parsed:
                        parsed['source'] = 'pc_posture_v4'
                        out = _add_compliance_followups(parsed)
                        result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                        disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                        return result
                except ET.ParseError:
                    continue

    # --- Strategy 2: PC posture info (no policy_id) ---
    _log("Compliance posture: trying posture/info endpoint...")
    data = api_get(f"{BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list", timeout=120)
    if data:
        try:
            root = ET.fromstring(data if isinstance(data, (str, bytes)) else data)
            parsed = _parse_controls(root)
            if parsed:
                parsed['source'] = 'pc_posture'
                out = _add_compliance_followups(parsed)
                result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                return result
        except ET.ParseError:
            _log("Compliance posture: posture/info returned non-XML")

    # --- Strategy 3: PC control list ---
    _log("Compliance posture: trying control list endpoint...")
    data2 = api_get(f"{BASE_URL}/api/2.0/fo/compliance/control/?action=list", timeout=60)
    if data2:
        try:
            root2 = ET.fromstring(data2 if isinstance(data2, (str, bytes)) else data2)
            parsed2 = _parse_controls(root2)
            if parsed2:
                parsed2['source'] = 'pc_control_list'
                out = _add_compliance_followups(parsed2)
                result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                return result
        except ET.ParseError:
            _log("Compliance posture: control list returned non-XML")

    # --- Strategy 4: fall back to cloud compliance (get_compliance_gaps) ---
    # Only use cloud fallback when no framework filter or when it matches cloud data
    # (cloud data is CIS-based). Skip for non-CIS frameworks to prevent wrong-framework results.
    _cloud_fw_match = not framework or 'cis' in framework.lower() or 'cloud' in framework.lower()
    if _cloud_fw_match:
        _log("Compliance posture: falling back to cloud compliance gaps...")
        try:
            gaps = get_compliance_gaps(limit=limit)
            if gaps and (gaps.get('failingControls', 0) > 0 or gaps.get('pass_pct', 0) > 0):
                total_failing = gaps.get('failingControls', 0)
                pass_rate = gaps.get('pass_pct', 0)
                total_ctrl = int(total_failing / (1 - pass_rate / 100)) if pass_rate < 100 and total_failing else total_failing
                passing = total_ctrl - total_failing

                res = _empty_result()
                res['summary']['controls'] = total_ctrl
                res['summary']['passing'] = passing
                res['summary']['failing'] = total_failing
                res['summary']['pass_pct'] = pass_rate
                res['summary']['frameworks'] = ['Cloud-CIS']
                res['topFailingControls'] = [
                    {
                        'controlId': f_item.get('controlId', ''),
                        'title': '',
                        'framework': 'Cloud-CIS',
                        'failingAssets': f_item.get('failCount', 0),
                        'severity': 'HIGH',
                    }
                    for f_item in gaps.get('topFailing', [])[:limit]
                ]
                res['source'] = 'cloud_compliance_fallback'
                res['note'] = 'Data from cloud compliance evaluations (TotalCloud). Enable Policy Compliance module for on-prem/endpoint posture.'
                out = _add_compliance_followups(_with_meta(res, 'topFailingControls'))
                result = _apply_detail_level(out, detail, list_keys=['topFailingControls'])
                disk_cache.set(_cache_key, result, TTL_COMPLIANCE)
                return result
        except Exception as e:
            _log(f"Compliance posture: cloud fallback failed: {e}")

    # --- No data available ---
    res = _empty_result()
    if framework:
        # Specific framework requested but no data found — return "not configured"
        available = _get_available_policy_titles()
        families = _detect_framework_families(available)
        cat_str = ', '.join(families) if families else 'none found'
        res['error'] = (
            f"{framework} compliance data not available on this tenant. "
            f"Configured policy families: {cat_str}. "
            f"Use get_compliance_posture() without framework filter to see all "
            f"configured policies, or get_compliance_posture(framework='list') "
            f"to list available frameworks."
        )
        res['availableFrameworks'] = families
    else:
        res['error'] = 'PC module not licensed or no compliance data available'
        res['suggestion'] = 'Enable the Qualys Policy Compliance (PC) module, or use get_cloud_risk() for cloud CIS compliance.'
    res['_followups'] = []
    return _with_meta(res, 'topFailingControls')


# ---------------------------------------------------------------------------
# trurisk_score
# ---------------------------------------------------------------------------

def trurisk_score(days: int = 30, breakdown_by: str = "tag", detail: str = "standard") -> dict:
    """Org-level TruRisk score with trending and breakdown."""
    result = {'aggregate': {}, 'trend': {}, 'topAssets': [], 'topQIDs': [], 'breakdown': []}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT00:00:00Z')

    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        risk_100=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "100"}]),
        top_assets=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}],
            limit=100, fields="truRisk,tags,operatingSystem,tagList,vulnerabilities"
        ),
    )

    total = concurrent.get('total') or 0
    result['aggregate'] = {
        'totalAssets': total,
        'criticalRisk_900plus': concurrent.get('risk_900') or 0,
        'highRisk_700plus': concurrent.get('risk_700') or 0,
        'elevatedRisk_500plus': concurrent.get('risk_500') or 0,
        'anyRisk_100plus': concurrent.get('risk_100') or 0,
    }

    top_assets = concurrent.get('top_assets') or []
    top_assets.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for asset in top_assets[:10]:
        tags = []
        for t in (asset.get('tagList') or asset.get('tags') or []):
            tag_name = t.get('name', '') if isinstance(t, dict) else str(t)
            if tag_name:
                tags.append(tag_name)
        result['topAssets'].append({
            'assetId': str(asset.get('assetId', '')),
            'hostname': short_host(asset.get('dnsHostName', '') or asset.get('dnsName', '')),
            'ip': asset.get('address', ''),
            'truriskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
            'tags': tags[:5],
        })

    r900 = concurrent.get('risk_900') or 0
    r700 = concurrent.get('risk_700') or 0
    r500 = concurrent.get('risk_500') or 0
    r100 = concurrent.get('risk_100') or 0
    if total > 0:
        weighted = (r900 * 950 + (r700 - r900) * 800 + (r500 - r700) * 600
                    + (r100 - r500) * 300 + (total - r100) * 50)
        avg_now = round(weighted / total)
    else:
        avg_now = 0
    result['aggregate']['avgTruRisk'] = avg_now

    delta = 0
    if delta < -5:
        direction = 'improving'
        arrow = '\u2193'
    elif delta > 5:
        direction = 'worsening'
        arrow = '\u2191'
    else:
        direction = 'stable'
        arrow = '\u2192'

    result['trend'] = {
        'days': days,
        'avgTruRiskCurrent': round(avg_now),
        'avgTruRiskPrior': round(avg_now),
        'delta': round(delta),
        'direction': direction,
        'display': f"TruRisk: {round(avg_now)} {arrow} {direction}",
    }

    qid_risk = {}
    for asset in top_assets[:50]:
        vulns = asset.get('vulnerabilities') or {}
        asset_risk = int(asset.get('riskScore') or 0)
        vuln_count = vulns.get('count', 0) or 0
        if vuln_count > 0 and asset_risk > 0:
            for qid_entry in (vulns.get('list') or [])[:20]:
                qid_val = qid_entry.get('qid') or qid_entry.get('qds', {}).get('qid')
                if qid_val:
                    qid_risk[qid_val] = qid_risk.get(qid_val, 0) + (asset_risk // max(vuln_count, 1))
    top_qids = sorted(qid_risk.items(), key=lambda x: -x[1])[:10]
    result['topQIDs'] = [{'qid': q, 'riskContribution': r} for q, r in top_qids]

    if breakdown_by == 'tag' and top_assets:
        tag_scores = {}
        for asset in top_assets:
            score = int(asset.get('riskScore') or 0)
            asset_tags = asset.get('tagList') or asset.get('tags') or []
            tag_names = []
            for t in asset_tags:
                name = t.get('name', '') if isinstance(t, dict) else str(t)
                if name:
                    tag_names.append(name)
            if not tag_names:
                tag_names = ['Untagged']
            for tn in tag_names:
                if tn not in tag_scores:
                    tag_scores[tn] = []
                tag_scores[tn].append(score)
        breakdown = []
        for tn, scores in tag_scores.items():
            breakdown.append({
                'tag': tn,
                'assetCount': len(scores),
                'avgTruRisk': round(sum(scores) / len(scores)),
                'maxTruRisk': max(scores),
            })
        breakdown.sort(key=lambda x: -x['avgTruRisk'])
        result['breakdown'] = breakdown[:20]

    out = _with_meta(result, 'topAssets')
    return _apply_detail_level(out, detail, list_keys=['topAssets', 'topQIDs', 'breakdown'])


# ---------------------------------------------------------------------------
# reports_agg  (no detail param — pass-through to API)
# ---------------------------------------------------------------------------

def reports_agg(action: str, report_id: str = "", template_id: str = "", asset_group_ids: str = "",
                template_name: str = "", report_title: str = "", output_format: str = "pdf") -> dict:
    """Unified report operations — list, templates, generate, status, download, delete."""
    action = action.strip().lower()

    if action == 'list':
        data = api_get(f"{BASE_URL}/api/2.0/fo/report/?action=list", timeout=30)
        if not data:
            return compact({'error': 'Failed to fetch report list', 'reports': [], '_meta': {'returned': 0, 'total': 0, 'truncated': False}})
        report_list = []
        try:
            root = ET.fromstring(data)
            for r in root.findall('.//REPORT'):
                report_list.append({
                    'id': r.findtext('ID', ''),
                    'title': r.findtext('TITLE', ''),
                    'type': r.findtext('TYPE', ''),
                    'status': r.findtext('STATUS/STATE', ''),
                    'percentComplete': r.findtext('STATUS/PERCENT', ''),
                    'launchDatetime': short_date(r.findtext('LAUNCH_DATETIME', '')),
                    'outputFormat': r.findtext('OUTPUT_FORMAT', ''),
                    'size': r.findtext('SIZE', ''),
                })
        except ET.ParseError:
            return compact({'error': 'Failed to parse report list XML', 'reports': [], '_meta': {'returned': 0, 'total': 0, 'truncated': False}})
        return compact({'total': len(report_list), 'reports': report_list,
                         '_meta': {'returned': len(report_list), 'total': len(report_list), 'truncated': False}})

    elif action == 'templates':
        data = api_get(f"{BASE_URL}/api/2.0/fo/report/template/?action=list", timeout=30)
        if not data:
            try:
                tpl_url = f"{BASE_URL}/api/2.0/fo/report/template/?action=list"
                tpl_req = Request(tpl_url, data=b'', method='POST')
                tpl_req.add_header('Authorization', f'Basic {BASIC_AUTH}')
                tpl_req.add_header('X-Requested-With', 'qualys-mcp')
                with _open(tpl_req, timeout=30) as resp:
                    data = resp.read()
            except Exception:
                pass
        if not data:
            return compact({'error': 'Failed to fetch report templates (API returned no data — check subscription permissions for /fo/report/template/)', 'templates': [], '_meta': {'returned': 0, 'total': 0, 'truncated': False}})
        templates = []
        try:
            root = ET.fromstring(data)
            for t in root.findall('.//REPORT_TEMPLATE'):
                title = t.findtext('TITLE', '')
                if template_name and template_name.lower() not in title.lower():
                    continue
                templates.append({
                    'id': t.findtext('ID', ''),
                    'title': title,
                    'type': t.findtext('TYPE', ''),
                    'isGlobal': t.findtext('GLOBAL', '') == '1',
                })
        except ET.ParseError:
            return compact({'error': 'Failed to parse template list XML', 'templates': [], '_meta': {'returned': 0, 'total': 0, 'truncated': False}})
        return compact({'total': len(templates), 'templates': templates,
                         '_meta': {'returned': len(templates), 'total': len(templates), 'truncated': False}})

    elif action == 'generate':
        if not template_id:
            return compact({'error': "template_id is required for action='generate'. Use reports(action='templates') to find available templates."})
        params = {'action': 'launch', 'template_id': template_id, 'output_format': output_format}
        if report_title:
            params['report_title'] = report_title
        if asset_group_ids:
            params['asset_group_ids'] = asset_group_ids
        post_data = urlencode(params).encode()
        req = Request(f"{BASE_URL}/api/2.0/fo/report/", data=post_data, method='POST')
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
        req.add_header('X-Requested-With', 'qualys-mcp')
        try:
            with _open(req, timeout=60) as resp:
                body = resp.read()
        except HTTPError as e:
            body = e.read() if hasattr(e, 'read') else b''
            _log(f"Report launch error {e.code}")
            return compact({'error': f'API error {e.code}', 'detail': body.decode(errors='replace')[:500]})
        except Exception as e:
            return compact({'error': str(e)})
        try:
            root = ET.fromstring(body)
            text = root.findtext('.//TEXT', '')
            rid = ''
            for item in root.findall('.//ITEM'):
                if item.findtext('KEY', '') == 'ID':
                    rid = item.findtext('VALUE', '')
                    break
            if rid:
                return compact({'reportId': rid, 'message': text, '_meta': {'returned': 1, 'total': 1, 'truncated': False}})
            return compact({'error': text or 'Unknown error launching report'})
        except ET.ParseError:
            return compact({'error': 'Failed to parse launch response', 'raw': body.decode(errors='replace')[:500]})

    elif action == 'status':
        if not report_id:
            return compact({'error': "report_id is required for action='status'"})
        data = api_get(f"{BASE_URL}/api/2.0/fo/report/?action=list&id={report_id}", timeout=30)
        if not data:
            return compact({'error': 'Failed to fetch report status'})
        try:
            root = ET.fromstring(data)
            r = root.find('.//REPORT')
            if r is None:
                return compact({'error': f'Report {report_id} not found'})
            return compact({
                'id': r.findtext('ID', ''),
                'title': r.findtext('TITLE', ''),
                'status': r.findtext('STATUS/STATE', ''),
                'percentComplete': r.findtext('STATUS/PERCENT', ''),
                'outputFormat': r.findtext('OUTPUT_FORMAT', ''),
                'size': r.findtext('SIZE', ''),
                'launchDatetime': short_date(r.findtext('LAUNCH_DATETIME', '')),
                '_meta': {'returned': 1, 'total': 1, 'truncated': False},
            })
        except ET.ParseError:
            return compact({'error': 'Failed to parse report status XML'})

    elif action == 'download':
        if not report_id:
            return compact({'error': "report_id is required for action='download'"})
        url = f"{BASE_URL}/api/2.0/fo/report/?action=fetch&id={report_id}"
        req = Request(url)
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
        req.add_header('X-Requested-With', 'qualys-mcp')
        try:
            with _open(req, timeout=120) as resp:
                content_type = resp.headers.get('Content-Type', 'application/octet-stream')
                body = resp.read()
        except HTTPError as e:
            return compact({'error': f'API error {e.code}'})
        except Exception as e:
            return compact({'error': str(e)})
        text_types = ('text/', 'application/xml', 'application/csv')
        if any(content_type.startswith(t) for t in text_types):
            return compact({
                'reportId': report_id, 'contentType': content_type,
                'encoding': 'text', 'data': body.decode(errors='replace'),
                '_meta': {'returned': 1, 'total': 1, 'truncated': False},
            })
        return compact({
            'reportId': report_id, 'contentType': content_type,
            'encoding': 'base64', 'data': base64.b64encode(body).decode(),
            '_meta': {'returned': 1, 'total': 1, 'truncated': False},
        })

    elif action == 'delete':
        if not report_id:
            return compact({'error': "report_id is required for action='delete'"})
        post_data = urlencode({'action': 'delete', 'id': report_id}).encode()
        req = Request(f"{BASE_URL}/api/2.0/fo/report/", data=post_data, method='POST')
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
        req.add_header('X-Requested-With', 'qualys-mcp')
        try:
            with _open(req, timeout=30) as resp:
                body = resp.read()
        except HTTPError as e:
            body = e.read() if hasattr(e, 'read') else b''
            return compact({'error': f'API error {e.code}', 'detail': body.decode(errors='replace')[:500]})
        except Exception as e:
            return compact({'error': str(e)})
        try:
            root = ET.fromstring(body)
            text = root.findtext('.//TEXT', '')
            return compact({'reportId': report_id, 'message': text or 'Report deleted', '_meta': {'returned': 1, 'total': 1, 'truncated': False}})
        except ET.ParseError:
            return compact({'reportId': report_id, 'message': 'Report deleted', '_meta': {'returned': 1, 'total': 1, 'truncated': False}})

    else:
        return compact({'error': f"Unknown action '{action}'. Valid actions: list, templates, generate, status, download, delete"})


# ---------------------------------------------------------------------------
# summarize_investigation_agg  (no detail param — text output)
# ---------------------------------------------------------------------------

def summarize_investigation_agg(findings: str, audience: str = "technical") -> str:
    """Generate a narrative summary of an investigation for sharing with team or management."""
    audience = (audience or 'technical').lower().strip()
    if audience not in ('technical', 'management', 'executive'):
        audience = 'technical'

    data = {}
    try:
        data = json.loads(findings)
    except (json.JSONDecodeError, TypeError):
        pass

    sections = []

    if audience == 'technical':
        sections.append('# Security Investigation Report\n')
        sections.append('## Scope')

        if data:
            topic = data.get('topic', data.get('cve', 'Security Investigation'))
            risk = data.get('risk_level', 'unknown')
            sections.append(f'**Investigation:** {topic}')
            sections.append(f'**Risk Level:** {risk.upper()}\n')

            facts = data.get('key_facts', [])
            if facts:
                sections.append('## Key Findings')
                for f in facts:
                    sections.append(f'- {f}')

            inv_findings = data.get('findings', {})
            if inv_findings:
                sections.append('\n## Technical Details')
                for key, val in inv_findings.items():
                    if val and key != 'prior_investigation':
                        sections.append(f'\n### {key.replace("_", " ").title()}')
                        if isinstance(val, dict):
                            summary = val.get('summary', '')
                            if summary:
                                sections.append(str(summary))
                            for k, v in val.items():
                                if k not in ('summary', '_meta', '_followups', '_next', '_gaps') and v:
                                    sections.append(f'- **{k}:** {json.dumps(v) if isinstance(v, (list, dict)) else v}')
                        else:
                            sections.append(str(val)[:500])

            actions = data.get('recommended_actions', [])
            if actions:
                sections.append('\n## Recommended Actions')
                for i, a in enumerate(actions, 1):
                    sections.append(f'{i}. {a}')

            if data.get('qids'):
                sections.append(f'\n**QIDs:** {", ".join(str(q) for q in data["qids"][:10])}')
            if data.get('severity'):
                sections.append(f'**Severity:** {data["severity"]}/5')
            if data.get('qds'):
                sections.append(f'**QDS:** {data["qds"]}/100')
        else:
            sections.append(findings)

    elif audience == 'management':
        sections.append('# Security Risk Summary\n')

        if data:
            topic = data.get('topic', data.get('cve', 'Security Assessment'))
            risk = data.get('risk_level', 'unknown')
            sections.append(f'## {topic} — Risk Assessment\n')
            sections.append(f'**Overall Risk:** {risk.upper()}\n')

            facts = data.get('key_facts', [])
            if facts:
                sections.append('### Impact')
                for f in facts:
                    sections.append(f'- {f}')

            summary = data.get('summary', '')
            if isinstance(summary, str) and summary:
                sections.append(f'\n### Summary\n{summary}')
            elif isinstance(summary, dict):
                affected = summary.get('assetsWithSoftware', 0)
                if affected:
                    sections.append(f'\n**Affected systems:** {affected}')

            actions = data.get('recommended_actions', [])
            if actions:
                sections.append('\n### Remediation Plan')
                for i, a in enumerate(actions, 1):
                    sections.append(f'{i}. {a}')
                sections.append('\n**Estimated timeline:** Immediate action required for critical items; standard SLA for remaining.')
        else:
            sections.append('### Findings Summary\n')
            sections.append(findings[:2000])

    elif audience == 'executive':
        sections.append('# Executive Security Brief\n')

        if data:
            topic = data.get('topic', data.get('cve', 'Security'))
            risk = data.get('risk_level', 'unknown')

            risk_labels = {
                'critical': 'CRITICAL — Immediate business risk requiring urgent action',
                'high': 'HIGH — Significant risk to operations, action needed this week',
                'medium': 'MEDIUM — Moderate risk, scheduled remediation recommended',
                'low': 'LOW — Minimal business impact, routine maintenance',
            }
            sections.append(f'**Topic:** {topic}')
            sections.append(f'**Business Risk:** {risk_labels.get(risk, risk.upper())}\n')

            facts = data.get('key_facts', [])
            if facts:
                sections.append('### What This Means')
                for f in facts:
                    sections.append(f'- {f}')

            actions = data.get('recommended_actions', [])
            if actions:
                sections.append('\n### What We Need To Do')
                for a in actions[:3]:
                    sections.append(f'- {a}')

            sections.append('\n### Cost Perspective')
            if risk in ('critical', 'high'):
                sections.append('- **Cost of inaction:** Potential breach, regulatory fines, operational disruption')
                sections.append('- **Cost of remediation:** Patch deployment and validation effort (days, not weeks)')
                sections.append('- **Recommendation:** Approve immediate remediation to minimize exposure window')
            else:
                sections.append('- **Current exposure:** Within acceptable risk tolerance with planned remediation')
                sections.append('- **Recommendation:** Continue standard remediation cycles')
        else:
            sections.append('### Brief\n')
            sections.append(findings[:1000])

    result_text = '\n'.join(sections)

    _track_usage('summarize_investigation', {'audience': audience},
                 {'gaps_found': 0, 'next_suggestions': 0})

    return result_text


# ---------------------------------------------------------------------------
# cache_status_agg  (no detail param — admin tool)
# ---------------------------------------------------------------------------

def cache_status_agg(clear: bool = False) -> dict:
    """Show cache stats or clear all caches."""
    from qualys.cache import disk_cache, DB_PATH
    from qualys.api import clear_memory_cache
    global ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    global SCANNER_CACHE, SCANNER_CACHE_TIME

    now = datetime.now(timezone.utc)
    result = {
        'kb_entries': len(KB_CACHE),
        'detection_entries': len(DETECTION_CACHE),
        'cache_age_s': None,
        'qds_entries': len(QDS_CACHE),
        'was_keys': len(WAS_CACHE),
        'scanner_cached': SCANNER_CACHE is not None,
        'scanner_cache_age_seconds': None,
        'etm_result_cached': ETM_RESULT_CACHE is not None,
        'etm_cache_age_seconds': None,
        'bearer_token_age_seconds': None,
        'disk_cache_path': str(DB_PATH),
        'disk_cache_size_kb': disk_cache.size_kb(),
    }

    # Disk age per cached key
    disk_keys = disk_cache.keys()
    if disk_keys:
        result['disk_age_s'] = {k: disk_cache.age(k) for k in disk_keys}

    if DETECTION_CACHE_TIME:
        newest = max(DETECTION_CACHE_TIME.values())
        result['cache_age_s'] = int((now - newest).total_seconds())
    if BEARER_TOKEN_TIME:
        result['bearer_token_age_seconds'] = int((now - BEARER_TOKEN_TIME).total_seconds())
    if SCANNER_CACHE_TIME:
        result['scanner_cache_age_seconds'] = int((now - SCANNER_CACHE_TIME).total_seconds())
    if ETM_RESULT_CACHE_TIME:
        result['etm_cache_age_seconds'] = int((now - ETM_RESULT_CACHE_TIME).total_seconds())

    if clear:
        clear_memory_cache()
        disk_cache.clear()
        result['cleared'] = True
        result['kb_entries'] = 0
        result['detection_entries'] = 0
        result['qds_entries'] = 0
        result['was_keys'] = 0
        result['scanner_cached'] = False
        result['etm_result_cached'] = False
        result['cache_age_s'] = None
        result['scanner_cache_age_seconds'] = None
        result['etm_cache_age_seconds'] = None
        result['disk_cache_size_kb'] = 0
        result.pop('disk_age_s', None)

    result['_meta'] = {'returned': 1, 'total': 1, 'truncated': False}
    return compact(result)


# ---------------------------------------------------------------------------
# Policy Audit aggregator
# ---------------------------------------------------------------------------

def policy_audit_agg(label: str = "", technology: str = "", policy_id: int = 0, limit: int = 20, detail: str = "standard") -> dict:
    """Browse CIS benchmarks, DISA STIGs, and other compliance policies from the Qualys library."""
    result = {'labels': [], 'policies': [], 'policyDetail': None, 'summary': ''}

    if policy_id:
        pd = get_policy_detail(policy_id)
        result['policyDetail'] = pd
        result['summary'] = f"Policy detail for ID {policy_id}: {pd.get('policyTitle', 'Unknown')}"
        return _with_meta(result, 'policies')

    concurrent = _run_concurrent(
        labels=lambda: get_policy_labels(),
        policies=lambda: get_policy_list(limit=limit),
    )

    labels = concurrent.get('labels') or []
    policies = concurrent.get('policies') or []

    if label:
        label_lower = label.lower()
        label_id = None
        for l in labels:
            if label_lower in l.get('labelName', '').lower():
                label_id = l.get('labelId')
                break
        if label_id:
            policies = get_policy_list(label_id=label_id, limit=limit)

    result['labels'] = labels
    result['policies'] = policies[:limit]
    result['totalPolicies'] = len(policies)
    result['summary'] = f"{len(policies)} compliance policies available across {len(labels)} categories"

    if labels:
        label_names = [l.get('labelName', '') for l in labels[:10]]
        result['summary'] += f" ({', '.join(label_names)})"

    return _apply_detail_level(_with_meta(result, 'policies', len(policies)), detail, list_keys=['policies', 'labels'])


# ---------------------------------------------------------------------------
# SaaS Detection and Response aggregator
# ---------------------------------------------------------------------------

def saasdr_controls_agg(limit: int = 50, detail: str = "standard") -> dict:
    """List SaaS security controls from Qualys SaaS Detection and Response."""
    data = get_saasdr_controls(limit=limit)
    if not data:
        return {'controls': [], 'summary': 'SaaS Detection and Response may not be enabled on this subscription.', '_meta': {'returned': 0, 'total': 0, 'truncated': False}}

    controls = data.get('content', [])
    total = data.get('totalElements', len(controls))

    result = {
        'controls': controls[:limit],
        'totalControls': total,
        'summary': f"{total} SaaS security controls configured",
    }

    return _apply_detail_level(_with_meta(result, 'controls', total), detail, list_keys=['controls'])


# ---------------------------------------------------------------------------
# TotalCloud v2 OCI resources aggregator
# ---------------------------------------------------------------------------

def oci_resources_agg(resource_type: str = "INSTANCE", limit: int = 50, detail: str = "standard") -> dict:
    """List OCI cloud resources via TotalCloud v2 API."""
    data = get_cloud_resources(provider='oci', resource_type=resource_type, limit=limit)

    content = data.get('content', [])
    total = data.get('totalHits', len(content))

    resources = []
    for r in content[:limit]:
        resources.append({
            'resourceId': r.get('resourceId', ''),
            'region': r.get('region', ''),
            'name': r.get('name', r.get('resourceId', '')[:30]),
            'evaluatedOn': r.get('evaluatedOn', ''),
            'connectorId': r.get('connectorId', ''),
        })

    result = {
        'resources': resources,
        'totalResources': total,
        'resourceType': resource_type,
        'summary': f"{total} OCI {resource_type.lower()} resources found",
    }

    return _apply_detail_level(_with_meta(result, 'resources', total), detail, list_keys=['resources'])


# ---------------------------------------------------------------------------
# TotalAI aggregator
# ---------------------------------------------------------------------------

def totalai_summary(limit: int = 20, detail: str = "standard") -> dict:
    """AI security posture — TotalAI model detections + AI asset inventory."""
    result = {'totalDetections': 0, 'aiAssets': 0, 'detections': [],
              'byCategory': {}, 'bySeverity': {}, 'summary': ''}

    concurrent = _run_concurrent(
        detection_count=lambda: get_totalai_detection_count(),
        detections=lambda: get_totalai_detections(limit=limit),
        ai_assets=lambda: csam_count([{"field": "software.name", "operator": "CONTAINS", "value": "GPT"}]),
    )

    total_detections = concurrent.get('detection_count') or 0
    search_result = concurrent.get('detections') or {}
    ai_assets = concurrent.get('ai_assets') or 0

    detections = search_result.get('content', [])
    result['totalDetections'] = total_detections
    result['aiAssets'] = ai_assets

    by_category = {}
    by_severity = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
    jailbreak_count = 0

    for d in detections:
        sev = d.get('severity', 0)
        if sev in by_severity:
            by_severity[sev] += 1
        if d.get('isJailBreak'):
            jailbreak_count += 1
        for cat in d.get('categories', []):
            name = cat.get('name', 'Other')
            by_category[name] = by_category.get(name, 0) + 1

        result['detections'].append({
            'id': d.get('id'),
            'qid': d.get('qid'),
            'name': d.get('name', ''),
            'attack': d.get('attack', ''),
            'severity': sev,
            'result': d.get('result', ''),
            'isJailBreak': d.get('isJailBreak', False),
            'failTestPercentage': d.get('failTestPercentage', 0),
            'model': (d.get('model') or {}).get('name', ''),
            'categories': [c.get('name', '') for c in d.get('categories', [])],
            'owaspTopTen': [o.get('name', '') for o in d.get('owaspTopTen', [])],
        })

    result['byCategory'] = dict(sorted(by_category.items(), key=lambda x: -x[1]))
    result['bySeverity'] = by_severity
    result['jailbreakCount'] = jailbreak_count

    parts = [f"{total_detections} TotalAI model detections"]
    if jailbreak_count:
        parts.append(f"{jailbreak_count} jailbreak attacks")
    if by_category:
        top_cats = list(result['byCategory'].keys())[:3]
        parts.append(f"top categories: {', '.join(top_cats)}")
    if ai_assets:
        parts.append(f"{ai_assets} AI/GPT assets in inventory")
    result['summary'] = '. '.join(parts) + '.'

    return _apply_detail_level(_with_meta(result, 'detections', total_detections), detail, list_keys=['detections'])
