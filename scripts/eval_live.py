#!/usr/bin/env python3
"""Live evaluation harness for qualys-mcp tools.

Imports qualys_mcp module directly and calls every registered MCP tool function,
recording status, latency, and output summary. Outputs a results table + JSON.

Usage:
    cd /path/to/qualys-mcp
    /path/to/.venv/bin/python3.12 scripts/eval_live.py
"""

import json
import os
import sys
import time
import traceback

# Load .env manually (no dotenv dependency needed)
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                os.environ.setdefault(key.strip(), val.strip())

# Add project root to path so we can import qualys_mcp
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import qualys_mcp  # noqa: E402

# ── Deprecated tools to skip (they just return error dicts) ─────────────
DEPRECATED = {
    'get_cdr_findings', 'get_asset_risk', 'get_asset_full_profile',
    'get_environment_summary', 'get_pm_status', 'get_tags',
    'get_asset_groups', 'get_assets_by_tag', 'list_reports',
    'list_report_templates', 'generate_report', 'get_report_status',
    'download_report', 'delete_report',
}

# ── Tool call specs: (function, kwargs, dependencies) ───────────────────
# Dependencies are tool names whose results we need first.
# A dependency result is stored in RESULTS[name] and can be referenced.

RESULTS = {}  # populated as tools complete


def get_result(name, key=None):
    """Get a previously-collected result value."""
    r = RESULTS.get(name, {}).get('result')
    if r is None:
        return None
    if key:
        if isinstance(r, dict):
            return r.get(key)
        return None
    return r


def get_first_asset_id():
    """Extract first asset ID from csam_search or get_asset_inventory results."""
    r = get_result('get_asset_inventory')
    if r and isinstance(r, dict):
        assets = r.get('assets', [])
        if assets:
            return str(assets[0].get('assetId', assets[0].get('id', '')))
    return None


def get_first_report_id():
    """Extract first report ID from reports(action='list') results."""
    r = get_result('reports_list')
    if r and isinstance(r, dict):
        reports = r.get('reports', [])
        if reports:
            return str(reports[0].get('id', ''))
    return None


def get_first_template_id():
    """Extract first template ID from reports(action='templates') results."""
    r = get_result('reports_templates')
    if r and isinstance(r, dict):
        templates = r.get('templates', [])
        if templates:
            return str(templates[0].get('id', ''))
    return None


# Errors that indicate tenant licensing/permission limits, not code bugs
KNOWN_LIMITATIONS = [
    'not licensed', 'not enabled', 'not subscribed', 'module not',
    'no compliance data', 'no asset_id', 'no tag found', 'no report_id',
]


def classify_result(result):
    """Classify a tool result as ok, error, skip (known limitation), or empty."""
    if result is None:
        return 'empty'
    if isinstance(result, dict):
        if 'error' in result:
            err_msg = str(result['error']).lower()
            if any(lim in err_msg for lim in KNOWN_LIMITATIONS):
                return 'skip'
            return 'error'
        # Check if it has meaningful data
        if not result or all(k.startswith('_') for k in result):
            return 'empty'
        return 'ok'
    if isinstance(result, str):
        return 'ok' if result.strip() else 'empty'
    if isinstance(result, list):
        return 'ok' if result else 'empty'
    return 'ok'


def truncate(val, maxlen=120):
    """Truncate a string representation for display."""
    s = str(val)
    return s[:maxlen] + '...' if len(s) > maxlen else s


def run_tool(name, fn, kwargs=None):
    """Run a single tool function, record timing and result."""
    kwargs = kwargs or {}
    t0 = time.time()
    try:
        result = fn(**kwargs)
        elapsed = time.time() - t0
        status = classify_result(result)
        notes = ''
        if status == 'error' and isinstance(result, dict):
            notes = truncate(result.get('error', ''))
        elif status == 'ok' and isinstance(result, dict):
            meta = result.get('_meta', {})
            if meta:
                notes = f"total={meta.get('total', '?')} returned={meta.get('returned', '?')}"
            else:
                notes = truncate(list(result.keys())[:5])
    except Exception as e:
        elapsed = time.time() - t0
        result = None
        status = 'error'
        notes = truncate(f"{type(e).__name__}: {e}")
        traceback.print_exc(file=sys.stderr)

    RESULTS[name] = {'result': result, 'status': status, 'latency': elapsed, 'notes': notes}
    return status, elapsed, notes


def main():
    print("=" * 90)
    print("Qualys MCP Live Eval Harness")
    print(f"POD: {os.environ.get('QUALYS_POD', 'unknown')}  |  "
          f"BASE_URL: {qualys_mcp.BASE_URL}  |  GATEWAY_URL: {qualys_mcp.GATEWAY_URL}")
    print("=" * 90)
    print()

    # ── Phase 1: Tools with no dependencies ─────────────────────────────
    phase1 = [
        ('cache_status',          qualys_mcp.cache_status,          {}),
        ('get_scanner_health',    qualys_mcp.get_scanner_health,    {}),
        ('get_scan_status',       qualys_mcp.get_scan_status,       {}),
        ('get_morning_report',    qualys_mcp.get_morning_report,    {'quick': True}),
        ('get_weekly_priorities', qualys_mcp.get_weekly_priorities,  {'limit': 5}),
        ('search_vulns',          qualys_mcp.search_vulns,          {'days': 7, 'limit': 10}),
        ('get_cve_details',       qualys_mcp.get_cve_details,       {'cves': 'CVE-2024-3094'}),
        ('get_qid_details',       qualys_mcp.get_qid_details,       {'qids': '38913'}),
        ('get_etm_findings',      qualys_mcp.get_etm_findings,      {}),
        ('get_patch_status',      qualys_mcp.get_patch_status,      {'limit': 5}),
        ('get_eliminate_status',  qualys_mcp.get_eliminate_status,   {}),
        ('get_recommendations',   qualys_mcp.get_recommendations,   {}),
        ('get_asset_inventory',   qualys_mcp.get_asset_inventory,   {'limit': 5}),
        ('get_tech_debt',         qualys_mcp.get_tech_debt,         {'limit': 5}),
        ('get_cloud_risk',        qualys_mcp.get_cloud_risk,        {'limit': 5}),
        ('get_webapp_vulns',      qualys_mcp.get_webapp_vulns,      {'limit': 5}),
        ('get_expiring_certs',    qualys_mcp.get_expiring_certs,    {'days': 90, 'limit': 5}),
        ('get_vuln_exceptions',   qualys_mcp.get_vuln_exceptions,   {'limit': 5}),
        ('get_compliance_posture', qualys_mcp.get_compliance_posture, {'limit': 5}),
        ('get_trurisk_score',     qualys_mcp.get_trurisk_score,     {}),
        ('get_edr_events',        qualys_mcp.get_edr_events,        {'days': 7, 'limit': 5}),
        ('get_fim_events',        qualys_mcp.get_fim_events,        {'days': 1, 'limit': 5}),
        ('reports_list',          qualys_mcp.reports,                {'action': 'list'}),
        ('reports_templates',     qualys_mcp.reports,                {'action': 'templates'}),
        ('get_asset_inventory_tags',   qualys_mcp.get_asset_inventory, {'list_tags': True}),
        ('get_asset_inventory_groups', qualys_mcp.get_asset_inventory, {'list_groups': True}),
    ]

    results_table = []

    for name, fn, kwargs in phase1:
        sys.stdout.write(f"  {name:<40} ... ")
        sys.stdout.flush()
        status, elapsed, notes = run_tool(name, fn, kwargs)
        emoji = {'ok': 'PASS', 'error': 'FAIL', 'empty': 'EMPTY', 'skip': 'SKIP'}[status]
        print(f"{emoji:>5}  {elapsed:6.1f}s  {notes}")
        results_table.append({'tool': name, 'status': status, 'latency': round(elapsed, 2), 'notes': notes})

    # ── Phase 2: Tools that depend on Phase 1 results ───────────────────
    print()
    print("Phase 2: dependent tools")
    print("-" * 90)

    # get_asset needs an asset_id from get_asset_inventory
    asset_id = get_first_asset_id()
    if asset_id:
        phase2 = [
            ('get_asset_summary', qualys_mcp.get_asset, {'asset_id': asset_id, 'detail': 'summary'}),
            ('get_asset_full',    qualys_mcp.get_asset, {'asset_id': asset_id, 'detail': 'full'}),
        ]
    else:
        phase2 = [
            ('get_asset_summary', lambda: {'error': 'no asset_id from phase 1'}, {}),
            ('get_asset_full',    lambda: {'error': 'no asset_id from phase 1'}, {}),
        ]

    # get_risk_by_tag — try a tag from inventory
    tag_name = None
    inv_result = get_result('get_asset_inventory')
    if inv_result and isinstance(inv_result, dict):
        assets = inv_result.get('assets', [])
        for a in assets:
            tags = a.get('tags', [])
            if tags:
                t = tags[0]
                tag_name = t.get('name', '') if isinstance(t, dict) else str(t)
                if tag_name:
                    break
    if not tag_name:
        # Try from list_tags result
        tags_result = get_result('get_asset_inventory_tags')
        if tags_result and isinstance(tags_result, dict):
            tag_list = tags_result.get('tags', [])
            if tag_list:
                tag_name = tag_list[0]
    if tag_name:
        phase2.append(('get_risk_by_tag', qualys_mcp.get_risk_by_tag, {'tag': tag_name, 'limit': 5}))
    else:
        phase2.append(('get_risk_by_tag', lambda: {'error': 'no tag found in phase 1'}, {}))

    # get_image_vulns — needs an image_id (may not have one)
    phase2.append(('get_image_vulns', qualys_mcp.get_image_vulns, {'image_id': 'sha256:test', 'limit': 5}))

    # investigate_cve
    phase2.append(('investigate_cve', qualys_mcp.investigate_cve, {'cve': 'CVE-2024-3094'}))

    # investigate — quick check
    phase2.append(('investigate', qualys_mcp.investigate, {'topic': 'ransomware', 'depth': 'quick'}))

    # summarize_investigation
    phase2.append(('summarize_investigation', qualys_mcp.summarize_investigation,
                   {'findings': '{"vulns": 5, "critical": 2}', 'audience': 'technical'}))

    # reports status (needs a report_id)
    report_id = get_first_report_id()
    if report_id:
        phase2.append(('reports_status', qualys_mcp.reports, {'action': 'status', 'report_id': report_id}))
    else:
        phase2.append(('reports_status', lambda: {'error': 'no report_id from phase 1'}, {}))

    for name, fn, kwargs in phase2:
        sys.stdout.write(f"  {name:<40} ... ")
        sys.stdout.flush()
        status, elapsed, notes = run_tool(name, fn, kwargs)
        emoji = {'ok': 'PASS', 'error': 'FAIL', 'empty': 'EMPTY', 'skip': 'SKIP'}[status]
        print(f"{emoji:>5}  {elapsed:6.1f}s  {notes}")
        results_table.append({'tool': name, 'status': status, 'latency': round(elapsed, 2), 'notes': notes})

    # ── Summary ─────────────────────────────────────────────────────────
    print()
    print("=" * 90)
    ok_count = sum(1 for r in results_table if r['status'] == 'ok')
    err_count = sum(1 for r in results_table if r['status'] == 'error')
    empty_count = sum(1 for r in results_table if r['status'] == 'empty')
    total = len(results_table)
    total_time = sum(r['latency'] for r in results_table)
    print(f"RESULTS: {ok_count}/{total} PASS  |  {err_count} FAIL  |  {empty_count} EMPTY  |  {total_time:.1f}s total")
    print()

    # Print failing tools
    failures = [r for r in results_table if r['status'] == 'error']
    if failures:
        print("FAILURES:")
        for r in failures:
            print(f"  - {r['tool']}: {r['notes']}")
        print()

    # Write JSON results
    out_path = os.path.join(os.path.dirname(__file__), '..', 'eval', 'live_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'pod': os.environ.get('QUALYS_POD', 'unknown'),
            'summary': {'total': total, 'ok': ok_count, 'error': err_count, 'empty': empty_count,
                        'total_latency_s': round(total_time, 2)},
            'results': results_table,
        }, f, indent=2)
    print(f"Results written to {out_path}")
    print("=" * 90)

    # Exit with non-zero if any failures
    sys.exit(1 if err_count > 0 else 0)


if __name__ == '__main__':
    main()
