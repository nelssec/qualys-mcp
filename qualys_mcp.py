#!/usr/bin/env python3
"""Qualys MCP Server - Pure Python implementation using FastMCP"""

import os
import json
import base64
from urllib.request import Request, urlopen
from urllib.parse import urlencode
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from fastmcp import FastMCP

mcp = FastMCP("qualys-mcp")

USERNAME = os.environ.get('QUALYS_USERNAME', '')
PASSWORD = os.environ.get('QUALYS_PASSWORD', '')
BASE_URL = os.environ.get('QUALYS_BASE_URL', '').rstrip('/')
GATEWAY_URL = os.environ.get('QUALYS_GATEWAY_URL', '').rstrip('/')
BASIC_AUTH = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
BEARER_TOKEN = None


def get_bearer_token():
    global BEARER_TOKEN
    if BEARER_TOKEN:
        return BEARER_TOKEN
    try:
        req = Request(f"{GATEWAY_URL}/auth", method='POST')
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urlopen(req, data=b'', timeout=30) as resp:
            BEARER_TOKEN = resp.read().decode().strip()
            return BEARER_TOKEN
    except:
        return None


def api_get(url, gateway=False):
    req = Request(url)
    if gateway:
        token = get_bearer_token()
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    else:
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=60) as resp:
            return resp.read()
    except:
        return None


def get_detections(severity=5, limit=500):
    data = api_get(f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list&severities={severity}&truncation_limit={limit}&status=Active")
    if not data:
        return []
    dets = []
    try:
        root = ET.fromstring(data)
        for host in root.findall('.//HOST'):
            hid, ip = host.findtext('ID', ''), host.findtext('IP', '')
            for d in host.findall('.//DETECTION'):
                dets.append({'host_id': hid, 'ip': ip, 'qid': int(d.findtext('QID', '0')),
                            'severity': int(d.findtext('SEVERITY', '0')), 'status': d.findtext('STATUS', '')})
    except:
        pass
    return dets


def get_kb(qid):
    data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={qid}")
    if not data:
        return None
    try:
        root = ET.fromstring(data)
        v = root.find('.//VULN')
        if not v:
            return None
        return {'qid': qid, 'title': v.findtext('TITLE', ''), 'severity': int(v.findtext('SEVERITY_LEVEL', '0')),
                'cves': [c.findtext('ID', '') for c in v.findall('.//CVE_LIST/CVE')],
                'solution': v.findtext('SOLUTION', ''), 'patch_available': v.findtext('PATCHABLE', '0') == '1'}
    except:
        return None


def get_cve_qids(cve):
    data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=Basic&cve_id={cve}")
    if not data:
        return []
    try:
        return [int(v.findtext('QID')) for v in ET.fromstring(data).findall('.//VULN') if v.findtext('QID')]
    except:
        return []


def get_assets(limit=100):
    data = api_get(f"{GATEWAY_URL}/am/v1/assets?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('assetListData', {}).get('asset', []) if data else []
    except:
        return []


def get_images(limit=100, severity=None):
    url = f"{GATEWAY_URL}/csapi/v1.3/images?pageSize={limit}"
    if severity:
        url += f"&filter=vulnerabilities.severity:{severity}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except:
        return []


def get_containers(limit=100):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/containers?pageSize={limit}&filter=state:RUNNING", gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except:
        return []


def get_connectors(provider='aws', limit=50):
    data = api_get(f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/connectors?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except:
        return []


def get_evaluations(account_id, provider='aws', limit=500):
    data = api_get(f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except:
        return []


def get_cdr(days=7, limit=100):
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    data = api_get(f"{GATEWAY_URL}/cdr-api/rest/v1/findings/?startAt={start.isoformat()}Z&endAt={end.isoformat()}Z&limit={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except:
        return []


@mcp.tool()
def get_weekly_priorities(limit: int = 10) -> dict:
    """Get prioritized security actions for the week. Returns top critical vulns and container risks ranked by severity and impact."""
    result = {'summary': {'totalCritical': 0, 'assetsAffected': 0, 'containersAtRisk': 0, 'patchable': 0},
              'priorities': [], 'byEffort': {'patch': 0, 'config': 0, 'upgrade': 0}}

    dets = get_detections(5, 500)
    qids = {}
    hosts = set()
    for d in dets:
        qid = d['qid']
        if qid not in qids:
            qids[qid] = {'count': 0, 'hosts': set(), 'sev': d['severity']}
        qids[qid]['count'] += 1
        qids[qid]['hosts'].add(d['host_id'])
        hosts.add(d['host_id'])

    for i, (qid, data) in enumerate(sorted(qids.items(), key=lambda x: (x[1]['sev'], len(x[1]['hosts'])), reverse=True)[:limit]):
        kb = get_kb(qid)
        patch = kb.get('patch_available', False) if kb else False
        result['byEffort']['patch' if patch else 'config'] += 1
        if patch:
            result['summary']['patchable'] += 1
        result['priorities'].append({
            'rank': i + 1, 'qid': qid, 'title': kb['title'] if kb else f"QID {qid}",
            'cves': kb.get('cves', [])[:3] if kb else [], 'hosts': len(data['hosts']),
            'effort': 'patch' if patch else 'config', 'fix': (kb.get('solution', '') if kb else '')[:100]
        })

    vuln_imgs = {img.get('imageId') for img in get_images(100, 5)}
    at_risk = [c for c in get_containers(500) if c.get('imageId') in vuln_imgs]
    if at_risk:
        result['priorities'].append({'rank': len(result['priorities']) + 1, 'title': 'Vulnerable containers',
                                     'containers': len(at_risk), 'effort': 'upgrade'})
        result['byEffort']['upgrade'] = len(at_risk)
        result['summary']['containersAtRisk'] = len(at_risk)

    result['summary']['totalCritical'] = len(qids)
    result['summary']['assetsAffected'] = len(hosts)
    return result


@mcp.tool()
def investigate_cve(cve: str) -> dict:
    """Investigate if your environment is affected by a specific CVE. Returns affected hosts, images, and remediation."""
    result = {'cve': cve, 'qids': [], 'affectedHosts': [], 'affectedImages': [], 'patchAvailable': False, 'fix': ''}

    qids = get_cve_qids(cve)
    result['qids'] = qids

    if qids:
        kb = get_kb(qids[0])
        if kb:
            result['patchAvailable'] = kb.get('patch_available', False)
            result['fix'] = kb.get('solution', '')[:500]

    for qid in qids[:2]:
        for d in get_detections(1, 300):
            if d['qid'] == qid:
                result['affectedHosts'].append({'id': d['host_id'], 'ip': d['ip']})

    for img in get_images(200):
        if any(cve in str(v) for v in img.get('vulnerabilities', [])):
            result['affectedImages'].append({'id': img.get('imageId'), 'repo': img.get('repo')})

    result['totalHosts'] = len(result['affectedHosts'])
    result['totalImages'] = len(result['affectedImages'])
    return result


@mcp.tool()
def get_security_posture() -> dict:
    """Get overall security health score and stats across assets, vulns, containers, and cloud."""
    health = 100
    result = {'healthScore': 0, 'assets': {'total': 0, 'highRisk': 0},
              'vulns': {'critical': 0, 'high': 0}, 'containers': {'total': 0, 'atRisk': 0},
              'cloud': {'accounts': 0, 'failedControls': 0}}

    assets = get_assets(500)
    result['assets']['total'] = len(assets)
    result['assets']['highRisk'] = len([a for a in assets if a.get('assetRiskScore', 0) >= 700])
    if assets:
        health -= int(result['assets']['highRisk'] / len(assets) * 50)

    result['vulns']['critical'] = len(get_detections(5, 200))
    result['vulns']['high'] = len(get_detections(4, 200))
    if result['vulns']['critical'] > 50:
        health -= 20
    elif result['vulns']['critical'] > 10:
        health -= 10

    imgs = get_images(500)
    result['containers']['total'] = len(imgs)
    vuln_ids = {i.get('imageId') for i in get_images(100, 5)}
    result['containers']['atRisk'] = len([c for c in get_containers(500) if c.get('imageId') in vuln_ids])

    for p in ['aws', 'azure', 'gcp']:
        conns = get_connectors(p, 20)
        result['cloud']['accounts'] += len(conns)
        if conns:
            acc = conns[0].get('awsAccountId') or conns[0].get('azureSubscriptionId') or conns[0].get('gcpProjectId')
            if acc:
                result['cloud']['failedControls'] += len([e for e in get_evaluations(acc, p, 500) if e.get('result') in ['FAIL', 'FAILED']])

    result['healthScore'] = max(0, health)
    return result


@mcp.tool()
def get_patch_status(limit: int = 20) -> dict:
    """Get patching coverage - how many assets need patches and which patches are most common."""
    result = {'coverage': 0, 'assetsTotal': 0, 'assetsNeedPatches': 0, 'topMissing': []}

    assets = get_assets(500)
    result['assetsTotal'] = len(assets)

    dets = get_detections(5, 500)
    qids = {}
    for d in dets:
        kb = get_kb(d['qid'])
        if kb and kb.get('patch_available'):
            qids[d['qid']] = qids.get(d['qid'], 0) + 1

    result['topMissing'] = [{'qid': q, 'count': c, 'title': (get_kb(q) or {}).get('title', '')}
                           for q, c in sorted(qids.items(), key=lambda x: x[1], reverse=True)[:limit]]

    hosts_need = set(d['host_id'] for d in dets if d['qid'] in qids)
    result['assetsNeedPatches'] = len(hosts_need)
    if result['assetsTotal']:
        result['coverage'] = round((result['assetsTotal'] - len(hosts_need)) / result['assetsTotal'] * 100, 1)

    return result


@mcp.tool()
def get_compliance_gaps(limit: int = 20) -> dict:
    """Get top failing compliance controls that could fail audits."""
    result = {'passRate': 0, 'failingControls': 0, 'topFailing': []}

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
    result['passRate'] = round(passes / total * 100, 1) if total else 0
    return result


@mcp.tool()
def get_cloud_risk(limit: int = 20) -> dict:
    """Get cloud security posture across AWS, Azure, GCP - accounts, failed controls, and threats."""
    result = {'accounts': [], 'failedControls': [], 'threats': [], 'stats': {'total': 0, 'critical': 0}}

    for p in ['aws', 'azure', 'gcp']:
        for c in get_connectors(p, 50):
            acc = c.get('awsAccountId') or c.get('azureSubscriptionId') or c.get('gcpProjectId', '')
            result['accounts'].append({'id': acc, 'provider': p.upper(), 'name': c.get('name', '')})

    result['stats']['total'] = len(result['accounts'])

    if result['accounts']:
        acc = result['accounts'][0]
        fails = {}
        for e in get_evaluations(acc['id'], acc['provider'].lower(), 500):
            if e.get('result') in ['FAIL', 'FAILED']:
                cid = e.get('controlId', '')
                fails[cid] = fails.get(cid, 0) + 1
        result['failedControls'] = [{'id': c, 'count': n} for c, n in sorted(fails.items(), key=lambda x: x[1], reverse=True)[:limit]]

    for f in get_cdr(7, limit):
        sev = str(f.get('severity', ''))
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        result['threats'].append({'severity': sev, 'category': f.get('category', ''), 'resource': f.get('resourceId', '')})

    return result


@mcp.tool()
def get_asset_risk(asset_id: str) -> dict:
    """Get risk summary for a specific asset - risk score, top vulnerabilities, and remediation."""
    result = {'assetId': asset_id, 'riskScore': 0, 'vulns': []}

    for a in get_assets(500):
        if str(a.get('assetId')) == str(asset_id):
            result['ip'] = a.get('address', '')
            result['hostname'] = a.get('dnsName', '')
            result['riskScore'] = int(a.get('assetRiskScore', 0))
            break

    for d in get_detections(4, 500):
        if d['host_id'] == asset_id and len(result['vulns']) < 10:
            kb = get_kb(d['qid'])
            result['vulns'].append({'qid': d['qid'], 'title': kb['title'] if kb else '', 'severity': d['severity']})

    return result


@mcp.tool()
def get_tech_debt(reduction_target: float = 30) -> dict:
    """Get EOL/EOS software tech debt and a plan to reduce it by target percentage."""
    result = {'stats': {'total': 0, 'eol': 0, 'percent': 0}, 'eolSystems': [], 'plan': {'target': reduction_target, 'toFix': 0}}

    assets = get_assets(500)
    result['stats']['total'] = len(assets)

    os_counts = {}
    for a in assets:
        os_info = a.get('operatingSystem', {})
        if isinstance(os_info, dict):
            lc = os_info.get('lifecycle', {})
            if isinstance(lc, dict) and lc.get('stage') in ['EOL', 'EOS']:
                result['stats']['eol'] += 1
                name = os_info.get('osName', 'Unknown')
                os_counts[name] = os_counts.get(name, 0) + 1

    if result['stats']['total']:
        result['stats']['percent'] = round(result['stats']['eol'] / result['stats']['total'] * 100, 1)

    result['eolSystems'] = [{'os': k, 'count': v} for k, v in sorted(os_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    result['plan']['toFix'] = int(result['stats']['eol'] * (reduction_target / 100))
    return result


if __name__ == "__main__":
    mcp.run()
