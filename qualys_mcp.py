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

def normalize_url(url):
    url = url.strip().rstrip('/')
    if url and not url.startswith('http'):
        url = f"https://{url}"
    return url

BASE_URL = normalize_url(os.environ.get('QUALYS_BASE_URL', ''))
GATEWAY_URL = normalize_url(os.environ.get('QUALYS_GATEWAY_URL', ''))
BASIC_AUTH = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
BEARER_TOKEN = None


AUTH_ERROR = None

def get_bearer_token():
    global BEARER_TOKEN, AUTH_ERROR
    if BEARER_TOKEN:
        return BEARER_TOKEN
    try:
        auth_data = urlencode({'username': USERNAME, 'password': PASSWORD, 'token': 'true'}).encode()
        req = Request(f"{GATEWAY_URL}/auth", data=auth_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urlopen(req, timeout=30) as resp:
            BEARER_TOKEN = resp.read().decode().strip()
            AUTH_ERROR = None
            return BEARER_TOKEN
    except Exception as e:
        AUTH_ERROR = str(e)
        return None


def api_get(url, gateway=False, timeout=30):
    req = Request(url)
    if gateway:
        token = get_bearer_token()
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    else:
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=timeout) as resp:
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


def get_assets(limit=100, qql=None):
    url = f"{GATEWAY_URL}/am/v1/assets?pageSize={limit}"
    if qql:
        from urllib.parse import quote
        url += f"&filter={quote(qql)}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('assetListData', {}).get('asset', []) if data else []
    except:
        return []


def get_eol_assets_by_qql(qql_filter, limit=500):
    """Query assets using QQL filter syntax"""
    url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={limit}"
    token = get_bearer_token()

    filter_body = json.dumps({"filter": qql_filter})

    req = Request(url, data=filter_body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')

    try:
        with urlopen(req, timeout=60) as resp:
            return json.loads(resp.read()).get('assetListData', {}).get('asset', [])
    except:
        return []


def get_all_eol_assets(limit=300):
    """Get all EOL/EOS assets across OS, hardware, and software"""
    results = {'os': [], 'hardware': [], 'software': []}

    os_assets = get_eol_assets_by_qql("operatingSystem.lifecycle.stage:EOL or operatingSystem.lifecycle.stage:EOS or operatingSystem.lifecycle.stage:`EOL/EOS`", limit)
    for a in os_assets:
        os_info = a.get('operatingSystem', {}) or {}
        lifecycle = os_info.get('lifecycle', {}) or {}
        results['os'].append({
            'assetId': a.get('assetId'),
            'address': a.get('address', ''),
            'dnsName': a.get('dnsHostName', '') or a.get('dnsName', ''),
            'type': 'os',
            'name': os_info.get('osName', '') or os_info.get('fullName', '') or 'Unknown',
            'stage': lifecycle.get('stage', ''),
            'eolDate': lifecycle.get('eolDate', ''),
            'eosDate': lifecycle.get('eosDate', '')
        })

    hw_assets = get_eol_assets_by_qql("hardware.lifecycle.stage:EOS or hardware.lifecycle.stage:EOL", limit)
    for a in hw_assets:
        hw_info = a.get('hardware', {}) or {}
        lifecycle = hw_info.get('lifecycle', {}) or {}
        results['hardware'].append({
            'assetId': a.get('assetId'),
            'address': a.get('address', ''),
            'dnsName': a.get('dnsHostName', '') or a.get('dnsName', ''),
            'type': 'hardware',
            'name': hw_info.get('model', '') or hw_info.get('name', '') or 'Unknown',
            'stage': lifecycle.get('stage', ''),
            'eolDate': lifecycle.get('eolDate', ''),
            'eosDate': lifecycle.get('eosDate', '')
        })

    sw_assets = get_eol_assets_by_qql("software:(lifecycle.stage:EOL)", limit)
    for a in sw_assets:
        results['software'].append({
            'assetId': a.get('assetId'),
            'address': a.get('address', ''),
            'dnsName': a.get('dnsHostName', '') or a.get('dnsName', ''),
            'type': 'software',
            'name': 'Has EOL software',
            'stage': 'EOL'
        })

    return results


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


def get_image_details(image_id):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/images/{image_id}", gateway=True)
    try:
        return json.loads(data) if data else None
    except:
        return None


def get_image_vulns_api(image_id):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/images/{image_id}/vuln", gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except:
        return []


def get_certificates(limit=100, days_expiring=None):
    url = f"{GATEWAY_URL}/certview/v1/certificates?pageSize={limit}"
    if days_expiring:
        future = (datetime.utcnow() + timedelta(days=days_expiring)).strftime('%Y-%m-%d')
        url += f"&filter=validTo:<{future}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except:
        return []


def get_fim_events(limit=100, days=7):
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    data = api_get(f"{BASE_URL}/fim/v2/events?filter=dateTime:[{start.strftime('%Y-%m-%dT%H:%M:%SZ')}...{end.strftime('%Y-%m-%dT%H:%M:%SZ')}]&pageSize={limit}")
    try:
        return json.loads(data).get('data', []) if data else []
    except:
        return []


def get_edr_events(limit=100, severity=None):
    url = f"{GATEWAY_URL}/edr/v1/events?pageSize={limit}"
    if severity:
        url += f"&filter=severity:{severity}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except:
        return []


def get_was_findings(limit=100, severity=None):
    url = f"{BASE_URL}/qps/rest/3.0/search/was/finding"
    criteria = "<ServiceRequest><filters><Criteria field=\"status\" operator=\"EQUALS\">ACTIVE</Criteria>"
    if severity:
        criteria += f"<Criteria field=\"severity\" operator=\"EQUALS\">{severity}</Criteria>"
    criteria += f"</filters><preferences><limitResults>{limit}</limitResults></preferences></ServiceRequest>"

    from urllib.request import Request
    req = Request(url, data=criteria.encode(), method='POST')
    req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'text/xml')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=60) as resp:
            root = ET.fromstring(resp.read())
            findings = []
            for f in root.findall('.//Finding'):
                findings.append({
                    'id': f.findtext('id', ''),
                    'qid': f.findtext('qid', ''),
                    'name': f.findtext('name', ''),
                    'severity': int(f.findtext('severity', '0')),
                    'url': f.findtext('url', ''),
                    'webAppId': f.findtext('webApp/id', ''),
                    'webAppName': f.findtext('webApp/name', '')
                })
            return findings
    except:
        return []


def get_was_webapps(limit=100):
    data = api_get(f"{BASE_URL}/qps/rest/3.0/count/was/webapp")
    webapps = []
    url = f"{BASE_URL}/qps/rest/3.0/search/was/webapp"
    criteria = f"<ServiceRequest><preferences><limitResults>{limit}</limitResults></preferences></ServiceRequest>"

    from urllib.request import Request
    req = Request(url, data=criteria.encode(), method='POST')
    req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'text/xml')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=60) as resp:
            root = ET.fromstring(resp.read())
            for wa in root.findall('.//WebApp'):
                webapps.append({
                    'id': wa.findtext('id', ''),
                    'name': wa.findtext('name', ''),
                    'url': wa.findtext('url', '')
                })
    except:
        pass
    return webapps


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
              'cloud': {'accounts': 0, 'failedControls': 0}, 'errors': []}

    try:
        assets = get_assets(100)
        result['assets']['total'] = len(assets)
        result['assets']['highRisk'] = len([a for a in assets if a.get('assetRiskScore', 0) >= 700])
        if assets:
            health -= int(result['assets']['highRisk'] / len(assets) * 50)
    except:
        result['errors'].append('assets')

    try:
        result['vulns']['critical'] = len(get_detections(5, 100))
        result['vulns']['high'] = len(get_detections(4, 100))
        if result['vulns']['critical'] > 50:
            health -= 20
        elif result['vulns']['critical'] > 10:
            health -= 10
    except:
        result['errors'].append('vulns')

    try:
        imgs = get_images(100)
        result['containers']['total'] = len(imgs)
        vuln_ids = {i.get('imageId') for i in get_images(50, 5)}
        result['containers']['atRisk'] = len([c for c in get_containers(100) if c.get('imageId') in vuln_ids])
    except:
        result['errors'].append('containers')

    try:
        for p in ['aws', 'azure', 'gcp']:
            conns = get_connectors(p, 5)
            if conns:
                result['cloud']['accounts'] += len(conns)
                acc = conns[0].get('awsAccountId') or conns[0].get('azureSubscriptionId') or conns[0].get('gcpProjectId')
                if acc:
                    evals = get_evaluations(acc, p, 100)
                    result['cloud']['failedControls'] += len([e for e in evals if e.get('result') in ['FAIL', 'FAILED']])
    except:
        result['errors'].append('cloud')

    if not result['errors']:
        del result['errors']
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
def get_tech_debt(days_until_eol: int = 0) -> dict:
    """Get EOL/EOS across OS, hardware, and software. Use days_until_eol to find items approaching end-of-life."""
    result = {
        'stats': {'osEOL': 0, 'osEOS': 0, 'hardwareEOL': 0, 'softwareEOL': 0, 'total': 0},
        'os': [],
        'hardware': [],
        'software': [],
        'byCategory': {}
    }

    all_eol = get_all_eol_assets(300)

    for item in all_eol['os']:
        stage = (item.get('stage', '') or '').upper()
        if 'EOL' in stage and 'EOS' not in stage:
            result['stats']['osEOL'] += 1
        else:
            result['stats']['osEOS'] += 1
        if len(result['os']) < 20:
            result['os'].append(item)

    for item in all_eol['hardware']:
        result['stats']['hardwareEOL'] += 1
        if len(result['hardware']) < 20:
            result['hardware'].append(item)

    sw_by_name = {}
    for item in all_eol['software']:
        name = item.get('name', 'Unknown')
        if name not in sw_by_name:
            sw_by_name[name] = {'name': name, 'version': item.get('version', ''), 'count': 0, 'stage': item.get('stage', '')}
        sw_by_name[name]['count'] += 1
        result['stats']['softwareEOL'] += 1

    result['software'] = sorted(sw_by_name.values(), key=lambda x: x['count'], reverse=True)[:20]

    result['stats']['total'] = (result['stats']['osEOL'] + result['stats']['osEOS'] +
                                 result['stats']['hardwareEOL'] + result['stats']['softwareEOL'])

    result['byCategory'] = {
        'operatingSystem': len(all_eol['os']),
        'hardware': len(all_eol['hardware']),
        'software': len(all_eol['software'])
    }

    return result


@mcp.tool()
def get_image_vulns(image_id: str, limit: int = 50) -> dict:
    """Get vulnerabilities for a specific container image. Returns severity breakdown and top vulns."""
    result = {
        'imageId': image_id,
        'repo': '',
        'tag': '',
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
        'vulns': []
    }

    img = get_image_details(image_id)
    if img:
        result['repo'] = img.get('repo', '')
        result['tag'] = img.get('tag', '')
        result['created'] = img.get('created', '')

    vulns = get_image_vulns_api(image_id)
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

        result['vulns'].append({
            'qid': v.get('qid'),
            'cve': v.get('cveId', ''),
            'severity': sev,
            'title': v.get('title', ''),
            'fixVersion': v.get('fixedVersion', '')
        })

    result['stats']['total'] = len(vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    return result


@mcp.tool()
def get_expiring_certs(days: int = 30, limit: int = 50) -> dict:
    """Get SSL/TLS certificates expiring within specified days. Default 30 days."""
    result = {
        'days': days,
        'stats': {'expiring': 0, 'expired': 0, 'valid': 0},
        'expiring': [],
        'expired': []
    }

    today = datetime.utcnow()
    cutoff = today + timedelta(days=days)

    certs = get_certificates(limit * 2, days)
    for c in certs:
        cert_info = {
            'id': c.get('id', ''),
            'subject': c.get('subject', {}).get('commonName', ''),
            'issuer': c.get('issuer', {}).get('commonName', ''),
            'validTo': c.get('validTo', ''),
            'hosts': [h.get('hostname', '') for h in c.get('hosts', [])[:5]]
        }

        valid_to = c.get('validTo', '')
        if valid_to:
            try:
                exp_date = datetime.strptime(valid_to[:10], '%Y-%m-%d')
                days_left = (exp_date - today).days
                cert_info['daysUntilExpiry'] = days_left

                if days_left < 0:
                    result['stats']['expired'] += 1
                    if len(result['expired']) < limit:
                        result['expired'].append(cert_info)
                elif days_left <= days:
                    result['stats']['expiring'] += 1
                    if len(result['expiring']) < limit:
                        result['expiring'].append(cert_info)
                else:
                    result['stats']['valid'] += 1
            except:
                pass

    result['expiring'] = sorted(result['expiring'], key=lambda x: x.get('daysUntilExpiry', 999))
    result['expired'] = sorted(result['expired'], key=lambda x: x.get('daysUntilExpiry', 0))
    return result


@mcp.tool()
def get_threats(days: int = 7, limit: int = 50) -> dict:
    """Get combined threat view from FIM (file integrity), EDR (endpoint), and CDR (cloud detection). Returns recent security events."""
    result = {
        'days': days,
        'stats': {'fim': 0, 'edr': 0, 'cdr': 0, 'critical': 0, 'high': 0},
        'fim': [],
        'edr': [],
        'cdr': []
    }

    fim_events = get_fim_events(limit, days)
    for e in fim_events:
        sev = e.get('severity', '')
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        elif sev in ['HIGH', '4']:
            result['stats']['high'] += 1
        result['fim'].append({
            'action': e.get('action', ''),
            'path': e.get('filePath', ''),
            'hostname': e.get('hostname', ''),
            'dateTime': e.get('dateTime', ''),
            'severity': sev
        })
    result['stats']['fim'] = len(fim_events)

    edr_events = get_edr_events(limit, 'Critical')
    edr_events += get_edr_events(limit, 'High')
    for e in edr_events[:limit]:
        sev = e.get('severity', '')
        if sev == 'Critical':
            result['stats']['critical'] += 1
        elif sev == 'High':
            result['stats']['high'] += 1
        result['edr'].append({
            'type': e.get('eventType', ''),
            'process': e.get('processName', ''),
            'hostname': e.get('hostname', ''),
            'dateTime': e.get('dateTime', ''),
            'severity': sev
        })
    result['stats']['edr'] = len(edr_events)

    cdr_findings = get_cdr(days, limit)
    for f in cdr_findings:
        sev = str(f.get('severity', ''))
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        elif sev in ['HIGH', '4']:
            result['stats']['high'] += 1
        result['cdr'].append({
            'category': f.get('category', ''),
            'resource': f.get('resourceId', ''),
            'provider': f.get('cloudProvider', ''),
            'dateTime': f.get('createdAt', ''),
            'severity': sev
        })
    result['stats']['cdr'] = len(cdr_findings)

    return result


@mcp.tool()
def get_webapp_vulns(severity: int = 4, limit: int = 50) -> dict:
    """Get web application vulnerabilities from WAS scans. Default severity 4+ (high/critical)."""
    result = {
        'minSeverity': severity,
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'total': 0, 'webApps': 0},
        'vulns': [],
        'byWebApp': []
    }

    findings = get_was_findings(limit * 2, severity)
    webapp_vulns = {}

    for f in findings:
        sev = f.get('severity', 0)
        if sev >= 5:
            result['stats']['critical'] += 1
        elif sev >= 4:
            result['stats']['high'] += 1
        elif sev >= 3:
            result['stats']['medium'] += 1

        webapp_id = f.get('webAppId', '')
        webapp_name = f.get('webAppName', '')
        if webapp_id:
            if webapp_id not in webapp_vulns:
                webapp_vulns[webapp_id] = {'id': webapp_id, 'name': webapp_name, 'critical': 0, 'high': 0, 'total': 0}
            webapp_vulns[webapp_id]['total'] += 1
            if sev >= 5:
                webapp_vulns[webapp_id]['critical'] += 1
            elif sev >= 4:
                webapp_vulns[webapp_id]['high'] += 1

        result['vulns'].append({
            'qid': f.get('qid'),
            'name': f.get('name', ''),
            'severity': sev,
            'url': f.get('url', ''),
            'webApp': webapp_name
        })

    result['stats']['total'] = len(findings)
    result['stats']['webApps'] = len(webapp_vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    result['byWebApp'] = sorted(webapp_vulns.values(), key=lambda x: (x['critical'], x['high'], x['total']), reverse=True)[:20]
    return result


@mcp.tool()
def debug_api(endpoint: str = "eol") -> dict:
    """Debug API connectivity. Use endpoint='eol' to test EOL query, 'assets' for basic assets, 'auth' for auth test."""
    result = {'endpoint': endpoint, 'gateway_url': GATEWAY_URL, 'base_url': BASE_URL}

    if endpoint == 'auth':
        result['username_set'] = bool(USERNAME)
        result['password_set'] = bool(PASSWORD)
        result['auth_url'] = f"{GATEWAY_URL}/auth"
        token = get_bearer_token()
        result['token_obtained'] = bool(token)
        result['token_preview'] = token[:20] + '...' if token else None
        result['auth_error'] = AUTH_ERROR
        return result

    if endpoint == 'assets':
        assets = get_assets(5)
        result['count'] = len(assets)
        result['sample'] = assets[:2] if assets else []
        return result

    if endpoint == 'eol':
        url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize=5"
        token = get_bearer_token()
        result['token_obtained'] = bool(token)

        filter_body = json.dumps({
            "filters": [
                {"field": "operatingSystem.lifecycle.stage", "operator": "IN", "value": "EOL,EOL/EOS,EOS"}
            ]
        })
        result['request_url'] = url
        result['request_body'] = filter_body

        req = Request(url, data=filter_body.encode(), method='POST')
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Requested-With', 'qualys-mcp')

        try:
            with urlopen(req, timeout=60) as resp:
                raw = resp.read()
                result['response_code'] = resp.status
                result['response_length'] = len(raw)
                data = json.loads(raw)
                result['has_assetListData'] = 'assetListData' in data
                result['asset_count'] = len(data.get('assetListData', {}).get('asset', []))
                if result['asset_count'] > 0:
                    result['sample_asset_raw'] = data['assetListData']['asset'][0]
                    parsed = get_eol_assets("EOL,EOL/EOS,EOS", 5)
                    result['parsed_count'] = len(parsed)
                    result['sample_asset_parsed'] = parsed[0] if parsed else None
        except Exception as e:
            result['error'] = str(e)

    return result


def main():
    mcp.run()


if __name__ == "__main__":
    main()
