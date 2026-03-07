#!/usr/bin/env python3
"""Qualys MCP Server - Pure Python implementation using FastMCP"""

import os
import sys
import json
import ssl
import base64
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
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
BEARER_TOKEN_TIME = None
KB_CACHE = {}
DETECTION_CACHE = {}
DETECTION_CACHE_TIME = None
QDS_CACHE = {}
QDS_CACHE_TIME = None

AUTH_ERROR = None
AUTH_LOCK = Lock()

# SSL context for environments with self-signed certificates
SSL_CTX = None
if os.environ.get('QUALYS_SSL_VERIFY', '').lower() in ('0', 'false', 'no'):
    SSL_CTX = ssl.create_default_context()
    SSL_CTX.check_hostname = False
    SSL_CTX.verify_mode = ssl.CERT_NONE

def _open(req, timeout=30):
    """urlopen wrapper that handles SSL context for self-signed certs."""
    return urlopen(req, timeout=timeout, context=SSL_CTX)

def _log(msg):
    """Log to stderr (visible in MCP server logs, not in protocol output)."""
    print(f"[qualys-mcp] {msg}", file=sys.stderr)


def get_bearer_token():
    """Get bearer token, refreshing if expired (tokens last ~4 hours). Thread-safe."""
    global BEARER_TOKEN, BEARER_TOKEN_TIME, AUTH_ERROR
    # Fast path: valid token, no lock needed
    if BEARER_TOKEN and BEARER_TOKEN_TIME:
        age = (datetime.now(timezone.utc) - BEARER_TOKEN_TIME).total_seconds()
        if age < 12600:  # 3.5 hours
            return BEARER_TOKEN
    # Serialize auth requests to prevent concurrent token fetches
    with AUTH_LOCK:
        # Double-check after acquiring lock (another thread may have refreshed)
        if BEARER_TOKEN and BEARER_TOKEN_TIME:
            age = (datetime.now(timezone.utc) - BEARER_TOKEN_TIME).total_seconds()
            if age < 12600:
                return BEARER_TOKEN
        _log("Refreshing bearer token...")
        try:
            auth_data = urlencode({'username': USERNAME, 'password': PASSWORD, 'token': 'true'}).encode()
            req = Request(f"{GATEWAY_URL}/auth", data=auth_data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with _open(req, timeout=30) as resp:
                BEARER_TOKEN = resp.read().decode().strip()
                BEARER_TOKEN_TIME = datetime.now(timezone.utc)
                AUTH_ERROR = None
                return BEARER_TOKEN
        except Exception as e:
            AUTH_ERROR = str(e)
            _log(f"Auth error: {e}")
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
        with _open(req, timeout=timeout) as resp:
            return resp.read()
    except HTTPError as e:
        _log(f"API error {e.code}: {url.split('?')[0]}")
        return None
    except URLError as e:
        _log(f"Connection error: {e.reason}")
        return None
    except Exception as e:
        _log(f"Request failed: {e}")
        return None


def get_detections(severity=5, limit=200, use_cache=True, days=30, qds_min=0):
    """Get VMDR detections with hostname and QDS. Uses 5-minute cache.
    Best practices: filter_superseded_qids, vm_processed_after, qds_min.
    Note: VMDR classic API is slow (~2min) for large environments."""
    global DETECTION_CACHE, DETECTION_CACHE_TIME

    cache_key = f"{severity}_{limit}_{qds_min}"
    now = datetime.now(timezone.utc)

    if use_cache and cache_key in DETECTION_CACHE and DETECTION_CACHE_TIME:
        age = (now - DETECTION_CACHE_TIME).total_seconds()
        if age < 300:  # 5-minute cache
            return DETECTION_CACHE[cache_key]

    after_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
    url = (
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
        f"&severities={severity}&truncation_limit={limit}&status=Active"
        f"&show_qds=1&filter_superseded_qids=1"
        f"&vm_processed_after={after_date}"
    )
    if qds_min > 0:
        url += f"&qds_min={qds_min}"

    data = api_get(url, timeout=180)
    if not data:
        return []
    dets = []
    try:
        root = ET.fromstring(data)
        for host in root.findall('.//HOST'):
            hid = host.findtext('ID', '')
            ip = host.findtext('IP', '')
            hostname = host.findtext('DNS', '')
            for d in host.findall('.//DETECTION'):
                qds_el = d.find('QDS')
                qds = 0
                if qds_el is not None and qds_el.text:
                    try:
                        qds = int(qds_el.text)
                    except ValueError:
                        pass
                dets.append({
                    'host_id': hid, 'ip': ip, 'hostname': hostname,
                    'qid': int(d.findtext('QID', '0')),
                    'severity': int(d.findtext('SEVERITY', '0')),
                    'status': d.findtext('STATUS', ''),
                    'qds': qds,
                    'first_found': d.findtext('FIRST_FOUND_DATETIME', ''),
                })
    except ET.ParseError as e:
        _log(f"XML parse error in detections: {e}")

    DETECTION_CACHE[cache_key] = dets
    DETECTION_CACHE_TIME = now
    return dets


def get_host_detections(host_id, severity=4, days=30):
    """Get detections for a specific host by ID."""
    after_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
        f"&ids={host_id}&severities={severity}&show_qds=1&filter_superseded_qids=1"
        f"&vm_processed_after={after_date}",
        timeout=120
    )
    if not data:
        return []
    dets = []
    try:
        root = ET.fromstring(data)
        for host in root.findall('.//HOST'):
            for d in host.findall('.//DETECTION'):
                qds_el = d.find('QDS')
                qds = 0
                if qds_el is not None and qds_el.text:
                    try:
                        qds = int(qds_el.text)
                    except ValueError:
                        pass
                dets.append({
                    'qid': int(d.findtext('QID', '0')),
                    'severity': int(d.findtext('SEVERITY', '0')),
                    'status': d.findtext('STATUS', ''),
                    'qds': qds,
                    'first_found': d.findtext('FIRST_FOUND_DATETIME', ''),
                })
    except ET.ParseError:
        pass
    return dets


def get_qds_for_qids(qids):
    """Fetch real QDS scores from the detection API for a list of QIDs.
    Returns {qid: max_qds} across all hosts/detections. Uses 5-minute cache.
    Gracefully returns {} on failure so callers can fall back to QDS=0."""
    global QDS_CACHE, QDS_CACHE_TIME
    if not qids:
        return {}

    now = datetime.now(timezone.utc)
    # Expire cache after 5 minutes
    if QDS_CACHE_TIME and (now - QDS_CACHE_TIME).total_seconds() > 300:
        QDS_CACHE = {}
        QDS_CACHE_TIME = None

    # Skip QIDs already cached
    uncached = [q for q in qids if q not in QDS_CACHE]
    if not uncached:
        return {q: QDS_CACHE.get(q, 0) for q in qids}

    # Batch into groups of 50 (URL length limits)
    for i in range(0, len(uncached), 50):
        batch = uncached[i:i+50]
        qid_str = ','.join(map(str, batch))
        try:
            data = api_get(
                f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
                f"&qids={qid_str}&show_qds=1&status=Active"
                f"&truncation_limit=500&filter_superseded_qids=1",
                timeout=60
            )
            if not data:
                _log(f"QDS fetch returned no data for {len(batch)} QIDs")
                continue
            root = ET.fromstring(data)
            # Track max QDS per QID across all hosts
            batch_qds = {}
            for host in root.findall('.//HOST'):
                for d in host.findall('.//DETECTION'):
                    qid = int(d.findtext('QID', '0'))
                    qds_el = d.find('QDS')
                    if qds_el is not None and qds_el.text:
                        try:
                            qds = int(qds_el.text)
                            if qds > batch_qds.get(qid, 0):
                                batch_qds[qid] = qds
                        except ValueError:
                            pass
            for qid, qds in batch_qds.items():
                QDS_CACHE[qid] = qds
            # Mark QIDs with no detections as 0 so we don't re-fetch
            for q in batch:
                if q not in QDS_CACHE:
                    QDS_CACHE[q] = 0
            QDS_CACHE_TIME = now
        except Exception as e:
            _log(f"QDS fetch failed for batch: {e}")

    return {q: QDS_CACHE.get(q, 0) for q in qids}


def parse_vuln_xml(v):
    """Parse a VULN XML element into a dict"""
    qid = int(v.findtext('QID', '0'))
    # Extract QDS (Qualys Detection Score) — 1-100 numeric score
    qds_el = v.find('QDS')
    qds = 0
    if qds_el is not None and qds_el.text:
        try:
            qds = int(qds_el.text)
        except ValueError:
            pass
    qds_factors = v.findtext('QDS_FACTORS', '')
    # Extract threat intelligence / RTI tags
    threat_intel = []
    ti = v.find('THREAT_INTELLIGENCE')
    if ti is not None:
        for t in ti.findall('THREAT_INTEL'):
            text = (t.text or '').strip()
            if text:
                threat_intel.append(text)
    return {
        'qid': qid,
        'title': v.findtext('TITLE', ''),
        'severity': int(v.findtext('SEVERITY_LEVEL', '0')),
        'qds': qds,
        'qds_factors': qds_factors,
        'cves': [c.findtext('ID', '') for c in v.findall('.//CVE_LIST/CVE')],
        'solution': v.findtext('SOLUTION', ''),
        'diagnosis': v.findtext('DIAGNOSIS', ''),
        'patch_available': v.findtext('PATCHABLE', '0') == '1',
        'threat_intel': threat_intel,
        'ransomware': 'Ransomware' in threat_intel,
    }


def get_kb(qid):
    """Get KB entry for a single QID (uses cache)"""
    if qid in KB_CACHE:
        return KB_CACHE[qid]
    data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={qid}&details=All")
    if not data:
        return None
    try:
        root = ET.fromstring(data)
        v = root.find('.//VULN')
        if v is None:
            return None
        result = parse_vuln_xml(v)
        KB_CACHE[qid] = result
        return result
    except ET.ParseError:
        return None


def get_kb_batch(qids):
    """Get KB entries for multiple QIDs in one API call (uses cache)"""
    if not qids:
        return {}

    uncached = [q for q in qids if q not in KB_CACHE]

    if uncached:
        # Fetch in batches of 50
        for i in range(0, len(uncached), 50):
            batch = uncached[i:i+50]
            ids_str = ','.join(map(str, batch))
            data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={ids_str}&details=All", timeout=60)
            if data:
                try:
                    root = ET.fromstring(data)
                    for v in root.findall('.//VULN'):
                        parsed = parse_vuln_xml(v)
                        KB_CACHE[parsed['qid']] = parsed
                except ET.ParseError:
                    pass

    return {q: KB_CACHE.get(q) for q in qids}


def get_cve_qids(cve):
    data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All&cve={cve}", timeout=60)
    if not data:
        return []
    try:
        result = []
        for v in ET.fromstring(data).findall('.//VULN'):
            qid = v.findtext('QID')
            if qid:
                parsed = parse_vuln_xml(v)
                KB_CACHE[parsed['qid']] = parsed  # Cache while we have it
                result.append(int(qid))
        return result
    except ET.ParseError:
        return []


def csam_count(filters=None):
    """Count assets with optional structured filters. Fast (~0.2s).
    filters: list of {"field": "...", "operator": "...", "value": "..."} dicts
    """
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/count/am/asset"
    body = json.dumps({"filters": filters}) if filters else "{}"
    req = Request(url, data=body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=30) as resp:
            return json.loads(resp.read()).get('count', 0)
    except Exception:
        return 0


def csam_search(filters=None, limit=100, fields=None):
    """Search assets with optional structured filters. Returns list of assets.
    filters: list of {"field": "...", "operator": "...", "value": "..."} dicts
    fields: comma-separated includeFields (e.g. "operatingSystem,hardware")
    """
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={limit}"
    if fields:
        url += f"&includeFields={fields}"
    body = json.dumps({"filters": filters}) if filters else "{}"
    req = Request(url, data=body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=30) as resp:
            return json.loads(resp.read()).get('assetListData', {}).get('asset', [])
    except Exception as e:
        _log(f"csam_search error: {e}")
        return []


def get_asset_by_id(asset_id):
    """Get a single asset by ID using CSAM v2 (fast, targeted)."""
    assets = csam_search(
        filters=[{"field": "asset.id", "operator": "EQUALS", "value": str(asset_id)}],
        limit=1
    )
    return assets[0] if assets else None


def get_assets(limit=100, filters=None):
    """Search assets using CSAM v2 structured filters."""
    return csam_search(filters=filters, limit=limit)


def get_asset_count():
    """Fast total asset count."""
    return csam_count()


def is_eol_stage(stage):
    """Check if stage indicates EOL/EOS status"""
    if not stage:
        return False
    s = stage.upper()
    return ('EOL' in s or 'EOS' in s) and s != 'NOT APPLICABLE'


def get_images(limit=100, severity=None):
    url = f"{GATEWAY_URL}/csapi/v1.3/images?pageSize={limit}"
    if severity:
        url += f"&filter=vulnerabilities.severity:{severity}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_containers(limit=100):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/containers?pageSize={limit}&filter=state:RUNNING", gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_connectors(provider='aws', limit=50):
    data = api_get(f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/connectors?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except json.JSONDecodeError:
        return []


def get_evaluations(account_id, provider='aws', limit=500):
    data = api_get(f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except json.JSONDecodeError:
        return []


def get_cdr(days=7, limit=100, severity=None, cloud_provider=None, category=None):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    url = f"{GATEWAY_URL}/cdr-api/rest/v1/findings/?startAt={start.isoformat()}Z&endAt={end.isoformat()}Z&limit={limit}"
    if severity:
        url += f"&severity={severity}"
    if cloud_provider:
        url += f"&cloudProvider={cloud_provider}"
    if category:
        url += f"&category={category}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except json.JSONDecodeError:
        return []


def get_image_details(image_id):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/images/{image_id}", gateway=True)
    try:
        return json.loads(data) if data else None
    except json.JSONDecodeError:
        return None


def get_image_vulns_api(image_id):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/images/{image_id}/vuln", gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_certificates(limit=100, days_expiring=None):
    url = f"{GATEWAY_URL}/certview/v1/certificates?pageSize={limit}"
    if days_expiring:
        future = (datetime.now(timezone.utc) + timedelta(days=days_expiring)).strftime('%Y-%m-%d')
        url += f"&filter=validTo:<{future}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def _fetch_fim_events_raw(limit=100, days=7):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    data = api_get(f"{BASE_URL}/fim/v2/events?filter=dateTime:[{start.strftime('%Y-%m-%dT%H:%M:%SZ')}...{end.strftime('%Y-%m-%dT%H:%M:%SZ')}]&pageSize={limit}")
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def _fetch_edr_events_raw(limit=100, severity=None):
    url = f"{GATEWAY_URL}/edr/v1/events?pageSize={limit}"
    if severity:
        url += f"&filter=severity:{severity}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_was_findings(limit=100, severity=None):
    url = f"{BASE_URL}/qps/rest/3.0/search/was/finding"
    criteria = "<ServiceRequest><filters><Criteria field=\"status\" operator=\"EQUALS\">ACTIVE</Criteria>"
    if severity:
        criteria += f"<Criteria field=\"severity\" operator=\"EQUALS\">{severity}</Criteria>"
    criteria += f"</filters><preferences><limitResults>{limit}</limitResults></preferences></ServiceRequest>"

    req = Request(url, data=criteria.encode(), method='POST')
    req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'text/xml')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=60) as resp:
            root = ET.fromstring(resp.read())
            findings = []
            for f in root.findall('.//Finding'):
                findings.append({
                    'id': f.findtext('id', ''),
                    'qid': int(f.findtext('qid', '0')),
                    'name': f.findtext('name', ''),
                    'severity': int(f.findtext('severity', '0')),
                    'url': f.findtext('url', ''),
                    'webAppId': f.findtext('webApp/id', ''),
                    'webAppName': f.findtext('webApp/name', '')
                })
            return findings
    except Exception as e:
        _log(f"TAS findings error: {e}")
        return []


def get_pm_jobs(platform='Windows', limit=10):
    """Get Patch Management deployment jobs"""
    data = api_get(f"{GATEWAY_URL}/pm/v1/deploymentjobs?platform={platform}&pageSize={limit}", gateway=True)
    try:
        return json.loads(data) if data else []
    except (json.JSONDecodeError, TypeError):
        return []


def get_pm_patches_count(platform='Windows', group_by=None):
    """Get patch counts, optionally grouped by vendorSeverity or appFamily"""
    url = f"{GATEWAY_URL}/pm/v1/patches/count?platform={platform}"
    if group_by:
        url += f"&groupBy={group_by}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def get_pm_assets(platform='Windows', limit=10):
    """Get Patch Management enabled assets"""
    data = api_get(f"{GATEWAY_URL}/pm/v1/assets?platform={platform}&pageSize={limit}", gateway=True)
    try:
        return json.loads(data) if data else []
    except (json.JSONDecodeError, TypeError):
        return []


def get_pm_job_summary(job_id):
    """Get deployment job result summary"""
    data = api_get(f"{GATEWAY_URL}/pm/v1/deploymentjob/{job_id}/deploymentjobresult/summary", gateway=True)
    try:
        return json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def get_mtg_jobs(platform='Windows', limit=10):
    """Get TruRisk Mitigate deployment jobs"""
    data = api_get(f"{GATEWAY_URL}/mtg/v1/deploymentjobs?platform={platform}&pageSize={limit}", gateway=True)
    try:
        return json.loads(data) if data else []
    except (json.JSONDecodeError, TypeError):
        return []


def get_mtg_job_detail(job_id):
    """Get mitigation job details"""
    data = api_get(f"{GATEWAY_URL}/mtg/v1/deploymentjob/{job_id}", gateway=True)
    try:
        return json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def etm_api(method, path, body=None, timeout=60):
    """Call ETM API. Returns parsed JSON or None on error."""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = Request(url, data=data, method=method)
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        _log(f"ETM API error: {e}")
        return None


def etm_download(report_id, resource_name, timeout=60):
    """Download ETM report resource as parsed JSON list."""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/etm/api/rest/v1/reports/{report_id}/resources/{resource_name}"
    req = Request(url, method='GET')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Accept', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        _log(f"ETM download error: {e}")
        return []


def get_scanner_list():
    """Get scanner appliance list with status and health metrics."""
    data = api_get(f"{BASE_URL}/api/2.0/fo/appliance/?action=list&output_mode=full", timeout=30)
    if not data:
        return []
    scanners = []
    try:
        root = ET.fromstring(data)
        for s in root.findall('.//APPLIANCE'):
            scanners.append({
                'id': s.findtext('ID', ''),
                'name': s.findtext('NAME', ''),
                'status': s.findtext('STATUS', ''),
                'type': s.findtext('TYPE', ''),
                'model': s.findtext('MODEL_NUMBER', ''),
                'runningScanCount': int(s.findtext('RUNNING_SCAN_COUNT', '0')),
                'runningSlices': int(s.findtext('RUNNING_SLICES_COUNT', '0')),
                'maxCapacity': int(s.findtext('MAX_CAPACITY_UNITS', '0')),
                'heartbeatsMissed': int(s.findtext('HEARTBEATS_MISSED', '0')),
                'softwareVersion': s.findtext('SOFTWARE_VERSION', ''),
                'vulnsigsVersion': s.findtext('VULNSIGS_VERSION', ''),
                'vulnsigsLatest': s.findtext('VULNSIGS_LATEST', ''),
                'lastUpdated': s.findtext('LAST_UPDATED_DATE', ''),
                'ssConnection': s.findtext('SS_CONNECTION', ''),
                'ssLastConnected': s.findtext('SS_LAST_CONNECTED', ''),
            })
    except ET.ParseError:
        pass
    return scanners


def get_scan_list(states='Running,Paused,Queued,Error,Finished', limit=100):
    """Get scan list filtered by state."""
    data = api_get(f"{BASE_URL}/api/2.0/fo/scan/?action=list&state={states}&show_status=1", timeout=30)
    if not data:
        return []
    scans = []
    try:
        root = ET.fromstring(data)
        for s in root.findall('.//SCAN')[:limit]:
            scans.append({
                'ref': s.findtext('REF', ''),
                'title': s.findtext('TITLE', ''),
                'state': s.findtext('STATUS/STATE', ''),
                'type': s.findtext('TYPE', ''),
                'target': s.findtext('TARGET', '')[:200] if s.findtext('TARGET', '') else '',
                'launched': s.findtext('LAUNCH_DATETIME', ''),
                'duration': s.findtext('DURATION', ''),
                'scannerName': s.findtext('SCANNER_APPLIANCE/FRIENDLY_NAME', ''),
            })
    except ET.ParseError:
        pass
    return scans


def get_criticality(asset):
    """Extract criticality score from asset"""
    crit = asset.get('criticality')
    if isinstance(crit, dict):
        return crit.get('score', 0) or 0
    return crit or 0


def fetch_all_eol(eol_type, limit=1000, max_pages=50):
    """Fetch EOL assets with pagination. eol_type is 'os' or 'hardware'."""
    token = get_bearer_token()
    if eol_type == 'os':
        filters = [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]
    else:
        filters = [{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]

    results = []
    seen = set()
    last_id = None

    for _ in range(max_pages):
        if len(results) >= limit:
            break

        url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize=100"
        if last_id:
            url += f"&lastSeenAssetId={last_id}"

        body = json.dumps({"filters": filters})
        req = Request(url, data=body.encode(), method='POST')
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('X-Requested-With', 'qualys-mcp')

        try:
            with _open(req, timeout=30) as resp:
                data = json.loads(resp.read())
                assets = data.get('assetListData', {}).get('asset', [])
                if not assets:
                    break

                for a in assets:
                    aid = a.get('assetId')
                    if aid in seen:
                        continue
                    seen.add(aid)

                    if eol_type == 'os':
                        info = a.get('operatingSystem', {}) or {}
                        name_field = 'os'
                        name_val = info.get('osName', '') or 'Unknown'
                    else:
                        info = a.get('hardware', {}) or {}
                        name_field = 'hardware'
                        name_val = info.get('model', '') or 'Unknown'

                    lifecycle = info.get('lifecycle', {}) or {}
                    stage = lifecycle.get('stage', '')

                    if is_eol_stage(stage):
                        results.append({
                            'assetId': aid,
                            'address': a.get('address', ''),
                            'hostname': a.get('dnsHostName', '') or a.get('dnsName', ''),
                            name_field: name_val,
                            'stage': stage,
                            'criticality': get_criticality(a),
                            'riskScore': a.get('riskScore') or 0
                        })

                if not data.get('hasMore'):
                    break
                last_id = assets[-1].get('assetId')
        except Exception:
            break

    return results[:limit]


# --- Concurrent helper ---
def _run_concurrent(**tasks):
    """Run named tasks concurrently. Returns dict of {name: result}.
    Each task value is a callable (lambda or function).
    """
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                _log(f"Concurrent task '{name}' failed: {e}")
                results[name] = None
    return results


@mcp.tool()
def get_weekly_priorities(limit: int = 10) -> dict:
    """[Risk Management] Prioritized security actions for the week — top high-risk assets ranked by TruRisk score, risk distribution across severity tiers, and container risks. Fast (~5s). Follow up with get_asset_risk(assetId) for per-asset vulnerability details."""
    result = {'summary': {}, 'priorities': [], 'topRiskAssets': []}

    # All fast CSAM v2 queries (~0.2-3s each, run in parallel)
    # Search at multiple risk tiers to ensure we get the actual highest-risk assets
    # (CSAM API doesn't sort results, so a broad >500 search may miss >900 assets)
    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        eol_count=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        assets_900=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}],
            limit=limit
        ),
        assets_700=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}],
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

    # Merge assets from multiple tiers, deduplicate, sort by risk
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
            'hostname': asset.get('dnsHostName', '') or asset.get('dnsName', ''),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
            'criticality': get_criticality(asset),
        })

    # Build actionable priorities
    rank = 1
    if risk_900 > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 5,
            'title': f"Remediate {risk_900} critical-risk assets (TruRisk > 900)",
            'action': 'Use get_asset_risk(assetId) for specific vulnerabilities per asset',
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

    # Container risks
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

    return result


def _extract_software_keywords(title):
    """Extract software name keywords from KB title for CSAM software search."""
    if not title:
        return []
    import re
    keywords = []
    # Extract parenthetical terms first (e.g., "PAN-OS" from "Palo Alto Networks (PAN-OS)")
    parens = re.findall(r'\(([^)]+)\)', title)
    for p in parens:
        p = p.strip()
        if len(p) >= 3 and not any(w in p.lower() for w in ['cve-', 'formerly', 'aka']):
            keywords.append(p)
    # Remove common vulnerability suffixes to isolate the product name
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
        # Skip parenthetical content in the word stream
        if word.startswith('(') and word.endswith(')'):
            continue
        product_words.append(word.strip('()'))
    # Build search terms: try full product name, then shorter versions
    if len(product_words) >= 2:
        full = ' '.join(product_words)
        keywords.append(full)
        if len(product_words) >= 3:
            keywords.append(' '.join(product_words[-2:]))
        if len(product_words) >= 4:
            keywords.append(' '.join(product_words[1:3]))
    return keywords


@mcp.tool()
def investigate_cve(cve: str) -> dict:
    """[Vulnerability Intelligence] Investigate a specific CVE across your environment — maps the CVE to Qualys QIDs, retrieves KB details (severity, patches, threat intel, ransomware linkage), and searches your asset inventory for systems running the affected software. Fast (~5s)."""
    result = {'cve': cve, 'qids': [], 'severity': 0, 'qds': 0,
              'qds_factors': '',
              'title': '', 'patchAvailable': False, 'solution': '',
              'allKbDetails': [], 'threatIntel': [],
              'ransomware': False, 'affectedAssets': {},
              'summary': {'qidCount': 0, 'patchAvailable': False,
                          'assetsWithSoftware': 0}}

    # Step 1: CVE -> QIDs + KB data (KB API is fast, ~3s)
    qids = get_cve_qids(cve)
    result['qids'] = qids
    result['summary']['qidCount'] = len(qids)

    if qids:
        # Get KB details and real QDS scores in parallel
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
                    result['solution'] = kb.get('solution', '')[:500]
                    result['diagnosis'] = kb.get('diagnosis', '')[:300]
                    result['summary']['patchAvailable'] = kb.get('patch_available', False)
                ti = kb.get('threat_intel', [])
                all_threat_intel.update(ti)
                if kb.get('ransomware'):
                    result['ransomware'] = True
                result['allKbDetails'].append({
                    'qid': qid,
                    'title': kb.get('title', ''),
                    'severity': kb.get('severity', 0),
                    'qds': real_qds or kb.get('qds', 0),
                    'patchAvailable': kb.get('patch_available', False),
                    'cves': kb.get('cves', [])[:5],
                    'threatIntel': ti,
                    'ransomware': kb.get('ransomware', False),
                })
                # Collect software keywords from titles
                for kw in _extract_software_keywords(kb.get('title', '')):
                    software_keywords.add(kw)

        result['threatIntel'] = sorted(all_threat_intel)
        result['allKbDetails'].sort(key=lambda x: x['severity'], reverse=True)

        # Step 2: Search CSAM for assets running the affected software (~0.5s)
        # Also detect the OS hint from KB title to filter accurately
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

            # If no software match found but we know the OS, count assets on that OS
            if best_count == 0 and os_filter:
                os_count = csam_count([os_filter])
                os_assets = csam_search([os_filter], limit=5)
                result['affectedAssets'] = {
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
                    'note': f'No specific software match but {os_count} {os_filter["value"]} assets could be affected. Use get_asset_risk(assetId) to confirm.',
                }
                result['summary']['assetsWithSoftware'] = 0
                result['summary']['osExposedAssets'] = os_count
            else:
                result['affectedAssets'] = {
                    'searchedSoftware': best_keyword,
                    'assetCount': best_count,
                    'sampleAssets': [{
                        'assetId': str(a.get('assetId', '')),
                        'name': a.get('assetName', ''),
                        'riskScore': a.get('riskScore', 0),
                        'os': (a.get('operatingSystem') or {}).get('osName', ''),
                    } for a in best_assets[:5]],
                    'note': 'Assets running the affected software (potential exposure). Use get_asset_risk(assetId) for confirmed vulnerability details.',
                }
                result['summary']['assetsWithSoftware'] = best_count

    return result


@mcp.tool()
def get_security_posture() -> dict:
    """[Dashboard] Overall security health score (0-100) with stats across assets, vulnerabilities, containers, and cloud accounts. Covers TruRisk distribution, EOL systems, container exposure, and cloud control failures. Fast (~5s)."""
    health = 100
    result = {'healthScore': 0, 'assets': {'total': 0, 'highRisk': 0},
              'vulns': {'critical': 0, 'high': 0}, 'containers': {'total': 0, 'atRisk': 0},
              'cloud': {'accounts': 0, 'failedControls': 0}, 'warnings': []}

    # All fast CSAM v2 count queries (~0.2s each, run in parallel)
    concurrent = _run_concurrent(
        asset_count=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        eol_os=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        images=lambda: get_images(50),
        vuln_images=lambda: get_images(30, 5),
        containers=lambda: get_containers(50),
    )

    # Assets
    total = concurrent.get('asset_count') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol_count = concurrent.get('eol_os') or 0
    result['assets']['total'] = total
    result['assets']['highRisk'] = risk_700
    if total > 0:
        health -= min(50, int(risk_700 / total * 100))

    # Risk-based severity (TruRisk ranges as proxy for vuln severity)
    result['vulns']['critical'] = risk_900  # assets with TruRisk > 900
    result['vulns']['high'] = risk_500  # assets with TruRisk > 500
    result['vulns']['eolSystems'] = eol_count
    if risk_900 > 50:
        health -= 20
    elif risk_900 > 10:
        health -= 10

    # Containers
    images = concurrent.get('images') or []
    vuln_images = concurrent.get('vuln_images') or []
    containers = concurrent.get('containers') or []
    result['containers']['total'] = len(images)
    vuln_ids = {i.get('imageId') for i in vuln_images}
    result['containers']['atRisk'] = len([c for c in containers if c.get('imageId') in vuln_ids])

    # Cloud (sequential since needs account ID from connectors)
    try:
        for p in ['aws', 'azure', 'gcp']:
            conns = get_connectors(p, 5)
            if conns:
                result['cloud']['accounts'] += len(conns)
                acc = conns[0].get('awsAccountId') or conns[0].get('azureSubscriptionId') or conns[0].get('gcpProjectId')
                if acc:
                    evals = get_evaluations(acc, p, 50)
                    result['cloud']['failedControls'] += len([e for e in evals if e.get('result') in ['FAIL', 'FAILED']])
    except Exception:
        result['warnings'].append('cloud data unavailable')

    if not result['warnings']:
        del result['warnings']
    result['healthScore'] = max(0, health)
    return result


@mcp.tool()
def get_patch_status(limit: int = 20) -> dict:
    """[Patch Management] Patching coverage and remediation gaps — TruRisk distribution across severity tiers and top unpatched assets ranked by risk score. Fast (~5s). Follow up with get_asset_risk(assetId) for per-asset patch details."""
    result = {'coverage': 0, 'assetsTotal': 0, 'riskDistribution': {},
              'highRiskAssets': []}

    # All fast CSAM v2 queries (~0.2-3s each, run in parallel)
    # Search at multiple risk tiers to ensure we get the actual highest-risk assets
    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        risk_100=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "100"}]),
        assets_900=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}],
            limit=limit
        ),
        assets_700=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}],
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

    # Merge assets from multiple tiers, deduplicate, sort by risk
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
            'hostname': asset.get('dnsHostName', '') or asset.get('dnsName', ''),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
        })

    # Coverage: % of assets with TruRisk < 100 (low risk)
    if total > 0:
        result['coverage'] = round((total - risk_100) / total * 100, 1)

    return result


@mcp.tool()
def get_threat_intel(threat_type: str = "", days: int = 30) -> dict:
    """[Threat Intelligence] Real-Time Threat Indicators (RTI) from the Qualys Knowledge Base — shows which recently published vulnerabilities have active exploits, ransomware linkage, or are on the CISA KEV list.

    threat_type filters: Ransomware, Malware, Active_Attacks, Exploit_Public, Easy_Exploit, Wormable, Cisa_Known_Exploited_Vulns, Denial_of_Service, Privilege_Escalation, Remote_Code_Execution, Predicted_High_Risk, Unauthenticated_Exploitation.

    Common queries: 'Ransomware' for ransomware-linked vulns, 'Active_Attacks' for actively exploited, 'Exploit_Public' for weaponized exploits, 'Cisa_Known_Exploited_Vulns' for CISA KEV list. Default (no filter) returns all RTI types for vulns published in last 30 days (~10s)."""
    from datetime import timedelta
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    result = {'days': days, 'threatFilter': threat_type or 'all',
              'matchingVulns': [], 'totalVulns': 0, 'totalWithThreatIntel': 0,
              'threatBreakdown': {}, 'summary': ''}

    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=30
    )
    if not data:
        result['summary'] = 'Failed to fetch KB data'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['summary'] = 'Failed to parse KB data'
        return result

    # Parse all vulns and collect threat intel
    matching = []
    threat_counts = {}
    all_vulns = root.findall('.//VULN')
    ti_count = 0
    for v in all_vulns:
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        ti = parsed.get('threat_intel', [])
        if ti:
            ti_count += 1
        for tag in ti:
            threat_counts[tag] = threat_counts.get(tag, 0) + 1
        # Filter by threat type if specified
        if threat_type:
            if any(threat_type.lower() in t.lower() for t in ti):
                matching.append(parsed)
        elif ti:
            matching.append(parsed)

    result['totalVulns'] = len(all_vulns)
    result['totalWithThreatIntel'] = ti_count
    result['threatBreakdown'] = dict(sorted(threat_counts.items(), key=lambda x: -x[1]))

    # Sort by severity desc, return top entries
    matching.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))

    # Enrich top 20 results with real QDS scores from detection API
    top_qids = [v['qid'] for v in matching[:20] if v.get('qid')]
    qds_scores = get_qds_for_qids(top_qids) if top_qids else {}

    for v in matching[:50]:
        real_qds = qds_scores.get(v['qid'], 0)
        result['matchingVulns'].append({
            'qid': v['qid'],
            'title': v['title'],
            'severity': v['severity'],
            'qds': real_qds or v.get('qds', 0),
            'cves': v.get('cves', [])[:5],
            'patchAvailable': v.get('patch_available', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    filter_label = f"'{threat_type}'" if threat_type else 'any RTI'
    patched = sum(1 for v in matching if v.get('patch_available'))
    result['totalMatching'] = len(matching)
    result['summary'] = (
        f"{len(matching)} vulns with {filter_label} out of {len(all_vulns)} "
        f"published in last {days} days. {patched} have patches available."
    )
    return result


def _get_first_cloud_evals():
    """Get evaluations from the first available cloud connector."""
    for provider, acc_key in [('aws', 'awsAccountId'), ('azure', 'azureSubscriptionId'), ('gcp', 'gcpProjectId')]:
        conns = get_connectors(provider, 1)
        if conns:
            acc = conns[0].get(acc_key)
            if acc:
                return get_evaluations(acc, provider, 100)
    return []


@mcp.tool()
def get_recommendations() -> dict:
    """[Program Advisor] Security program coach — analyzes your environment and recommends Qualys modules and actions to reduce risk. Probes all data sources (VMDR, TotalCloud, TotalAppSec, FIM, EDR, CertView, Patch Management) to find coverage gaps. Returns prioritized recommendations with eliminate/mitigate risk actions."""
    result = {'recommendations': [], 'coverage': {}, 'summary': ''}
    recs = []

    # Probe all data sources concurrently to find gaps
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
        cloud_evals=lambda: _get_first_cloud_evals(),
        was=lambda: get_was_findings(5, 4),
        fim=lambda: _fetch_fim_events_raw(5, 7),
        edr=lambda: _fetch_edr_events_raw(5),
        certs=lambda: get_certificates(5, 30),
        ransomware_vulns=lambda: get_threat_intel.fn(threat_type='Ransomware', days=30),
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

    # Track what's active vs missing
    coverage = {
        'vmdr': True,  # If we got asset counts, VMDR is active
        'totalCloud': len(images) > 0 or len(cloud_aws) + len(cloud_azure) + len(cloud_gcp) > 0,
        'totalAppSec': len(was) > 0,
        'fileIntegrityMonitoring': len(fim) > 0,
        'endpointDetection': len(edr) > 0,
        'certificateView': len(certs) > 0,
    }
    result['coverage'] = coverage

    rank = 1

    # --- Critical risk assets ---
    if risk_900 > 0:
        recs.append({
            'rank': rank, 'priority': 'CRITICAL',
            'area': 'Risk Elimination',
            'finding': f'{risk_900} assets have TruRisk scores above 900 (maximum risk)',
            'recommendation': f'Eliminate risk on {risk_900} critical assets with Qualys Patch Management. Auto-deploy patches for vulnerabilities with active exploits and ransomware linkage — each patch eliminates the associated TruRisk. For vulnerabilities without patches, use Qualys VMDR mitigations (compensating controls, network segmentation) to reduce risk until a fix is available.',
            'qualysModule': 'Patch Management + VMDR',
            'riskAction': 'eliminate',
        })
        rank += 1

    # --- EOL/EOS systems ---
    if eol_count > 0:
        pct = round(eol_count / total * 100, 1) if total else 0
        recs.append({
            'rank': rank, 'priority': 'HIGH',
            'area': 'Asset Lifecycle',
            'finding': f'{eol_count} systems ({pct}% of environment) are running EOL/EOS operating systems that no longer receive security patches',
            'recommendation': f'Eliminate risk by migrating {eol_count} EOL/EOS systems to supported versions. Use CSAM lifecycle tracking to plan upgrades. For systems that cannot be migrated immediately, mitigate risk with Policy Compliance compensating controls and network segmentation until migration is complete.',
            'qualysModule': 'CSAM + Patch Management',
            'riskAction': 'eliminate',
        })
        rank += 1

    # --- Container security gaps ---
    if not images:
        recs.append({
            'rank': rank, 'priority': 'HIGH',
            'area': 'Container & Cloud Security',
            'finding': 'No container images detected — container workloads may be running unscanned',
            'recommendation': 'Deploy Qualys TotalCloud to scan container images in registries and running containers. Integrate with CI/CD pipelines to catch and eliminate vulnerabilities before deployment.',
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
                'recommendation': f'Eliminate container risk by rebuilding {len(at_risk)} affected images with patched base images. Set up Qualys TotalCloud runtime policies to block deployment of vulnerable images and prevent future risk.',
                'qualysModule': 'TotalCloud',
                'riskAction': 'eliminate',
            })
            rank += 1

    # --- Cloud security gaps ---
    cloud_total = len(cloud_aws) + len(cloud_azure) + len(cloud_gcp)
    cloud_evals = concurrent.get('cloud_evals') or []
    if not cloud_total:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Cloud Security Posture',
            'finding': 'No cloud connectors configured — cloud assets may have unmonitored misconfigurations',
            'recommendation': 'Connect AWS, Azure, and/or GCP accounts using Qualys TotalCloud. Eliminate cloud misconfigurations with continuous posture monitoring, auto-remediation, and Cloud Detection & Response (CDR).',
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
                'recommendation': f'Eliminate {len(fails)} failing cloud controls by remediating CIS Benchmark violations. Use TotalCloud auto-remediation to fix common misconfigurations automatically. Mitigate remaining gaps with Policy Compliance continuous monitoring.',
                'qualysModule': 'TotalCloud + Policy Compliance',
                'riskAction': 'eliminate',
            })
            rank += 1

    # --- Application security ---
    if not was:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Application Security',
            'finding': 'No application scan findings detected — web apps and APIs may not be scanned for vulnerabilities like SQLi, XSS, and OWASP Top 10',
            'recommendation': 'Deploy Qualys TotalAppSec (TAS) to discover and scan web applications and APIs. Eliminate application-layer risk by identifying and fixing OWASP Top 10 vulnerabilities. Integrate with CI/CD to prevent vulnerable code from reaching production.',
            'qualysModule': 'TotalAppSec (TAS)',
            'riskAction': 'eliminate',
        })
        rank += 1

    # --- FIM ---
    if not fim:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'File Integrity Monitoring',
            'finding': 'No file integrity monitoring events detected — unauthorized changes to critical files may go undetected',
            'recommendation': 'Mitigate risk of undetected tampering by deploying Qualys FIM on critical servers. Monitor changes to system files, configurations, and registries in real time. Required for PCI DSS Requirement 11.5 and many compliance frameworks.',
            'qualysModule': 'File Integrity Monitoring (FIM)',
            'riskAction': 'mitigate',
        })
        rank += 1

    # --- EDR ---
    if not edr:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Endpoint Detection & Response',
            'finding': 'No endpoint detection events — active threats and malicious behaviors may not be detected in real time',
            'recommendation': 'Mitigate active threat risk by enabling Qualys Multi-Vector EDR. Detect and respond to endpoint threats in real time. Combines vulnerability context with behavioral detection — when a patch cannot eliminate a vulnerability, EDR provides the mitigation layer.',
            'qualysModule': 'Multi-Vector EDR',
            'riskAction': 'mitigate',
        })
        rank += 1

    # --- Certificate management ---
    if not certs:
        recs.append({
            'rank': rank, 'priority': 'LOW',
            'area': 'Certificate Management',
            'finding': 'No certificate data available — expired or weak SSL/TLS certificates may cause outages or security gaps',
            'recommendation': 'Mitigate certificate-related risk by deploying Qualys CertView to discover and monitor all SSL/TLS certificates. Eliminate expired and weak certificates before they cause outages or man-in-the-middle exposure.',
            'qualysModule': 'CertView',
            'riskAction': 'mitigate',
        })
        rank += 1

    # --- Ransomware exposure ---
    ransomware_count = ransomware.get('totalMatching', 0)
    if ransomware_count > 0:
        recs.append({
            'rank': rank, 'priority': 'HIGH',
            'area': 'Ransomware Defense',
            'finding': f'{ransomware_count} vulnerabilities with ransomware linkage published in last 30 days',
            'recommendation': f'Eliminate ransomware risk by patching {ransomware_count} ransomware-linked vulnerabilities with Qualys Patch Management. Patches directly eliminate the TruRisk associated with each CVE. For zero-days without patches, mitigate risk using VMDR virtual patching and network-level controls. Deploy EDR for real-time behavioral detection as a last line of defense.',
            'qualysModule': 'Patch Management + VMDR + EDR',
            'riskAction': 'eliminate',
        })
        rank += 1

    # --- High unpatched ratio ---
    if total > 0 and risk_500 > 0:
        risk_pct = round(risk_500 / total * 100, 1)
        if risk_pct > 10:
            recs.append({
                'rank': rank, 'priority': 'HIGH',
                'area': 'Patch Coverage',
                'finding': f'{risk_500} assets ({risk_pct}%) have elevated risk (TruRisk > 500) indicating significant unpatched vulnerabilities',
                'recommendation': f'Eliminate risk across {risk_500} elevated-risk assets with Qualys Patch Management. Each successfully deployed patch eliminates TruRisk for those CVEs. Target highest-TruRisk assets first for maximum risk reduction. Where patches cannot be applied immediately, mitigate with VMDR compensating controls to reduce exposure while scheduling maintenance windows.',
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

    return result


@mcp.tool()
def get_eliminate_status() -> dict:
    """[TruRisk Eliminate] Patch and mitigation deployment status — shows active patch jobs (Qualys Patch Management), mitigation jobs (TruRisk Mitigate), patch catalog coverage, and managed asset counts for both Windows and Linux. Returns job status, completion rates, and patch counts by vendor severity. Use when asked about patching progress, risk elimination, or mitigation status."""
    result = {
        'patchManagement': {'windows': {}, 'linux': {}},
        'mitigations': {'windows': {}, 'linux': {}},
        'patchCatalog': {},
        'summary': '',
    }

    # Fetch everything concurrently
    concurrent = _run_concurrent(
        windows_pm_jobs=lambda: get_pm_jobs('Windows', 20),
        linux_pm_jobs=lambda: get_pm_jobs('Linux', 20),
        windows_mtg_jobs=lambda: get_mtg_jobs('Windows', 20),
        linux_mtg_jobs=lambda: get_mtg_jobs('Linux', 20),
        windows_patches=lambda: get_pm_patches_count('Windows', 'vendorSeverity'),
        linux_patches=lambda: get_pm_patches_count('Linux'),
        windows_assets=lambda: get_pm_assets('Windows', 5),
        linux_assets=lambda: get_pm_assets('Linux', 5),
    )

    total_patch_jobs = 0
    total_mtg_jobs = 0
    active_patch_jobs = 0
    active_mtg_jobs = 0

    for platform in ['windows', 'linux']:
        plat_key = platform.capitalize()

        # Patch jobs
        pm_jobs = concurrent.get(f'{platform}_pm_jobs') or []
        patch_jobs = [j for j in pm_jobs if j.get('subCategory') == 'Patch']
        total_patch_jobs += len(patch_jobs)

        active = [j for j in patch_jobs if j.get('status') not in ('Disabled', 'Deleted')]
        active_patch_jobs += len(active)

        by_status = {}
        for j in patch_jobs:
            status = j.get('status', 'Unknown')
            by_status[status] = by_status.get(status, 0) + 1

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
            'totalJobs': len(patch_jobs),
            'activeJobs': len(active),
            'byStatus': by_status,
            'recentJobs': recent_jobs,
            'managedAssets': len(pm_assets),
        }

        # Mitigation jobs
        mtg_jobs = concurrent.get(f'{platform}_mtg_jobs') or []
        total_mtg_jobs += len(mtg_jobs)

        mtg_active = [j for j in mtg_jobs if j.get('status') not in ('Disabled', 'Deleted')]
        active_mtg_jobs += len(mtg_active)

        mtg_by_status = {}
        for j in mtg_jobs:
            status = j.get('status', 'Unknown')
            mtg_by_status[status] = mtg_by_status.get(status, 0) + 1

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
            'totalJobs': len(mtg_jobs),
            'activeJobs': len(mtg_active),
            'byStatus': mtg_by_status,
            'recentJobs': mtg_recent,
        }

    # Patch catalog
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

    result['summary'] = (
        f'TruRisk Eliminate: {total_patch_jobs} patch jobs ({active_patch_jobs} active), '
        f'{total_mtg_jobs} mitigation jobs ({active_mtg_jobs} active). '
        f'Patch catalog: {total_catalog:,} patches available. '
        f'Use Patch to eliminate risk by deploying fixes. '
        f'Use Mitigate to apply compensating controls when no patch exists.'
    )

    return result


@mcp.tool()
def get_scanner_health() -> dict:
    """[Infrastructure] Scanner appliance health — online/offline status, running and failed scans, capacity utilization, and vulnerability signature currency. Use when asked about scan failures, scanner health, or scanning infrastructure. Fast (~5s)."""
    result = {
        'scanners': [],
        'scanStatus': {},
        'summary': '',
    }

    # Fetch scanner list and active/error scans concurrently
    concurrent = _run_concurrent(
        scanners=lambda: get_scanner_list(),
        active_scans=lambda: get_scan_list('Running,Paused,Queued', 100),
        error_scans=lambda: get_scan_list('Error', 50),
    )

    scanners = concurrent.get('scanners') or []
    active_scans = concurrent.get('active_scans') or []
    error_scans = concurrent.get('error_scans') or []

    # Scanner status
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

        # Check if vulnsigs are outdated
        sigs_outdated = (s.get('vulnsigsVersion', '') != s.get('vulnsigsLatest', '') and s.get('vulnsigsLatest', ''))

        if sigs_outdated:
            outdated_sigs += 1

        scanner_info = {
            'name': s.get('name', ''),
            'status': s.get('status', ''),
            'runningScanCount': running,
            'maxCapacity': capacity,
            'heartbeatsMissed': s.get('heartbeatsMissed', 0),
            'lastUpdated': s.get('lastUpdated', ''),
        }
        if sigs_outdated:
            scanner_info['vulnsigsOutdated'] = True
            scanner_info['vulnsigsVersion'] = s.get('vulnsigsVersion', '')
            scanner_info['vulnsigsLatest'] = s.get('vulnsigsLatest', '')
        result['scanners'].append(scanner_info)

    # Sort: online first, then by running scan count desc
    result['scanners'].sort(key=lambda x: (x['status'] != 'Online', -x['runningScanCount']))

    # Scan status summary
    scan_states = {}
    for s in active_scans + error_scans:
        state = s.get('state', 'Unknown')
        scan_states[state] = scan_states.get(state, 0) + 1

    result['scanStatus'] = {
        'byState': scan_states,
        'errorScans': [{
            'title': s.get('title', ''),
            'launched': s.get('launched', ''),
            'scanner': s.get('scannerName', ''),
        } for s in error_scans[:10]],
        'activeScans': [{
            'title': s.get('title', ''),
            'state': s.get('state', ''),
            'scanner': s.get('scannerName', ''),
        } for s in active_scans[:10]],
    }

    # Utilization
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

    return result


@mcp.tool()
def get_etm_findings(qql: str = "", report_id: str = "") -> dict:
    """[Enterprise TruRisk] Query ETM for confirmed vulnerability and misconfiguration findings across all sources — VMDR, TotalCloud, and third-party scanners. Returns per-asset findings with TruRisk scores, QDS, CVSS, patch status, and remediation details.

    Use qql to filter with Qualys Query Language:
      - 'vulnerabilities.vulnerability.cveIds:CVE-2021-44228' — find Log4Shell
      - 'vulnerabilities.vulnerability.severity:5' — critical findings only
      - 'asset.name:web-server' — findings for a specific asset
      - 'vulnerabilities.vulnerability.isPatchAvailable:true' — patchable findings

    ETM reports are async. If a completed report exists, findings return immediately (~1-2s). Otherwise a new report is created — call again with that report_id to retrieve results. This is the most comprehensive view of confirmed vulnerabilities in your environment."""
    result = {'findings': [], 'summary': {}, 'reportStatus': ''}

    # If report_id provided, check its status and download if ready
    if report_id:
        detail = etm_api('GET', f'/etm/api/rest/v1/reports/{report_id}')
        if not detail:
            result['reportStatus'] = 'error'
            result['summary'] = {'error': 'Could not retrieve report status'}
            return result

        result['reportStatus'] = detail.get('status', 'UNKNOWN')
        if detail['status'] == 'COMPLETED':
            resources = detail.get('resources', [])
            all_findings = []
            for res_name in resources[:5]:  # Cap at 5 resource files
                findings = etm_download(detail['id'], res_name)
                if findings:
                    all_findings.extend(findings)

            return _format_etm_findings(all_findings, detail)

        elif detail['status'] == 'FAILED':
            result['summary'] = {'error': 'Report generation failed', 'reportId': report_id}
            return result
        else:
            result['summary'] = {
                'message': f'Report is still processing (status: {detail["status"]}). Try again in 30-60 seconds.',
                'reportId': report_id,
            }
            return result

    # No report_id — check for a recent completed report matching the query
    reports = etm_api('POST', '/etm/api/rest/v1/reports/list', {'pageSize': 50})
    if reports:
        # Look for a recent completed JSON report (prefer matching name/filter)
        completed = [r for r in reports if r.get('status') == 'COMPLETED' and r.get('reportFormat') == 'JSON']
        # If no specific QQL, use the most recent completed report
        if not qql and completed:
            target = completed[0]
            detail = etm_api('GET', f'/etm/api/rest/v1/reports/{target["id"]}')
            if detail and detail.get('resources'):
                all_findings = []
                for res_name in detail['resources'][:5]:
                    findings = etm_download(detail['id'], res_name)
                    if findings:
                        all_findings.extend(findings)
                if all_findings:
                    return _format_etm_findings(all_findings, detail)

    # Create a new report
    body = {
        'reportName': f'mcp-{int(datetime.now(timezone.utc).timestamp())}',
        'reportFormat': 'JSON',
    }
    if qql:
        body['findingFilter'] = {'qql': qql}

    new_report = etm_api('POST', '/etm/api/rest/v1/reports/findings', body)
    if not new_report:
        result['reportStatus'] = 'error'
        result['summary'] = {'error': 'Failed to create ETM report. ETM module may not be enabled.'}
        return result

    rid = new_report.get('id', '')
    result['reportStatus'] = 'REQUESTED'
    result['summary'] = {
        'message': 'ETM report requested. Reports typically take 1-5 minutes to generate. Call get_etm_findings(report_id="' + rid + '") to check status and retrieve results.',
        'reportId': rid,
        'qql': qql or '(all findings)',
    }
    return result


def _format_etm_findings(all_findings, report_detail):
    """Format ETM findings into a structured response."""
    # Aggregate stats
    by_severity = {}
    by_status = {}
    by_cve = {}
    by_category = {}
    by_source = {}
    by_misconfig_type = {}
    assets_seen = set()
    patchable = 0

    vulns = []
    misconfigs = []
    for f in all_findings:
        sev = f.get('severity', 0)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        status = f.get('status', 'Unknown')
        by_status[status] = by_status.get(status, 0) + 1

        category = f.get('category', 'VULNERABILITY')
        by_category[category] = by_category.get(category, 0) + 1
        source = f.get('vendorProductName', 'Unknown')
        by_source[source] = by_source.get(source, 0) + 1

        cve = f.get('cveId', '')
        if cve:
            if cve not in by_cve:
                by_cve[cve] = {'count': 0, 'severity': sev, 'title': f.get('title', ''), 'qid': f.get('vendorId', '')}
            by_cve[cve]['count'] += 1

        asset = f.get('asset', {})
        asset_name = asset.get('assetName', '') or f.get('assetName', '')
        if asset_name:
            assets_seen.add(asset_name)

        if f.get('isPatchAvailable'):
            patchable += 1

        trurisk = f.get('truRiskScore') or 0
        qid = f.get('vendorId', '')
        qds = f.get('qds', 0)
        qvss_raw = f.get('qvss')
        qvss = qvss_raw if isinstance(qvss_raw, (int, float)) else (qvss_raw.get('score') or qvss_raw.get('base') if isinstance(qvss_raw, dict) else None)

        entry = {
            'cveId': cve,
            'qid': qid,
            'title': f.get('title', ''),
            'severity': sev,
            'qds': qds,
            'qvss': qvss,
            'truRiskScore': trurisk,
            'status': status,
            'category': category,
            'assetName': asset_name,
            'assetId': asset.get('internalAssetId', ''),
            'isPatchAvailable': f.get('isPatchAvailable', False),
            'isQualysPatchable': f.get('isQualysPatchable', False),
            'cvss': f.get('cvss', {}),
            'source': source,
            'firstFound': f.get('firstFound'),
            'lastFound': f.get('lastFound'),
        }

        if category == 'MISCONFIGURATION':
            sub = f.get('subCategory', '')
            entry['subCategory'] = sub
            by_misconfig_type[sub] = by_misconfig_type.get(sub, 0) + 1
            misconfigs.append(entry)
        else:
            vulns.append(entry)

    # Sort vulns and misconfigs separately by severity/TruRisk
    vulns.sort(key=lambda x: (-x['severity'], -(x['truRiskScore'] or 0)))
    misconfigs.sort(key=lambda x: (-x['severity'], -(x['truRiskScore'] or 0)))

    # Include top vulns + top misconfigs (ensure both are represented)
    findings = vulns[:150] + misconfigs[:50]

    # Top CVEs by affected asset count
    top_cves = sorted(by_cve.items(), key=lambda x: (-x[1]['count'], -x[1]['severity']))[:20]

    result = {
        'reportStatus': 'COMPLETED',
        'reportId': report_detail.get('id', ''),
        'reportName': report_detail.get('name', ''),
        'findings': findings,
        'totalFindings': len(all_findings),
        'summary': {
            'totalFindings': len(all_findings),
            'uniqueAssets': len(assets_seen),
            'uniqueCVEs': len(by_cve),
            'patchable': patchable,
            'bySeverity': {f'sev{k}': v for k, v in sorted(by_severity.items(), reverse=True)},
            'byStatus': by_status,
            'byCategory': by_category,
            'bySource': by_source,
        },
        'topCVEs': [{'cve': cve, 'qid': info.get('qid', ''), 'affectedAssets': info['count'], 'severity': info['severity'], 'title': info['title'][:80]} for cve, info in top_cves],
    }

    # Add misconfiguration breakdown if any exist
    if misconfigs:
        result['misconfigurations'] = {
            'total': len(misconfigs),
            'byType': by_misconfig_type,
            'topFindings': [{
                'title': m['title'][:80],
                'assetName': m['assetName'],
                'severity': m['severity'],
                'truRiskScore': m['truRiskScore'],
                'subCategory': m.get('subCategory', ''),
            } for m in misconfigs[:10]],
        }

    return result


@mcp.tool()
def get_morning_report() -> dict:
    """[Daily Briefing] Morning security report — what happened overnight. New vulnerabilities (last 24h) with ransomware and active exploit flags, environment health score, top risk assets, EOL count, and prioritized action items. Use this first thing in the morning or at shift start."""
    result = {'report': 'Daily Security Briefing', 'environment': {},
              'newVulns': {}, 'threats': {}, 'topRiskAssets': [],
              'actionItems': []}

    # Run everything concurrently for speed
    concurrent = _run_concurrent(
        posture=lambda: get_security_posture.fn(),
        priorities=lambda: get_weekly_priorities.fn(),
        new_vulns=lambda: get_new_vulns.fn(days=1),
        ransomware=lambda: get_threat_intel.fn(threat_type='Ransomware', days=1),
        active=lambda: get_threat_intel.fn(threat_type='Active_Attacks', days=1),
        cisa=lambda: get_threat_intel.fn(threat_type='Cisa_Known_Exploited_Vulns', days=1),
    )

    # Environment status
    posture = concurrent.get('posture') or {}
    result['environment'] = {
        'healthScore': posture.get('healthScore', 0),
        'totalAssets': (posture.get('assets') or {}).get('total', 0),
        'highRiskAssets': (posture.get('assets') or {}).get('highRisk', 0),
        'eolSystems': (posture.get('vulns') or {}).get('eolSystems', 0),
        'containersAtRisk': (posture.get('containers') or {}).get('atRisk', 0),
        'cloudAccounts': (posture.get('cloud') or {}).get('accounts', 0),
    }

    # New vulns
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

    # Threat flags
    ransomware = concurrent.get('ransomware') or {}
    active = concurrent.get('active') or {}
    cisa = concurrent.get('cisa') or {}
    result['threats'] = {
        'ransomwareLinked': ransomware.get('totalMatching', 0),
        'activelyExploited': active.get('totalMatching', 0),
        'cisaKev': cisa.get('totalMatching', 0),
    }

    # Top critical new vulns
    critical_new = []
    for v in (new.get('vulns') or []):
        if v['severity'] >= 5 and len(critical_new) < 10:
            critical_new.append({
                'qid': v['qid'],
                'title': v['title'],
                'cves': v.get('cves', [])[:3],
                'patchAvailable': v.get('patchAvailable', False),
                'threatIntel': v.get('threatIntel', []),
                'ransomware': v.get('ransomware', False),
            })
    result['newVulns']['criticalVulns'] = critical_new

    # Top risk assets
    priorities = concurrent.get('priorities') or {}
    result['topRiskAssets'] = (priorities.get('topRiskAssets') or [])[:5]

    # Action items
    result['actionItems'] = priorities.get('priorities') or []

    return result


@mcp.tool()
def get_new_vulns(days: int = 7) -> dict:
    """[Vulnerability Intelligence] Newly published vulnerabilities from the Qualys Knowledge Base — CVEs, severity, RTI threat tags (ransomware, active exploits, CISA KEV), and patch availability for vulns published in the last N days. Fast (~5s). Use days=1 for today's vulns, days=30 for the last month."""
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    result = {'days': days, 'publishedAfter': after, 'totalVulns': 0,
              'severityBreakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
              'withPatch': 0, 'withThreatIntel': 0, 'vulns': []}

    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=30
    )
    if not data:
        result['error'] = 'Failed to fetch KB data'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['error'] = 'Failed to parse KB data'
        return result

    all_vulns = []
    for v in root.findall('.//VULN'):
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        all_vulns.append(parsed)

        sev = parsed['severity']
        if sev >= 5:
            result['severityBreakdown']['critical'] += 1
        elif sev >= 4:
            result['severityBreakdown']['high'] += 1
        elif sev >= 3:
            result['severityBreakdown']['medium'] += 1
        else:
            result['severityBreakdown']['low'] += 1

        if parsed.get('patch_available'):
            result['withPatch'] += 1
        if parsed.get('threat_intel'):
            result['withThreatIntel'] += 1

    result['totalVulns'] = len(all_vulns)

    # Sort by severity desc, then by threat intel count
    all_vulns.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))

    # Enrich top 20 results with real QDS scores from detection API
    top_qids = [v['qid'] for v in all_vulns[:20] if v.get('qid')]
    qds_scores = get_qds_for_qids(top_qids) if top_qids else {}

    for v in all_vulns[:100]:
        real_qds = qds_scores.get(v['qid'], 0)
        result['vulns'].append({
            'qid': v['qid'],
            'title': v['title'],
            'severity': v['severity'],
            'qds': real_qds or v.get('qds', 0),
            'cves': v.get('cves', [])[:5],
            'patchAvailable': v.get('patch_available', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    return result


@mcp.tool()
def get_vulns_by_software(software: str) -> dict:
    """[Vulnerability Intelligence] Search for vulnerabilities affecting a specific software, vendor, or product — searches Qualys KB titles and diagnosis text for matches. Examples: 'Apache', 'F5 BIG-IP', 'OpenSSL', 'Microsoft Exchange', 'Palo Alto PAN-OS'. Fast (~5s)."""
    result = {'software': software, 'totalVulns': 0,
              'severityBreakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
              'withPatch': 0, 'vulns': []}

    # KB API doesn't have a server-side software filter, so we search by title
    # Use the most recent vulns (last 90 days) to keep it fast
    after = (datetime.now(timezone.utc) - timedelta(days=90)).strftime('%Y-%m-%d')
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=30
    )
    if not data:
        result['error'] = 'Failed to fetch KB data'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['error'] = 'Failed to parse KB data'
        return result

    search_lower = software.lower()
    matching = []
    for v in root.findall('.//VULN'):
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        title = parsed.get('title', '').lower()
        diagnosis = parsed.get('diagnosis', '').lower()
        if search_lower in title or search_lower in diagnosis:
            matching.append(parsed)

    result['totalVulns'] = len(matching)
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

    # Enrich top 20 results with real QDS scores from detection API
    top_qids = [v['qid'] for v in matching[:20] if v.get('qid')]
    qds_scores = get_qds_for_qids(top_qids) if top_qids else {}

    for v in matching[:100]:
        real_qds = qds_scores.get(v['qid'], 0)
        result['vulns'].append({
            'qid': v['qid'],
            'title': v['title'],
            'severity': v['severity'],
            'qds': real_qds or v.get('qds', 0),
            'cves': v.get('cves', [])[:5],
            'patchAvailable': v.get('patch_available', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    return result


@mcp.tool()
def get_cve_details(cves: str) -> dict:
    """[Vulnerability Intelligence] Bulk CVE lookup — get severity, patches, threat intel, and remediation for multiple CVEs at once. Accepts comma-separated CVE IDs (e.g. 'CVE-2021-44228,CVE-2024-3400'). Up to 20 CVEs per call. Fast (~5s)."""
    cve_list = [c.strip() for c in cves.split(',') if c.strip()]
    result = {'requested': len(cve_list), 'found': 0, 'cves': []}

    def fetch_cve(cve):
        qids = get_cve_qids(cve)
        if not qids:
            return {'cve': cve, 'found': False}
        kb_data = get_kb_batch(qids[:20])
        # Fetch real QDS scores from detection API
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
                all_kb.append({
                    'qid': qid,
                    'title': kb.get('title', ''),
                    'severity': kb.get('severity', 0),
                    'qds': real_qds or kb.get('qds', 0),
                    'patchAvailable': kb.get('patch_available', False),
                })
        best_qds = qds_scores.get(best_qid, 0) if best_qid else 0
        entry = {
            'cve': cve, 'found': True, 'qids': qids,
            'severity': max_sev,
            'qds': best_qds or (best.get('qds', 0) if best else 0),
            'qds_factors': best.get('qds_factors', '') if best else '',
            'title': best.get('title', '') if best else '',
            'patchAvailable': best.get('patch_available', False) if best else False,
            'solution': (best.get('solution', '') if best else '')[:500],
            'diagnosis': (best.get('diagnosis', '') if best else '')[:300],
            'threatIntel': sorted(all_threat_intel),
            'ransomware': is_ransomware,
            'kbEntries': all_kb,
        }
        return entry

    # Fetch all CVEs concurrently
    tasks = {cve: (lambda c=cve: fetch_cve(c)) for cve in cve_list[:20]}
    fetched = _run_concurrent(**tasks)

    for cve in cve_list[:20]:
        entry = fetched.get(cve)
        if entry:
            if entry.get('found'):
                result['found'] += 1
            result['cves'].append(entry)

    result['cves'].sort(key=lambda x: (-x.get('severity', 0), x['cve']))
    return result


@mcp.tool()
def get_qid_details(qids: str) -> dict:
    """[Vulnerability Intelligence] Direct QID lookup — get KB details (severity, QDS, patches, threat intel, CVEs) for specific Qualys QIDs. Accepts comma-separated QIDs (e.g. '38747,376418'). Up to 50 QIDs per call. Fast (~3s)."""
    qid_list = []
    for q in qids.split(','):
        q = q.strip()
        if q.isdigit():
            qid_list.append(int(q))
    if not qid_list:
        return {'error': 'No valid QIDs provided', 'requested': 0, 'found': 0, 'qids': []}

    result = {'requested': len(qid_list), 'found': 0, 'qids': []}

    # Fetch KB data and real QDS scores in parallel
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
            result['qids'].append({
                'qid': qid,
                'title': kb.get('title', ''),
                'severity': kb.get('severity', 0),
                'qds': real_qds or kb.get('qds', 0),
                'qds_factors': kb.get('qds_factors', ''),
                'cves': kb.get('cves', [])[:10],
                'patchAvailable': kb.get('patch_available', False),
                'solution': kb.get('solution', '')[:500],
                'diagnosis': kb.get('diagnosis', '')[:300],
                'threatIntel': kb.get('threat_intel', []),
                'ransomware': kb.get('ransomware', False),
            })
        else:
            result['qids'].append({'qid': qid, 'found': False})

    result['qids'].sort(key=lambda x: (-x.get('severity', 0), -x.get('qds', 0)))
    return result


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
    """[Cloud Security] Cloud security posture across AWS, Azure, and GCP — connected accounts, CIS benchmark control failures, and CDR threat summary. Use get_cdr_findings() for detailed cloud threat investigation."""
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
def get_cdr_findings(days: int = 7, limit: int = 50, severity: str = "", cloud_provider: str = "") -> dict:
    """[Cloud Security] Cloud Detection and Response (CDR) threat findings from Qualys TotalCloud.

    Shows real-time cloud threats detected by deep learning AI across your cloud workloads:
    malware, ransomware, crypto-miners, C2 callbacks, lateral movement, and malicious
    network activity — detected via VPC traffic mirroring and cloud-native log analysis.

    Filters: severity (CRITICAL, HIGH, MEDIUM, LOW), cloud_provider (AWS, AZURE, GCP).
    Returns threat findings with severity/provider/category breakdowns, remote IP attribution,
    and affected resources. Use get_cloud_risk() for broader cloud posture including misconfigurations."""
    result = {
        'days': days,
        'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'byProvider': {},
        'byCategory': {},
        'findings': [],
        'summary': '',
    }

    findings = get_cdr(days, limit, severity=severity or None, cloud_provider=cloud_provider or None)

    sev_map = {'1': 'LOW', '2': 'MEDIUM', '3': 'HIGH', '4': 'CRITICAL'}

    for f in findings:
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
        result['byProvider'][provider] = result['byProvider'].get(provider, 0) + 1

        cat = f.get('threatCategory', '') or f.get('category', '') or f.get('alertClass', '') or 'Unknown'
        result['byCategory'][cat] = result['byCategory'].get(cat, 0) + 1

        remote = f.get('remoteIpDetails', {}) or {}
        remote_info = {}
        if remote:
            remote_info = {
                'ip': remote.get('ipAddressV4', '') or remote.get('ip', ''),
                'country': remote.get('country', ''),
                'city': remote.get('city', ''),
            }

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
        if remote_info and remote_info.get('ip'):
            entry['remoteIp'] = remote_info

        result['findings'].append(entry)

    result['stats']['total'] = len(findings)
    result['byCategory'] = dict(sorted(result['byCategory'].items(), key=lambda x: -x[1]))
    result['byProvider'] = dict(sorted(result['byProvider'].items(), key=lambda x: -x[1]))

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    result['findings'].sort(key=lambda x: sev_order.get(x.get('severity', ''), 4))

    crit = result['stats']['critical']
    high = result['stats']['high']
    total = result['stats']['total']
    providers = ', '.join(result['byProvider'].keys()) or 'none'
    top_cats = ', '.join(list(result['byCategory'].keys())[:3]) or 'none'
    result['summary'] = (
        f"{total} cloud threat findings in last {days} days. "
        f"{crit} critical, {high} high severity. "
        f"Providers: {providers}. Top categories: {top_cats}."
    )

    return result


@mcp.tool()
def get_asset_risk(asset_id: str) -> dict:
    """[Asset Risk] Detailed risk profile for a specific asset — TruRisk score, OS, criticality, installed software with lifecycle status, and EOL flags. Accepts a CSAM assetId (from get_weekly_priorities, get_patch_status, etc). Fast (~3s)."""
    result = {'assetId': asset_id, 'riskScore': 0, 'software': [], 'eolSoftware': []}

    asset = get_asset_by_id(asset_id)
    if asset:
        result['ip'] = asset.get('address', '')
        result['hostname'] = asset.get('dnsHostName', '') or asset.get('dnsName', '')
        result['riskScore'] = int(asset.get('riskScore') or 0)
        result['os'] = (asset.get('operatingSystem') or {}).get('osName', '')
        result['criticality'] = get_criticality(asset)
        result['hostId'] = str(asset.get('hostId') or '')
        result['lastUpdated'] = asset.get('lastModifiedDate', '')
        result['provider'] = (asset.get('cloudProvider') or {}).get('aws', {}).get('ec2', {}).get('region', {}).get('name', '') if asset.get('cloudProvider') else ''

        # Extract software info if available
        sw_list = asset.get('softwareListData', {})
        if sw_list and isinstance(sw_list, dict):
            for sw in (sw_list.get('software') or [])[:30]:
                name = sw.get('fullName') or sw.get('productName') or sw.get('name') or ''
                sw_info = {
                    'name': name.strip(),
                    'version': sw.get('version', ''),
                    'category': sw.get('category', ''),
                }
                lifecycle = (sw.get('lifecycle') or {})
                if lifecycle.get('stage') and lifecycle['stage'] not in ('Unknown', 'Not Applicable', 'OS Dependent'):
                    sw_info['lifecycleStage'] = lifecycle['stage']
                    if is_eol_stage(lifecycle['stage']):
                        result['eolSoftware'].append(sw_info)
                result['software'].append(sw_info)

        # Extract OS lifecycle
        os_info = asset.get('operatingSystem') or {}
        os_lifecycle = (os_info.get('lifecycle') or {})
        if os_lifecycle.get('stage'):
            result['osLifecycle'] = os_lifecycle['stage']

    return result


@mcp.tool()
def get_tech_debt(limit: int = 100) -> dict:
    """[Asset Lifecycle] End-of-life and end-of-support systems — OS and hardware assets running unsupported software that no longer receives security patches, sorted by criticality and risk score. Default limit=100 (~25s). Use limit=500 for full inventory (~2min)."""
    max_pages = max(5, (limit // 10) + 2)

    # Run OS and hardware EOL fetches concurrently
    concurrent = _run_concurrent(
        os_eol=lambda: fetch_all_eol('os', limit, max_pages),
        hw_eol=lambda: fetch_all_eol('hardware', limit, max_pages),
    )

    result = {
        'os': concurrent.get('os_eol') or [],
        'hardware': concurrent.get('hw_eol') or [],
    }

    result['os'].sort(key=lambda x: (-x['criticality'], -x['riskScore']))
    result['hardware'].sort(key=lambda x: (-x['criticality'], -x['riskScore']))
    result['summary'] = {'osEOL': len(result['os']), 'hardwareEOL': len(result['hardware'])}

    return result


@mcp.tool()
def get_image_vulns(image_id: str, limit: int = 50) -> dict:
    """[Container Security] Vulnerabilities for a specific container image — severity breakdown (critical/high/medium/low) and individual vulnerability details with fix versions. Accepts a TotalCloud imageId."""
    result = {
        'imageId': image_id, 'repo': '', 'tag': '',
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
        'vulns': []
    }

    # Run image details and vulns concurrently
    concurrent = _run_concurrent(
        img=lambda: get_image_details(image_id),
        vulns=lambda: get_image_vulns_api(image_id),
    )

    img = concurrent.get('img')
    if img:
        result['repo'] = img.get('repo', '')
        result['tag'] = img.get('tag', '')
        result['created'] = img.get('created', '')

    vulns = concurrent.get('vulns') or []
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
            'qid': v.get('qid'), 'cve': v.get('cveId', ''),
            'severity': sev, 'title': v.get('title', ''),
            'fixVersion': v.get('fixedVersion', '')
        })

    result['stats']['total'] = len(vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    return result


@mcp.tool()
def get_expiring_certs(days: int = 30, include_expired: bool = True, limit: int = 50) -> dict:
    """[CertView] SSL/TLS certificates expiring within N days. Identifies weak algorithms (SHA1, MD5), lists expiring and expired certs with hostname and days until expiry. Use get_security_posture() for overall risk."""
    result = {
        'days': days,
        'stats': {'expiring': 0, 'expired': 0, 'valid': 0, 'weakAlgorithm': 0},
        'expiring': [], 'expired': []
    }

    today = datetime.now(timezone.utc)
    weak_algos = ('sha1', 'md5')

    certs = get_certificates(limit * 2, days)
    for c in certs:
        issuer_obj = c.get('issuer', {}) or {}
        sig_algo = (c.get('signatureAlgorithm', '') or issuer_obj.get('signatureAlgorithm', '') or '').lower()
        is_weak = any(w in sig_algo for w in weak_algos)
        if is_weak:
            result['stats']['weakAlgorithm'] += 1

        cert_info = {
            'id': c.get('id', ''),
            'subject': c.get('subject', {}).get('commonName', ''),
            'issuer': issuer_obj.get('commonName', ''),
            'validTo': c.get('validTo', ''),
            'hosts': [h.get('hostname', '') for h in c.get('hosts', [])[:5]],
        }
        if is_weak:
            cert_info['weakAlgorithm'] = sig_algo

        valid_to = c.get('validTo', '')
        if valid_to:
            try:
                exp_date = datetime.strptime(valid_to[:10], '%Y-%m-%d')
                days_left = (exp_date - today).days
                cert_info['daysUntilExpiry'] = days_left

                if days_left < 0:
                    result['stats']['expired'] += 1
                    if include_expired and len(result['expired']) < limit:
                        result['expired'].append(cert_info)
                elif days_left <= days:
                    result['stats']['expiring'] += 1
                    if len(result['expiring']) < limit:
                        result['expiring'].append(cert_info)
                else:
                    result['stats']['valid'] += 1
            except ValueError:
                pass

    result['expiring'] = sorted(result['expiring'], key=lambda x: x.get('daysUntilExpiry', 999))
    result['expired'] = sorted(result['expired'], key=lambda x: x.get('daysUntilExpiry', 0))
    return result


def get_threats(days: int = 7, limit: int = 50) -> dict:
    """Get combined threat view from FIM (file integrity), EDR (endpoint), and CDR (cloud detection). Returns recent security events."""
    result = {
        'days': days,
        'stats': {'fim': 0, 'edr': 0, 'cdr': 0, 'critical': 0, 'high': 0},
        'fim': [], 'edr': [], 'cdr': []
    }

    # Run all three sources concurrently
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


@mcp.tool()
def get_webapp_vulns(severity: int = 4, days: int = 30, app_name: str = "", limit: int = 50) -> dict:
    """[WAS] Web application vulnerabilities from TotalAppSec scans. Severity breakdown per web app, OWASP categories, critical/high findings. Use get_asset_risk() for host-based vulns."""
    owasp_map = {
        'SQL Injection': 'A03:Injection', 'Cross-Site Scripting': 'A03:Injection',
        'Command Injection': 'A03:Injection', 'LDAP Injection': 'A03:Injection',
        'XSS': 'A03:Injection', 'XXE': 'A05:Security Misconfiguration',
        'SSRF': 'A10:SSRF', 'CSRF': 'A01:Broken Access Control',
        'Authentication': 'A07:Identification and Authentication Failures',
        'Cryptographic': 'A02:Cryptographic Failures', 'Sensitive Data': 'A02:Cryptographic Failures',
    }
    result = {
        'minSeverity': severity, 'days': days,
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'total': 0, 'webApps': 0},
        'vulns': [], 'byWebApp': [], 'owaspHints': {}
    }

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    findings = get_was_findings(limit * 2, severity)
    webapp_vulns = {}

    for f in findings:
        # Filter by app_name if specified
        webapp_name = f.get('webAppName', '')
        if app_name and app_name.lower() not in webapp_name.lower():
            continue

        sev = f.get('severity', 0)
        if sev >= 5:
            result['stats']['critical'] += 1
        elif sev >= 4:
            result['stats']['high'] += 1
        elif sev >= 3:
            result['stats']['medium'] += 1

        # OWASP category hint
        name = f.get('name', '')
        for keyword, owasp in owasp_map.items():
            if keyword.lower() in name.lower():
                result['owaspHints'][owasp] = result['owaspHints'].get(owasp, 0) + 1
                break

        webapp_id = f.get('webAppId', '')
        if webapp_id:
            if webapp_id not in webapp_vulns:
                webapp_vulns[webapp_id] = {'id': webapp_id, 'name': webapp_name, 'critical': 0, 'high': 0, 'total': 0}
            webapp_vulns[webapp_id]['total'] += 1
            if sev >= 5:
                webapp_vulns[webapp_id]['critical'] += 1
            elif sev >= 4:
                webapp_vulns[webapp_id]['high'] += 1

        result['vulns'].append({
            'qid': f.get('qid'), 'name': name,
            'severity': sev, 'url': f.get('url', ''), 'webApp': webapp_name
        })

    result['stats']['total'] = len(result['vulns'])
    result['stats']['webApps'] = len(webapp_vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    result['byWebApp'] = sorted(webapp_vulns.values(), key=lambda x: (x['critical'], x['high'], x['total']), reverse=True)[:20]
    return result


@mcp.tool()
def cache_status(clear: bool = False) -> dict:
    """[Admin] Show cache stats or clear all caches. Use clear=True to reset caches."""
    global DETECTION_CACHE_TIME

    result = {
        'kb_entries': len(KB_CACHE),
        'detection_entries': len(DETECTION_CACHE),
        'detection_cache_age_seconds': None,
        'bearer_token_age_seconds': None,
    }

    if DETECTION_CACHE_TIME:
        result['detection_cache_age_seconds'] = int((datetime.now(timezone.utc) - DETECTION_CACHE_TIME).total_seconds())
    if BEARER_TOKEN_TIME:
        result['bearer_token_age_seconds'] = int((datetime.now(timezone.utc) - BEARER_TOKEN_TIME).total_seconds())

    if clear:
        KB_CACHE.clear()
        DETECTION_CACHE.clear()
        DETECTION_CACHE_TIME = None
        result['cleared'] = True
        result['kb_entries'] = 0
        result['detection_entries'] = 0
        result['detection_cache_age_seconds'] = None

    return result


@mcp.tool()
def get_edr_events(days: int = 7, severity: str = "", category: str = "", host: str = "", limit: int = 50) -> dict:
    """[EDR] Endpoint Detection & Response events — process injections, lateral movement, suspicious executions. Aggregated by host and event type. Use get_fim_events() for file integrity events."""
    result = {
        'days': days,
        'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'bySeverity': {}, 'byCategory': {}},
        'events': [], 'byHost': {}
    }

    sev_filter = severity if severity else None
    events = _fetch_edr_events_raw(limit * 2, sev_filter)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    for e in events:
        # Filter by days
        dt = e.get('dateTime', '')
        if dt:
            try:
                event_time = datetime.strptime(dt[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                if event_time < cutoff:
                    continue
            except ValueError:
                pass

        # Filter by category
        evt_category = e.get('eventType', '') or e.get('category', '')
        if category and category.lower() not in evt_category.lower():
            continue

        # Filter by host
        hostname = e.get('hostname', '') or e.get('asset', {}).get('hostname', '')
        if host and host.lower() not in hostname.lower():
            continue

        sev = e.get('severity', 'Unknown')
        result['stats']['bySeverity'][sev] = result['stats']['bySeverity'].get(sev, 0) + 1
        if sev in ('Critical', 'CRITICAL', '5'):
            result['stats']['critical'] += 1
        elif sev in ('High', 'HIGH', '4'):
            result['stats']['high'] += 1
        elif sev in ('Medium', 'MEDIUM', '3'):
            result['stats']['medium'] += 1

        result['stats']['byCategory'][evt_category] = result['stats']['byCategory'].get(evt_category, 0) + 1

        if hostname:
            if hostname not in result['byHost']:
                result['byHost'][hostname] = 0
            result['byHost'][hostname] += 1

        if len(result['events']) < limit:
            result['events'].append({
                'type': evt_category, 'process': e.get('processName', ''),
                'hostname': hostname, 'dateTime': dt, 'severity': sev,
            })

    result['stats']['total'] = sum(result['stats']['bySeverity'].values())
    return result


@mcp.tool()
def get_fim_events(days: int = 7, severity: str = "", host: str = "", path: str = "", limit: int = 50) -> dict:
    """[FIM] File Integrity Monitoring events — unauthorized file changes, critical system file modifications, suspicious paths (/etc/passwd, registry run keys). Use get_edr_events() for process-level threats."""
    critical_paths = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', 'C:\\Windows\\System32',
                      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run']
    result = {
        'days': days,
        'stats': {'total': 0, 'criticalPathEvents': 0, 'bySeverity': {}},
        'events': [], 'byHost': {}, 'criticalPathAlerts': []
    }

    events = _fetch_fim_events_raw(limit * 2, days)

    for e in events:
        file_path = e.get('filePath', '') or e.get('fullPath', '')
        hostname = e.get('hostname', '') or e.get('asset', {}).get('hostname', '')
        sev = e.get('severity', '') or 'Unknown'

        # Filter by severity
        if severity and severity.lower() != str(sev).lower():
            continue
        # Filter by host
        if host and host.lower() not in hostname.lower():
            continue
        # Filter by path
        if path and path.lower() not in file_path.lower():
            continue

        result['stats']['bySeverity'][str(sev)] = result['stats']['bySeverity'].get(str(sev), 0) + 1

        # Critical path detection
        is_critical = any(cp.lower() in file_path.lower() for cp in critical_paths if file_path)
        if is_critical:
            result['stats']['criticalPathEvents'] += 1
            result['criticalPathAlerts'].append({
                'path': file_path, 'hostname': hostname,
                'action': e.get('action', ''), 'dateTime': e.get('dateTime', '')
            })

        if hostname:
            result['byHost'][hostname] = result['byHost'].get(hostname, 0) + 1

        if len(result['events']) < limit:
            event_info = {
                'action': e.get('action', ''), 'path': file_path,
                'hostname': hostname, 'dateTime': e.get('dateTime', ''),
                'severity': sev,
            }
            if is_critical:
                event_info['criticalPath'] = True
            result['events'].append(event_info)

    result['stats']['total'] = sum(result['stats']['bySeverity'].values())
    return result


@mcp.tool()
def get_scan_status(state: str = "Running,Queued,Error", days: int = 1, limit: int = 50) -> dict:
    """[VM] Scan status summary — running, queued, failed scans with duration and target info. Use get_scanner_health() for appliance status."""
    result = {
        'states': state,
        'stats': {'total': 0, 'byState': {}},
        'scans': []
    }

    scans = get_scan_list(state, limit)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    for s in scans:
        scan_state = s.get('state', '')
        launched = s.get('launched', '')

        # Filter by days if launched date available
        if launched and days:
            try:
                launch_time = datetime.strptime(launched[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                if launch_time < cutoff:
                    continue
            except ValueError:
                pass

        result['stats']['byState'][scan_state] = result['stats']['byState'].get(scan_state, 0) + 1

        if len(result['scans']) < limit:
            result['scans'].append({
                'ref': s.get('ref', ''), 'title': s.get('title', ''),
                'state': scan_state, 'type': s.get('type', ''),
                'target': s.get('target', ''), 'launched': launched,
                'duration': s.get('duration', ''), 'scanner': s.get('scannerName', ''),
            })

    result['stats']['total'] = sum(result['stats']['byState'].values())
    return result


@mcp.tool()
def get_pm_status(platform: str = "Windows", days: int = 30, limit: int = 20) -> dict:
    """[PM] Patch Management deployment status — jobs, patch counts by severity, asset coverage. Platform: Windows or Linux. Use get_eliminate_status() for TruRisk Eliminate/Mitigate."""
    concurrent = _run_concurrent(
        jobs=lambda: get_pm_jobs(platform, limit),
        patches_total=lambda: get_pm_patches_count(platform),
        patches_by_sev=lambda: get_pm_patches_count(platform, 'vendorSeverity'),
        assets=lambda: get_pm_assets(platform, limit),
    )

    jobs = concurrent.get('jobs') or []
    patches_total = concurrent.get('patches_total') or {}
    patches_by_sev = concurrent.get('patches_by_sev') or {}
    assets = concurrent.get('assets') or []

    job_list = []
    if isinstance(jobs, list):
        for j in jobs[:limit]:
            if isinstance(j, dict):
                job_list.append({
                    'id': j.get('id', ''), 'name': j.get('name', ''),
                    'status': j.get('status', ''), 'platform': platform,
                    'createdDate': j.get('createdDate', ''),
                })
    elif isinstance(jobs, dict):
        for j in jobs.get('jobs', jobs.get('data', []))[:limit]:
            if isinstance(j, dict):
                job_list.append({
                    'id': j.get('id', ''), 'name': j.get('name', ''),
                    'status': j.get('status', ''), 'platform': platform,
                })

    asset_list = []
    if isinstance(assets, list):
        for a in assets[:limit]:
            if isinstance(a, dict):
                asset_list.append({
                    'id': a.get('id', ''), 'name': a.get('name', '') or a.get('hostname', ''),
                    'os': a.get('os', '') or a.get('operatingSystem', ''),
                })
    elif isinstance(assets, dict):
        for a in assets.get('assets', assets.get('data', []))[:limit]:
            if isinstance(a, dict):
                asset_list.append({
                    'id': a.get('id', ''), 'name': a.get('name', ''),
                })

    return {
        'platform': platform,
        'stats': {
            'totalPatches': patches_total.get('count', patches_total) if isinstance(patches_total, dict) else patches_total,
            'patchesBySeverity': patches_by_sev,
            'totalJobs': len(job_list),
            'totalAssets': len(asset_list),
        },
        'jobs': job_list,
        'assets': asset_list,
    }


@mcp.tool()
def get_asset_inventory(query: str = "", tag: str = "", os: str = "", days_since_seen: int = 30, eol_only: bool = False, limit: int = 50) -> dict:
    """[CSAM] Asset inventory — search by OS, tag, or keyword. EOL/EOS filtering, last seen filtering, platform breakdown. Use get_asset_risk() for a specific asset's vulnerability details."""
    filters = []
    if os:
        filters.append({"field": "operatingSystem.osName", "operator": "CONTAINS", "value": os})
    if tag:
        filters.append({"field": "tags.name", "operator": "CONTAINS", "value": tag})
    if query:
        filters.append({"field": "asset.name", "operator": "CONTAINS", "value": query})
    if days_since_seen:
        since = (datetime.now(timezone.utc) - timedelta(days=days_since_seen)).strftime('%Y-%m-%dT00:00:00Z')
        filters.append({"field": "asset.lastSeen", "operator": "GREATER", "value": since})
    if eol_only:
        filters.append({"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"})

    assets = csam_search(filters=filters if filters else None, limit=limit,
                         fields="operatingSystem,hardware,tags")

    result = {
        'stats': {'total': len(assets), 'byOS': {}, 'byPlatform': {}, 'eolCount': 0},
        'assets': []
    }

    for a in assets:
        os_info = a.get('operatingSystem', {}) or {}
        hw_info = a.get('hardware', {}) or {}
        os_name = os_info.get('osName', '') or 'Unknown'
        platform = hw_info.get('manufacturer', '') or os_info.get('category', '') or 'Unknown'
        lifecycle = (os_info.get('lifecycle', {}) or {}).get('stage', '')
        is_eol = is_eol_stage(lifecycle)

        if is_eol:
            result['stats']['eolCount'] += 1

        result['stats']['byOS'][os_name] = result['stats']['byOS'].get(os_name, 0) + 1
        result['stats']['byPlatform'][platform] = result['stats']['byPlatform'].get(platform, 0) + 1

        result['assets'].append({
            'assetId': a.get('assetId', ''),
            'name': a.get('name', '') or a.get('dnsName', ''),
            'os': os_name,
            'lastSeen': a.get('lastSeen', ''),
            'riskScore': a.get('riskScore', 0) or 0,
            'isEOL': is_eol,
        })

    result['assets'].sort(key=lambda x: -x['riskScore'])
    return result


@mcp.tool()
def get_vuln_exceptions(status: str = "active", vuln_type: str = "", days_to_expiry: int = 0, limit: int = 50) -> dict:
    """[VM] Vulnerability exceptions — approved risk acceptances, false positives, compensating controls. Shows expiring exceptions needing review. Use get_patch_status() for remediation status."""
    result = {
        'status': status,
        'stats': {'total': 0, 'byType': {}, 'expiringSoon': 0},
        'exceptions': []
    }

    url = f"{BASE_URL}/api/2.0/fo/exception/vuln/?action=list&status={status}"
    data = api_get(url, timeout=30)
    if not data:
        result['note'] = 'Exceptions API not available — may require additional Qualys subscription'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['note'] = 'Exceptions API returned invalid response'
        return result

    today = datetime.now(timezone.utc)
    expiry_cutoff = today + timedelta(days=days_to_expiry) if days_to_expiry > 0 else None

    for exc in root.findall('.//EXCEPTION')[:limit * 2]:
        exc_type = exc.findtext('EXCEPTION_TYPE', '') or exc.findtext('TYPE', '')
        if vuln_type and vuln_type.lower() not in exc_type.lower():
            continue

        expiry = exc.findtext('EXPIRY_DATE', '') or exc.findtext('EXPIRATION_DATE', '')
        days_left = None
        if expiry:
            try:
                exp_date = datetime.strptime(expiry[:10], '%Y-%m-%d').replace(tzinfo=timezone.utc)
                days_left = (exp_date - today).days
                if days_left <= 30:
                    result['stats']['expiringSoon'] += 1
                if expiry_cutoff and exp_date > expiry_cutoff:
                    continue
            except ValueError:
                pass

        result['stats']['byType'][exc_type] = result['stats']['byType'].get(exc_type, 0) + 1

        if len(result['exceptions']) < limit:
            entry = {
                'id': exc.findtext('EXCEPTION_NUMBER', '') or exc.findtext('ID', ''),
                'qid': exc.findtext('QID', ''),
                'type': exc_type,
                'status': exc.findtext('STATUS', status),
                'comments': exc.findtext('COMMENTS', '') or exc.findtext('REASON', ''),
                'hostIp': exc.findtext('HOST_IP', '') or exc.findtext('IP', ''),
                'expiryDate': expiry,
            }
            if days_left is not None:
                entry['daysUntilExpiry'] = days_left
            result['exceptions'].append(entry)

    result['stats']['total'] = sum(result['stats']['byType'].values())
    return result


@mcp.tool()
def get_compliance_posture(framework: str = "", platform: str = "", limit: int = 50) -> dict:
    """[PC] Policy Compliance posture — pass/fail rates by framework (PCI-DSS, CIS, NIST, HIPAA), top failing controls, compliance trend. Use get_cloud_risk() for cloud-specific compliance."""
    result = {
        'available': False,
        'stats': {'passRate': 0, 'failRate': 0, 'totalControls': 0},
        'byFramework': {}, 'topFailing': []
    }

    # Try posture info endpoint
    data = api_get(f"{BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list", timeout=30)
    if data:
        try:
            root = ET.fromstring(data)
            result['available'] = True
            controls = root.findall('.//CONTROL') or root.findall('.//POSTURE')
            passed = 0
            failed = 0
            failing = []

            for c in controls[:limit * 2]:
                status = (c.findtext('STATUS', '') or c.findtext('RESULT', '')).upper()
                ctrl_framework = c.findtext('FRAMEWORK', '') or c.findtext('TECHNOLOGY', '')
                ctrl_name = c.findtext('CONTROL_NAME', '') or c.findtext('TITLE', '')

                if framework and framework.lower() not in ctrl_framework.lower():
                    continue
                if platform and platform.lower() not in (c.findtext('PLATFORM', '') or '').lower():
                    continue

                if 'PASS' in status:
                    passed += 1
                elif 'FAIL' in status:
                    failed += 1
                    failing.append({'control': ctrl_name, 'framework': ctrl_framework, 'status': status})

                if ctrl_framework:
                    if ctrl_framework not in result['byFramework']:
                        result['byFramework'][ctrl_framework] = {'pass': 0, 'fail': 0}
                    if 'PASS' in status:
                        result['byFramework'][ctrl_framework]['pass'] += 1
                    elif 'FAIL' in status:
                        result['byFramework'][ctrl_framework]['fail'] += 1

            total = passed + failed
            result['stats']['totalControls'] = total
            result['stats']['passRate'] = round(passed / total * 100, 1) if total else 0
            result['stats']['failRate'] = round(failed / total * 100, 1) if total else 0
            result['topFailing'] = failing[:limit]
            return result
        except ET.ParseError:
            pass

    # Fallback: try compliance report list
    data2 = api_get(f"{BASE_URL}/api/2.0/fo/report/?action=list&report_type=Compliance", timeout=30)
    if data2:
        try:
            root = ET.fromstring(data2)
            reports = root.findall('.//REPORT')
            if reports:
                result['available'] = True
                result['reports'] = []
                for r in reports[:limit]:
                    result['reports'].append({
                        'id': r.findtext('ID', ''),
                        'title': r.findtext('TITLE', ''),
                        'date': r.findtext('LAUNCH_DATETIME', ''),
                        'status': r.findtext('STATUS/STATE', ''),
                    })
                result['note'] = 'Detailed posture data requires Policy Compliance module. Compliance reports listed.'
                return result
        except ET.ParseError:
            pass

    result['note'] = 'Policy Compliance module not licensed or no data available'
    return result


def main():
    mcp.run()


if __name__ == "__main__":
    main()
