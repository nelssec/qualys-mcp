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
KB_CACHE_TIME = {}  # {qid: datetime} for per-entry TTL (1 hour)
DETECTION_CACHE = {}
DETECTION_CACHE_TIME = {}    # {cache_key: datetime} for per-key TTL
QDS_CACHE = {}
QDS_CACHE_TIME = None
WAS_CACHE = {}          # {cache_key: findings_list}
WAS_CACHE_TIME = {}     # {cache_key: datetime}
SCANNER_CACHE = None    # list of scanner dicts
SCANNER_CACHE_TIME = None
ETM_RESULT_CACHE = None     # last completed ETM report result dict
ETM_RESULT_CACHE_TIME = None  # datetime of cache fill

AUTH_ERROR = None
AUTH_LOCK = Lock()

# Per-key cache locks for _get_or_fetch request deduplication
_cache_locks = {}
_cache_locks_lock = Lock()

# Pagination safety: max pages any helper will fetch to prevent runaway loops.
# Set QUALYS_MAX_PAGES env var to override. 0 = unlimited (default).
# Tools needing just a count use count_only=True (1 API call).
MAX_PAGES = int(os.environ.get('QUALYS_MAX_PAGES', '0'))

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


def _get_or_fetch(cache_dict, cache_time_dict, key, fetch_fn, ttl):
    """Thread-safe cache get-or-fetch with per-key locking.
    Prevents duplicate concurrent requests for the same cache key.
    Uses datetime objects for timestamps to match existing cache patterns."""
    with _cache_locks_lock:
        if key not in _cache_locks:
            _cache_locks[key] = Lock()
        lock = _cache_locks[key]
    with lock:
        now = datetime.now(timezone.utc)
        cached_time = cache_time_dict.get(key)
        if key in cache_dict and cached_time and (now - cached_time).total_seconds() < ttl:
            return cache_dict[key]
        result = fetch_fn()
        cache_dict[key] = result
        cache_time_dict[key] = datetime.now(timezone.utc)
        return result


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


def _parse_detections_xml(data):
    """Parse VMDR detection XML into a list of dicts. Returns (dets, is_truncated, max_host_id).
    Detects WARNING CODE 1980 (truncation) for id_min pagination."""
    dets = []
    is_truncated = False
    max_host_id = 0
    try:
        root = ET.fromstring(data)
        # Check for truncation warning (CODE 1980)
        for warning in root.findall('.//WARNING'):
            code = warning.findtext('CODE', '')
            if code == '1980':
                is_truncated = True
                _log("VMDR detection API: truncation warning (CODE 1980) — more records exist")
        for host in root.findall('.//HOST'):
            hid = host.findtext('ID', '')
            ip = host.findtext('IP', '')
            hostname = host.findtext('DNS', '')
            try:
                host_id_int = int(hid) if hid else 0
                if host_id_int > max_host_id:
                    max_host_id = host_id_int
            except ValueError:
                pass
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
    return dets, is_truncated, max_host_id


def get_detections(severity=5, limit=0, use_cache=True, days=30, qds_min=0, fetch_all=True):
    """Get VMDR detections with hostname and QDS. Uses 5-minute cache (TTL 300s).
    Thread-safe via _get_or_fetch — concurrent calls for the same params are deduplicated.
    Best practices: filter_superseded_qids, vm_processed_after, qds_min.
    Note: VMDR classic API is slow (~2min) for large environments.
    When fetch_all=True (default), paginates using id_min until no truncation warning.
    Set limit>0 to cap returned results (0=all)."""
    cache_key = f"detections_{severity}_{days}_{qds_min}"

    def _fetch():
        after_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
        base_url = (
            f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
            f"&severities={severity}&status=Active"
            f"&show_qds=1&filter_superseded_qids=1"
            f"&vm_processed_after={after_date}"
        )
        if qds_min > 0:
            base_url += f"&qds_min={qds_min}"

        all_dets = []
        id_min = 0
        max_page_cap = MAX_PAGES if MAX_PAGES > 0 else 0  # 0 = unlimited
        pages = 0
        while True:
            if max_page_cap > 0 and pages >= max_page_cap:
                _log(f"VMDR detections: hit MAX_PAGES cap ({max_page_cap})")
                break
            url = base_url
            if id_min > 0:
                url += f"&id_min={id_min}"
            data = api_get(url, timeout=180)
            if not data:
                break
            dets, is_truncated, max_host_id = _parse_detections_xml(data)
            all_dets.extend(dets)
            pages += 1
            if not is_truncated or max_host_id == 0:
                break
            id_min = max_host_id + 1
        if pages > 1:
            _log(f"VMDR detections: fetched {len(all_dets)} records across {pages} pages")
        return all_dets

    if not use_cache:
        result = _fetch()
        DETECTION_CACHE[cache_key] = result
        DETECTION_CACHE_TIME[cache_key] = datetime.now(timezone.utc)
        return result[:limit] if limit > 0 else result

    dets = _get_or_fetch(DETECTION_CACHE, DETECTION_CACHE_TIME, cache_key, _fetch, 300)
    return dets[:limit] if limit > 0 else dets


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
                f"&filter_superseded_qids=1",
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
    # CVSS v3 — base score, temporal score, and vector string
    cvss_v3 = v.find('CVSS_V3')
    cvss_v3_base = None
    cvss_v3_temporal = None
    cvss_v3_vector = ''
    if cvss_v3 is not None:
        try:
            base_text = cvss_v3.findtext('BASE', '')
            if base_text:
                cvss_v3_base = float(base_text)
        except (ValueError, TypeError):
            pass
        try:
            temp_text = cvss_v3.findtext('TEMPORAL', '')
            if temp_text:
                cvss_v3_temporal = float(temp_text)
        except (ValueError, TypeError):
            pass
        cvss_v3_vector = cvss_v3.findtext('VECTOR_STRING', '') or ''

    # Exploit availability — check EXPLOIT_LIST for any exploit entries
    has_exploit = v.find('.//EXPLOIT_LIST/EXPLOIT') is not None

    return {
        'qid': qid,
        'title': v.findtext('TITLE', ''),
        'severity': int(v.findtext('SEVERITY_LEVEL', '0')),
        'qds': qds,
        'qds_factors': qds_factors,
        'cvss_v3': cvss_v3_base,
        'cvss_v3_temporal': cvss_v3_temporal,
        'cvss_v3_vector': cvss_v3_vector,
        'cves': [c.findtext('ID', '') for c in v.findall('.//CVE_LIST/CVE')],
        'solution': v.findtext('SOLUTION', ''),
        'diagnosis': v.findtext('DIAGNOSIS', ''),
        'patch_available': v.findtext('PATCHABLE', '0') == '1',
        'has_exploit': has_exploit,
        'threat_intel': threat_intel,
        'ransomware': 'Ransomware' in threat_intel,
    }


def get_kb(qid):
    """Get KB entry for a single QID (uses cache with 1-hour TTL)"""
    now = datetime.now(timezone.utc)
    if qid in KB_CACHE:
        cached_time = KB_CACHE_TIME.get(qid)
        if cached_time and (now - cached_time).total_seconds() < 3600:
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
        KB_CACHE_TIME[qid] = now
        return result
    except ET.ParseError:
        return None


def get_kb_batch(qids):
    """Get KB entries for multiple QIDs in one API call (uses cache with 1-hour TTL)"""
    if not qids:
        return {}

    now = datetime.now(timezone.utc)
    # Only fetch QIDs not in cache or with expired TTL (> 1 hour)
    uncached = [
        q for q in qids
        if q not in KB_CACHE or
        (KB_CACHE_TIME.get(q) and (now - KB_CACHE_TIME[q]).total_seconds() >= 3600)
    ]

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
                        KB_CACHE_TIME[parsed['qid']] = now
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


def _scope_filters(base_filters, tag='', asset_group=''):
    """Append tag and/or asset_group CSAM filters to a base filter list."""
    filters = list(base_filters) if base_filters else []
    if tag:
        filters.append({"field": "asset.tags.name", "operator": "EQUALS", "value": tag})
    if asset_group:
        filters.append({"field": "asset.assetGroups.name", "operator": "EQUALS", "value": asset_group})
    return filters or None


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


def csam_search(filters=None, limit=100, fields=None, fetch_all=True):
    """Search assets with optional structured filters. Returns list of assets.
    filters: list of {"field": "...", "operator": "...", "value": "..."} dicts
    fields: comma-separated includeFields (e.g. "operatingSystem,hardware")
    When fetch_all=True (default), paginates using lastSeenAssetId cursor until all pages exhausted.
    """
    token = get_bearer_token()
    # Always include tags so every asset response has tags[]
    if fields:
        if 'tags' not in fields:
            fields = f"{fields},tags"
    else:
        fields = "tags"
    page_size = min(limit, 100) if not fetch_all else 100
    body = json.dumps({"filters": filters}) if filters else "{}"
    all_assets = []
    last_id = None
    max_page_cap = MAX_PAGES if MAX_PAGES > 0 else 0  # 0 = unlimited
    pages = 0
    while True:
        if max_page_cap > 0 and pages >= max_page_cap:
            _log(f"CSAM search: hit MAX_PAGES cap ({max_page_cap})")
            break
        if not fetch_all and len(all_assets) >= limit:
            break
        url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={page_size}"
        if fields:
            url += f"&includeFields={fields}"
        if last_id:
            url += f"&lastSeenAssetId={last_id}"
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
                all_assets.extend(assets)
                pages += 1
                if not data.get('hasMore'):
                    break
                last_id = assets[-1].get('assetId')
        except Exception as e:
            _log(f"csam_search error: {e}")
            break
    if pages > 1:
        _log(f"CSAM search: fetched {len(all_assets)} assets across {pages} pages")
    if not fetch_all:
        return all_assets[:limit]
    return all_assets


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


def _paginate_json(base_url, limit, data_key='data', count_key='count',
                    page_param='pageNumber', size_param='pageSize',
                    count_only=False, gateway=True, fetch_all=True):
    """Generic paginated fetch for JSON APIs. Returns list or int (count_only).
    When fetch_all=True (default), fetches all pages up to MAX_PAGES (0=unlimited).
    When fetch_all=False, respects the limit parameter strictly."""
    page_size = min(limit, 100)
    results = []
    page = 1
    # Determine page cap: fetch_all ignores limit-based cap; MAX_PAGES=0 means unlimited
    if fetch_all:
        cap = MAX_PAGES if MAX_PAGES > 0 else 0  # 0 = unlimited
    else:
        cap = max(1, (limit // page_size) + 1)
        if MAX_PAGES > 0:
            cap = min(cap, MAX_PAGES)
    sep = '&' if '?' in base_url else '?'
    pages_fetched = 0
    while True:
        if cap > 0 and pages_fetched >= cap:
            _log(f"Pagination: hit MAX_PAGES cap ({cap}) for {base_url.split('?')[0]}")
            break
        if not fetch_all and len(results) >= limit:
            break
        url = f"{base_url}{sep}{size_param}={page_size}&{page_param}={page}"
        data = api_get(url, gateway=gateway)
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            break
        if count_only and page == 1:
            return parsed.get(count_key, len(parsed.get(data_key, [])))
        batch = parsed.get(data_key, [])
        if not batch:
            break
        results.extend(batch)
        pages_fetched += 1
        if len(batch) < page_size:
            break
        page += 1
    if count_only:
        return len(results)
    if not fetch_all:
        return results[:limit]
    if len(results) > limit:
        _log(f"Pagination: fetched {len(results)} records (requested limit={limit}) from {base_url.split('?')[0]}")
    return results


def get_images(limit=100, severity=None, count_only=False):
    """Fetch container images with pagination. Set count_only=True to return just the int count."""
    url = f"{GATEWAY_URL}/csapi/v1.3/images?sort=created:desc"
    if severity:
        url += f"&filter=vulnerabilities.severity:{severity}"
    return _paginate_json(url, limit, count_only=count_only)


def get_containers(limit=100, count_only=False):
    """Fetch running containers with pagination. Set count_only=True to return just the int count."""
    url = f"{GATEWAY_URL}/csapi/v1.3/containers?filter=state:RUNNING"
    return _paginate_json(url, limit, count_only=count_only)


def get_connectors(provider='aws', limit=50):
    url = f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/connectors"
    return _paginate_json(url, limit, data_key='content', count_key='totalElements',
                          page_param='pageNo', size_param='pageSize')


def get_evaluations(account_id, provider='aws', limit=500):
    url = f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}"
    return _paginate_json(url, limit, data_key='content', count_key='totalElements',
                          page_param='pageNo', size_param='pageSize')


def get_cdr(days=7, limit=100, severity=None, cloud_provider=None, category=None):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    url = f"{GATEWAY_URL}/cdr-api/rest/v1/findings/?startAt={start.isoformat()}Z&endAt={end.isoformat()}Z"
    if severity:
        url += f"&severity={severity}"
    if cloud_provider:
        url += f"&cloudProvider={cloud_provider}"
    if category:
        url += f"&category={category}"
    return _paginate_json(url, limit, data_key='content', count_key='totalElements',
                          page_param='pageNumber', size_param='limit')


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
    url = f"{GATEWAY_URL}/certview/v1/certificates"
    if days_expiring:
        future = (datetime.now(timezone.utc) + timedelta(days=days_expiring)).strftime('%Y-%m-%d')
        url += f"?filter=validTo:<{future}"
    return _paginate_json(url, limit)


def _fetch_fim_events_raw(limit=100, days=7, host=''):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    filt = f"dateTime:[{start.strftime('%Y-%m-%dT%H:%M:%SZ')}...{end.strftime('%Y-%m-%dT%H:%M:%SZ')}]"
    if host:
        filt += f" and asset.hostname:{host}"
    url = f"{BASE_URL}/fim/v2/events?filter={filt}"
    return _paginate_json(url, limit, gateway=False)


def _fetch_edr_events_raw(limit=100, severity=None):
    url = f"{GATEWAY_URL}/edr/v1/events"
    if severity:
        url += f"?filter=severity:{severity}"
    return _paginate_json(url, limit)


def get_was_findings(limit=100, severity=None, days=None, app_name=None):
    """Get WAS findings with optional server-side filters. Uses 10-minute per-key cache (TTL 600s).
    Thread-safe via _get_or_fetch — concurrent calls for the same params are deduplicated.
    days: only findings detected in the last N days (detectedDate filter).
    app_name: substring match on webApp.name (server-side CONTAINS filter).
    severity: exact severity level filter (1-5).
    """
    cache_key = f"was_{limit}_{severity}_{days}_{app_name}"

    def _fetch():
        now = datetime.now(timezone.utc)
        url = f"{BASE_URL}/qps/rest/3.0/search/was/finding"
        criteria = "<ServiceRequest><filters><Criteria field=\"status\" operator=\"EQUALS\">ACTIVE</Criteria>"
        if severity:
            criteria += f"<Criteria field=\"severity\" operator=\"EQUALS\">{severity}</Criteria>"
        if days:
            cutoff = (now - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
            criteria += f"<Criteria field=\"detectedDate\" operator=\"GREATER\">{cutoff}</Criteria>"
        if app_name:
            criteria += f"<Criteria field=\"webApp.name\" operator=\"CONTAINS\">{app_name}</Criteria>"
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
                        'webAppName': f.findtext('webApp/name', ''),
                        'detectedDate': f.findtext('detectedDate', ''),
                        'type': f.findtext('type', ''),
                    })
                return findings
        except Exception as e:
            _log(f"WAS findings error: {e}")
            return []

    return _get_or_fetch(WAS_CACHE, WAS_CACHE_TIME, cache_key, _fetch, 600)


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
    """Get scanner appliance list with status and health metrics. Uses 5-minute cache."""
    global SCANNER_CACHE, SCANNER_CACHE_TIME
    now = datetime.now(timezone.utc)

    if SCANNER_CACHE is not None and SCANNER_CACHE_TIME:
        age = (now - SCANNER_CACHE_TIME).total_seconds()
        if age < 300:  # 5-minute cache
            return SCANNER_CACHE

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
    SCANNER_CACHE = scanners
    SCANNER_CACHE_TIME = now
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


def fetch_all_eol(eol_type, limit=0, max_pages=0):
    """Fetch EOL assets with pagination. eol_type is 'os' or 'hardware'.
    limit=0 means fetch all. max_pages=0 means use global MAX_PAGES (0=unlimited)."""
    token = get_bearer_token()
    if eol_type == 'os':
        filters = [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]
    else:
        filters = [{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]

    results = []
    seen = set()
    last_id = None
    page_cap = max_pages if max_pages > 0 else (MAX_PAGES if MAX_PAGES > 0 else 0)
    pages = 0

    while True:
        if page_cap > 0 and pages >= page_cap:
            _log(f"fetch_all_eol({eol_type}): hit page cap ({page_cap})")
            break
        if limit > 0 and len(results) >= limit:
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

                pages += 1
                if not data.get('hasMore'):
                    break
                last_id = assets[-1].get('assetId')
        except Exception:
            break

    if pages > 1:
        _log(f"fetch_all_eol({eol_type}): fetched {len(results)} EOL assets across {pages} pages")
    return results[:limit] if limit > 0 else results


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
def get_weekly_priorities(limit: int = 10, sort_by: str = "trurisk", tag: str = "", asset_group: str = "") -> dict:
    """[Risk Management] Prioritized security actions for the week — top high-risk assets ranked by TruRisk score, risk distribution across severity tiers, and container risks. Fast (~5s).

    **Use when:** Starting the week, planning sprint priorities, asking "what should we fix first?", or looking for the top assets to remediate.
    **NOT for:** Daily threat monitoring (use get_morning_report), single-asset details (use get_asset_risk), or cloud posture (use get_cloud_risk).

    Parameters:
        limit: max top-risk assets to return (default 10)
        sort_by: ranking method — 'trurisk' (default, CSAM field truRisk DESC) or 'severity'
        tag: filter to assets with this tag (e.g. Production, PCI, cloud)
        asset_group: filter to assets in this Qualys asset group

    Returns: topRiskAssets (ranked by TruRisk), priorities (actionable items), summary counts by risk tier.
    Follow up with get_asset_risk(assetId) for per-asset vulnerability details. For actual patch deployment status, use get_eliminate_status. For a patch catalog view, use get_patch_status."""
    result = {'summary': {}, 'priorities': [], 'topRiskAssets': []}

    # All fast CSAM v2 queries (~0.2-3s each, run in parallel)
    # Search at multiple risk tiers to ensure we get the actual highest-risk assets
    # (CSAM API doesn't sort results, so a broad >500 search may miss >900 assets)
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
    """[Vulnerability Intelligence] Investigate a specific CVE across your environment — maps the CVE to Qualys QIDs, retrieves KB details (severity, patches, threat intel, ransomware linkage), and searches your asset inventory for systems running the affected software. Fast (~5s).

    **Use when:** Deep-diving a single CVE — "are we affected by CVE-2024-3400?", incident response triage, or tracing a CVE to specific assets. Returns KB + asset impact in one call.
    **NOT for:** Bulk CVE lookup (use get_cve_details for up to 20 CVEs at once), KB-only search without asset context (use search_vulns), or confirmed finding status (use get_etm_findings with QQL `vulnerabilities.vulnerability.cveIds:CVE-...`).

    **Difference from get_cve_details:** investigate_cve does a single CVE but also searches your asset inventory for systems running affected software. get_cve_details handles up to 20 CVEs but returns KB data only (no asset search)."""
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
                    result['has_exploit'] = kb.get('has_exploit', False)
                    result['cvss_v3'] = kb.get('cvss_v3')
                    result['cvss_v3_vector'] = kb.get('cvss_v3_vector', '')
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
                    'cvss_v3': kb.get('cvss_v3'),
                    'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                    'patchAvailable': kb.get('patch_available', False),
                    'has_exploit': kb.get('has_exploit', False),
                    'cves': kb.get('cves', []),
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


def get_security_posture(tag: str = "", asset_group: str = "") -> dict:
    """Internal helper — overall security health score (0-100). Called by get_morning_report.
    Not exposed as an MCP tool; use get_morning_report or get_weekly_priorities instead.

    tag: filter to assets with this tag (e.g. Production, PCI, cloud)
    asset_group: filter to assets in this Qualys asset group

    Returns: healthScore (0-100), asset counts by risk tier, container exposure, cloud account/control counts."""
    health = 100
    result = {'healthScore': 0, 'assets': {'total': 0, 'highRisk': 0},
              'vulns': {'critical': 0, 'high': 0}, 'containers': {'total': 0, 'atRisk': 0},
              'cloud': {'accounts': 0, 'failedControls': 0}, 'warnings': []}

    base = _scope_filters(None, tag, asset_group)
    # All fast CSAM v2 count queries (~0.2s each, run in parallel)
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

    # Cloud — fetch all three providers' connectors in parallel, then evals in parallel (#17)
    try:
        cloud_conns = _run_concurrent(
            aws=lambda: get_connectors('aws', 5),
            azure=lambda: get_connectors('azure', 5),
            gcp=lambda: get_connectors('gcp', 5),
        )
        acc_key_map = {'aws': 'awsAccountId', 'azure': 'azureSubscriptionId', 'gcp': 'gcpProjectId'}
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


@mcp.tool()
def get_patch_status(limit: int = 20, tag: str = "", asset_group: str = "") -> dict:
    """[Patch Management] Patching coverage and remediation gaps — TruRisk distribution across severity tiers and top unpatched assets ranked by risk score. Fast (~5s).

    **Use when:** Assessing patch posture, "how many assets are unpatched?", or identifying top unpatched assets by risk. Returns risk distribution tiers and highest-risk assets.
    **NOT for:** Active patch job deployment status (use get_eliminate_status), PM catalog/job details per platform (use get_pm_status), or single-asset patch details (use get_asset_risk).

    Parameters:
        limit: max high-risk assets to return (default 20)
        tag: filter to assets with this tag (e.g. Production, PCI, cloud)
        asset_group: filter to assets in this Qualys asset group

    Follow up with get_asset_risk(assetId) for per-asset vulnerability details."""
    result = {'coverage': 0, 'assetsTotal': 0, 'riskDistribution': {},
              'highRiskAssets': []}

    # All fast CSAM v2 queries (~0.2-3s each, run in parallel)
    # Search at multiple risk tiers to ensure we get the actual highest-risk assets
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
def search_vulns(days: int = 7, threat_type: str = "", software: str = "", limit: int = 50, tag: str = "", asset_group: str = "") -> dict:
    """[Vulnerability Intelligence] Unified vulnerability search across the Qualys Knowledge Base — find newly published vulns, filter by threat intel (RTI) tags, and/or search by affected software name. One API call covers all use cases.

    **Use when:** Searching for new vulns, threat intel queries ("any ransomware vulns this week?"), or software-specific vuln lookups ("what vulns affect Apache?"). Replaces separate get_threat_intel / get_vulns_by_software / get_new_vulns calls.
    **NOT for:** Cross-environment tracing of a single CVE with asset impact (use investigate_cve), bulk CVE lookup (use get_cve_details), or confirmed findings in your environment (use get_etm_findings).

    days: how far back to search (default 7). Use days=1 for today, days=30 for last month.

    threat_type: RTI filter — one of the 12 Real-Time Threat Indicator tags:
      - Ransomware              — linked to ransomware campaigns
      - Malware                 — associated with known malware
      - Active_Attacks          — seen in active exploitation in the wild
      - Exploit_Public          — public exploit code available
      - Easy_Exploit            — low-skill exploitation possible
      - Wormable                — can spread without user interaction
      - Cisa_Known_Exploited_Vulns — on CISA KEV catalog
      - Denial_of_Service       — can cause service disruption
      - Privilege_Escalation    — enables privilege elevation
      - Remote_Code_Execution   — enables remote code execution
      - Predicted_High_Risk     — ML-predicted high risk
      - Unauthenticated_Exploitation — exploitable without authentication

    software: filter by product name in KB title/diagnosis. Fuzzy substring match — partial names work.
      Examples: 'Apache', 'OpenSSL', 'Microsoft Exchange', 'Chrome', 'nginx', 'Java', 'Log4j',
                'Cisco IOS', 'VMware', 'WordPress', 'PHP', 'PostgreSQL', 'Docker'

    tag: filter to assets with this tag (e.g. Production, PCI, cloud) — scopes affected-asset counts
    asset_group: filter to assets in this Qualys asset group — scopes affected-asset counts

    Filters combine: search_vulns(days=30, threat_type='Ransomware', software='Apache') returns Apache vulns with ransomware linkage from the last 30 days. Fast (~5s).

    For cross-product tracing of a single CVE, use investigate_cve. For bulk CVE lookup, use get_cve_details. For direct QID lookup, use get_qid_details."""
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

    # Parse all vulns, apply filters client-side
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
        for tag in ti:
            threat_counts[tag] = threat_counts.get(tag, 0) + 1

        # Apply threat_type filter
        if threat_type:
            if not any(threat_type.lower() in t.lower() for t in ti):
                continue
        # Apply software filter
        if search_lower:
            title = parsed.get('title', '').lower()
            diagnosis = parsed.get('diagnosis', '').lower()
            if search_lower not in title and search_lower not in diagnosis:
                continue

        matching.append(parsed)

    result['withThreatIntel'] = ti_count
    result['threatBreakdown'] = dict(sorted(threat_counts.items(), key=lambda x: -x[1]))

    # Severity breakdown of matching vulns
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

    # Sort by severity desc, then by threat intel count
    matching.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))

    # Enrich top 20 results with real QDS scores from detection API
    top_qids = [v['qid'] for v in matching[:20] if v.get('qid')]
    qds_scores = get_qds_for_qids(top_qids) if top_qids else {}

    for v in matching[:limit]:
        real_qds = qds_scores.get(v['qid'], 0)
        result['vulns'].append({
            'qid': v['qid'],
            'title': v['title'],
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
    return result


def _get_first_cloud_evals():
    """Get evaluations from the first available cloud connector. Fetches all providers in parallel."""
    # Fetch all three providers' first connector in parallel
    connector_results = _run_concurrent(
        aws=lambda: get_connectors('aws', 1),
        azure=lambda: get_connectors('azure', 1),
        gcp=lambda: get_connectors('gcp', 1),
    )
    # Find first provider with a connector
    for provider, acc_key in [('aws', 'awsAccountId'), ('azure', 'azureSubscriptionId'), ('gcp', 'gcpProjectId')]:
        conns = connector_results.get(provider) or []
        if conns:
            acc = conns[0].get(acc_key)
            if acc:
                return get_evaluations(acc, provider, 100)
    return []


@mcp.tool()
def get_recommendations() -> dict:
    """[Program Advisor] Security program coach — analyzes your environment and recommends Qualys modules and actions to reduce risk. Probes all data sources (VMDR, TotalCloud, TotalAppSec, FIM, EDR, CertView, Patch Management) to find coverage gaps.

    **Use when:** Gap analysis, program improvement, "what modules should we add?", "what should we invest in?", "what's missing from our security program?", or "how do we reduce our TruRisk score?". Identifies both eliminate (patch/fix) and mitigate (compensating control) actions.
    **NOT for:** Immediate threat response (use get_morning_report), asset-level vuln details (use get_asset_risk), or patching status (use get_eliminate_status).

    Returns: prioritized recommendations with riskAction (eliminate/mitigate), qualysModule, finding, and coverage map of active vs missing security capabilities."""
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
        ransomware_vulns=lambda: search_vulns.fn(days=30, threat_type='Ransomware'),
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
    """[TruRisk Eliminate] Patch and mitigation deployment status — shows active patch jobs (Qualys Patch Management), mitigation jobs (TruRisk Mitigate), patch catalog coverage, and managed asset counts for both Windows and Linux. Returns job status, completion rates, and patch counts by vendor severity.

    **Use when:** Asked about patching progress, risk elimination, or mitigation status — "are patches deploying?", "how many mitigation jobs are running?", "what's our patch catalog size?".
    **NOT for:** Patch coverage by risk tier (use get_patch_status), per-platform PM job details (use get_pm_status), or per-asset patch status (use get_asset_risk)."""
    result = {
        'patchManagement': {'windows': {}, 'linux': {}},
        'mitigations': {'windows': {}, 'linux': {}},
        'patchCatalog': {},
        'summary': '',
    }

    # Fetch everything concurrently — already parallel, audited in #17
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
    """[Infrastructure] Scanner appliance health — online/offline status, running and failed scans, capacity utilization, and vulnerability signature currency. Fast (~5s).

    **Use when:** Scanners appear offline, coverage seems low, checking last scan times, "why did my scan fail?", or verifying scanner infrastructure health.
    **NOT for:** Scan job status/history (use get_scan_status), vulnerability findings (use get_etm_findings), or patch deployment status (use get_eliminate_status)."""
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

    **Use when:** Searching for confirmed vulnerabilities with rich filtering, compliance evidence, or cross-source vuln aggregation. Best for "show me all critical vulns on PCI assets" or "find Log4Shell across the environment".
    **NOT for:** New KB-only vulns not yet confirmed in scans (use search_vulns), cloud misconfigs (use get_cloud_risk), or single-CVE deep-dive with asset software search (use investigate_cve).

    Use qql to filter findings with Qualys Query Language (QQL):

    **CVE and vulnerability filters:**
      - `vulnerabilities.vulnerability.cveIds:CVE-2021-44228`  — Log4Shell across all assets
      - `vulnerabilities.vulnerability.severity:5`  — critical findings only
      - `vulnerabilities.vulnerability.isPatchAvailable:true`  — patchable findings
      - `vulnerabilities.vulnerability.qds:[70 TO 100]`  — high QDS range (range syntax)
      - `vulnerabilities.vulnerability.qid:38580`  — specific QID
      - `vulnerabilities.vulnerability.cvss3Base:[9.0 TO 10.0]`  — CVSS v3 critical

    **Asset filters:**
      - `asset.name:web-server`  — findings for a specific asset
      - `asset.tags.name:PCI`  — assets with a specific tag
      - `asset.operatingSystem:Windows`  — OS filter
      - `asset.criticality:[8 TO 10]`  — business-critical assets only

    **Status and source filters:**
      - `status:ACTIVE`  — confirmed active findings (default)
      - `vendorProductName:Qualys VMDR`  — source filter
      - `category:MISCONFIGURATION`  — misconfigs only
      - `category:VULNERABILITY`  — vulns only

    **Combining filters (AND/OR/NOT):**
      - `vulnerabilities.vulnerability.severity:5 AND asset.tags.name:PCI`
      - `vulnerabilities.vulnerability.cveIds:CVE-2024-3400 OR vulnerabilities.vulnerability.cveIds:CVE-2023-20198`

    For full QQL operator reference, see docs/query-languages.md.

    **How async reports work:** ETM reports are async — completed reports are cached in-memory for 1 hour for instant warm retrieval. If no cached result exists, a new report is created and `{status: "creating", reportId: "..."}` is returned — call again with that reportId to poll for completion (typically 1–5 minutes). Filtered QQL queries always create a fresh report."""
    global ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    now = datetime.now(timezone.utc)
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
            # NOTE: sequential ETM resource downloads could be parallelized with
            # _run_concurrent() but left as-is — typically 1-2 resources (#17)
            for res_name in resources[:5]:  # Cap at 5 resource files
                findings = etm_download(detail['id'], res_name)
                if findings:
                    all_findings.extend(findings)

            formatted = _format_etm_findings(all_findings, detail)
            # Cache completed unfiltered reports for 1 hour
            if not qql:
                ETM_RESULT_CACHE = formatted
                ETM_RESULT_CACHE_TIME = now
            return formatted

        elif detail['status'] == 'FAILED':
            result['summary'] = {'error': 'Report generation failed', 'reportId': report_id}
            return result
        else:
            result['summary'] = {
                'message': f'Report is still processing (status: {detail["status"]}). Try again in 30-60 seconds.',
                'reportId': report_id,
            }
            return result

    # For unfiltered queries: check in-memory cache first (1-hour TTL)
    if not qql and ETM_RESULT_CACHE is not None and ETM_RESULT_CACHE_TIME:
        age = (now - ETM_RESULT_CACHE_TIME).total_seconds()
        if age < 3600:
            _log(f"ETM result cache hit (age {int(age)}s)")
            cached = dict(ETM_RESULT_CACHE)
            cached['cacheAge'] = int(age)
            return cached

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
                # NOTE: sequential downloads — same as above, left as-is (#17)
                for res_name in detail['resources'][:5]:
                    findings = etm_download(detail['id'], res_name)
                    if findings:
                        all_findings.extend(findings)
                if all_findings:
                    formatted = _format_etm_findings(all_findings, detail)
                    # Cache for 1 hour
                    ETM_RESULT_CACHE = formatted
                    ETM_RESULT_CACHE_TIME = now
                    return formatted

    # Create a new report
    body = {
        'reportName': f'mcp-{int(now.timestamp())}',
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
    result['reportStatus'] = 'creating'
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
    """[Daily Briefing] Morning security report — what happened overnight. New vulnerabilities (last 24h) with ransomware and active exploit flags, environment health score, top risk assets, EOL count, and prioritized action items.

    **Use when:** Starting the day, shift handover, "what's new today?", or "give me a briefing". Use this first in a session — gives a complete picture. Combines security posture + weekly priorities + threat intel in one fast call.
    **NOT for:** Deep vulnerability investigation (use investigate_cve), week-level planning (use get_weekly_priorities), or cloud-specific threats (use get_cdr_findings).

    Returns: environment health, new vuln counts (24h), threat flags (ransomware/exploits/CISA KEV), top risk assets, and prioritized action items."""
    result = {'report': 'Daily Security Briefing', 'environment': {},
              'newVulns': {}, 'threats': {}, 'topRiskAssets': [],
              'actionItems': [], 'truriskTrend': {}}

    # Run everything concurrently for speed
    concurrent = _run_concurrent(
        posture=lambda: get_security_posture(),
        priorities=lambda: get_weekly_priorities.fn(),
        new_vulns=lambda: search_vulns.fn(days=1),
        ransomware=lambda: search_vulns.fn(days=1, threat_type='Ransomware'),
        active=lambda: search_vulns.fn(days=1, threat_type='Active_Attacks'),
        cisa=lambda: search_vulns.fn(days=1, threat_type='Cisa_Known_Exploited_Vulns'),
        trurisk_now=lambda: csam_search(limit=100, fields="truRisk"),
        trurisk_7d=lambda: csam_search(
            filters=[{"field": "asset.lastModifiedDate", "operator": "LESS",
                      "value": (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT00:00:00Z')}],
            limit=100, fields="truRisk", fetch_all=False),
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

    # Top risk assets
    priorities = concurrent.get('priorities') or {}
    result['topRiskAssets'] = (priorities.get('topRiskAssets') or [])[:5]

    # Action items
    result['actionItems'] = priorities.get('priorities') or []

    # TruRisk trend direction
    now_assets = concurrent.get('trurisk_now') or []
    old_assets = concurrent.get('trurisk_7d') or []
    if now_assets:
        avg_now = sum(int(a.get('riskScore') or 0) for a in now_assets) / len(now_assets)
        avg_old = (sum(int(a.get('riskScore') or 0) for a in old_assets) / len(old_assets)) if old_assets else avg_now
        delta = avg_now - avg_old
        if delta < -5:
            direction = 'improving'
            arrow = '↓'
        elif delta > 5:
            direction = 'worsening'
            arrow = '↑'
        else:
            direction = 'stable'
            arrow = '→'
        result['truriskTrend'] = {
            'current': round(avg_now),
            'direction': direction,
            'display': f"TruRisk: {round(avg_now)} {arrow} {direction}",
            'delta': round(delta),
        }

    return result


@mcp.tool()
def get_cve_details(cves: str) -> dict:
    """[Vulnerability Intelligence] Bulk CVE lookup — get severity, patches, threat intel, and remediation for multiple CVEs at once. Accepts comma-separated CVE IDs (e.g. 'CVE-2021-44228,CVE-2024-3400,CVE-2023-20198'). Up to 20 CVEs per call; 10 recommended for best performance. Fast (~5s).

    **Use when:** Looking up multiple CVEs at once — "what's the severity of these CVEs?", comparing CVE risk, or building a CVE summary table. KB data only (no asset search).
    **NOT for:** Single CVE with asset impact analysis (use investigate_cve), QID-based lookup (use get_qid_details), or confirmed findings in your environment (use get_etm_findings)."""
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
                    'cvss_v3': kb.get('cvss_v3'),
                    'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                    'patchAvailable': kb.get('patch_available', False),
                    'has_exploit': kb.get('has_exploit', False),
                })
        best_qds = qds_scores.get(best_qid, 0) if best_qid else 0
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
    """[Vulnerability Intelligence] Direct QID lookup — get KB details (severity, QDS, patches, threat intel, CVEs) for specific Qualys QIDs. Accepts comma-separated QIDs (e.g. '38747,376418'). Up to 50 QIDs per call. Fast (~3s).

    **Use when:** You have specific QID numbers (from ETM findings, scan reports, or VMDR detections) and need KB details. QIDs are Qualys-internal vulnerability identifiers.
    **NOT for:** CVE-based lookup (use get_cve_details), KB search by software or threat type (use search_vulns), or confirmed findings across assets (use get_etm_findings)."""
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
                'cvss_v3': kb.get('cvss_v3'),
                'cvss_v3_temporal': kb.get('cvss_v3_temporal'),
                'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                'cves': kb.get('cves', []),
                'patchAvailable': kb.get('patch_available', False),
                'has_exploit': kb.get('has_exploit', False),
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
    """[Cloud Security] Cloud security posture across AWS, Azure, and GCP — connected accounts, CIS benchmark control failures, and CDR threat summary. Fetches all cloud providers in parallel for fast results (~6s cold).

    **Use when:** Asked about cloud security posture, "how are our cloud accounts doing?", CIS benchmark compliance, or cloud risk overview. Shows all providers in one call.
    **NOT for:** CDR threat details/incident response (use get_cdr_findings), host-based vulnerabilities (use get_etm_findings), or on-prem compliance (use get_compliance_posture).

    Note: CIS benchmark evaluations are fetched from the first cloud account per provider. For multi-account evaluation, use the Qualys TotalCloud console directly. For CDR threat details, use get_cdr_findings."""
    result = {'accounts': [], 'failedControls': [], 'threats': [], 'stats': {'total': 0, 'critical': 0}}

    # Fetch all three cloud providers' connectors in parallel
    connector_results = _run_concurrent(
        aws=lambda: get_connectors('aws', 50),
        azure=lambda: get_connectors('azure', 50),
        gcp=lambda: get_connectors('gcp', 50),
    )

    # Build account list and collect first account per provider for eval fetch
    first_accounts = {}
    for provider, conns in connector_results.items():
        if not conns:
            continue
        acc_key = {'aws': 'awsAccountId', 'azure': 'azureSubscriptionId', 'gcp': 'gcpProjectId'}[provider]
        for c in conns:
            acc = c.get(acc_key, '')
            result['accounts'].append({'id': acc, 'provider': provider.upper(), 'name': c.get('name', '')})
        # Track first account per provider for evaluation fetch
        first_acc = conns[0].get(acc_key, '')
        if first_acc:
            first_accounts[provider] = first_acc

    result['stats']['total'] = len(result['accounts'])

    # Fetch evaluations for first account of each provider AND CDR in parallel
    eval_tasks = {
        f'evals_{p}': (lambda p=p, a=a: get_evaluations(a, p, 500))
        for p, a in first_accounts.items()
    }
    eval_tasks['cdr'] = lambda: get_cdr(7, limit)
    eval_results = _run_concurrent(**eval_tasks)

    # Aggregate evaluation failures across all providers
    fails = {}
    for p in first_accounts:
        evals = eval_results.get(f'evals_{p}') or []
        for e in evals:
            if e.get('result') in ['FAIL', 'FAILED']:
                cid = e.get('controlId', '')
                fails[cid] = fails.get(cid, 0) + 1
    result['failedControls'] = [
        {'id': c, 'count': n}
        for c, n in sorted(fails.items(), key=lambda x: x[1], reverse=True)[:limit]
    ]

    # CDR threats
    for f in (eval_results.get('cdr') or []):
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
    and affected resources.

    **Use when:** Investigating active cloud threats, lateral movement alerts, or suspicious network activity in cloud accounts. Best for incident response and threat hunting in cloud environments.
    **NOT for:** Cloud posture / CIS benchmarks (use get_cloud_risk), host-based threats (use get_edr_events), or file integrity monitoring (use get_fim_events).

    CDR category examples: Malware, Ransomware, CryptoMiner, C2, LateralMovement, Reconnaissance, DataExfiltration, SuspiciousNetworkActivity, UnauthorizedAccess, PrivilegeEscalation.

    **Cross-reference:** Use get_cloud_risk() for broader cloud posture (CIS benchmark failures, account inventory, and misconfigurations) alongside CDR threat detections."""
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
def get_asset_risk(asset_id: str, tag: str = "", asset_group: str = "") -> dict:
    """[Asset Risk] Detailed risk profile for a specific asset — TruRisk score, OS, criticality, installed software with lifecycle status, and EOL flags. Accepts a CSAM assetId (from get_weekly_priorities, get_patch_status, etc). Fast (~3s).

    **Use when:** Investigating a specific asset — "what's the risk on this server?", checking installed software, or confirming EOL status. Pass assetId from get_weekly_priorities, get_patch_status, get_etm_findings, or get_asset_inventory results.
    **NOT for:** Full asset profile with ETM findings + VMDR detections (use get_asset_full_profile), browsing multiple assets (use get_weekly_priorities or get_asset_inventory), or environment-wide risk (use get_weekly_priorities).

    tag: filter to assets with this tag (e.g. Production, PCI, cloud) — confirms asset belongs to tag scope
    asset_group: filter to assets in this Qualys asset group — confirms asset belongs to group scope"""
    result = {'assetId': asset_id, 'riskScore': 0, 'truriskScore': 0, 'software': [], 'eolSoftware': []}

    filters = _scope_filters([{"field": "asset.id", "operator": "EQUALS", "value": str(asset_id)}], tag, asset_group)
    asset = csam_search(filters=filters, limit=1)
    asset = asset[0] if asset else None
    if asset:
        result['ip'] = asset.get('address', '')
        result['hostname'] = asset.get('dnsHostName', '') or asset.get('dnsName', '')
        trurisk = int(asset.get('riskScore') or 0)
        result['riskScore'] = trurisk
        result['truriskScore'] = trurisk
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

        # Fetch VMDR detections for this host and enrich with KB data
        host_id = result.get('hostId', '')
        if host_id:
            dets = get_host_detections(host_id, severity=3, days=90)
            if dets:
                det_qids = list({d['qid'] for d in dets if d.get('qid')})
                kb_data = get_kb_batch(det_qids[:50]) if det_qids else {}
                vulns = []
                for d in sorted(dets, key=lambda x: (-x.get('severity', 0), -x.get('qds', 0))):
                    kb = kb_data.get(d['qid']) or {}
                    vulns.append({
                        'qid': d['qid'],
                        'title': kb.get('title', ''),
                        'severity': d.get('severity', 0),
                        'qds': d.get('qds', 0) or kb.get('qds', 0),
                        'cvss_v3': kb.get('cvss_v3'),
                        'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                        'cves': kb.get('cves', []),
                        'patchAvailable': kb.get('patch_available', False),
                        'has_exploit': kb.get('has_exploit', False),
                        'ransomware': kb.get('ransomware', False),
                        'first_found': d.get('first_found', ''),
                    })
                result['vulns'] = vulns[:50]
                result['vulnCount'] = len(dets)

    return result


@mcp.tool()
def get_tech_debt(limit: int = 100) -> dict:
    """[Asset Lifecycle] End-of-life and end-of-support systems — OS and hardware assets running unsupported software that no longer receives security patches, sorted by criticality and risk score. Default limit=100 (~25s). Use limit=500 for full inventory (~2min).

    **Use when:** Asked about tech debt, EOL/EOS exposure, "which systems are unsupported?", or upgrade planning. Returns both OS EOL (e.g. Windows Server 2012) and hardware EOL assets.
    **NOT for:** Single-asset EOL check (use get_asset_risk), general asset inventory (use get_asset_inventory), or environment overview (use get_environment_summary).

    CSAM filter examples used internally: operatingSystem.lifecycle.stage CONTAINS 'EOL', hardware.lifecycle.stage CONTAINS 'EOL'. Results are sorted by criticality then risk score.

    Note: limit=500 takes ~2 minutes due to paginated CSAM API calls."""
    # Run OS and hardware EOL fetches concurrently (fetch all, no artificial page cap)
    concurrent = _run_concurrent(
        os_eol=lambda: fetch_all_eol('os', limit),
        hw_eol=lambda: fetch_all_eol('hardware', limit),
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
    """[Container Security] Vulnerabilities for a specific container image — severity breakdown (critical/high/medium/low) and individual vulnerability details with fix versions.

    **Use when:** Investigating vulnerabilities in a specific container image, pre-deployment image scanning review, or container remediation planning.
    **NOT for:** Listing all container images (use get_asset_inventory), host-based vulnerabilities (use get_asset_risk), or cloud posture (use get_cloud_risk).

    Accepts a TotalCloud imageId. To find container image IDs, use get_asset_inventory or check get_weekly_priorities container risk section."""
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
def get_expiring_certs(days: int = 90, include_expired: bool = True, weak_only: bool = False, limit: int = 100) -> dict:
    """[CertView] SSL/TLS certificate expiry monitoring and configuration issue detection. Finds expiring/expired certificates, weak key sizes, SHA-1 signatures, self-signed certs, and TLS 1.0/1.1 usage. Returns per-cert issue lists with severity grades.

    **Use when:** Asked about certificate expiry, SSL/TLS health, weak ciphers, self-signed certs, or TLS version compliance. Great for outage prevention and compliance audits.
    **NOT for:** Vulnerability scanning (use get_etm_findings), cloud posture (use get_cloud_risk), or general security health (use get_security_posture).

    Parameters:
      - days: Look-ahead window for expiring certs (default 90)
      - include_expired: Include already-expired certs in results (default True)
      - weak_only: Only return certs that have at least one issue (default False)
      - limit: Max certs to return (default 100)

    **Example questions:**
      - "Which SSL certs expire in the next 30 days?" → get_expiring_certs(days=30)
      - "Are any certificates already expired?" → get_expiring_certs(include_expired=True)
      - "Which servers are using weak cipher suites?" → get_expiring_certs(weak_only=True)
      - "Show me all self-signed certificates" → get_expiring_certs(weak_only=True)
      - "Are any servers still using TLS 1.0?" → get_expiring_certs(weak_only=True)

    **Grades:** A = no issues, B = nearing expiry (<30 days), C = self-signed or weak key, F = expired or SHA-1"""
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

        # --- Issue detection ---
        cert_issues = []

        # SHA-1 / MD5 signature
        if 'sha1' in sig_algo:
            cert_issues.append({'issue': 'SHA-1 signature algorithm', 'severity': 'CRITICAL'})
        elif 'md5' in sig_algo:
            cert_issues.append({'issue': 'MD5 signature algorithm', 'severity': 'CRITICAL'})

        # Weak key size
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

        # Self-signed detection
        is_self_signed = False
        if subject_cn and issuer_cn and subject_cn.strip().lower() == issuer_cn.strip().lower():
            is_self_signed = True
            cert_issues.append({'issue': 'Self-signed certificate', 'severity': 'MEDIUM'})

        # TLS version (from host-level protocol fields if exposed)
        for h in hosts_raw[:5]:
            tls_version = h.get('protocol', '') or h.get('tlsVersion', '') or h.get('sslProtocol', '') or ''
            tls_version_lower = tls_version.lower()
            if 'tls1.0' in tls_version_lower or 'tlsv1.0' in tls_version_lower or tls_version_lower == 'tls 1.0' or 'ssl' in tls_version_lower:
                cert_issues.append({'issue': f'TLS 1.0 enabled on {h.get("hostname", "unknown")}', 'severity': 'HIGH'})
                break
            elif 'tls1.1' in tls_version_lower or 'tlsv1.1' in tls_version_lower or tls_version_lower == 'tls 1.1':
                cert_issues.append({'issue': f'TLS 1.1 enabled on {h.get("hostname", "unknown")}', 'severity': 'HIGH'})
                break

        # Also check cert-level grade field from CertView if present
        certview_grade = c.get('grade', '') or c.get('sslGrade', '') or ''

        # --- Expiry computation ---
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

        # --- Compute grade ---
        has_critical = any(i['severity'] == 'CRITICAL' for i in cert_issues)
        has_high = any(i['severity'] == 'HIGH' for i in cert_issues)
        has_medium = any(i['severity'] == 'MEDIUM' for i in cert_issues)

        if is_expired or has_critical:
            grade = 'F'
        elif has_high or is_self_signed:
            grade = 'C'
        elif days_left is not None and 0 <= days_left <= 30:
            grade = 'B'
        else:
            grade = certview_grade.upper() if certview_grade else 'A'

        # --- Update summary counts ---
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

        # --- Build cert entry ---
        cert_entry = {
            'subject': subject_cn,
            'expiryDate': valid_to[:10] if valid_to else '',
            'daysRemaining': days_left,
            'host': first_host,
            'hosts': host_list,
            'grade': grade,
            'issues': cert_issues,
        }

        # Add to issues flat list
        for ci in cert_issues:
            result['issues'].append({
                'host': first_host or subject_cn,
                'issue': ci['issue'],
                'severity': ci['severity'],
            })

        # Filter and collect
        if weak_only and not cert_issues:
            continue

        if is_expired:
            if include_expired:
                all_certs.append(cert_entry)
        elif days_left is not None and days_left <= days:
            all_certs.append(cert_entry)
        elif days_left is None or days_left > days:
            # Outside expiry window — only include if it has issues and weak_only is set
            if weak_only and cert_issues:
                all_certs.append(cert_entry)

    # Sort by daysRemaining ascending (expired first, then nearest expiry)
    all_certs.sort(key=lambda x: x.get('daysRemaining') if x.get('daysRemaining') is not None else 9999)
    result['expiringSoon'] = all_certs[:limit]

    # Sort issues by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    result['issues'].sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))

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
def get_webapp_vulns(severity: int = 0, days: int = 30, app_name: str = "", owasp_category: str = "", limit: int = 50) -> dict:
    """[Web Application Security] Web application vulnerabilities from Qualys WAS / TotalAppSec scans — severity breakdown per web app, OWASP Top 10 classification, and vulnerability categories.

    **Use when:** Asked about web application vulnerabilities, OWASP Top 10 findings, XSS/SQLi/CSRF issues, or per-app vulnerability posture.
    **NOT for:** Host-based vulnerabilities (use get_security_posture or get_asset_risk), network-level findings (use get_etm_findings), or SSL/TLS certificate issues (use get_expiring_certs).

    Parameters:
        severity: Minimum severity filter (0=all, 1-5). 4=high+critical, 5=critical only.
        days: Only findings detected in the last N days (default 30). Use 7 for weekly review.
        app_name: Filter by web app name (substring match, e.g. "portal", "api").
        owasp_category: Filter results by OWASP Top 10 category keyword (e.g. "Injection", "XSS", "SSRF", "Access Control", "Cryptographic"). Case-insensitive substring match.
        limit: Max findings to return (default 50).

    Returns: summary stats, per-app breakdown (byWebApp), vulnerability categories (byCategory), OWASP Top 10 mapping (owaspTop10), and individual findings sorted by severity."""

    # OWASP Top 10 (2021) keyword-to-category mapping
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

    # Push severity, days, and app_name filters to the WAS API for server-side filtering
    sev_arg = severity if severity > 0 else None
    days_arg = days if days > 0 else None
    app_arg = app_name if app_name else None
    findings = get_was_findings(limit * 3, severity=sev_arg, days=days_arg, app_name=app_arg)

    webapp_vulns = {}

    for f in findings:
        sev = f.get('severity', 0)
        name = f.get('name', '')

        # Classify into OWASP category and vuln category
        owasp_cat = ''
        vuln_category = 'Other'
        for keyword, owasp in owasp_map.items():
            if keyword.lower() in name.lower():
                owasp_cat = owasp
                vuln_category = keyword
                break

        # Filter by owasp_category if specified
        if owasp_category:
            match = owasp_category.lower()
            if match not in owasp_cat.lower() and match not in vuln_category.lower() and match not in name.lower():
                continue

        # Severity counts
        if sev >= 5:
            result['stats']['critical'] += 1
        elif sev >= 4:
            result['stats']['high'] += 1
        elif sev >= 3:
            result['stats']['medium'] += 1
        else:
            result['stats']['low'] += 1

        # OWASP Top 10 aggregation
        if owasp_cat:
            result['owaspTop10'][owasp_cat] = result['owaspTop10'].get(owasp_cat, 0) + 1

        # byCategory aggregation (human-readable category names)
        result['byCategory'][vuln_category] = result['byCategory'].get(vuln_category, 0) + 1

        # Per-webapp aggregation
        webapp_name = f.get('webAppName', '')
        webapp_id = f.get('webAppId', '')
        if webapp_id:
            if webapp_id not in webapp_vulns:
                webapp_vulns[webapp_id] = {
                    'id': webapp_id, 'appName': webapp_name,
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0
                }
            webapp_vulns[webapp_id]['total'] += 1
            if sev >= 5:
                webapp_vulns[webapp_id]['critical'] += 1
            elif sev >= 4:
                webapp_vulns[webapp_id]['high'] += 1
            elif sev >= 3:
                webapp_vulns[webapp_id]['medium'] += 1
            else:
                webapp_vulns[webapp_id]['low'] += 1

        result['findings'].append({
            'id': f.get('id', ''),
            'qid': f.get('qid'),
            'name': name,
            'severity': sev,
            'url': f.get('url', ''),
            'webApp': webapp_name,
            'detectedDate': f.get('detectedDate', ''),
            'type': f.get('type', ''),
            'owaspCategory': owasp_cat,
        })

    result['stats']['total'] = len(result['findings'])
    result['stats']['webApps'] = len(webapp_vulns)
    result['findings'] = sorted(result['findings'], key=lambda x: x['severity'], reverse=True)[:limit]
    result['byWebApp'] = sorted(
        webapp_vulns.values(),
        key=lambda x: (x['critical'], x['high'], x['total']),
        reverse=True
    )[:20]
    # Sort byCategory and owaspTop10 by count descending
    result['byCategory'] = dict(sorted(result['byCategory'].items(), key=lambda x: x[1], reverse=True))
    result['owaspTop10'] = dict(sorted(result['owaspTop10'].items(), key=lambda x: x[1], reverse=True))
    return result


@mcp.tool()
def get_asset_full_profile(asset_id: str) -> dict:
    """[Asset Risk] Comprehensive single-asset risk profile combining CSAM inventory, ETM confirmed findings, and VMDR host detections — all fetched in parallel for fast results (~5-8s cold, ~2s warm).

    **Use when:** Asked about a specific asset's full risk posture, pre-remediation planning, or building a per-asset remediation ticket. Combines data from three sources to give the most complete picture.
    **NOT for:** Browsing multiple assets (use get_weekly_priorities), software inventory only (use get_asset_risk), or environment-wide vulnerability counts (use get_security_posture).

    Returns: CSAM asset metadata (OS, IP, tags, criticality, software), ETM confirmed findings (QDS, CVSS, patch status, TruRisk), and VMDR active detections for the host ID."""
    result = {
        'assetId': asset_id,
        'csam': {},
        'etmFindings': [],
        'vmdrDetections': [],
        'summary': {},
    }

    # Step 1: Fetch CSAM asset to get metadata including hostId
    asset = get_asset_by_id(asset_id)
    if not asset:
        result['summary'] = {'error': f'Asset {asset_id} not found in CSAM'}
        return result

    host_id = str(asset.get('hostId') or '')
    hostname = asset.get('dnsHostName', '') or asset.get('dnsName', '') or asset.get('address', '')
    os_name = (asset.get('operatingSystem') or {}).get('osName', '')

    # Build CSAM profile
    sw_list = asset.get('softwareListData', {}) or {}
    software = []
    eol_software = []
    for sw in (sw_list.get('software') or [])[:30]:
        name = sw.get('fullName') or sw.get('productName') or sw.get('name') or ''
        sw_info = {'name': name.strip(), 'version': sw.get('version', '')}
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
        'lastSeen': asset.get('lastModifiedDate', ''),
        'software': software[:20],
        'eolSoftware': eol_software,
        'tags': [t.get('name', '') for t in (asset.get('tags') or {}).get('tag', [])[:10]],
    }

    # Step 2: Fetch ETM findings and VMDR detections in parallel
    def _fetch_etm():
        """Fetch ETM findings filtered to this asset."""
        # Use cached ETM result if available, filter to this asset
        if ETM_RESULT_CACHE:
            all_findings = ETM_RESULT_CACHE.get('findings', [])
            return [f for f in all_findings if
                    f.get('assetId') == asset_id or
                    f.get('assetName', '').lower() == hostname.lower()][:50]
        # Otherwise query ETM by asset name
        if hostname:
            qql = f'asset.name:{hostname}'
            body = {
                'reportName': f'mcp-profile-{int(datetime.now(timezone.utc).timestamp())}',
                'reportFormat': 'JSON',
                'findingFilter': {'qql': qql},
            }
            new_report = etm_api('POST', '/etm/api/rest/v1/reports/findings', body)
            if new_report:
                return [{'_async': True, 'reportId': new_report.get('id', ''),
                         'message': 'ETM report requested — call get_etm_findings(report_id=...) to retrieve'}]
        return []

    def _fetch_vmdr():
        """Fetch VMDR host detections for this asset's hostId."""
        if not host_id:
            return []
        return get_host_detections(host_id, severity=4, days=30)

    parallel = _run_concurrent(
        etm=_fetch_etm,
        vmdr=_fetch_vmdr,
    )

    etm_raw = parallel.get('etm') or []
    vmdr_raw = parallel.get('vmdr') or []

    # Format ETM findings
    etm_findings = []
    etm_async = False
    for f in etm_raw:
        if f.get('_async'):
            etm_async = True
            result['etmAsync'] = f
            break
        etm_findings.append({
            'title': f.get('title', '')[:100],
            'cveId': f.get('cveId', ''),
            'severity': f.get('severity', 0),
            'qds': f.get('qds', 0),
            'truRiskScore': f.get('truRiskScore', 0),
            'isPatchAvailable': f.get('isPatchAvailable', False),
            'status': f.get('status', ''),
            'category': f.get('category', ''),
        })
    etm_findings.sort(key=lambda x: (-x['severity'], -(x['truRiskScore'] or 0)))
    result['etmFindings'] = etm_findings[:30]

    # Format VMDR detections — enrich with KB data
    vmdr_qids = list({d.get('qid', 0) for d in vmdr_raw if d.get('qid')})
    vmdr_kb = get_kb_batch(vmdr_qids[:50]) if vmdr_qids else {}
    vmdr_dets = []
    for d in vmdr_raw:
        kb = vmdr_kb.get(d.get('qid', 0)) or {}
        vmdr_dets.append({
            'qid': d.get('qid', 0),
            'title': kb.get('title', ''),
            'severity': d.get('severity', 0),
            'qds': d.get('qds', 0) or kb.get('qds', 0),
            'cvss_v3': kb.get('cvss_v3'),
            'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
            'cves': kb.get('cves', []),
            'patchAvailable': kb.get('patch_available', False),
            'has_exploit': kb.get('has_exploit', False),
            'ransomware': kb.get('ransomware', False),
            'status': d.get('status', ''),
            'firstFound': d.get('first_found', ''),
        })
    vmdr_dets.sort(key=lambda x: (-x['severity'], -x['qds']))
    result['vmdrDetections'] = vmdr_dets[:30]

    # Summary
    crit_etm = sum(1 for f in etm_findings if f['severity'] >= 5)
    high_etm = sum(1 for f in etm_findings if f['severity'] == 4)
    patchable_etm = sum(1 for f in etm_findings if f['isPatchAvailable'])
    result['summary'] = {
        'riskScore': result['csam']['riskScore'],
        'criticality': result['csam']['criticality'],
        'etmFindings': len(etm_findings),
        'etmCritical': crit_etm,
        'etmHigh': high_etm,
        'etmPatchable': patchable_etm,
        'vmdrDetections': len(vmdr_dets),
        'eolSoftware': len(eol_software),
        'etmAsync': etm_async,
    }

    return result


@mcp.tool()
def get_risk_by_tag(tag: str, limit: int = 10) -> dict:
    """[Asset Risk] Risk distribution for all assets with a specific tag — TruRisk tiers, top risky assets, and EOL counts for the tagged asset group. Useful for team-based or environment-based risk segmentation (e.g., 'PCI', 'Production', 'DMZ', 'AWS').

    **Use when:** Asked about risk for a business unit, environment tier, compliance scope (PCI, HIPAA), or cloud provider tag. Combines CSAM count queries in parallel for fast results (~3s).
    **NOT for:** Global risk overview (use get_weekly_priorities), single asset details (use get_asset_full_profile), or cloud posture (use get_cloud_risk).

    Returns: asset count with tag, risk tier distribution (TruRisk > 900/700/500), top risky assets, and EOL count within the tagged group."""
    result = {
        'tag': tag,
        'assets': {'total': 0, 'critical': 0, 'high': 0, 'elevated': 0},
        'topRiskAssets': [],
        'eolCount': 0,
        'summary': '',
    }

    tag_filter = [{"field": "asset.tags.name", "operator": "EQUALS", "value": tag}]

    # Run all CSAM queries in parallel
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
            'hostname': a.get('dnsHostName', '') or a.get('dnsName', ''),
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

    return result


@mcp.tool()
def get_environment_summary() -> dict:
    """[Dashboard] Fast all-CSAM environment snapshot (<3s) — asset counts by OS family, cloud provider, EOL status, and criticality tiers. Use for a quick environment orientation before deeper analysis.

    **Use when:** Asked for environment overview, asset demographics, "what does our environment look like?", or orientation before diving into risk/vulnerability data. Much faster than get_security_posture (no vuln or container data).
    **NOT for:** Vulnerability counts (use get_security_posture), top risky assets (use get_weekly_priorities), or detailed risk scores (use get_asset_risk).

    Returns: total assets, OS family breakdown, cloud vs on-prem split, EOL counts, criticality distribution — all from parallel CSAM count queries."""
    result = {
        'totalAssets': 0,
        'byOS': {},
        'byCloud': {},
        'eolCounts': {},
        'byCriticality': {},
        'summary': '',
    }

    # All parallel CSAM count queries
    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        windows=lambda: csam_count([{"field": "operatingSystem.name", "operator": "CONTAINS", "value": "Windows"}]),
        linux=lambda: csam_count([{"field": "operatingSystem.name", "operator": "CONTAINS", "value": "Linux"}]),
        macos=lambda: csam_count([{"field": "operatingSystem.name", "operator": "CONTAINS", "value": "Mac"}]),
        cloud_aws=lambda: csam_count([{"field": "asset.cloudProvider", "operator": "EQUALS", "value": "AWS"}]),
        cloud_azure=lambda: csam_count([{"field": "asset.cloudProvider", "operator": "EQUALS", "value": "AZURE"}]),
        cloud_gcp=lambda: csam_count([{"field": "asset.cloudProvider", "operator": "EQUALS", "value": "GCP"}]),
        eol_os=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        eol_hw=lambda: csam_count([{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        crit_high=lambda: csam_count([{"field": "asset.criticality", "operator": "GREATER", "value": "7"}]),
        crit_med=lambda: csam_count([{"field": "asset.criticality", "operator": "GREATER", "value": "4"}]),
    )

    total = concurrent.get('total') or 0
    result['totalAssets'] = total

    windows = concurrent.get('windows') or 0
    linux = concurrent.get('linux') or 0
    macos = concurrent.get('macos') or 0
    result['byOS'] = {
        'Windows': windows,
        'Linux': linux,
        'macOS': macos,
        'Other': max(0, total - windows - linux - macos),
    }

    aws = concurrent.get('cloud_aws') or 0
    azure = concurrent.get('cloud_azure') or 0
    gcp = concurrent.get('cloud_gcp') or 0
    cloud_total = aws + azure + gcp
    result['byCloud'] = {
        'AWS': aws,
        'Azure': azure,
        'GCP': gcp,
        'OnPrem': max(0, total - cloud_total),
    }

    result['eolCounts'] = {
        'eolOS': concurrent.get('eol_os') or 0,
        'eolHardware': concurrent.get('eol_hw') or 0,
    }

    crit_high = concurrent.get('crit_high') or 0
    crit_med = concurrent.get('crit_med') or 0
    result['byCriticality'] = {
        'high_8to10': crit_high,
        'medium_5to7': max(0, crit_med - crit_high),
        'low_1to4': max(0, total - crit_med),
    }

    result['summary'] = (
        f"{total} total assets. "
        f"OS: {windows} Windows, {linux} Linux, {macos} macOS. "
        f"Cloud: {aws} AWS, {azure} Azure, {gcp} GCP, {max(0, total - cloud_total)} on-prem. "
        f"EOL: {result['eolCounts']['eolOS']} OS, {result['eolCounts']['eolHardware']} hardware. "
        f"Criticality: {crit_high} high-criticality assets."
    )

    return result


@mcp.tool()
def cache_status(clear: bool = False) -> dict:
    """[Admin] Show cache stats or clear all caches. Use clear=True to reset caches.

    **Use when:** Debugging stale data, checking cache freshness, or forcing a cache refresh before re-running a tool.
    **NOT for:** Any security analysis — this is an administrative/diagnostic tool only."""
    global ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    global SCANNER_CACHE, SCANNER_CACHE_TIME

    now = datetime.now(timezone.utc)
    result = {
        'kb_entries': len(KB_CACHE),
        'detection_entries': len(DETECTION_CACHE),
        'detection_cache_age_seconds': None,
        'qds_entries': len(QDS_CACHE),
        'was_keys': len(WAS_CACHE),
        'scanner_cached': SCANNER_CACHE is not None,
        'scanner_cache_age_seconds': None,
        'etm_result_cached': ETM_RESULT_CACHE is not None,
        'etm_cache_age_seconds': None,
        'bearer_token_age_seconds': None,
    }

    if DETECTION_CACHE_TIME:
        newest = max(DETECTION_CACHE_TIME.values())
        result['detection_cache_age_seconds'] = int((now - newest).total_seconds())
    if BEARER_TOKEN_TIME:
        result['bearer_token_age_seconds'] = int((now - BEARER_TOKEN_TIME).total_seconds())
    if SCANNER_CACHE_TIME:
        result['scanner_cache_age_seconds'] = int((now - SCANNER_CACHE_TIME).total_seconds())
    if ETM_RESULT_CACHE_TIME:
        result['etm_cache_age_seconds'] = int((now - ETM_RESULT_CACHE_TIME).total_seconds())

    if clear:
        KB_CACHE.clear()
        KB_CACHE_TIME.clear()
        DETECTION_CACHE.clear()
        DETECTION_CACHE_TIME.clear()
        QDS_CACHE.clear()
        WAS_CACHE.clear()
        WAS_CACHE_TIME.clear()
        SCANNER_CACHE = None
        SCANNER_CACHE_TIME = None
        ETM_RESULT_CACHE = None
        ETM_RESULT_CACHE_TIME = None
        result['cleared'] = True
        result['kb_entries'] = 0
        result['detection_entries'] = 0
        result['qds_entries'] = 0
        result['was_keys'] = 0
        result['scanner_cached'] = False
        result['etm_result_cached'] = False
        result['detection_cache_age_seconds'] = None
        result['scanner_cache_age_seconds'] = None
        result['etm_cache_age_seconds'] = None

    return result


@mcp.tool()
def get_edr_events(days: int = 7, severity: str = "", category: str = "", host: str = "", limit: int = 50) -> dict:
    """[EDR] Endpoint Detection & Response events — malware, ransomware, C2 beaconing, process injection, lateral movement, suspicious executions. Returns summary counts, per-category breakdown, and top affected hosts.

    **Use when:** Investigating endpoint threats, malware detections, suspicious process executions, or host-level incident response. Filter by severity, category, or specific host.
    **NOT for:** File integrity changes (use get_fim_events), cloud threats (use get_cdr_findings), or network-level vulnerabilities (use get_etm_findings)."""

    # Severity normalization: numeric or mixed-case → canonical label
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
        # Date-range filter
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

        # Normalize severity
        raw_sev = str(e.get('severity', '') or '').strip()
        sev = SEV_NORM.get(raw_sev.lower(), raw_sev.upper() or 'UNKNOWN')

        # Apply filters
        if severity and severity.upper() != sev:
            continue
        if category and category.lower() not in evt_category.lower():
            continue
        if host and host.lower() not in hostname.lower():
            continue

        # Tally
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

    return {
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


@mcp.tool()
def get_fim_events(days: int = 1, severity: str = "", host: str = "", path: str = "", limit: int = 100) -> dict:
    """[FIM] File Integrity Monitoring events — unauthorized file changes, critical system file modifications, suspicious paths (/etc/passwd, /etc/shadow, registry keys). Returns summary counts (modified/created/deleted), top affected hosts, critical-path changes with off-hours flagging.

    **Use when:** investigating file changes on hosts, checking for unauthorized modifications to system files, reviewing off-hours activity, auditing /etc/passwd or registry changes.
    **NOT for:** process-level threats or malware detection — use get_edr_events() instead.

    Returns: summary (total, critical, high, affectedHosts, modified, created, deleted), topHosts, criticalChanges with offHours flag.
    """
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

        # Normalize severity
        raw_sev = str(e.get('severity', '') or '').strip()
        sev = SEV_NORM.get(raw_sev.lower(), raw_sev.upper() or 'UNKNOWN')

        # Filters
        if severity and severity.upper() != sev:
            continue
        if host and host.lower() not in hostname.lower():
            continue
        if path and not file_path.lower().startswith(path.lower()):
            continue

        # Tally severity
        if sev in sev_counts:
            sev_counts[sev] += 1

        # Tally action
        action_key = action.lower()
        if 'modif' in action_key:
            action_counts['modified'] += 1
        elif 'creat' in action_key or 'add' in action_key:
            action_counts['created'] += 1
        elif 'delet' in action_key or 'remov' in action_key:
            action_counts['deleted'] += 1

        # Host tracking
        if hostname:
            affected_hosts.add(hostname)
            host_counts[hostname] = host_counts.get(hostname, 0) + 1

        # Off-hours detection (outside 08:00-18:00)
        off_hours = False
        if dt:
            try:
                event_time = datetime.strptime(dt[:19], '%Y-%m-%dT%H:%M:%S')
                if event_time.hour < 8 or event_time.hour >= 18:
                    off_hours = True
            except ValueError:
                pass

        # Critical path detection
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

    return {
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


def _parse_duration(duration_str):
    """Parse Qualys duration string into human-readable format (e.g. '2h 15m')."""
    if not duration_str:
        return ''
    try:
        parts = duration_str.strip().split(':')
        if len(parts) == 3:
            h, m, s = int(parts[0]), int(parts[1]), int(parts[2])
            pieces = []
            if h:
                pieces.append(f"{h}h")
            if m:
                pieces.append(f"{m}m")
            if not pieces:
                pieces.append(f"{s}s")
            return ' '.join(pieces)
    except (ValueError, IndexError):
        pass
    return duration_str


@mcp.tool()
def get_scan_status(state: str = "Running,Paused,Queued,Error", days: int = 7, limit: int = 50) -> dict:
    """[VM] Scan status summary — running, queued, failed scans with duration and target info.

    Shows active scans filtered by state, plus recently finished scans within the look-back window.
    Includes error details and suggestions when failures are detected.

    **Use when:** Checking scan progress, "are any scans running?", troubleshooting failed scans, or reviewing scan history for the week.
    **NOT for:** Scanner appliance health (use get_scanner_health), vulnerability findings from scans (use get_etm_findings), or patch deployment status (use get_pm_status).

    Args:
        state: comma-separated states to filter (Running,Paused,Queued,Error)
        days: look-back window in days for finished/history scans
        limit: max results to return
    """
    result = {
        'states': state,
        'stats': {'total': 0, 'byState': {}, 'running': 0, 'queued': 0, 'errors': 0, 'completedToday': 0},
        'scans': [],
        'failedScans': [],
        'summary': '',
    }

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    # Fetch active scans and finished scans concurrently
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

        # Filter by days window
        if launch_time and launch_time < cutoff:
            return

        result['stats']['byState'][scan_state] = result['stats']['byState'].get(scan_state, 0) + 1

        scan_entry = {
            'ref': s.get('ref', ''), 'title': s.get('title', ''),
            'state': scan_state, 'type': s.get('type', ''),
            'target': s.get('target', ''), 'launched': launched,
            'duration': _parse_duration(s.get('duration', '')),
            'scanner': s.get('scannerName', ''),
        }

        if len(result['scans']) < limit:
            result['scans'].append(scan_entry)

        # Track failed scans separately
        if scan_state == 'Error':
            result['failedScans'].append({
                'ref': scan_entry['ref'], 'title': scan_entry['title'],
                'scanner': scan_entry['scanner'], 'target': scan_entry['target'],
                'launched': launched,
            })

    # Process active scans
    for s in active_scans:
        _process_scan(s)

    # Process finished scans within the look-back window
    for s in finished_scans:
        launched = s.get('launched', '')
        launch_time = _parse_launch_time(launched)
        if launch_time and launch_time >= cutoff:
            _process_scan(s)
            # Count completions today
            if launch_time >= today_start:
                result['stats']['completedToday'] += 1

    # Populate convenience counters
    by_state = result['stats']['byState']
    result['stats']['running'] = by_state.get('Running', 0)
    result['stats']['queued'] = by_state.get('Queued', 0)
    result['stats']['errors'] = by_state.get('Error', 0)
    result['stats']['total'] = sum(by_state.values())

    # Build summary
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
    result['summary'] = ' · '.join(parts)

    if result['failedScans']:
        result['summary'] += ' ⚠ Use get_scanner_health() to check scanner appliance status for failed scans.'

    return result


@mcp.tool()
def get_pm_status(platform: str = "Windows", days: int = 30, status: str = "", limit: int = 20) -> dict:
    """[PM] Patch Management deployment status — jobs, patch severity breakdown, asset coverage %.

    **Use when:** Reviewing PM job details per platform, patch severity breakdown, or asset coverage percentage. More granular than get_eliminate_status — shows individual jobs, filter by platform/status.
    **NOT for:** High-level eliminate/mitigate overview (use get_eliminate_status), risk-tier-based patch coverage (use get_patch_status), or per-asset patch details (use get_asset_risk).

    platform: Windows, Linux, macOS, or 'all' (loops all three).
    days: only include jobs from the last N days.
    status: filter by job status (e.g. 'Success', 'Failed', 'Running'). Empty = all."""
    platforms = ['Windows', 'Linux', 'macOS'] if platform.lower() == 'all' else [platform]

    def _pm_for_platform(plat):
        try:
            concurrent = _run_concurrent(
                jobs=lambda p=plat: get_pm_jobs(p, limit),
                patches_by_sev=lambda p=plat: get_pm_patches_count(p, 'vendorSeverity'),
                assets=lambda p=plat: get_pm_assets(p, limit),
            )

            # --- Jobs ---
            raw_jobs = concurrent.get('jobs') or []
            if isinstance(raw_jobs, dict):
                raw_jobs = raw_jobs.get('jobs', raw_jobs.get('data', []))
            if not isinstance(raw_jobs, list):
                raw_jobs = []

            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            job_list = []
            active_count = 0
            failed_count = 0
            for j in raw_jobs:
                if not isinstance(j, dict):
                    continue
                # Date filter
                created = j.get('createdDate', '') or j.get('created', '')
                if created:
                    try:
                        job_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        if job_dt < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass
                # Status filter
                job_status = j.get('status', '')
                if status and job_status.lower() != status.lower():
                    continue
                if job_status in ('Running', 'Queued', 'Scheduled', 'InProgress'):
                    active_count += 1
                if job_status in ('Failed', 'Error'):
                    failed_count += 1
                job_list.append({
                    'id': j.get('id', ''),
                    'name': j.get('name', ''),
                    'status': job_status,
                    'platform': plat,
                    'createdDate': created,
                    'completion': j.get('completionPercent'),
                    'assets': j.get('applicableAssetCount') or j.get('assetCount') or 0,
                })
                if len(job_list) >= limit:
                    break

            # --- Patch severity ---
            patches_by_sev = concurrent.get('patches_by_sev') or {}
            sev_data = patches_by_sev.get('vendorSeverity', patches_by_sev) if isinstance(patches_by_sev, dict) else {}
            critical = 0
            if isinstance(sev_data, dict):
                critical = sev_data.get('Critical', 0) + sev_data.get('critical', 0)

            # --- Assets & coverage ---
            raw_assets = concurrent.get('assets') or []
            if isinstance(raw_assets, dict):
                raw_assets = raw_assets.get('assets', raw_assets.get('data', []))
            if not isinstance(raw_assets, list):
                raw_assets = []

            total_assets = len(raw_assets)
            patched_assets = sum(1 for a in raw_assets if isinstance(a, dict) and a.get('patchStatus', '') in ('Patched', 'UpToDate', 'patched'))
            coverage_pct = round(patched_assets / total_assets * 100, 1) if total_assets > 0 else 0.0

            top_assets = []
            for a in raw_assets[:limit]:
                if isinstance(a, dict):
                    top_assets.append({
                        'id': a.get('id', ''),
                        'name': a.get('name', '') or a.get('hostname', ''),
                        'os': a.get('os', '') or a.get('operatingSystem', ''),
                        'patchStatus': a.get('patchStatus', ''),
                    })

            return {
                'summary': {
                    'platform': plat,
                    'totalJobs': len(job_list),
                    'activeJobs': active_count,
                    'failedJobs': failed_count,
                    'patchCoverage': f"{coverage_pct}%",
                    'criticalPatches': critical,
                },
                'jobs': job_list,
                'patchSeverity': sev_data,
                'topAssets': top_assets,
            }
        except Exception as e:
            _log(f"PM status error for {plat}: {e}")
            return {
                'summary': {'platform': plat, 'error': str(e)},
                'jobs': [], 'patchSeverity': {}, 'topAssets': [],
            }

    if len(platforms) == 1:
        return _pm_for_platform(platforms[0])

    # Multi-platform: run in parallel
    tasks = {p: lambda p=p: _pm_for_platform(p) for p in platforms}
    concurrent = _run_concurrent(**tasks)
    results = {}
    for p in platforms:
        results[p.lower()] = concurrent.get(p) or {
            'summary': {'platform': p, 'error': 'No data'},
            'jobs': [], 'patchSeverity': {}, 'topAssets': [],
        }
    # Aggregate summary
    total_jobs = sum(r['summary'].get('totalJobs', 0) for r in results.values())
    active_jobs = sum(r['summary'].get('activeJobs', 0) for r in results.values())
    failed_jobs = sum(r['summary'].get('failedJobs', 0) for r in results.values())
    results['summary'] = f"All platforms: {total_jobs} jobs ({active_jobs} active, {failed_jobs} failed)"
    return results


@mcp.tool()
def get_asset_inventory(query: str = "", tag: str = "", os: str = "", days_since_seen: int = 0, eol_only: bool = False, limit: int = 50) -> dict:
    """[CSAM] Asset inventory — search by OS, tag, or keyword. EOL/EOS filtering, stale-asset filtering, OS and tag breakdowns.

    **Use when:** Searching for assets by name/OS/tag, finding stale assets, or building asset lists for remediation. Also useful for finding container image IDs for get_image_vulns.
    **NOT for:** Single-asset risk details (use get_asset_risk), environment-wide counts only (use get_environment_summary), or risk-ranked asset lists (use get_weekly_priorities).

    CSAM filter examples (applied automatically from parameters):
      - os="Windows Server 2019"      → operatingSystem.osName CONTAINS 'Windows Server 2019'
      - tag="PCI"                      → tags.name CONTAINS 'PCI'
      - eol_only=True                  → operatingSystem.lifecycle.stage CONTAINS 'EOL'
      - days_since_seen=30             → assets not seen in 30+ days (stale)

    Parameters:
        query: free-text search on hostname/name
        tag: filter by asset tag name
        os: filter by OS (e.g. "Windows", "Linux", "Ubuntu", "CentOS")
        days_since_seen: only assets NOT seen in last N days (stale assets); 0 = no filter
        eol_only: only return end-of-life assets
        limit: max results (default 50)
    """
    filters = []
    if os:
        filters.append({"field": "operatingSystem.osName", "operator": "CONTAINS", "value": os})
    if tag:
        filters.append({"field": "tags.name", "operator": "CONTAINS", "value": tag})
    if query:
        filters.append({"field": "asset.name", "operator": "CONTAINS", "value": query})
    if days_since_seen > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_since_seen)).strftime('%Y-%m-%dT00:00:00Z')
        filters.append({"field": "asset.lastSeen", "operator": "LESS", "value": cutoff})
    if eol_only:
        filters.append({"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"})

    f = filters if filters else None
    data = _run_concurrent(
        assets=lambda: csam_search(filters=f, limit=limit,
                                   fields="operatingSystem,hardware,tags,vulnerabilities,tagList,truRisk,truRiskScoreFactors"),
        total=lambda: csam_count(filters=f),
    )
    assets = data.get('assets', [])
    total_count = data.get('total', len(assets))

    summary = {'total': total_count, 'returned': len(assets), 'byOS': {}, 'byTag': {}, 'eolCount': 0}
    result_assets = []

    for a in assets:
        os_info = a.get('operatingSystem', {}) or {}
        os_name = os_info.get('osName', '') or 'Unknown'
        lifecycle = (os_info.get('lifecycle', {}) or {}).get('stage', '')
        is_eol = is_eol_stage(lifecycle)

        if is_eol:
            summary['eolCount'] += 1

        summary['byOS'][os_name] = summary['byOS'].get(os_name, 0) + 1

        asset_tags = []
        for t in a.get('tags', []) or a.get('tagList', []) or []:
            tag_name = t.get('name', '') if isinstance(t, dict) else str(t)
            if tag_name:
                asset_tags.append(tag_name)
                summary['byTag'][tag_name] = summary['byTag'].get(tag_name, 0) + 1

        vulns = a.get('vulnerabilities', {}) or {}
        open_vulns = vulns.get('count', 0) or 0

        result_assets.append({
            'id': a.get('assetId', ''),
            'name': a.get('name', '') or a.get('dnsName', ''),
            'ip': a.get('address', '') or a.get('ipAddress', ''),
            'os': os_name,
            'lastSeen': a.get('lastSeen', ''),
            'tags': asset_tags,
            'truRiskScore': a.get('riskScore', 0) or a.get('truRiskScore', 0) or 0,
            'openVulns': open_vulns,
            'eolStatus': lifecycle if lifecycle else 'Active',
        })

    result_assets.sort(key=lambda x: -x['truRiskScore'])
    return {'summary': summary, 'assets': result_assets}


@mcp.tool()
def get_vuln_exceptions(status: str = "Active", vuln_type: str = "", days_to_expiry: int = 30, limit: int = 50) -> dict:
    """[VM] Vulnerability exceptions — approved risk acceptances, false positives, compensating controls. Shows expiring exceptions needing review.

    **Use when:** Reviewing active risk acceptances/waivers, finding expiring exceptions that need renewal, or auditing false positive classifications.
    **NOT for:** Remediation/patching status (use get_patch_status or get_eliminate_status), vulnerability findings (use get_etm_findings), or compliance controls (use get_compliance_posture)."""
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
    return result


@mcp.tool()
def get_compliance_posture(framework: str = "", platform: str = "", limit: int = 20) -> dict:
    """[PC] Qualys Policy Compliance (PC) module posture — surfaces pass/fail rates, top failing controls, and per-framework breakdown for CIS Benchmark, PCI-DSS, HIPAA, NIST, SOC2, and ISO27001 compliance frameworks. Filter by framework or platform (Linux, Windows, etc.).

    **Use when:** Asked about compliance posture, audit readiness, "are we passing CIS benchmarks?", or framework-specific control status. Covers on-prem and host-level compliance.
    **NOT for:** Cloud-specific CIS compliance (use get_cloud_risk), vulnerability findings (use get_etm_findings), or certificate compliance (use get_expiring_certs)."""

    def _empty_result():
        return {
            'summary': {
                'totalControls': 0, 'passing': 0, 'failing': 0,
                'passRate': 0.0, 'affectedAssets': 0, 'frameworks': [],
            },
            'topFailingControls': [],
            'byFramework': {},
        }

    def _parse_controls(root):
        """Parse controls from XML response and build result dict."""
        controls = (root.findall('.//CONTROL') or root.findall('.//POSTURE')
                    or root.findall('.//COMPLIANCE_CONTROL'))
        if not controls:
            return None

        passed = 0
        failed = 0
        failing = []
        frameworks_seen = set()
        affected_hosts = set()
        by_fw = {}

        for c in controls:
            status = (c.findtext('STATUS', '') or c.findtext('RESULT', '')).upper()
            ctrl_fw = (c.findtext('FRAMEWORK', '') or c.findtext('TECHNOLOGY', '')
                       or c.findtext('POLICY', ''))
            ctrl_id = c.findtext('CONTROL_ID', '') or c.findtext('CID', '') or c.findtext('ID', '')
            ctrl_name = c.findtext('CONTROL_NAME', '') or c.findtext('TITLE', '') or c.findtext('STATEMENT', '')
            ctrl_sev = (c.findtext('SEVERITY', '') or c.findtext('CRITICALITY', '')).upper()
            ctrl_platform = c.findtext('PLATFORM', '') or c.findtext('TECHNOLOGY', '') or ''
            host_count_text = c.findtext('HOST_COUNT', '') or c.findtext('ASSET_COUNT', '')

            # Apply filters
            if framework and framework.lower() not in ctrl_fw.lower():
                continue
            if platform and platform.lower() not in ctrl_platform.lower():
                continue

            if 'PASS' in status:
                passed += 1
            elif 'FAIL' in status or 'ERROR' in status:
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
                if 'PASS' in status:
                    by_fw[ctrl_fw]['pass'] += 1
                elif 'FAIL' in status or 'ERROR' in status:
                    by_fw[ctrl_fw]['fail'] += 1

        total = passed + failed
        if total == 0:
            return None

        # Sort failing by asset count desc, then severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'URGENT': 1, 'MEDIUM': 2, 'LOW': 3}
        failing.sort(key=lambda x: (-x['failingAssets'], sev_order.get(x['severity'], 9)))

        result = _empty_result()
        result['summary']['totalControls'] = total
        result['summary']['passing'] = passed
        result['summary']['failing'] = failed
        result['summary']['passRate'] = round(passed / total * 100, 1)
        result['summary']['affectedAssets'] = max(affected_hosts) if affected_hosts else 0
        result['summary']['frameworks'] = sorted(frameworks_seen)
        result['topFailingControls'] = failing[:limit]

        for fw_name, counts in by_fw.items():
            fw_total = counts['pass'] + counts['fail']
            result['byFramework'][fw_name] = {
                'passRate': round(counts['pass'] / fw_total * 100, 1) if fw_total else 0,
                'failing': counts['fail'],
            }

        return result

    # --- Strategy 1: PC posture info endpoint ---
    _log("Compliance posture: trying posture/info endpoint...")
    data = api_get(f"{BASE_URL}/api/2.0/fo/compliance/posture/info/?action=list", timeout=30)
    if data:
        try:
            root = ET.fromstring(data if isinstance(data, (str, bytes)) else data)
            parsed = _parse_controls(root)
            if parsed:
                parsed['source'] = 'pc_posture'
                return parsed
        except ET.ParseError:
            _log("Compliance posture: posture/info returned non-XML")

    # --- Strategy 2: PC control list endpoint ---
    _log("Compliance posture: trying control list endpoint...")
    data2 = api_get(f"{BASE_URL}/api/2.0/fo/compliance/control/?action=list", timeout=30)
    if data2:
        try:
            root2 = ET.fromstring(data2 if isinstance(data2, (str, bytes)) else data2)
            parsed2 = _parse_controls(root2)
            if parsed2:
                parsed2['source'] = 'pc_control_list'
                return parsed2
        except ET.ParseError:
            _log("Compliance posture: control list returned non-XML")

    # --- Strategy 3: fall back to cloud compliance (get_compliance_gaps) ---
    _log("Compliance posture: falling back to cloud compliance gaps...")
    try:
        gaps = get_compliance_gaps(limit=limit)
        if gaps and (gaps.get('failingControls', 0) > 0 or gaps.get('passRate', 0) > 0):
            total_failing = gaps.get('failingControls', 0)
            pass_rate = gaps.get('passRate', 0)
            # Estimate total from pass rate
            total = int(total_failing / (1 - pass_rate / 100)) if pass_rate < 100 and total_failing else total_failing
            passing = total - total_failing

            result = _empty_result()
            result['summary']['totalControls'] = total
            result['summary']['passing'] = passing
            result['summary']['failing'] = total_failing
            result['summary']['passRate'] = pass_rate
            result['summary']['frameworks'] = ['Cloud-CIS']
            result['topFailingControls'] = [
                {
                    'controlId': f.get('controlId', ''),
                    'title': '',
                    'framework': 'Cloud-CIS',
                    'failingAssets': f.get('failCount', 0),
                    'severity': 'HIGH',
                }
                for f in gaps.get('topFailing', [])[:limit]
            ]
            result['source'] = 'cloud_compliance_fallback'
            result['note'] = 'Data from cloud compliance evaluations (TotalCloud). Enable Policy Compliance module for on-prem/endpoint posture.'
            return result
    except Exception as e:
        _log(f"Compliance posture: cloud fallback failed: {e}")

    # --- No data available ---
    result = _empty_result()
    result['error'] = 'PC module not licensed or no compliance data available'
    result['suggestion'] = 'Enable the Qualys Policy Compliance (PC) module, or use get_cloud_risk() for cloud CIS compliance.'
    return result


@mcp.tool()
def get_trurisk_score(days: int = 30, breakdown_by: str = "tag") -> dict:
    """[Risk Management] Org-level TruRisk score with trending and breakdown — current aggregate TruRisk, trend over N days, top 10 assets by TruRisk, top 10 vulnerability QIDs contributing most, and optional breakdown by tag. Fast (~5s).

    **Use when:** Asked about overall TruRisk score, risk trends, "what's our org risk?", "is risk going up or down?", or risk breakdown by business unit/tag.
    **NOT for:** Single-asset risk (use get_asset_risk), weekly remediation planning (use get_weekly_priorities), or vulnerability investigation (use investigate_cve).

    Parameters:
        days: trend window in days (default 30). Compares current avg TruRisk vs N days ago.
        breakdown_by: 'tag' groups assets by their tags showing TruRisk per tag, 'none' skips breakdown.

    Returns: aggregate TruRisk, trend direction, top 10 assets, top 10 QIDs by contribution, and tag breakdown."""
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
        old_assets=lambda: csam_search(
            filters=[{"field": "asset.lastModifiedDate", "operator": "LESS", "value": cutoff}],
            limit=100, fields="truRisk", fetch_all=False
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

    # Top 10 assets by TruRisk
    top_assets = concurrent.get('top_assets') or []
    top_assets.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for asset in top_assets[:10]:
        tags = []
        for t in (asset.get('tags') or asset.get('tagList') or []):
            tag_name = t.get('name', '') if isinstance(t, dict) else str(t)
            if tag_name:
                tags.append(tag_name)
        result['topAssets'].append({
            'assetId': str(asset.get('assetId', '')),
            'hostname': asset.get('dnsHostName', '') or asset.get('dnsName', ''),
            'ip': asset.get('address', ''),
            'truriskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
            'tags': tags[:5],
        })

    # Compute avg TruRisk now vs N days ago for trend
    if top_assets:
        avg_now = sum(int(a.get('riskScore') or 0) for a in top_assets) / len(top_assets)
    else:
        avg_now = 0

    old_assets = concurrent.get('old_assets') or []
    if old_assets:
        avg_old = sum(int(a.get('riskScore') or 0) for a in old_assets) / len(old_assets)
    else:
        avg_old = avg_now

    delta = avg_now - avg_old
    if delta < -5:
        direction = 'improving'
        arrow = '↓'
    elif delta > 5:
        direction = 'worsening'
        arrow = '↑'
    else:
        direction = 'stable'
        arrow = '→'

    result['trend'] = {
        'days': days,
        'avgTruRiskCurrent': round(avg_now),
        'avgTruRiskPrior': round(avg_old),
        'delta': round(delta),
        'direction': direction,
        'display': f"TruRisk: {round(avg_now)} {arrow} {direction}",
    }

    # Top QIDs contributing to risk — extract from top assets' vulnerability data if available
    qid_risk = {}
    for asset in top_assets[:50]:
        vulns = asset.get('vulnerabilities') or {}
        asset_risk = int(asset.get('riskScore') or 0)
        # CSAM may include vulnerability counts but not individual QIDs in search results;
        # count contribution by asset presence for the top-risk assets
        vuln_count = vulns.get('count', 0) or 0
        if vuln_count > 0 and asset_risk > 0:
            # Attribute asset risk proportionally as a proxy
            for qid_entry in (vulns.get('list') or [])[:20]:
                qid_val = qid_entry.get('qid') or qid_entry.get('qds', {}).get('qid')
                if qid_val:
                    qid_risk[qid_val] = qid_risk.get(qid_val, 0) + (asset_risk // max(vuln_count, 1))
    top_qids = sorted(qid_risk.items(), key=lambda x: -x[1])[:10]
    result['topQIDs'] = [{'qid': q, 'riskContribution': r} for q, r in top_qids]

    # Tag breakdown
    if breakdown_by == 'tag' and top_assets:
        tag_scores = {}  # {tag: [scores]}
        for asset in top_assets:
            score = int(asset.get('riskScore') or 0)
            asset_tags = asset.get('tags') or asset.get('tagList') or []
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

    return result


@mcp.tool()
def get_tags(limit: int = 500) -> dict:
    """[CSAM] List all asset tags defined in the environment.
    Use when: browsing available tags, looking up tag names before filtering,
    or giving an LLM the tag vocabulary to use in other tool calls.

    Returns: list of distinct tag names found across all assets."""
    assets = csam_search(limit=limit, fields="tags,tagList", fetch_all=False)
    tag_set = set()
    for a in assets:
        for t in a.get('tags', []) or a.get('tagList', []) or []:
            name = t.get('name', '') if isinstance(t, dict) else str(t)
            if name:
                tag_set.add(name)
    tags_sorted = sorted(tag_set)
    return {'totalTags': len(tags_sorted), 'tags': tags_sorted}


@mcp.tool()
def get_asset_groups(limit: int = 500) -> dict:
    """[CSAM] List all asset groups defined in Qualys.
    Use when: user asks about asset groups, wants to scope queries to a group,
    or needs group names for filtering other tools.

    Returns: list of distinct asset group names found across all assets."""
    assets = csam_search(limit=limit, fields="assetGroups,tags", fetch_all=False)
    group_set = set()
    for a in assets:
        for g in a.get('assetGroups', []) or []:
            name = g.get('name', '') if isinstance(g, dict) else str(g)
            if name:
                group_set.add(name)
    groups_sorted = sorted(group_set)
    return {'totalGroups': len(groups_sorted), 'assetGroups': groups_sorted}


@mcp.tool()
def get_assets_by_tag(tag_name: str, limit: int = 50) -> dict:
    """[CSAM] List assets matching a specific tag.
    Use when: user asks 'show me Production assets', 'list assets tagged PCI', etc.
    Returns full asset list with truRisk, OS, tags, last seen.

    Parameters:
        tag_name: the tag to filter by (e.g. Production, PCI, cloud, DMZ)
        limit: max assets to return (default 50)"""
    filters = [{"field": "asset.tags.name", "operator": "EQUALS", "value": tag_name}]
    data = _run_concurrent(
        assets=lambda: csam_search(
            filters=filters, limit=limit,
            fields="operatingSystem,hardware,tags,tagList,truRisk,truRiskScoreFactors"
        ),
        total=lambda: csam_count(filters),
    )
    assets = data.get('assets', [])
    total_count = data.get('total', len(assets))

    result_assets = []
    for a in assets:
        os_info = a.get('operatingSystem', {}) or {}
        asset_tags = []
        for t in a.get('tags', []) or a.get('tagList', []) or []:
            name = t.get('name', '') if isinstance(t, dict) else str(t)
            if name:
                asset_tags.append(name)
        result_assets.append({
            'assetId': str(a.get('assetId', '')),
            'hostname': a.get('dnsHostName', '') or a.get('dnsName', ''),
            'ip': a.get('address', ''),
            'riskScore': int(a.get('riskScore') or 0),
            'os': os_info.get('osName', ''),
            'tags': asset_tags,
            'lastSeen': a.get('lastModifiedDate', ''),
            'criticality': get_criticality(a),
        })

    result_assets.sort(key=lambda x: -x['riskScore'])
    return {
        'tag': tag_name,
        'total': total_count,
        'returned': len(result_assets),
        'assets': result_assets,
    }


def main():
    mcp.run()


if __name__ == "__main__":
    main()
