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
from threading import Lock, Thread, Event
from fastmcp import FastMCP

mcp = FastMCP("qualys-mcp")


def compact(d):
    """Recursively remove None values and empty lists/dicts."""
    if isinstance(d, dict):
        return {k: compact(v) for k, v in d.items()
                if v is not None and v != [] and v != {}}
    if isinstance(d, list):
        return [compact(i) for i in d]
    return d


def _with_meta(result, list_key=None, total=None):
    """Add _meta block to result dict and compact it."""
    if list_key and list_key in result:
        items = result[list_key]
        n = len(items) if isinstance(items, list) else 1
        t = total if total is not None else n
    else:
        n = 1
        t = 1
    result['_meta'] = {'returned': n, 'total': t, 'truncated': n < t}
    return compact(result)


def short_date(dt_str):
    """Strip time from ISO datetime if time is midnight."""
    if dt_str and "T" in str(dt_str):
        date_part, time_part = str(dt_str).split("T", 1)
        if time_part in ("00:00:00Z", "00:00:00", "00:00:00+00:00"):
            return date_part
    return dt_str


def short_host(hostname):
    """Truncate FQDN to first label."""
    if hostname and "." in hostname:
        return hostname.split(".")[0]
    return hostname

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

# Per-key in-flight deduplication: maps cache key -> Event (set when fetch completes)
_inflight = {}          # {key: Event}
_inflight_lock = Lock() # protects _inflight dict

# Pagination safety: max pages any helper will fetch to prevent runaway loops.
# Set QUALYS_MAX_PAGES env var to override. 0 = unlimited (default).
# Tools needing just a count use count_only=True (1 API call).
MAX_PAGES = int(os.environ.get('QUALYS_MAX_PAGES', '0'))

# VMDR cache TTL (detection + QDS caches). Default 30 minutes; override via env.
VMDR_CACHE_TTL = int(os.environ.get('VMDR_CACHE_TTL_SECONDS', 1800))

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
    """Thread-safe cache get-or-fetch with in-flight request deduplication.
    If a fetch is already in progress for *key*, subsequent callers wait on a
    threading.Event instead of issuing a duplicate API call."""
    now = datetime.now(timezone.utc)
    cached_time = cache_time_dict.get(key)
    if key in cache_dict and cached_time and (now - cached_time).total_seconds() < ttl:
        return cache_dict[key]

    with _inflight_lock:
        # Re-check cache inside lock (another thread may have just finished)
        now = datetime.now(timezone.utc)
        cached_time = cache_time_dict.get(key)
        if key in cache_dict and cached_time and (now - cached_time).total_seconds() < ttl:
            return cache_dict[key]
        evt = _inflight.get(key)
        if evt is not None:
            # Another thread is already fetching — wait for it
            is_owner = False
        else:
            evt = Event()
            _inflight[key] = evt
            is_owner = True

    if not is_owner:
        evt.wait()  # block until the fetching thread signals completion
        return cache_dict.get(key)  # return whatever the owner stored

    try:
        result = fetch_fn()
        cache_dict[key] = result
        cache_time_dict[key] = datetime.now(timezone.utc)
        return result
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        evt.set()  # wake up any waiters


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
    """Get VMDR detections with hostname and QDS. Uses VMDR_CACHE_TTL (default 30min).
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

    dets = _get_or_fetch(DETECTION_CACHE, DETECTION_CACHE_TIME, cache_key, _fetch, VMDR_CACHE_TTL)
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
    Returns {qid: max_qds} across all hosts/detections. Uses VMDR_CACHE_TTL (default 30min).
    Gracefully returns {} on failure so callers can fall back to QDS=0."""
    global QDS_CACHE, QDS_CACHE_TIME
    if not qids:
        return {}

    now = datetime.now(timezone.utc)
    # Expire cache after VMDR_CACHE_TTL (default 30 minutes)
    if QDS_CACHE_TIME and (now - QDS_CACHE_TIME).total_seconds() > VMDR_CACHE_TTL:
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
                cvss_v3_base = round(float(base_text), 1)
        except (ValueError, TypeError):
            pass
        try:
            temp_text = cvss_v3.findtext('TEMPORAL', '')
            if temp_text:
                cvss_v3_temporal = round(float(temp_text), 1)
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
                            'hostname': short_host(a.get('dnsHostName', '') or a.get('dnsName', '')),
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
    """[Risk Management] Weekly priorities — top high-risk assets ranked by TruRisk, risk distribution across severity tiers, and container risks. @slow

    USE WHEN: "what should I work on this week?", "top priorities", "what should we fix first?", sprint planning, or risk-ranked remediation lists.
    DO NOT USE WHEN: Asking about what happened today/overnight, drilling into a single asset, or checking cloud posture.
    PREFER INSTEAD: get_morning_report for daily briefing ("what happened overnight?"); get_asset for single-asset drill-down; get_cloud_risk for cloud posture; get_eliminate_status for patch deployment status.

    Parameters:
        limit: max top-risk assets to return (default 10)
        sort_by: ranking method — 'trurisk' (default, CSAM field truRisk DESC) or 'severity'
        tag: filter to assets with this tag (e.g. Production, PCI, cloud)
        asset_group: filter to assets in this Qualys asset group

    Returns: topRiskAssets (ranked list with assetId, hostname, ip, riskScore, os, criticality), priorities (actionable items with severity rank), summary (asset counts by risk tier, container risks).

    Performance: ~5s cold / ~3s warm (parallel CSAM queries)."""
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
            'hostname': short_host(asset.get('dnsHostName', '') or asset.get('dnsName', '')),
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

    return _with_meta(result, 'topRiskAssets')


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
    """[Vulnerability Intelligence] Single-CVE deep investigation — maps CVE to QIDs, retrieves KB details (severity, patches, threat intel, ransomware), and searches your asset inventory for affected software. @slow

    USE WHEN: Deep-diving a single CVE — "are we affected by CVE-2024-3400?", incident response triage, tracing a CVE to specific assets, or "what's the impact of CVE-X?"
    DO NOT USE WHEN: Looking up multiple CVEs at once (bulk metadata), searching KB by software/threat type, or checking confirmed detection status on assets.
    PREFER INSTEAD: get_cve_details when you need KB metadata for 2-20 CVEs without asset search; search_vulns when searching KB by software name or threat type; get_etm_findings with QQL `vulnerabilities.vulnerability.cveIds:CVE-...` when you need confirmed finding status.

    Parameters:
        cve: single CVE ID, e.g. 'CVE-2024-3400'

    Returns: qids (mapped QIDs), severity, qds, title, patchAvailable, solution, allKbDetails, threatIntel, ransomware flag, affectedAssets (CSAM software search with sample assets), summary.

    Performance: ~5s cold / ~3s warm (KB cached)."""
    result = {'cve': cve, 'qids': [], 'severity': 0, 'qds': 0,
              'qds_factors': '',
              'title': '', 'patchAvailable': False, 'solution': '',
              'allKbDetails': [], 'threatIntel': [],
              'ransomware': False,
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
                    'title': kb.get('title', '')[:80],
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

    return _with_meta(result, 'allKbDetails')


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
    """[Patch Management] Patching coverage and gaps — TruRisk distribution across severity tiers and top unpatched assets ranked by risk.

    USE WHEN: "how is our patching going?", "how many assets are unpatched?", assessing patch posture, or identifying top unpatched assets by risk tier.
    DO NOT USE WHEN: Checking active patch job deployment, viewing PM job details per platform, or looking at single-asset patch details.
    PREFER INSTEAD: get_eliminate_status when "what patches are deploying right now?" or active job status; get_asset for single-asset patch/vuln details.

    Parameters:
        limit: max high-risk assets to return (default 20)
        tag: filter to assets with this tag (e.g. Production, PCI, cloud)
        asset_group: filter to assets in this Qualys asset group

    Returns: coverage (% of assets with TruRisk < 100), assetsTotal, riskDistribution (critical_900plus, high_700plus, elevated_500plus, medium_100plus, low_under100), highRiskAssets (ranked list).

    Performance: ~5s cold / ~3s warm (parallel CSAM queries)."""
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
            'hostname': short_host(asset.get('dnsHostName', '') or asset.get('dnsName', '')),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
        })

    # Coverage: % of assets with TruRisk < 100 (low risk)
    if total > 0:
        result['coverage'] = round((total - risk_100) / total * 100, 1)

    return _with_meta(result, 'highRiskAssets', total)


@mcp.tool()
def search_vulns(days: int = 7, threat_type: str = "", software: str = "", limit: int = 50, tag: str = "", asset_group: str = "") -> dict:
    """[Vulnerability Intelligence] KB search — newly published vulns, threat intel (RTI) filtering, and software-specific vuln lookups from the Qualys Knowledge Base.

    USE WHEN: Searching for new vulns ("what was published this week?"), threat intel queries ("any ransomware vulns?", "CISA KEV additions?"), or software-specific lookups ("what vulns affect Apache?"). This searches the KB (published vulns), NOT your detections.
    DO NOT USE WHEN: Tracing a single CVE to affected assets in your environment, doing bulk CVE metadata lookup, or querying confirmed detections on your assets.
    PREFER INSTEAD: investigate_cve for single-CVE deep-dive with asset impact; get_cve_details for bulk CVE metadata; get_etm_findings for confirmed detections in YOUR environment.

    Parameters:
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

    Filters combine: search_vulns(days=30, threat_type='Ransomware', software='Apache') returns Apache vulns with ransomware linkage from the last 30 days.

    Returns: totalVulns, severityBreakdown, withPatch, withThreatIntel, threatBreakdown (RTI tag counts), vulns (list with qid, title, severity, qds, cves, patchAvailable, threatIntel), summary.

    Performance: ~5s cold / ~3s warm (KB cached)."""
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
        return _with_meta(result, 'vulns')

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['summary'] = 'Failed to parse KB data'
        return _with_meta(result, 'vulns')

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
            'title': v['title'][:80],
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
    return _with_meta(result, 'vulns', result.get('totalMatching', len(matching)))


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
    """[Program Advisor] Security program recommendations — analyzes your environment and identifies coverage gaps across VMDR, TotalCloud, TotalAppSec, FIM, EDR, CertView, and Patch Management.

    USE WHEN: Gap analysis, program improvement, "what modules should we add?", "what should we invest in?", "what's missing from our security program?", or "how do we reduce our TruRisk score?"
    DO NOT USE WHEN: Responding to immediate threats, looking at asset-level vuln details, or checking patching status.
    PREFER INSTEAD: get_morning_report for immediate threat response; get_asset for asset-level details; get_eliminate_status for patching status.

    Returns: recommendations (prioritized list with priority, area, finding, qualysModule, riskAction=eliminate|mitigate), coverage (map of active vs missing capabilities), riskActions (eliminate/mitigate counts), summary.

    Performance: ~10s cold / ~5s warm (probes all data sources in parallel)."""
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

    # --- Cloud security gaps ---
    cloud_total = len(cloud_aws) + len(cloud_azure) + len(cloud_gcp)
    cloud_evals = concurrent.get('cloud_evals') or []
    if not cloud_total:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Cloud Security Posture',
            'finding': 'No cloud connectors configured — cloud assets may have unmonitored misconfigurations',
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

    # --- Application security ---
    if not was:
        recs.append({
            'rank': rank, 'priority': 'MEDIUM',
            'area': 'Application Security',
            'finding': 'No application scan findings detected — web apps and APIs may not be scanned for vulnerabilities like SQLi, XSS, and OWASP Top 10',
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

    return _with_meta(result, 'recommendations')


@mcp.tool()
def get_eliminate_status() -> dict:
    """[TruRisk Eliminate] Active patch and mitigation deployment status — PM jobs, MTG jobs, patch catalog size, and managed asset counts for Windows and Linux.

    USE WHEN: "what patches are deploying right now?", "are patches deploying?", "how many mitigation jobs are running?", "what's our patch catalog size?", or checking active risk elimination progress.
    DO NOT USE WHEN: Assessing overall patch coverage by risk tier, viewing per-platform PM job details, or checking single-asset patch status.
    PREFER INSTEAD: get_patch_status when "how is our patching going?" (coverage/gaps summary); get_asset for per-asset details.

    Returns: patchManagement (per-platform: totalJobs, activeJobs, byStatus, recentJobs, managedAssets), mitigations (per-platform: totalJobs, activeJobs, byStatus, recentJobs), patchCatalog (windows/linux totals and severity breakdown), summary.

    Performance: ~5s cold / ~3s warm (parallel PM+MTG+catalog queries)."""
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
            'total': len(patch_jobs),
            'active': len(active),
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
            'total': len(mtg_jobs),
            'active': len(mtg_active),
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

    return _with_meta(result)


@mcp.tool()
def get_scanner_health() -> dict:
    """[Infrastructure] Scanner appliance health — online/offline status, running/failed scans, capacity utilization, and vuln signature currency.

    USE WHEN: Scanners appear offline, coverage seems low, "why did my scan fail?", checking last scan times, or verifying scanner infrastructure health before a scan window.
    DO NOT USE WHEN: Checking scan job status/history, looking at vulnerability findings from scans, or checking patch deployment status.
    PREFER INSTEAD: get_scan_status for scan job status/history; get_etm_findings for vulnerability findings; get_eliminate_status for patch deployment status.

    Returns: scanners (list with name, status, runningScanCount, maxCapacity, heartbeatsMissed, vulnsigs currency), scanStatus (byState, errorScans, activeScans), summary.

    Performance: ~5s cold / ~3s warm (parallel scanner list + scan list queries)."""
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
            'lastUpdated': short_date(s.get('lastUpdated', '')),
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
            'launched': short_date(s.get('launched', '')),
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

    return _with_meta(result, 'scanners')


@mcp.tool()
def get_etm_findings(qql: str = "", report_id: str = "") -> dict:
    """[Enterprise TruRisk] Confirmed vulnerability and misconfiguration findings in YOUR environment — from VMDR, TotalCloud, and third-party scanners. Returns per-asset findings with TruRisk, QDS, CVSS, patch status. @slow

    USE WHEN: User asks what vulns exist on their assets — "show me all critical vulns on PCI assets", "find Log4Shell across the environment", "what's confirmed in our scans?". Best for rich QQL filtering across confirmed detections.
    DO NOT USE WHEN: Searching the KB for newly published vulns (not yet scanned), doing single-CVE investigation with asset software search, or checking cloud misconfigs.
    PREFER INSTEAD: search_vulns for KB-only search (published vulns, not your detections); investigate_cve for single-CVE deep-dive with asset impact; get_cloud_risk for cloud misconfigurations.

    Parameters:
    qql: Qualys Query Language filter string (optional). Use to filter findings.
    report_id: resume polling an async ETM report (optional).

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

    Returns: findings (per-asset entries with cveId, qid, severity, qds, truRiskScore, isPatchAvailable, category), summary (totalFindings, uniqueAssets, uniqueCVEs, patchable, bySeverity), topCVEs.

    **How async reports work:** ETM reports are async — completed reports are cached in-memory for 1 hour for instant warm retrieval. If no cached result exists, a new report is created and `{status: "creating", reportId: "..."}` is returned — call again with that reportId to poll for completion (typically 1–5 minutes). Filtered QQL queries always create a fresh report.

    Performance: ~2s warm (cached report) / 1-5 min cold (async report generation). Unfiltered queries reuse cached reports for 1 hour."""
    global ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    now = datetime.now(timezone.utc)
    result = {'findings': [], 'summary': {}, 'reportStatus': ''}

    # If report_id provided, check its status and download if ready
    if report_id:
        detail = etm_api('GET', f'/etm/api/rest/v1/reports/{report_id}')
        if not detail:
            result['reportStatus'] = 'error'
            result['summary'] = {'error': 'Could not retrieve report status'}
            return _with_meta(result, 'findings')

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
            return _with_meta(formatted, 'findings', formatted.get('totalFindings', len(formatted.get('findings', []))))

        elif detail['status'] == 'FAILED':
            result['summary'] = {'error': 'Report generation failed', 'reportId': report_id}
            return _with_meta(result, 'findings')
        else:
            result['summary'] = {
                'message': f'Report is still processing (status: {detail["status"]}). Try again in 30-60 seconds.',
                'reportId': report_id,
            }
            return _with_meta(result, 'findings')

    # For unfiltered queries: check in-memory cache first (1-hour TTL)
    if not qql and ETM_RESULT_CACHE is not None and ETM_RESULT_CACHE_TIME:
        age = (now - ETM_RESULT_CACHE_TIME).total_seconds()
        if age < 3600:
            _log(f"ETM result cache hit (age {int(age)}s)")
            cached = dict(ETM_RESULT_CACHE)
            cached['cacheAge'] = int(age)
            return compact(cached)

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
        return _with_meta(result, 'findings')

    rid = new_report.get('id', '')
    result['reportStatus'] = 'creating'
    result['summary'] = {
        'message': 'ETM report requested. Reports typically take 1-5 minutes to generate. Call get_etm_findings(report_id="' + rid + '") to check status and retrieve results.',
        'reportId': rid,
        'qql': qql or '(all findings)',
    }
    return _with_meta(result, 'findings')


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
            'title': f.get('title', '')[:80],
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
            'firstFound': short_date(f.get('firstFound')),
            'lastFound': short_date(f.get('lastFound')),
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
        'topCVEs': [{'cve': cve, 'qid': info.get('qid', ''), 'assets': info['count'], 'severity': info['severity'], 'title': info['title'][:80]} for cve, info in top_cves],
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
def get_morning_report(quick: bool = False) -> dict:
    """[Daily Briefing] Morning security report or fast environment snapshot. @slow when quick=False

    USE WHEN: "what happened overnight?", "morning report", "give me a briefing", "what's new today?", "what does our environment look like?", environment overview, asset demographics, shift handover, or starting a session. This is the best first-call for daily situational awareness.
    DO NOT USE WHEN: Planning the week's work, deep-diving a specific CVE, or investigating cloud-specific threats.
    PREFER INSTEAD: get_weekly_priorities when "what should I work on this week?" or "top priorities"; investigate_cve for single-CVE deep-dive; get_cloud_risk for cloud threat hunting.

    Parameters:
        quick: True for fast environment snapshot only (<3s) — asset counts by OS, cloud, EOL, criticality. False (default) for full daily briefing (~8s).

    Returns (quick=False): environment (healthScore, totalAssets, highRiskAssets, eolSystems), newVulns (24h counts by severity + criticalVulns list), threats (ransomwareLinked, activelyExploited, cisaKev), topRiskAssets, actionItems, truriskTrend.
    Returns (quick=True): totalAssets, byOS, byCloud, eolCounts, byCriticality, summary.

    Performance: ~8s cold / ~4s warm (quick=False). <3s (quick=True)."""
    # quick=True: fast environment snapshot (replaces get_environment_summary)
    if quick:
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
        return compact(snap)

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

    return _with_meta(result, 'topRiskAssets')


@mcp.tool()
def get_cve_details(cves: str) -> dict:
    """[Vulnerability Intelligence] Bulk CVE lookup — severity, patches, threat intel, and remediation for 1-20 CVEs at once. KB data only (no asset search). @slow

    USE WHEN: Looking up multiple CVEs at once — "what's the severity of these CVEs?", comparing CVE risk, building a CVE summary table, or quick metadata check for a list of CVEs.
    DO NOT USE WHEN: Investigating a single CVE with asset impact analysis, looking up QIDs (not CVEs), or querying confirmed findings in your environment.
    PREFER INSTEAD: investigate_cve when you need a single CVE traced to affected assets in your environment; get_qid_details for QID-based lookup; get_etm_findings for confirmed detections.

    Parameters:
        cves: comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2024-3400'. Up to 20 per call; 10 recommended for best performance.

    Returns: per-CVE entries with severity, qds, cvss_v3, title, patchAvailable, has_exploit, solution, threatIntel, ransomware flag, and kbEntries (all mapped QIDs).

    Performance: ~5s cold / ~3s warm (KB cached). Scales linearly with CVE count."""
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
                    'title': kb.get('title', '')[:80],
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
            'solution': (best.get('solution', '') if best else '')[:120],
            'diagnosis': (best.get('diagnosis', '') if best else '')[:120],
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
    return _with_meta(result, 'cves')


@mcp.tool()
def get_qid_details(qids: str) -> dict:
    """[Vulnerability Intelligence] Direct QID lookup — KB details (severity, QDS, patches, threat intel, CVEs) for specific Qualys QIDs.

    USE WHEN: You have specific QID numbers from ETM findings, scan reports, or VMDR detections and need KB details. QIDs are Qualys-internal vulnerability identifiers.
    DO NOT USE WHEN: You have CVE IDs (not QIDs), searching KB by software/threat type, or querying confirmed findings across assets.
    PREFER INSTEAD: get_cve_details for CVE-based lookup; search_vulns for KB search by software or threat type; get_etm_findings for confirmed findings across assets.

    Parameters:
        qids: comma-separated QIDs, e.g. '38747,376418'. Up to 50 per call.

    Returns: per-QID entries with title, severity, qds, qds_factors, cvss_v3, cves, patchAvailable, has_exploit, solution, diagnosis, threatIntel, ransomware flag.

    Performance: ~3s cold / ~1s warm (KB cached)."""
    qid_list = []
    for q in qids.split(','):
        q = q.strip()
        if q.isdigit():
            qid_list.append(int(q))
    if not qid_list:
        return compact({'error': 'No valid QIDs provided', 'requested': 0, 'found': 0, 'qids': []})

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
                'title': kb.get('title', '')[:80],
                'severity': kb.get('severity', 0),
                'qds': real_qds or kb.get('qds', 0),
                'qds_factors': kb.get('qds_factors', ''),
                'cvss_v3': kb.get('cvss_v3'),
                'cvss_v3_temporal': kb.get('cvss_v3_temporal'),
                'cvss_v3_vector': kb.get('cvss_v3_vector', ''),
                'cves': kb.get('cves', []),
                'patchAvailable': kb.get('patch_available', False),
                'has_exploit': kb.get('has_exploit', False),
                'solution': kb.get('solution', '')[:120],
                'diagnosis': kb.get('diagnosis', '')[:120],
                'threatIntel': kb.get('threat_intel', []),
                'ransomware': kb.get('ransomware', False),
            })
        else:
            result['qids'].append({'qid': qid, 'found': False})

    result['qids'].sort(key=lambda x: (-x.get('severity', 0), -x.get('qds', 0)))
    return _with_meta(result, 'qids')


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


@mcp.tool()
def get_cloud_risk(limit: int = 20, include_threats: bool = True, days: int = 7) -> dict:
    """[Cloud Security] Cloud security posture + CDR threat findings across AWS, Azure, and GCP — connected accounts, CIS benchmark control failures, and detailed CDR threats. @slow

    USE WHEN: "how are our cloud accounts doing?", cloud security posture overview, CIS benchmark compliance, cloud risk summary, investigating active cloud threats, lateral movement, suspicious network activity, or cloud incident response.
    DO NOT USE WHEN: Looking at host-based vulnerabilities or checking on-prem compliance.
    PREFER INSTEAD: get_etm_findings for host-based vulnerabilities; get_compliance_posture for on-prem/Policy Compliance posture; get_edr_events for host-based endpoint threats.

    Parameters:
        limit: max failed controls and CDR threats to return (default 20)
        include_threats: include detailed CDR threat findings (default True). Set False for posture-only.
        days: CDR look-back window in days (default 7). Only used when include_threats=True.

    Returns: accounts (list with id, provider, name), failedControls (CIS benchmark failures by controlId), threats (CDR findings with severity, category, resourceId, provider, account, region), stats (total accounts, critical threats).

    Note: CIS evaluations fetched from first account per provider. For multi-account evaluation, use Qualys TotalCloud console.

    Performance: ~6s cold / ~3s warm (parallel: 3 provider connectors + evaluations + CDR)."""
    result = {'accounts': [], 'failedControls': [], 'threats': [], 'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}}

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
        first_acc = conns[0].get(acc_key, '')
        if first_acc:
            first_accounts[provider] = first_acc

    result['stats']['total'] = len(result['accounts'])

    # Fetch evaluations for first account of each provider AND CDR in parallel
    eval_tasks = {
        f'evals_{p}': (lambda p=p, a=a: get_evaluations(a, p, 500))
        for p, a in first_accounts.items()
    }
    if include_threats:
        eval_tasks['cdr'] = lambda: get_cdr(days, limit)
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

    # CDR threats — detailed findings (merged from get_cdr_findings)
    if include_threats:
        sev_map = {'1': 'LOW', '2': 'MEDIUM', '3': 'HIGH', '4': 'CRITICAL'}
        by_provider = {}
        by_category = {}
        findings = eval_results.get('cdr') or []

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

        crit = result['stats']['critical']
        high = result['stats']['high']
        total_threats = len(findings)
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

    return compact(result)


@mcp.tool()
def get_cdr_findings(days: int = 7, limit: int = 50, severity: str = "", cloud_provider: str = "") -> dict:
    """DEPRECATED: Use get_cloud_risk(include_threats=True, days=N) instead. CDR findings are now included in get_cloud_risk."""
    return {'error': "get_cdr_findings has been removed. Use get_cloud_risk(include_threats=True, days=...) instead.", 'replacement': 'get_cloud_risk'}


@mcp.tool()
def get_asset(asset_id: str, detail: str = "summary") -> dict:
    """[Asset Risk] Single-asset risk profile — TruRisk score, OS, criticality, software, EOL flags, and vulnerability detections. @slow when detail='full'

    USE WHEN: Drilling into one specific asset — "what's the risk on this server?", "full profile", "complete profile", or "everything about this asset". Pass assetId from get_weekly_priorities, get_patch_status, get_etm_findings, or get_asset_inventory.
    DO NOT USE WHEN: Browsing multiple assets or viewing environment-wide risk.
    PREFER INSTEAD: get_weekly_priorities or get_asset_inventory for multi-asset browsing; get_risk_by_tag for aggregate risk by tag group.

    Parameters:
        asset_id: CSAM assetId (string) from any tool that returns asset lists
        detail: 'summary' (fast, CSAM+VMDR only, ~2s) or 'full' (complete, CSAM+ETM+VMDR parallel, ~6s)

    Returns: riskScore, hostname, ip, os, criticality, software, eolSoftware, vulns.
    With detail='full': also etmFindings, vmdrDetections, tags, and summary counts.

    Performance: ~3s cold / ~2s warm (detail='summary'). ~5-8s cold / ~2s warm (detail='full')."""
    result = {
        'assetId': asset_id, 'riskScore': 0, 'truriskScore': 0,
        'software': [], 'eolSoftware': [],
        '_meta': {'returned': 1, 'total': 1, 'truncated': False},
    }

    if detail == 'full':
        # Full profile: CSAM + ETM + VMDR in parallel
        asset = get_asset_by_id(asset_id)
        if not asset:
            result['_meta'] = {'returned': 0, 'total': 0, 'truncated': False}
            result['error'] = f'Asset {asset_id} not found in CSAM'
            return compact(result)

        host_id = str(asset.get('hostId') or '')
        hostname = asset.get('dnsHostName', '') or asset.get('dnsName', '') or asset.get('address', '')
        os_name = (asset.get('operatingSystem') or {}).get('osName', '')

        # Build CSAM profile
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

        # Fetch ETM findings and VMDR detections in parallel
        def _fetch_etm():
            if ETM_RESULT_CACHE:
                all_findings = ETM_RESULT_CACHE.get('findings', [])
                return [f for f in all_findings if
                        f.get('assetId') == asset_id or
                        f.get('assetName', '').lower() == hostname.lower()][:50]
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
            if not host_id:
                return []
            return get_host_detections(host_id, severity=4, days=30)

        parallel = _run_concurrent(etm=_fetch_etm, vmdr=_fetch_vmdr)

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
                'title': kb.get('title', '')[:80],
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

        return compact(result)

    # detail='summary' — fast path (CSAM + VMDR only)
    filters = [{"field": "asset.id", "operator": "EQUALS", "value": str(asset_id)}]
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
                        'title': kb.get('title', '')[:80],
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


@mcp.tool()
def get_asset_risk(asset_id: str, tag: str = "", asset_group: str = "") -> dict:
    """DEPRECATED: Use get_asset(asset_id, detail='summary') instead. This tool has been consolidated into get_asset()."""
    return {'error': "get_asset_risk has been removed. Use get_asset(asset_id='...', detail='summary') instead.", 'replacement': 'get_asset'}


@mcp.tool()
def get_tech_debt(limit: int = 100) -> dict:
    """[Asset Lifecycle] End-of-life and end-of-support systems — OS and hardware assets running unsupported software, sorted by criticality and risk score. @slow

    USE WHEN: "which systems are unsupported?", tech debt assessment, EOL/EOS exposure audit, or upgrade planning. Returns both OS EOL (e.g. Windows Server 2012) and hardware EOL assets.
    DO NOT USE WHEN: Checking EOL status for a single asset, browsing general asset inventory, or getting environment overview counts.
    PREFER INSTEAD: get_asset for single-asset EOL check; get_asset_inventory for general asset browsing; get_morning_report(quick=True) for quick environment counts.

    Parameters:
        limit: max assets per category (default 100). Use 500 for full inventory.

    Returns: os (list of OS EOL assets with assetId, hostname, os, riskScore, criticality, lifecycleStage), hardware (list of hardware EOL assets), summary (osEOL count, hardwareEOL count).

    Performance: ~25s for limit=100 / ~2min for limit=500 (paginated CSAM API)."""
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

    return _with_meta(result, 'os', len(result['os']) + len(result['hardware']))


@mcp.tool()
def get_image_vulns(image_id: str, limit: int = 50) -> dict:
    """[Container Security] Vulnerabilities for a specific container image — severity breakdown and individual vuln details with fix versions.

    USE WHEN: Investigating vulnerabilities in a specific container image, pre-deployment image scanning review, or container remediation planning.
    DO NOT USE WHEN: Listing all container images, checking host-based vulnerabilities, or viewing cloud posture.
    PREFER INSTEAD: get_asset_inventory for listing container images; get_asset for host-based vulnerabilities; get_cloud_risk for cloud posture overview.

    Parameters:
        image_id: TotalCloud imageId (from get_asset_inventory or get_weekly_priorities container risk section)
        limit: max vulns to return (default 50)

    Returns: imageId, repo, tag, created, stats (critical/high/medium/low/total), vulns (list with qid, cve, severity, title, fixVersion).

    Performance: ~3s (parallel image details + vulns API)."""
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
            'severity': sev, 'title': v.get('title', '')[:80],
            'fixVersion': v.get('fixedVersion', '')
        })

    result['stats']['total'] = len(vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    return _with_meta(result, 'vulns', len(vulns))


@mcp.tool()
def get_expiring_certs(days: int = 90, include_expired: bool = True, weak_only: bool = False, limit: int = 100) -> dict:
    """[CertView] SSL/TLS certificate expiry monitoring and configuration issue detection — expiring/expired certs, weak keys, SHA-1, self-signed, and TLS 1.0/1.1 usage.

    USE WHEN: "which SSL certs expire soon?", certificate expiry audit, weak cipher detection, self-signed cert inventory, TLS version compliance, or outage prevention.
    DO NOT USE WHEN: Scanning for host vulnerabilities, checking cloud posture, or general security health overview.
    PREFER INSTEAD: get_etm_findings for vulnerability scanning; get_cloud_risk for cloud posture; get_morning_report or get_weekly_priorities for general security health.

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

    Returns: summary (total, expired, expiring30Days, expiring90Days, weakCiphers, selfSigned, weakKeySize, tls10or11), expiringSoon (list with subject, expiryDate, daysRemaining, host, grade, issues), issues (flat list with host, issue, severity).

    **Grades:** A = no issues, B = nearing expiry (<30 days), C = self-signed or weak key, F = expired or SHA-1.

    Performance: ~5s cold / ~3s warm."""
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

    return _with_meta(result, 'expiringSoon', result.get('summary', {}).get('total', len(result.get('expiringSoon', []))))


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
    """[Web Application Security] Web application vulnerabilities from Qualys WAS / TotalAppSec — severity breakdown per app, OWASP Top 10 classification, and vuln categories.

    USE WHEN: "what web app vulns do we have?", OWASP Top 10 findings, XSS/SQLi/CSRF issues, per-app vulnerability posture, or web application security audit.
    DO NOT USE WHEN: Looking at host-based vulnerabilities, network-level findings, or SSL/TLS certificate issues.
    PREFER INSTEAD: get_etm_findings for host/network-level vulnerability findings; get_asset for host-based vuln details; get_expiring_certs for SSL/TLS certificate issues.

    Parameters:
        severity: Minimum severity filter (0=all, 1-5). 4=high+critical, 5=critical only.
        days: Only findings detected in the last N days (default 30). Use 7 for weekly review.
        app_name: Filter by web app name (substring match, e.g. "portal", "api").
        owasp_category: Filter results by OWASP Top 10 category keyword (e.g. "Injection", "XSS", "SSRF", "Access Control", "Cryptographic"). Case-insensitive substring match.
        limit: Max findings to return (default 50).

    Returns: stats (total, critical, high, medium, low, webApps), findings (list with id, qid, name, severity, url, webApp, owaspCategory), byWebApp (per-app severity counts), byCategory, owaspTop10 mapping.

    Performance: ~5s cold / ~3s warm (WAS API cached)."""

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
            'detectedDate': short_date(f.get('detectedDate', '')),
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
    return _with_meta(result, 'findings', result['stats']['total'])


@mcp.tool()
def get_asset_full_profile(asset_id: str) -> dict:
    """DEPRECATED: Use get_asset(asset_id, detail='full') instead. This tool has been consolidated into get_asset()."""
    return {'error': "get_asset_full_profile has been removed. Use get_asset(asset_id='...', detail='full') instead.", 'replacement': 'get_asset'}


@mcp.tool()
def get_risk_by_tag(tag: str, limit: int = 10) -> dict:
    """[Asset Risk] Aggregate risk for a tag group — TruRisk tier distribution, top risky assets, and EOL counts scoped to a specific tag.

    USE WHEN: User asks about risk for a team, environment, or tag segment — "what's the risk for PCI assets?", "show me Production risk", "how is the DMZ doing?", or any business-unit/compliance-scope risk question.
    DO NOT USE WHEN: You need global risk overview (not scoped to a tag), single-asset details, or cloud posture.
    PREFER INSTEAD: get_weekly_priorities for global risk overview across all assets; get_asset for single-asset drill-down; get_cloud_risk for cloud-specific posture.

    Parameters:
        tag: tag name to filter by (e.g. 'PCI', 'Production', 'DMZ', 'AWS', 'HIPAA')
        limit: max top-risk assets to return (default 10)

    Returns: assets (total, critical, high, elevated counts), topRiskAssets (ranked list), eolCount, summary string.

    Performance: ~3s (parallel CSAM count queries)."""
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

    return _with_meta(result, 'topRiskAssets', total)


@mcp.tool()
def get_environment_summary() -> dict:
    """DEPRECATED: Use get_morning_report(quick=True) instead. Environment snapshot is now part of get_morning_report."""
    return {'error': "get_environment_summary has been removed. Use get_morning_report(quick=True) instead.", 'replacement': 'get_morning_report'}


@mcp.tool()
def cache_status(clear: bool = False) -> dict:
    """[Admin] Show cache stats or clear all caches.

    USE WHEN: Debugging stale data, checking cache freshness, or forcing a cache refresh before re-running a tool.
    DO NOT USE WHEN: Performing any security analysis — this is an administrative/diagnostic tool only.
    PREFER INSTEAD: Any security analysis tool (get_morning_report, get_weekly_priorities, etc.) for actual security work.

    Parameters:
        clear: set True to reset all caches (default False)

    Returns: kb_entries, detection_entries, qds_entries, was_keys, scanner_cached, etm_result_cached, cache ages in seconds.

    Performance: <1s."""
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
    }

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
        result['cache_age_s'] = None
        result['scanner_cache_age_seconds'] = None
        result['etm_cache_age_seconds'] = None

    result['_meta'] = {'returned': 1, 'total': 1, 'truncated': False}
    return compact(result)


@mcp.tool()
def get_edr_events(days: int = 7, severity: str = "", category: str = "", host: str = "", limit: int = 50) -> dict:
    """[EDR] Endpoint Detection & Response events — malware, ransomware, C2 beaconing, process injection, lateral movement, and suspicious executions.

    USE WHEN: Investigating endpoint threats, malware detections, suspicious process executions, or host-level incident response. Filter by severity, category, or specific host.
    DO NOT USE WHEN: Monitoring file integrity changes, investigating cloud threats, or querying network-level vulnerability findings.
    PREFER INSTEAD: get_fim_events for file integrity changes; get_cloud_risk(include_threats=True) for cloud threats (CDR); get_etm_findings for network-level vulnerability findings.

    Parameters:
        days: look-back window in days (default 7)
        severity: filter by severity — CRITICAL, HIGH, MEDIUM, LOW (empty = all)
        category: filter by event category substring (e.g. 'Malware', 'C2', 'LateralMovement')
        host: filter by hostname substring
        limit: max events to return (default 50)

    Returns: summary (total, critical, high, medium, low, affectedHosts), byCategory, topHosts, events (list with id, severity, category, name, hostname, ip, user, process, timestamp).

    Performance: ~3s cold / ~2s warm."""

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
    return _with_meta(_r, 'events', total)


@mcp.tool()
def get_fim_events(days: int = 1, severity: str = "", host: str = "", path: str = "", limit: int = 100) -> dict:
    """[FIM] File Integrity Monitoring events — unauthorized file changes, critical system file modifications, and suspicious path activity.

    USE WHEN: Investigating file changes on hosts, "were any system files modified?", checking /etc/passwd or registry changes, reviewing off-hours activity, or auditing file integrity for compliance.
    DO NOT USE WHEN: Investigating process-level threats, malware detection, or cloud threat activity.
    PREFER INSTEAD: get_edr_events for process-level threats and malware detection; get_cloud_risk(include_threats=True) for cloud threat activity.

    Parameters:
        days: look-back window in days (default 1)
        severity: filter by severity — CRITICAL, HIGH, MEDIUM, LOW (empty = all)
        host: filter by hostname substring
        path: filter by file path prefix (e.g. '/etc/', 'C:\\Windows\\System32')
        limit: max events to return (default 100)

    Returns: summary (total, critical, high, affectedHosts, modified, created, deleted), topHosts, criticalChanges (with offHours flag), events (list with action, path, hostname, timestamp, severity, user, offHours).

    Performance: ~3s cold / ~2s warm."""
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
    return _with_meta(_r, 'events', total)


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
    """[VM] Scan status — running, queued, and failed scans with duration and target info.

    USE WHEN: "are any scans running?", checking scan progress, troubleshooting failed scans, or reviewing scan history for the week.
    DO NOT USE WHEN: Checking scanner appliance health, looking at vulnerability findings from scans, or checking patch deployment status.
    PREFER INSTEAD: get_scanner_health for scanner appliance health (online/offline, capacity); get_etm_findings for vulnerability findings from scans; get_eliminate_status for patch deployment status.

    Parameters:
        state: comma-separated states to filter — Running, Paused, Queued, Error (default all four)
        days: look-back window in days for finished/history scans (default 7)
        limit: max results to return (default 50)

    Returns: stats (total, byState, running, queued, errors, completedToday), scans (list with ref, title, state, target, launched, duration, scanner), failedScans, summary.

    Performance: ~3s (parallel active + finished scan list queries)."""
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
            'target': s.get('target', ''), 'launched': short_date(launched),
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
                'launched': short_date(launched),
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

    return _with_meta(result, 'scans', total)


@mcp.tool()
def get_pm_status(platform: str = "Windows", days: int = 30, status: str = "", limit: int = 20) -> dict:
    """DEPRECATED: Use get_eliminate_status() instead. PM status is fully covered by get_eliminate_status."""
    return {'error': "get_pm_status has been removed. Use get_eliminate_status() instead — it covers PM+MTG combined.", 'replacement': 'get_eliminate_status'}


@mcp.tool()
def get_asset_inventory(query: str = "", tag: str = "", os: str = "", days_since_seen: int = 0,
                        eol_only: bool = False, limit: int = 50,
                        list_tags: bool = False, list_groups: bool = False) -> dict:
    """[CSAM] Asset inventory search — find assets by OS, tag, keyword, EOL status, or staleness. Also lists tags and asset groups.

    USE WHEN: Searching for assets by name/OS/tag, finding stale assets, building asset lists for remediation, finding container image IDs for get_image_vulns, browsing available tags, or listing asset groups.
    DO NOT USE WHEN: Looking at single-asset risk details or wanting risk-ranked asset lists.
    PREFER INSTEAD: get_asset for single-asset risk details; get_weekly_priorities for risk-ranked asset lists; get_morning_report(quick=True) for quick environment counts.

    CSAM filter examples (applied automatically from parameters):
      - os="Windows Server 2019"      -> operatingSystem.osName CONTAINS 'Windows Server 2019'
      - tag="PCI"                      -> tags.name CONTAINS 'PCI'
      - eol_only=True                  -> operatingSystem.lifecycle.stage CONTAINS 'EOL'
      - days_since_seen=30             -> assets not seen in 30+ days (stale)

    Parameters:
        query: free-text search on hostname/name
        tag: filter by asset tag name (also replaces get_assets_by_tag)
        os: filter by OS (e.g. "Windows", "Linux", "Ubuntu", "CentOS")
        days_since_seen: only assets NOT seen in last N days (stale assets); 0 = no filter
        eol_only: only return end-of-life assets
        limit: max results (default 50)
        list_tags: if True, return sorted list of all distinct tag names (replaces get_tags)
        list_groups: if True, return sorted list of all distinct asset group names (replaces get_asset_groups)

    Returns: summary (total, returned, byOS, byTag, eolCount), assets (list with id, name, ip, os, lastSeen, tags, truRiskScore, openVulns, eolStatus).
    With list_tags=True: adds tags (sorted list of distinct tag names).
    With list_groups=True: adds assetGroups (sorted list of distinct group names).

    Performance: ~3s (parallel CSAM search + count)."""
    # Handle list_tags and list_groups metadata queries
    if list_tags or list_groups:
        fields = "tags,tagList"
        if list_groups:
            fields += ",assetGroups"
        assets_raw = csam_search(limit=limit or 500, fields=fields, fetch_all=False)
        result = {}
        if list_tags:
            tag_set = set()
            for a in assets_raw:
                for t in a.get('tags', []) or a.get('tagList', []) or []:
                    name = t.get('name', '') if isinstance(t, dict) else str(t)
                    if name:
                        tag_set.add(name)
            tags_sorted = sorted(tag_set)
            result['totalTags'] = len(tags_sorted)
            result['tags'] = tags_sorted
        if list_groups:
            group_set = set()
            for a in assets_raw:
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
            'lastSeen': short_date(a.get('lastSeen', '')),
            'tags': asset_tags,
            'truRiskScore': a.get('riskScore', 0) or a.get('truRiskScore', 0) or 0,
            'openVulns': open_vulns,
            'eolStatus': lifecycle if lifecycle else 'Active',
        })

    result_assets.sort(key=lambda x: -x['truRiskScore'])
    return compact({
        'summary': summary, 'assets': result_assets,
        '_meta': {'returned': len(result_assets), 'total': total_count, 'truncated': len(result_assets) < total_count},
    })


@mcp.tool()
def get_vuln_exceptions(status: str = "Active", vuln_type: str = "", days_to_expiry: int = 30, limit: int = 50) -> dict:
    """[VM] Vulnerability exceptions — approved risk acceptances, false positives, and compensating controls with expiry tracking.

    USE WHEN: Reviewing active risk acceptances/waivers, "which exceptions are expiring?", finding exceptions that need renewal, or auditing false positive classifications.
    DO NOT USE WHEN: Checking remediation/patching status, querying vulnerability findings, or reviewing compliance controls.
    PREFER INSTEAD: get_patch_status or get_eliminate_status for patching status; get_etm_findings for vulnerability findings; get_compliance_posture for compliance controls.

    Parameters:
        status: exception status filter — 'Active' (default), 'Expired', 'Pending'
        vuln_type: filter by exception type (e.g. 'False Positive', 'Compensating Control')
        days_to_expiry: only show exceptions expiring within N days (default 30). 0 = all.
        limit: max exceptions to return (default 50)

    Returns: stats (total, active, expiringSoon, expired, byType), exceptions (list with id, qid, title, type, status, reason, approvedBy, expiryDate, daysUntilExpiry).

    Performance: ~3s."""
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
    return _with_meta(result, 'exceptions', result['stats']['total'])


@mcp.tool()
def get_compliance_posture(framework: str = "", platform: str = "", limit: int = 20) -> dict:
    """[PC] Qualys Policy Compliance posture — pass/fail rates, top failing controls, and per-framework breakdown (CIS, PCI-DSS, HIPAA, NIST, SOC2, ISO27001).

    USE WHEN: "are we passing CIS benchmarks?", compliance posture audit, audit readiness, or framework-specific control status. Covers on-prem and host-level compliance.
    DO NOT USE WHEN: Checking cloud-specific CIS compliance, querying vulnerability findings, or checking certificate compliance.
    PREFER INSTEAD: get_cloud_risk for cloud CIS compliance (TotalCloud); get_etm_findings for vulnerability findings; get_expiring_certs for certificate compliance.

    Parameters:
        framework: filter by framework name substring (e.g. 'CIS', 'PCI', 'HIPAA', 'NIST'). Empty = all.
        platform: filter by platform (e.g. 'Linux', 'Windows'). Empty = all.
        limit: max failing controls to return (default 20)

    Returns: summary (totalControls, passing, failing, passRate, affectedAssets, frameworks), topFailingControls (list with controlId, title, framework, failingAssets, severity), byFramework (pass rate per framework).

    Performance: ~5s cold. Falls back to cloud compliance if PC module not licensed."""

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
        result['summary']['controls'] = total
        result['summary']['passing'] = passed
        result['summary']['failing'] = failed
        result['summary']['pass_pct'] = round(passed / total * 100, 1)
        result['summary']['assets'] = max(affected_hosts) if affected_hosts else 0
        result['summary']['frameworks'] = sorted(frameworks_seen)
        result['topFailingControls'] = failing[:limit]

        for fw_name, counts in by_fw.items():
            fw_total = counts['pass'] + counts['fail']
            result['byFramework'][fw_name] = {
                'pass_pct': round(counts['pass'] / fw_total * 100, 1) if fw_total else 0,
                'failing': counts['fail'],
            }

        return compact(result)

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
        if gaps and (gaps.get('failingControls', 0) > 0 or gaps.get('pass_pct', 0) > 0):
            total_failing = gaps.get('failingControls', 0)
            pass_rate = gaps.get('pass_pct', 0)
            # Estimate total from pass rate
            total = int(total_failing / (1 - pass_rate / 100)) if pass_rate < 100 and total_failing else total_failing
            passing = total - total_failing

            result = _empty_result()
            result['summary']['controls'] = total
            result['summary']['passing'] = passing
            result['summary']['failing'] = total_failing
            result['summary']['pass_pct'] = pass_rate
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
            return _with_meta(result, 'topFailingControls')
    except Exception as e:
        _log(f"Compliance posture: cloud fallback failed: {e}")

    # --- No data available ---
    result = _empty_result()
    result['error'] = 'PC module not licensed or no compliance data available'
    result['suggestion'] = 'Enable the Qualys Policy Compliance (PC) module, or use get_cloud_risk() for cloud CIS compliance.'
    return _with_meta(result, 'topFailingControls')


@mcp.tool()
def get_trurisk_score(days: int = 30, breakdown_by: str = "tag") -> dict:
    """[Risk Management] Org-level TruRisk score with trending and breakdown — aggregate risk, trend direction, top assets, top QIDs, and tag breakdown.

    USE WHEN: "what's our org risk?", "is risk going up or down?", overall TruRisk score, risk trends, or risk breakdown by business unit/tag.
    DO NOT USE WHEN: Drilling into a single asset, planning weekly remediation, or investigating a specific vulnerability.
    PREFER INSTEAD: get_asset for single-asset risk; get_weekly_priorities for weekly remediation planning; investigate_cve for vulnerability investigation.

    Parameters:
        days: trend window in days (default 30). Compares current avg TruRisk vs N days ago.
        breakdown_by: 'tag' groups assets by their tags showing TruRisk per tag, 'none' skips breakdown.

    Returns: aggregate (totalAssets, risk tier counts), trend (avgTruRiskCurrent, avgTruRiskPrior, delta, direction=improving|stable|worsening), topAssets (top 10 by TruRisk with tags), topQIDs (top 10 by risk contribution), breakdown (per-tag avg/max TruRisk).

    Performance: ~5s cold / ~3s warm (parallel CSAM queries)."""
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
            'hostname': short_host(asset.get('dnsHostName', '') or asset.get('dnsName', '')),
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

    return _with_meta(result, 'topAssets')


@mcp.tool()
def get_tags(limit: int = 500) -> dict:
    """DEPRECATED: Use get_asset_inventory(list_tags=True) instead."""
    return {'error': "get_tags has been removed. Use get_asset_inventory(list_tags=True) instead.", 'replacement': 'get_asset_inventory'}

@mcp.tool()
def get_asset_groups(limit: int = 500) -> dict:
    """DEPRECATED: Use get_asset_inventory(list_groups=True) instead."""
    return {'error': "get_asset_groups has been removed. Use get_asset_inventory(list_groups=True) instead.", 'replacement': 'get_asset_inventory'}

@mcp.tool()
def get_assets_by_tag(tag_name: str, limit: int = 50) -> dict:
    """DEPRECATED: Use get_asset_inventory(tag='...') instead."""
    return {'error': f"get_assets_by_tag has been removed. Use get_asset_inventory(tag='{tag_name}') instead.", 'replacement': 'get_asset_inventory'}


# ---------------------------------------------------------------------------
# Report Center — consolidated reports() tool
# ---------------------------------------------------------------------------

@mcp.tool()
def reports(action: str, report_id: str = "", template_id: str = "", asset_group_ids: str = "",
            template_name: str = "", report_title: str = "", output_format: str = "pdf") -> dict:
    """[Reporting] Unified report operations — list, templates, generate, status, download, delete.

    USE WHEN: Any report-related task — listing reports, finding templates, generating, checking status, downloading, or deleting reports.
    DO NOT USE WHEN: You need real-time security data — use analysis tools instead. Reports are pre-generated snapshots.

    Parameters:
        action: 'list' | 'templates' | 'generate' | 'status' | 'download' | 'delete'
        report_id: required for 'status', 'download', 'delete'
        template_id: required for 'generate' (from action='templates')
        asset_group_ids: optional comma-separated asset group IDs for 'generate'
        template_name: optional filter substring for 'templates'
        report_title: optional title for 'generate'
        output_format: pdf, html, mht, xml, csv, or docx (default 'pdf') for 'generate'

    Returns vary by action:
        list: total, reports (id, title, type, status, percentComplete, launchDatetime, outputFormat, size)
        templates: total, templates (id, title, type, isGlobal)
        generate: reportId, message
        status: id, title, status, percentComplete, outputFormat, size, launchDatetime
        download: reportId, contentType, encoding, data
        delete: reportId, message

    Performance: ~2-5s depending on action."""
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
            return compact({'error': 'Failed to fetch report templates', 'templates': [], '_meta': {'returned': 0, 'total': 0, 'truncated': False}})
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


# Deprecation stubs for old report tools
@mcp.tool()
def list_reports(limit: int = 50) -> dict:
    """DEPRECATED: Use reports(action='list') instead."""
    return {'error': "list_reports has been removed. Use reports(action='list') instead.", 'replacement': 'reports'}

@mcp.tool()
def list_report_templates(limit: int = 100) -> dict:
    """DEPRECATED: Use reports(action='templates') instead."""
    return {'error': "list_report_templates has been removed. Use reports(action='templates') instead.", 'replacement': 'reports'}

@mcp.tool()
def generate_report(template_id: str, report_title: str = "", output_format: str = "pdf",
                    asset_group_ids: str = "", ips: str = "", tags: str = "") -> dict:
    """DEPRECATED: Use reports(action='generate', template_id='...') instead."""
    return {'error': "generate_report has been removed. Use reports(action='generate', template_id='...') instead.", 'replacement': 'reports'}

@mcp.tool()
def get_report_status(report_id: str) -> dict:
    """DEPRECATED: Use reports(action='status', report_id='...') instead."""
    return {'error': "get_report_status has been removed. Use reports(action='status', report_id='...') instead.", 'replacement': 'reports'}

@mcp.tool()
def download_report(report_id: str) -> dict:
    """DEPRECATED: Use reports(action='download', report_id='...') instead."""
    return {'error': "download_report has been removed. Use reports(action='download', report_id='...') instead.", 'replacement': 'reports'}

@mcp.tool()
def delete_report(report_id: str) -> dict:
    """DEPRECATED: Use reports(action='delete', report_id='...') instead."""
    return {'error': "delete_report has been removed. Use reports(action='delete', report_id='...') instead.", 'replacement': 'reports'}


def _warmup_vmdr_cache():
    """Background thread: pre-fetch VMDR detections for severity 3-5 to warm cache."""
    import time
    time.sleep(2)  # brief delay to let server finish startup
    for sev in (5, 4, 3):
        try:
            _log(f"Cache warm-up: fetching severity {sev} detections...")
            get_detections(severity=sev)
            _log(f"Cache warm-up: severity {sev} done")
        except Exception as e:
            _log(f"Cache warm-up: severity {sev} failed: {e}")
    _log("Cache warm-up: complete")


def main():
    # Spawn background daemon thread to warm VMDR detection cache
    warmup = Thread(target=_warmup_vmdr_cache, daemon=True, name="vmdr-cache-warmup")
    warmup.start()
    mcp.run()


if __name__ == "__main__":
    main()
