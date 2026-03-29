"""Qualys API client — auth, HTTP helpers, pagination, caching, rate limiting.

All pure data-fetching functions live here. No business logic or aggregation.
"""

import os
import sys
import json
import ssl
import time
import random
import base64
import threading
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Thread, Event, Semaphore
from qualys.cache import (
    disk_cache,
    TTL_VMDR as DISK_TTL_VMDR,
    TTL_WAS as DISK_TTL_WAS,
    TTL_SCANNERS as DISK_TTL_SCANNERS,
    TTL_ETM as DISK_TTL_ETM,
    TTL_CSAM as DISK_TTL_CSAM,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RETRY_STATUS = {429, 503, 502}
KB_CONFLICT_RETRY_STATUS = {409}
MAX_RETRIES = 4
KB_CONFLICT_MAX_RETRIES = 3
KB_CONFLICT_BASE_DELAY = 3  # seconds
KB_BUSY_MSG = "Knowledge base export is currently busy (concurrent request in progress). Please try again in a moment."
CDR_UNAVAILABLE_MSG = "CDR findings currently unavailable"
CSAM_MAX_RETRIES = int(os.environ.get("CSAM_MAX_RETRIES", "3"))
CSAM_RATE_LIMITED_MSG = "Asset search temporarily unavailable due to rate limiting. Please try again in a moment."
# Cap concurrent CSAM requests to avoid 429 floods at high worker concurrency
_CSAM_SEM = Semaphore(int(os.environ.get("CSAM_MAX_CONCURRENT", "2")))
_CSAM_COUNT_CACHE = {}
_CSAM_COUNT_CACHE_TTL = 300
_CSAM_SEARCH_CACHE = {}
_CSAM_SEARCH_CACHE_TTL = 300

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


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


def safe_int(val, default=0):
    """Parse int from string, returning default for empty/invalid values."""
    if not val or not val.strip():
        return default
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return default


def short_host(hostname):
    """Truncate FQDN to first label."""
    if hostname and "." in hostname:
        return hostname.split(".")[0]
    return hostname


def is_eol_stage(stage):
    """Check if stage indicates EOL/EOS status"""
    if not stage:
        return False
    s = stage.upper()
    return ('EOL' in s or 'EOS' in s) and s != 'NOT APPLICABLE'


def get_criticality(asset):
    """Extract criticality score from asset"""
    crit = asset.get('criticality')
    if isinstance(crit, dict):
        return crit.get('score', 0) or 0
    return crit or 0


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


# ---------------------------------------------------------------------------
# Auth & URL resolution
# ---------------------------------------------------------------------------

USERNAME = os.environ.get('QUALYS_USERNAME', '')
PASSWORD = os.environ.get('QUALYS_PASSWORD', '')


def normalize_url(url):
    url = url.strip().rstrip('/')
    if url and not url.startswith('http'):
        url = f"https://{url}"
    return url


# POD-based URL resolution
POD_MAP = {
    'US1': ('qualysapi.qualys.com',       'gateway.qg1.apps.qualys.com'),
    'US2': ('qualysapi.qg2.apps.qualys.com', 'gateway.qg2.apps.qualys.com'),
    'US3': ('qualysapi.qg3.apps.qualys.com', 'gateway.qg3.apps.qualys.com'),
    'US4': ('qualysapi.qg4.apps.qualys.com', 'gateway.qg4.apps.qualys.com'),
    'EU1': ('qualysapi.qualys.eu',         'gateway.qg1.apps.qualys.eu'),
    'EU2': ('qualysapi.qg2.apps.qualys.eu', 'gateway.qg2.apps.qualys.eu'),
    'EU3': ('qualysapi.qg3.apps.qualys.eu', 'gateway.qg3.apps.qualys.eu'),
    'IN1': ('qualysapi.qg1.apps.qualys.in', 'gateway.qg1.apps.qualys.in'),
    'CA1': ('qualysapi.qg1.apps.qualys.ca', 'gateway.qg1.apps.qualys.ca'),
    'AE1': ('qualysapi.qg1.apps.qualys.ae', 'gateway.qg1.apps.qualys.ae'),
    'UK1': ('qualysapi.qg1.apps.qualys.co.uk', 'gateway.qg1.apps.qualys.co.uk'),
    'AU1': ('qualysapi.qg1.apps.qualys.com.au', 'gateway.qg1.apps.qualys.com.au'),
    'KSA1': ('qualysapi.qg1.apps.qualys.sa', 'gateway.qg1.apps.qualys.sa'),
}


def resolve_platform(pod):
    """Return (base_url, gateway_url) for a given POD identifier."""
    key = pod.strip().upper()
    if key not in POD_MAP:
        valid = ', '.join(sorted(POD_MAP))
        raise ValueError(f"Unknown QUALYS_POD '{pod}'. Valid pods: {valid}")
    base, gw = POD_MAP[key]
    return f"https://{base}", f"https://{gw}"


# URL resolution priority:
#   1. Explicit QUALYS_BASE_URL / QUALYS_GATEWAY_URL env vars
#   2. QUALYS_POD env var  (e.g. US1, EU2, IN1)
#   3. Error with guidance
_explicit_base = os.environ.get('QUALYS_BASE_URL', '').strip()
_explicit_gw   = os.environ.get('QUALYS_GATEWAY_URL', '').strip()
_pod_env       = os.environ.get('QUALYS_POD', '').strip()

if _explicit_base or _explicit_gw:
    BASE_URL    = normalize_url(_explicit_base)
    GATEWAY_URL = normalize_url(_explicit_gw)
    _resolved_pod = None
elif _pod_env:
    BASE_URL, GATEWAY_URL = resolve_platform(_pod_env)
    _resolved_pod = _pod_env.upper()
else:
    # Defer error to main() so the module can be imported for tests/tooling
    BASE_URL    = ''
    GATEWAY_URL = ''
    _resolved_pod = None

BASIC_AUTH = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
BEARER_TOKEN = None
BEARER_TOKEN_TIME = None

# ---------------------------------------------------------------------------
# Cache stores
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Cache infrastructure
# ---------------------------------------------------------------------------


def _get_or_fetch(cache_dict, cache_time_dict, key, fetch_fn, ttl, disk_ttl=None):
    """Thread-safe cache get-or-fetch with in-flight request deduplication.
    If a fetch is already in progress for *key*, subsequent callers wait on a
    threading.Event instead of issuing a duplicate API call.

    When *disk_ttl* is set, the SQLite L2 cache is checked on L1 miss and
    written after a successful fetch."""
    now = datetime.now(timezone.utc)
    cached_time = cache_time_dict.get(key)
    if key in cache_dict and cached_time and (now - cached_time).total_seconds() < ttl:
        return cache_dict[key]

    # L2 disk cache check (before acquiring inflight lock)
    if disk_ttl is not None:
        disk_hit = disk_cache.get(key)
        if disk_hit is not None:
            cache_dict[key] = disk_hit
            cache_time_dict[key] = datetime.now(timezone.utc)
            _log(f"Disk cache hit for {key}")
            return disk_hit

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
        if disk_ttl is not None:
            disk_cache.set(key, result, disk_ttl)
        return result
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        evt.set()  # wake up any waiters


def clear_memory_cache(key=None):
    """Clear in-memory L1 caches. If *key* is given, clear only that key."""
    global SCANNER_CACHE, SCANNER_CACHE_TIME, ETM_RESULT_CACHE, ETM_RESULT_CACHE_TIME
    if key:
        DETECTION_CACHE.pop(key, None)
        DETECTION_CACHE_TIME.pop(key, None)
        KB_CACHE.pop(key, None)
        KB_CACHE_TIME.pop(key, None)
        WAS_CACHE.pop(key, None)
        WAS_CACHE_TIME.pop(key, None)
    else:
        DETECTION_CACHE.clear()
        DETECTION_CACHE_TIME.clear()
        KB_CACHE.clear()
        KB_CACHE_TIME.clear()
        WAS_CACHE.clear()
        WAS_CACHE_TIME.clear()
        QDS_CACHE.clear()
        SCANNER_CACHE = None
        SCANNER_CACHE_TIME = None
        ETM_RESULT_CACHE = None
        ETM_RESULT_CACHE_TIME = None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def api_get(url, gateway=False, timeout=30, not_found_ok=False, server_error_sentinel=None):
    for attempt in range(MAX_RETRIES):
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
            if e.code in RETRY_STATUS and attempt < MAX_RETRIES - 1:
                retry_after = e.headers.get('Retry-After') if e.headers else None
                if retry_after:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = 2 ** attempt + random.uniform(0, 1)
                else:
                    delay = 2 ** attempt + random.uniform(0, 1)
                _log(f"Retry {attempt + 1}/{MAX_RETRIES} after {e.code} for {url.split('?')[0]} (wait {delay:.1f}s)")
                time.sleep(delay)
                continue
            if e.code in KB_CONFLICT_RETRY_STATUS and attempt < KB_CONFLICT_MAX_RETRIES - 1:
                delay = KB_CONFLICT_BASE_DELAY + random.uniform(0, 2)
                _log(f"KB conflict retry {attempt + 1}/{KB_CONFLICT_MAX_RETRIES} for {url.split('?')[0]} (wait {delay:.1f}s)")
                time.sleep(delay)
                continue
            if e.code == 404 and not_found_ok:
                return None  # 404 means resource not configured — treat as empty, not an error
            if e.code in KB_CONFLICT_RETRY_STATUS:
                _log(f"KB busy (409 conflict) after {KB_CONFLICT_MAX_RETRIES} retries: {url.split('?')[0]}")
                return 'KB_BUSY'
            if e.code == 500 and server_error_sentinel:
                _log(f"[WARN] Server error 500 for {url.split('?')[0]} — returning sentinel")
                return server_error_sentinel
            _log(f"API error {e.code}: {url.split('?')[0]}")
            return None
        except URLError as e:
            _log(f"Connection error: {e.reason}")
            return None
        except Exception as e:
            _log(f"Request failed: {e}")
            return None
    _log(f"Max retries exceeded for {url.split('?')[0]}")
    return None


def _csam_request(url, body, timeout=30):
    """POST to a CSAM endpoint with retry logic for 429/503/502."""
    token = get_bearer_token()
    for attempt in range(CSAM_MAX_RETRIES):
        req = Request(url, data=body.encode(), method='POST')
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('X-Requested-With', 'qualys-mcp')
        try:
            with _open(req, timeout=timeout) as resp:
                raw = resp.read()
                if not raw or not raw.strip():
                    _log("[DEBUG] csam_search: empty response body — returning empty result")
                    return {}
                return json.loads(raw)
        except HTTPError as e:
            if e.code in RETRY_STATUS and attempt < CSAM_MAX_RETRIES - 1:
                retry_after = e.headers.get('Retry-After') if e.headers else None
                if retry_after:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = 2 ** attempt + random.uniform(0, 1)
                else:
                    delay = 2 ** attempt + random.uniform(0, 1)
                _log(f"CSAM retry {attempt + 1}/{CSAM_MAX_RETRIES} after {e.code} (wait {delay:.1f}s)")
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS:
                _log(f"CSAM rate-limited after {CSAM_MAX_RETRIES} retries — returning degraded response")
                return {"_degraded": True, "_message": CSAM_RATE_LIMITED_MSG}
            _log(f"csam_search error: HTTP Error {e.code}: {e.reason}")
            return None
        except Exception as e:
            _log(f"csam_search error: {e}")
            return None
    _log(f"CSAM rate-limited after {CSAM_MAX_RETRIES} retries — returning degraded response")
    return {"_degraded": True, "_message": CSAM_RATE_LIMITED_MSG}


ETM_401_MSG = 'TruRisk Eliminate is not available on your current Qualys subscription or requires additional configuration. Please contact your Qualys administrator.'
ETM_401_SENTINEL = {'_etm_401': True, 'error': ETM_401_MSG}


def _is_etm_401(val):
    """Check if a value is the ETM 401 sentinel."""
    return isinstance(val, dict) and val.get('_etm_401')


def etm_api(method, path, body=None, timeout=60):
    """Call ETM API. Returns parsed JSON, ETM_401_SENTINEL on 401, None on 404 or other errors."""
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
    except HTTPError as e:
        if e.code == 401:
            _log(f"ETM API 401 Unauthorized: {path}")
            return ETM_401_SENTINEL
        if e.code == 404:
            _log(f"ETM API 404 Not Found: {path}")
            return None
        _log(f"ETM API error: {e}")
        return None
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
    except HTTPError as e:
        if e.code == 401:
            _log(f"ETM download 401 Unauthorized: report {report_id}")
            return ETM_401_SENTINEL
        _log(f"ETM download error: {e}")
        return []
    except Exception as e:
        _log(f"ETM download error: {e}")
        return []


# ---------------------------------------------------------------------------
# VMDR detection API
# ---------------------------------------------------------------------------


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
                    'qid': safe_int(d.findtext('QID', '0')),
                    'severity': safe_int(d.findtext('SEVERITY', '0')),
                    'status': d.findtext('STATUS', ''),
                    'qds': qds,
                    'first_found': d.findtext('FIRST_FOUND_DATETIME', ''),
                })
    except ET.ParseError as e:
        _log(f"XML parse error in detections: {e}")
    return dets, is_truncated, max_host_id


def get_detections(severity=5, limit=0, use_cache=True, days=30, qds_min=0, fetch_all=True):
    """Get VMDR detections with hostname and QDS. Uses VMDR_CACHE_TTL (default 30min).
    Thread-safe via _get_or_fetch — concurrent calls for the same params are deduplicated."""
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
        disk_cache.set(cache_key, result, DISK_TTL_VMDR)
        return result[:limit] if limit > 0 else result

    dets = _get_or_fetch(DETECTION_CACHE, DETECTION_CACHE_TIME, cache_key, _fetch, VMDR_CACHE_TTL, disk_ttl=DISK_TTL_VMDR)
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
                    'qid': safe_int(d.findtext('QID', '0')),
                    'severity': safe_int(d.findtext('SEVERITY', '0')),
                    'status': d.findtext('STATUS', ''),
                    'qds': qds,
                    'first_found': d.findtext('FIRST_FOUND_DATETIME', ''),
                })
    except ET.ParseError:
        pass
    return dets


def get_qds_for_qids(qids):
    """Fetch real QDS scores from the detection API for a list of QIDs.
    Returns {qid: max_qds} across all hosts/detections."""
    global QDS_CACHE, QDS_CACHE_TIME
    if not qids:
        return {}

    now = datetime.now(timezone.utc)
    if QDS_CACHE_TIME and (now - QDS_CACHE_TIME).total_seconds() > VMDR_CACHE_TTL:
        QDS_CACHE = {}
        QDS_CACHE_TIME = None

    uncached = [q for q in qids if q not in QDS_CACHE]
    if not uncached:
        return {q: QDS_CACHE.get(q, 0) for q in qids}

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
            batch_qds = {}
            for host in root.findall('.//HOST'):
                for d in host.findall('.//DETECTION'):
                    qid = safe_int(d.findtext('QID', '0'))
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
            for q in batch:
                if q not in QDS_CACHE:
                    QDS_CACHE[q] = 0
            QDS_CACHE_TIME = now
        except Exception as e:
            _log(f"QDS fetch failed for batch: {e}")

    return {q: QDS_CACHE.get(q, 0) for q in qids}


# ---------------------------------------------------------------------------
# Knowledge Base
# ---------------------------------------------------------------------------


def parse_vuln_xml(v):
    """Parse a VULN XML element into a dict"""
    qid = safe_int(v.findtext('QID', '0'))
    qds_el = v.find('QDS')
    qds = 0
    if qds_el is not None and qds_el.text:
        try:
            qds = int(qds_el.text)
        except ValueError:
            pass
    qds_factors = v.findtext('QDS_FACTORS', '')
    threat_intel = []
    ti = v.find('THREAT_INTELLIGENCE')
    if ti is not None:
        for t in ti.findall('THREAT_INTEL'):
            text = (t.text or '').strip()
            if text:
                threat_intel.append(text)
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

    has_exploit = v.find('.//EXPLOIT_LIST/EXPLOIT') is not None

    return {
        'qid': qid,
        'title': v.findtext('TITLE', ''),
        'severity': safe_int(v.findtext('SEVERITY_LEVEL', '0')),
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
    if data == 'KB_BUSY':
        return {'error': KB_BUSY_MSG}
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
    uncached = [
        q for q in qids
        if q not in KB_CACHE or
        (KB_CACHE_TIME.get(q) and (now - KB_CACHE_TIME[q]).total_seconds() >= 3600)
    ]

    if uncached:
        for i in range(0, len(uncached), 50):
            batch = uncached[i:i+50]
            ids_str = ','.join(map(str, batch))
            data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={ids_str}&details=All", timeout=60)
            if data == 'KB_BUSY':
                return {q: {'error': KB_BUSY_MSG} if q in uncached else KB_CACHE.get(q) for q in qids}
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
    if data == 'KB_BUSY':
        return [{'error': KB_BUSY_MSG}]
    if not data:
        return []
    try:
        result = []
        for v in ET.fromstring(data).findall('.//VULN'):
            qid = v.findtext('QID')
            if qid:
                parsed = parse_vuln_xml(v)
                KB_CACHE[parsed['qid']] = parsed  # Cache while we have it
                result.append(safe_int(qid))
        return result
    except ET.ParseError:
        return []


# ---------------------------------------------------------------------------
# CSAM (CyberSecurity Asset Management)
# ---------------------------------------------------------------------------


def _scope_filters(base_filters, tag='', asset_group=''):
    """Append tag and/or asset_group CSAM filters to a base filter list."""
    filters = list(base_filters) if base_filters else []
    if tag:
        filters.append({"field": "asset.tags.name", "operator": "EQUALS", "value": tag})
    if asset_group:
        filters.append({"field": "asset.assetGroups.name", "operator": "EQUALS", "value": asset_group})
    return filters or None


def csam_count(filters=None):
    """Count assets with optional structured filters. Fast (~0.2s)."""
    with _CSAM_SEM:
        cache_key = json.dumps(filters, sort_keys=True) if filters else "__all__"
        cached = _CSAM_COUNT_CACHE.get(cache_key)
        if cached and (time.time() - cached[1]) < _CSAM_COUNT_CACHE_TTL:
            return cached[0]
        url = f"{GATEWAY_URL}/rest/2.0/count/am/asset"
        body = json.dumps({"filters": filters or []})
        data = _csam_request(url, body)
        if data is not None and not data.get("_degraded"):
            count = data.get('count', 0)
            _CSAM_COUNT_CACHE[cache_key] = (count, time.time())
            return count
        return 0


def csam_search(filters=None, limit=100, fields=None, fetch_all=True):
    """Search assets with optional structured filters. Returns list of assets."""
    with _CSAM_SEM:
        cache_key = json.dumps({"filters": filters, "limit": limit, "fields": fields, "fetch_all": fetch_all}, sort_keys=True)
        cached = _CSAM_SEARCH_CACHE.get(cache_key)
        if cached and (time.time() - cached[1]) < _CSAM_SEARCH_CACHE_TTL:
            _log("CSAM search: returning cached result")
            return cached[0]
        if fields:
            if 'tagList' not in fields:
                fields = f"{fields},tagList"
        else:
            fields = "tagList"
        page_size = min(limit, 100) if not fetch_all else 100
        body = json.dumps({"filters": filters or []})
        all_assets = []
        last_id = None
        max_page_cap = MAX_PAGES if MAX_PAGES > 0 else 0
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
            data = _csam_request(url, body)
            if data is None:
                break
            if data.get("_degraded"):
                _log(f"CSAM search: degraded — {data['_message']}")
                return all_assets if all_assets else []
            assets = data.get('assetListData', {}).get('asset', [])
            if not assets:
                break
            all_assets.extend(assets)
            pages += 1
            if not data.get('hasMore'):
                break
            last_id = assets[-1].get('assetId')
        if pages > 1:
            _log(f"CSAM search: fetched {len(all_assets)} assets across {pages} pages")
        result = all_assets[:limit] if not fetch_all else all_assets
        if result:
            _CSAM_SEARCH_CACHE[cache_key] = (result, time.time())
        return result


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


# ---------------------------------------------------------------------------
# Paginated JSON API helper
# ---------------------------------------------------------------------------


def _paginate_json(base_url, limit, data_key='data', count_key='count',
                    page_param='pageNumber', size_param='pageSize',
                    count_only=False, gateway=True, fetch_all=True, not_found_ok=False,
                    page_start=1, server_error_sentinel=None):
    """Generic paginated fetch for JSON APIs. Returns list or int (count_only)."""
    page_size = min(limit, 100)
    results = []
    page = page_start
    if fetch_all:
        cap = MAX_PAGES if MAX_PAGES > 0 else 0
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
        data = api_get(url, gateway=gateway, not_found_ok=not_found_ok,
                       server_error_sentinel=server_error_sentinel)
        if server_error_sentinel and data == server_error_sentinel:
            return data
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


# ---------------------------------------------------------------------------
# Specialized data-fetching functions
# ---------------------------------------------------------------------------


def get_images(limit=100, severity=None, count_only=False):
    """Fetch container images with pagination."""
    url = f"{GATEWAY_URL}/csapi/v1.3/images?sort=created:desc"
    if severity:
        url += f"&filter=vulnerabilities.severity:{severity}"
    return _paginate_json(url, limit, count_only=count_only)


def get_images_by_vulns(limit=50):
    """Fetch container images ranked by critical vulnerability count (descending)."""
    url = f"{GATEWAY_URL}/csapi/v1.3/images?sort=vulnerabilities.severity5:desc"
    return _paginate_json(url, limit, fetch_all=False)


def get_containers(limit=100, count_only=False, filter_str=None):
    """Fetch containers with pagination. Default filter: state:RUNNING."""
    filt = filter_str or "state:RUNNING"
    url = f"{GATEWAY_URL}/csapi/v1.3/containers?filter={filt}"
    return _paginate_json(url, limit, count_only=count_only)


def get_connectors(provider='aws', limit=50):
    url = f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/connectors"
    return _paginate_json(url, limit, data_key='content', count_key='totalElements',
                          page_param='pageNo', size_param='pageSize',
                          not_found_ok=True, page_start=0)


def get_evaluations(account_id, provider='aws', limit=500):
    url = f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}"
    return _paginate_json(url, limit, data_key='content', count_key='totalElements',
                          page_param='pageNo', size_param='pageSize', page_start=0,
                          not_found_ok=True)


def get_evaluation_count(account_id, provider='aws', filter_str=''):
    """Fetch pageSize=1 to get just totalElements (fast count). Returns {total, failed} or None."""
    url = f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}?pageSize=1&pageNo=0"
    if filter_str:
        url += f"&filter={filter_str}"
    data = api_get(url, gateway=True, timeout=15, not_found_ok=True)
    if not data:
        return None
    try:
        parsed = json.loads(data) if isinstance(data, (str, bytes)) else {}
        total = parsed.get('totalElements', 0)
        # Count failed from the single item if present
        content = parsed.get('content', [])
        return {'total': total, 'content': content}
    except (json.JSONDecodeError, TypeError):
        return None


def get_evaluations_filtered(account_id, provider='aws', limit=500, filter_str=''):
    """Fetch evaluations with optional filter string (e.g. 'service:S3')."""
    url = f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}"
    if filter_str:
        sep = '&' if '?' in url else '?'
        url += f"{sep}filter={filter_str}"
    return _paginate_json(url, limit, data_key='content', count_key='totalElements',
                          page_param='pageNo', size_param='pageSize', page_start=0,
                          not_found_ok=True)


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
    results = _paginate_json(url, limit, data_key='content', count_key='totalElements',
                              page_param='pageNumber', size_param='limit',
                              server_error_sentinel='CDR_UNAVAILABLE',
                              not_found_ok=True)
    return results


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
        url += f"?pageSize={min(limit, 100)}&filter={quote(f'validTo:<{future}')}"
    try:
        return _paginate_json(url, limit, not_found_ok=True)
    except Exception:
        return None


def _fetch_ioc_events(limit=200):
    """Fetch events from the unified /ioc/v1/events endpoint."""
    url = f"{GATEWAY_URL}/ioc/v1/events?pageSize={min(limit, 200)}"
    data = api_get(url, gateway=True, timeout=30)
    if not data:
        return []
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            return parsed[:limit]
        if isinstance(parsed, dict):
            return (parsed.get('data', []) or parsed.get('events', []) or parsed.get('items', []))[:limit]
        return []
    except (json.JSONDecodeError, TypeError):
        return []


def _fetch_fim_events_raw(limit=100, days=7, host=''):
    all_events = _fetch_ioc_events(limit * 3)
    fim_events = []
    for e in all_events:
        src = str(e.get('eventSource', '') or e.get('type', '') or '').upper()
        if src in ('FIM', 'FILE', 'FILE_CHANGE', 'FILE CHANGE'):
            fim_events.append(e)
    return fim_events[:limit]


def _fetch_edr_events_raw(limit=100, severity=None):
    all_events = _fetch_ioc_events(limit * 3)
    edr_events = []
    for e in all_events:
        src = str(e.get('eventSource', '') or e.get('type', '') or '').upper()
        if src not in ('FIM', 'FILE', 'FILE_CHANGE', 'FILE CHANGE'):
            edr_events.append(e)
    return edr_events[:limit]


def get_was_findings(limit=100, severity=None, days=None, app_name=None):
    """Get WAS findings with optional server-side filters. Uses 10-minute per-key cache."""
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
                        'qid': safe_int(f.findtext('qid', '0')),
                        'name': f.findtext('name', ''),
                        'severity': safe_int(f.findtext('severity', '0')),
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

    return _get_or_fetch(WAS_CACHE, WAS_CACHE_TIME, cache_key, _fetch, 600, disk_ttl=DISK_TTL_WAS)


# ---------------------------------------------------------------------------
# Patch Management & TruRisk Mitigate
# ---------------------------------------------------------------------------


def get_pm_jobs(platform='Windows', limit=10):
    """Get Patch Management deployment jobs"""
    data = api_get(f"{GATEWAY_URL}/pm/v1/deploymentjobs?platform={platform}&pageSize={limit}", gateway=True, not_found_ok=True)
    if data is None:
        return []
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return []


def get_pm_patches_count(platform='Windows', group_by=None):
    """Get patch counts, optionally grouped by vendorSeverity or appFamily"""
    url = f"{GATEWAY_URL}/pm/v1/patches/count?platform={platform}"
    if group_by:
        url += f"&groupBy={group_by}"
    data = api_get(url, gateway=True, not_found_ok=True)
    if data is None:
        return {}
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return {}


def get_pm_assets(platform='Windows', limit=10):
    """Get Patch Management enabled assets"""
    data = api_get(f"{GATEWAY_URL}/pm/v1/assets?platform={platform}&pageSize={limit}", gateway=True, not_found_ok=True)
    if data is None:
        return []
    try:
        return json.loads(data)
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
    data = api_get(f"{GATEWAY_URL}/mtg/v1/deploymentjobs?platform={platform}&pageSize={limit}", gateway=True, not_found_ok=True)
    if data is None:
        return []
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return []


def get_mtg_job_detail(job_id):
    """Get mitigation job details"""
    data = api_get(f"{GATEWAY_URL}/mtg/v1/deploymentjob/{job_id}", gateway=True)
    try:
        return json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return {}


# ---------------------------------------------------------------------------
# Scanner & Scan management
# ---------------------------------------------------------------------------


def get_scanner_list():
    """Get scanner appliance list with status and health metrics. Uses 5-minute L1 / 12-hour disk cache."""
    global SCANNER_CACHE, SCANNER_CACHE_TIME
    now = datetime.now(timezone.utc)

    if SCANNER_CACHE is not None and SCANNER_CACHE_TIME:
        age = (now - SCANNER_CACHE_TIME).total_seconds()
        if age < 300:
            return SCANNER_CACHE

    # L2 disk cache check
    _SCANNER_DISK_KEY = "scanner_list"
    disk_hit = disk_cache.get(_SCANNER_DISK_KEY)
    if disk_hit is not None:
        SCANNER_CACHE = disk_hit
        SCANNER_CACHE_TIME = now
        _log("Disk cache hit for scanner_list")
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
                'runningScanCount': safe_int(s.findtext('RUNNING_SCAN_COUNT', '0')),
                'runningSlices': safe_int(s.findtext('RUNNING_SLICES_COUNT', '0')),
                'maxCapacity': safe_int(s.findtext('MAX_CAPACITY_UNITS', '0')),
                'heartbeatsMissed': safe_int(s.findtext('HEARTBEATS_MISSED', '0')),
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
    disk_cache.set("scanner_list", scanners, DISK_TTL_SCANNERS)
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


# ---------------------------------------------------------------------------
# EOL asset fetching
# ---------------------------------------------------------------------------


def fetch_all_eol(eol_type, limit=0, max_pages=0, cutoff_date=None):
    """Fetch EOL assets with pagination. eol_type is 'os' or 'hardware'."""
    token = get_bearer_token()
    if eol_type == 'os':
        filters = [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]
    else:
        filters = [{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]
    if cutoff_date:
        filters.append({"field": "asset.lastUpdatedDate", "operator": "GREATER", "value": cutoff_date})

    results = []
    seen = set()
    last_id = None
    page_cap = max_pages if max_pages > 0 else (MAX_PAGES if MAX_PAGES > 0 else 0)
    pages = 0

    while True:
        if page_cap > 0 and pages >= page_cap:
            _log(f"fetch_all_eol({eol_type}): hit page cap ({page_cap})")
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


# ---------------------------------------------------------------------------
# Concurrency helper
# ---------------------------------------------------------------------------


def _run_concurrent(**tasks):
    """Run named tasks concurrently. Returns dict of {name: result}.
    Each task value is a callable (lambda or function).
    """
    if not tasks:
        return {}
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


# ---------------------------------------------------------------------------
# VMDR cache warm-up
# ---------------------------------------------------------------------------


def _warmup_vmdr_cache():
    """Background thread: pre-fetch VMDR detections for severity 3-5 to warm cache."""
    import time
    time.sleep(2)  # brief delay to let server finish startup
    for sev in (5, 4, 3):
        try:
            cache_key = f"detections_{sev}_30_0"
            disk_hit = disk_cache.get(cache_key)
            if disk_hit is not None:
                DETECTION_CACHE[cache_key] = disk_hit
                DETECTION_CACHE_TIME[cache_key] = datetime.now(timezone.utc)
                _log(f"Disk cache hit during warmup for {cache_key}")
                continue
            _log(f"Cache warm-up: fetching severity {sev} detections...")
            get_detections(severity=sev, use_cache=False)
            _log(f"Cache warm-up: severity {sev} done")
        except Exception as e:
            _log(f"Cache warm-up: severity {sev} failed: {e}")
    _log("Cache warm-up: complete")
