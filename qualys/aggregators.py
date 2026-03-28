"""Data aggregation layer — enrichment with configurable detail levels.

detail="summary"   → counts, scores, top-N only
detail="standard"  → key fields (default, matches current behavior exactly)
detail="detailed"  → full profiles with all metadata
"""

from qualys.api import (
    get_detections, get_host_detections, get_kb, get_kb_batch, get_cve_qids,
    csam_search, csam_count, get_asset_by_id, get_assets, get_asset_count,
    get_images, get_containers, get_connectors, get_evaluations, get_cdr,
    get_image_details, get_image_vulns_api, get_certificates,
    _fetch_ioc_events, _fetch_fim_events_raw, _fetch_edr_events_raw,
    get_was_findings, get_pm_jobs, get_pm_patches_count, get_pm_assets,
    get_pm_job_summary, get_mtg_jobs, get_mtg_job_detail, etm_api,
    etm_download, get_scanner_list, get_scan_list, fetch_all_eol,
    compact, _with_meta, short_date, safe_int, short_host, is_eol_stage,
    get_criticality, normalize_url, resolve_platform, _run_concurrent,
    get_qds_for_qids, _scope_filters, get_bearer_token, api_get,
    _warmup_vmdr_cache, _CSAM_SEM, CSAM_RATE_LIMITED_MSG, KB_BUSY_MSG,
    CDR_UNAVAILABLE_MSG, ETM_401_MSG, ETM_401_SENTINEL, _is_etm_401,
    RETRY_STATUS, MAX_RETRIES, parse_vuln_xml, _parse_detections_xml,
)

# ---------------------------------------------------------------------------
# Detail-level constants
# ---------------------------------------------------------------------------

DETAIL_LEVELS = ("summary", "standard", "detailed")


def _validate_detail(detail: str) -> str:
    """Normalise and validate a detail-level string."""
    if detail not in DETAIL_LEVELS:
        return "standard"
    return detail


# ---------------------------------------------------------------------------
# Asset aggregators
# ---------------------------------------------------------------------------

_ASSET_SUMMARY_KEYS = (
    "id", "name", "hostname", "address", "operatingSystem",
    "truRisk", "riskScore", "lastSeen",
)


def aggregate_asset(asset: dict, detail: str = "standard") -> dict:
    """Filter an asset dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: asset[k] for k in _ASSET_SUMMARY_KEYS if k in asset}
    # standard and detailed return the asset as-is (current behaviour)
    return asset


def aggregate_assets_list(assets: list, detail: str = "standard") -> list:
    """Apply detail-level filtering to a list of assets."""
    return [aggregate_asset(a, detail) for a in assets]


# ---------------------------------------------------------------------------
# Vulnerability aggregators
# ---------------------------------------------------------------------------

_VULN_SUMMARY_KEYS = (
    "qid", "severity", "cvss", "qds", "status",
    "hostName", "firstFound", "lastFound",
)


def aggregate_vuln(vuln: dict, detail: str = "standard") -> dict:
    """Filter a vulnerability dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: vuln[k] for k in _VULN_SUMMARY_KEYS if k in vuln}
    return vuln


def aggregate_vulns_list(vulns: list, detail: str = "standard") -> list:
    """Apply detail-level filtering to a list of vulns."""
    return [aggregate_vuln(v, detail) for v in vulns]


# ---------------------------------------------------------------------------
# Patch-management aggregators
# ---------------------------------------------------------------------------

_PM_JOB_SUMMARY_KEYS = (
    "id", "name", "status", "platform", "patchCount", "assetCount",
)


def aggregate_pm_job(job: dict, detail: str = "standard") -> dict:
    """Filter a patch-management job dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: job[k] for k in _PM_JOB_SUMMARY_KEYS if k in job}
    return job


def aggregate_pm_jobs_list(jobs: list, detail: str = "standard") -> list:
    """Apply detail-level filtering to a list of PM jobs."""
    return [aggregate_pm_job(j, detail) for j in jobs]


# ---------------------------------------------------------------------------
# Cloud / CDR aggregators
# ---------------------------------------------------------------------------

_CLOUD_SUMMARY_KEYS = (
    "accountId", "cloudProvider", "severity", "controlId", "status",
)


def aggregate_cloud_finding(finding: dict, detail: str = "standard") -> dict:
    """Filter a cloud/CDR finding dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: finding[k] for k in _CLOUD_SUMMARY_KEYS if k in finding}
    return finding


def aggregate_cloud_findings_list(
    findings: list, detail: str = "standard",
) -> list:
    """Apply detail-level filtering to a list of cloud findings."""
    return [aggregate_cloud_finding(f, detail) for f in findings]


# ---------------------------------------------------------------------------
# EDR / FIM event aggregators
# ---------------------------------------------------------------------------

_EDR_SUMMARY_KEYS = (
    "id", "severity", "category", "hostName", "timestamp",
)


def aggregate_edr_event(event: dict, detail: str = "standard") -> dict:
    """Filter an EDR event dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: event[k] for k in _EDR_SUMMARY_KEYS if k in event}
    return event


def aggregate_edr_events_list(events: list, detail: str = "standard") -> list:
    """Apply detail-level filtering to a list of EDR events."""
    return [aggregate_edr_event(e, detail) for e in events]


# ---------------------------------------------------------------------------
# WAS (Web App Scanning) aggregators
# ---------------------------------------------------------------------------

_WAS_SUMMARY_KEYS = (
    "qid", "severity", "title", "url", "status", "webApp",
)


def aggregate_was_finding(finding: dict, detail: str = "standard") -> dict:
    """Filter a WAS finding dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: finding[k] for k in _WAS_SUMMARY_KEYS if k in finding}
    return finding


def aggregate_was_findings_list(
    findings: list, detail: str = "standard",
) -> list:
    """Apply detail-level filtering to a list of WAS findings."""
    return [aggregate_was_finding(f, detail) for f in findings]


# ---------------------------------------------------------------------------
# Certificate aggregators
# ---------------------------------------------------------------------------

_CERT_SUMMARY_KEYS = (
    "id", "commonName", "issuer", "validTo", "daysRemaining", "grade",
)


def aggregate_cert(cert: dict, detail: str = "standard") -> dict:
    """Filter a certificate dict based on detail level."""
    detail = _validate_detail(detail)
    if detail == "summary":
        return {k: cert[k] for k in _CERT_SUMMARY_KEYS if k in cert}
    return cert


def aggregate_certs_list(certs: list, detail: str = "standard") -> list:
    """Apply detail-level filtering to a list of certificates."""
    return [aggregate_cert(c, detail) for c in certs]


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    # detail-level helpers
    "DETAIL_LEVELS", "_validate_detail",
    # asset
    "aggregate_asset", "aggregate_assets_list",
    # vuln
    "aggregate_vuln", "aggregate_vulns_list",
    # patch management
    "aggregate_pm_job", "aggregate_pm_jobs_list",
    # cloud / CDR
    "aggregate_cloud_finding", "aggregate_cloud_findings_list",
    # EDR / FIM
    "aggregate_edr_event", "aggregate_edr_events_list",
    # WAS
    "aggregate_was_finding", "aggregate_was_findings_list",
    # certificates
    "aggregate_cert", "aggregate_certs_list",
    # re-exported from qualys.api for convenience
    "get_detections", "get_host_detections", "get_kb", "get_kb_batch",
    "get_cve_qids", "csam_search", "csam_count", "get_asset_by_id",
    "get_assets", "get_asset_count", "get_images", "get_containers",
    "get_connectors", "get_evaluations", "get_cdr", "get_image_details",
    "get_image_vulns_api", "get_certificates", "_fetch_ioc_events",
    "_fetch_fim_events_raw", "_fetch_edr_events_raw", "get_was_findings",
    "get_pm_jobs", "get_pm_patches_count", "get_pm_assets",
    "get_pm_job_summary", "get_mtg_jobs", "get_mtg_job_detail",
    "etm_api", "etm_download", "get_scanner_list", "get_scan_list",
    "fetch_all_eol", "compact", "_with_meta", "short_date", "safe_int",
    "short_host", "is_eol_stage", "get_criticality", "normalize_url",
    "resolve_platform", "_run_concurrent", "get_qds_for_qids",
    "_scope_filters", "get_bearer_token", "api_get", "_warmup_vmdr_cache",
    "_CSAM_SEM", "CSAM_RATE_LIMITED_MSG", "KB_BUSY_MSG",
    "CDR_UNAVAILABLE_MSG", "ETM_401_MSG", "ETM_401_SENTINEL",
    "_is_etm_401", "RETRY_STATUS", "MAX_RETRIES", "parse_vuln_xml",
    "_parse_detections_xml",
]
