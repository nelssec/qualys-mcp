"""Shared workflow utilities used by all workflow modules.

Provides dispatch, result normalization, envelope construction, and detail
filtering helpers.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from qualys.api import _run_concurrent, _log

AGGREGATOR_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Safe call wrapper
# ---------------------------------------------------------------------------


def _safe_call(name, fn):
    """Wrap fn() in try/except. Returns result or None on failure, logging errors."""
    try:
        return fn()
    except Exception as e:
        _log(f"Workflow aggregator '{name}' failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Concurrent dispatch
# ---------------------------------------------------------------------------


def _dispatch(plan, timeout=AGGREGATOR_TIMEOUT):
    """Run a dict of {name: callable} concurrently with per-task timeout.

    Each callable is wrapped in _safe_call so failures are captured as None.
    Tasks that exceed `timeout` seconds are cancelled and return None.

    Returns:
        (results_dict, elapsed_ms) — elapsed_ms is an int.
    """
    if not plan:
        return {}, 0

    start = time.monotonic()
    results = {}
    executor = ThreadPoolExecutor(max_workers=min(len(plan), 8))

    try:
        futures = {
            executor.submit(_safe_call, name, fn): name
            for name, fn in plan.items()
        }
        try:
            for future in as_completed(futures, timeout=timeout):
                name = futures[future]
                try:
                    results[name] = future.result(timeout=5)
                except (FuturesTimeout, TimeoutError):
                    _log(f"Workflow aggregator '{name}' timed out after {timeout}s")
                    results[name] = None
                except Exception as e:
                    _log(f"Workflow aggregator '{name}' failed: {e}")
                    results[name] = None
        except (FuturesTimeout, TimeoutError):
            _log(f"Workflow dispatch timed out after {timeout}s — some aggregators incomplete")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    for name in plan:
        if name not in results:
            _log(f"Workflow aggregator '{name}' did not complete within timeout")
            results[name] = None

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return results, elapsed_ms


# ---------------------------------------------------------------------------
# Vulnerability identity normalisation
# ---------------------------------------------------------------------------

_VULN_FIELDS = ("qid", "cve", "qvs", "cvss", "severity", "title", "patch_available", "threat_intel")
_NUMERIC_VULN_FIELDS = ("qvs", "cvss")


def _vuln_identity(item):
    """Ensure a dict has all vuln identity fields; fill missing ones with None.

    qvs and cvss are coerced to numeric types (int or float) when possible.
    """
    result = dict(item)

    for field in _VULN_FIELDS:
        if field not in result:
            result[field] = None

    for field in _NUMERIC_VULN_FIELDS:
        val = result.get(field)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            continue
        try:
            as_float = float(val)
            as_int = int(as_float)
            result[field] = as_int if as_int == as_float else as_float
        except (TypeError, ValueError):
            pass  # leave as-is if conversion fails

    return result


# ---------------------------------------------------------------------------
# Risk level determination
# ---------------------------------------------------------------------------

_RISK_SCORE_KEYS = ("score", "truriskScore", "riskScore", "avgTruRiskCurrent", "trurisk")


def _determine_risk_level(data):
    """Determine overall risk level from aggregator results.

    Searches for risk scores in multiple locations:
    - Direct score fields (score, truriskScore, riskScore)
    - TruRisk aggregate counts (criticalRisk_900plus, highRisk_700plus)
    - Trend data (avgTruRiskCurrent)
    - Coverage/pass rate inversion

    Returns:
        "critical", "high", "medium", "low", or "unknown".
    """
    score = None

    for _agg_name, value in data.items():
        if not isinstance(value, dict):
            continue

        for key in _RISK_SCORE_KEYS:
            if key in value and value[key] is not None:
                try:
                    score = float(value[key])
                    if score > 0:
                        break
                except (TypeError, ValueError):
                    pass

        if score and score > 0:
            break

        agg = value.get("aggregate") or value.get("summary") or {}
        if isinstance(agg, dict):
            for key in _RISK_SCORE_KEYS:
                if key in agg and agg[key] is not None:
                    try:
                        score = float(agg[key])
                        if score > 0:
                            break
                    except (TypeError, ValueError):
                        pass

        if score and score > 0:
            break

        trend = value.get("trend")
        if isinstance(trend, dict) and trend.get("avgTruRiskCurrent"):
            try:
                score = float(trend["avgTruRiskCurrent"])
                if score > 0:
                    break
            except (TypeError, ValueError):
                pass

        crit = (agg if isinstance(agg, dict) else value).get("criticalRisk_900plus", 0)
        high = (agg if isinstance(agg, dict) else value).get("highRisk_700plus", 0)
        if crit or high:
            total = (agg if isinstance(agg, dict) else value).get("totalAssets", 1)
            if total > 0:
                crit_pct = (crit / total) * 100
                high_pct = (high / total) * 100
                if crit_pct > 5:
                    return "critical"
                if high_pct > 10:
                    return "high"
                if high_pct > 2:
                    return "medium"
                return "low"

    if score is None:
        return "unknown"
    if score >= 900:
        return "critical"
    if score >= 700:
        return "high"
    if score >= 300:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Response envelope construction
# ---------------------------------------------------------------------------


def _build_envelope(
    workflow,
    aggregators_called,
    results,
    execution_time_ms,
    summary_fn=None,
    correlate_fn=None,
    actions_fn=None,
):
    """Build unified response envelope from aggregator results.

    Args:
        workflow: name of the workflow (str)
        aggregators_called: list of aggregator names that were called
        results: dict of {name: result_or_None} from dispatch
        execution_time_ms: int elapsed time
        summary_fn: optional callable(data) -> summary dict
        correlate_fn: optional callable(data) -> list of correlation dicts
        actions_fn: optional callable(data) -> list of action dicts

    Returns:
        Envelope dict with keys: workflow, aggregators_called,
        execution_time_ms, summary, data, correlations, actions, _meta.
        Failures are tracked in _errors.
    """
    # Filter None results
    data = {k: v for k, v in results.items() if v is not None}
    errors = [k for k, v in results.items() if v is None]

    risk_level = _determine_risk_level(data)

    summary = None
    correlations = []
    actions = []

    if data:
        if summary_fn is not None:
            try:
                summary = summary_fn(data)
            except Exception as e:
                _log(f"Workflow '{workflow}' summary_fn failed: {e}")

        if correlate_fn is not None:
            try:
                correlations = correlate_fn(data) or []
            except Exception as e:
                _log(f"Workflow '{workflow}' correlate_fn failed: {e}")

        if actions_fn is not None:
            try:
                actions = actions_fn(data) or []
            except Exception as e:
                _log(f"Workflow '{workflow}' actions_fn failed: {e}")

    # Default summary if nothing produced one
    if summary is None:
        if data:
            summary = {
                "headline": f"{workflow} completed with {len(data)} data source(s).",
                "risk_level": risk_level,
                "key_findings": [],
                "stats": {},
            }
        else:
            summary = {
                "headline": "No data available — all aggregators failed or returned empty results.",
                "risk_level": "unknown",
                "key_findings": [],
                "stats": {},
            }

    total_results = sum(
        len(v) if isinstance(v, (list, dict)) else 1
        for v in data.values()
    )

    envelope = {
        "workflow": workflow,
        "aggregators_called": aggregators_called,
        "execution_time_ms": execution_time_ms,
        "summary": summary,
        "data": data,
        "correlations": correlations,
        "actions": actions,
        "_meta": {
            "total_results": total_results,
            "returned": total_results,
            "truncated": False,
        },
    }

    if errors:
        envelope["_errors"] = errors
        error_notes = []
        for err_name in errors:
            note = _error_explanation(err_name)
            if note:
                error_notes.append(note)
        if error_notes:
            envelope["_notes"] = error_notes

    return envelope


_ERROR_HINTS = {
    "cloud_risk": "Cloud risk data unavailable — the CDR or cloud evaluation API may be temporarily down. Try again shortly.",
    "etm_findings": "ETM findings unavailable — the Enterprise TruRisk Management module may not be enabled. Ask your Qualys admin to verify ETM is licensed.",
    "expiring_certs": "Certificate data unavailable — CertView may not be configured or no certificates have been scanned.",
    "webapp_vulns": "Web application vulnerability data unavailable — WAS/TotalAppSec may not be configured or no web apps have been scanned.",
    "threat_actor": "Threat actor data unavailable — the Knowledge Base search timed out or returned no results for this actor.",
    "edr_events": "EDR event data unavailable — Endpoint Detection & Response may not be enabled on this subscription.",
    "fim_events": "FIM event data unavailable — File Integrity Monitoring may not be enabled on this subscription.",
    "scanner_health": "Scanner health data unavailable — check scanner appliance connectivity.",
    "vuln_exceptions": "Vulnerability exceptions unavailable — the exception/waiver API may not be enabled.",
    "compliance_posture": "Compliance data unavailable — Policy Compliance may not be configured or no policies are assigned.",
    "morning_report": "Morning report data unavailable — asset data could not be retrieved.",
}


def _error_explanation(aggregator_name):
    return _ERROR_HINTS.get(aggregator_name)


# ---------------------------------------------------------------------------
# Detail level filtering
# ---------------------------------------------------------------------------


def _apply_detail(envelope, detail):
    """Filter envelope fields according to requested detail level.

    Levels:
        "summary"  — strips data and correlations, caps key_findings at 5.
        "standard" — returns envelope as-is.
        "detailed" — moves _raw_results to _raw.
    """
    result = dict(envelope)

    if detail == "summary":
        result.pop("data", None)
        result.pop("correlations", None)
        summary = dict(result.get("summary", {}))
        findings = summary.get("key_findings", [])
        if isinstance(findings, list) and len(findings) > 5:
            summary["key_findings"] = findings[:5]
        result["summary"] = summary

    elif detail == "detailed":
        raw = result.pop("_raw_results", None)
        if raw is not None:
            result["_raw"] = raw

    # "standard" — no changes

    return result
