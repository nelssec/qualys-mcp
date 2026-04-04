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

_RISK_SCORE_KEYS = ("score", "truriskScore", "riskScore")


def _determine_risk_level(data):
    """Search aggregator results for a risk score and return a risk label.

    Searches nested dicts for keys matching known score field names.

    Returns:
        "critical" (>=900), "high" (>=700), "medium" (>=300), "low" (<300),
        or "unknown" if no score is found.
    """
    score = None

    for _agg_name, value in data.items():
        if not isinstance(value, dict):
            continue
        for key in _RISK_SCORE_KEYS:
            if key in value:
                try:
                    score = float(value[key])
                    break
                except (TypeError, ValueError):
                    pass
        if score is not None:
            break

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

    return envelope


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
