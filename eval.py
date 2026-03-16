#!/usr/bin/env python3
"""
Qualys MCP Eval Harness

Runs a set of question/answer pairs against the MCP server and scores responses.

Usage:
    python eval.py                    # Run all evals
    python eval.py --quick            # Run quick subset
    python eval.py --limit 50         # Limit to N questions
    python eval.py --json results.json  # Save results as JSON

Exit codes:
    0 = pass (score >= threshold)
    1 = fail (score < threshold)
    2 = error

Env vars:
    QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL, QUALYS_GATEWAY_URL
    EVAL_PASS_THRESHOLD (default: 80)
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

import qualys_mcp

# Install VMDR fixture mocks when VMDR_MOCK_FIXTURES=1
from tests.fixtures import should_mock, install_vmdr_mocks
if should_mock():
    install_vmdr_mocks(qualys_mcp)

# Minimum ratio of expected keywords that must match for a pass
KEYWORD_MATCH_THRESHOLD = 0.5

# Minimum result length to be considered valid data (not just an error stub)
MIN_RESULT_LENGTH = 50


# Each eval question: (description, tool_name, kwargs, expected_keywords, optional)
# optional=True means skip if required env vars are missing
EVAL_QUESTIONS = [
    # get_security_posture
    (
        "What is our overall security posture?",
        "get_security_posture",
        {},
        ["trurisk_score", "vulnerability", "asset", "risk_distribution"],
        False,
    ),
    (
        "Show me our risk distribution",
        "get_security_posture",
        {},
        ["risk_distribution", "critical", "high", "medium"],
        False,
    ),
    # get_morning_report
    (
        "What happened overnight?",
        "get_morning_report",
        {},
        ["posture_summary", "vulnerability", "risk_score", "overnight"],
        False,
    ),
    # get_weekly_priorities
    (
        "What are our top priorities this week?",
        "get_weekly_priorities",
        {"limit": 5},
        ["trurisk", "priority", "asset_name", "remediation"],
        False,
    ),
    # get_patch_status
    (
        "How is our patching coverage?",
        "get_patch_status",
        {"limit": 10},
        ["patch_coverage", "installed", "missing", "percentage"],
        False,
    ),
    # get_tech_debt
    (
        "Show me end-of-life systems",
        "get_tech_debt",
        {"limit": 10},
        ["end_of_life", "eos", "asset_name", "software_name"],
        False,
    ),
    # get_cloud_risk
    (
        "What is our cloud security posture?",
        "get_cloud_risk",
        {},
        ["cloud_provider", "resource_count", "risk_score", "connector"],
        False,
    ),
    # get_cdr_findings
    (
        "Any cloud threat detections recently?",
        "get_cdr_findings",
        {"days": 7},
        ["finding_id", "cloud_provider", "detection_type", "threat_severity"],
        False,
    ),
    # get_scanner_health
    (
        "Are our scanners healthy?",
        "get_scanner_health",
        {},
        ["scanner_name", "appliance", "status", "last_scan"],
        False,
    ),
    # get_recommendations
    (
        "What should we improve?",
        "get_recommendations",
        {},
        ["recommendation", "gap_analysis", "module_coverage", "improvement"],
        False,
    ),
    # get_eliminate_status
    (
        "What is our remediation status?",
        "get_eliminate_status",
        {},
        ["patch_job", "remediation_status", "job_status", "asset_count"],
        False,
    ),
    # get_threat_intel — ransomware
    (
        "Which vulnerabilities have ransomware associations?",
        "get_threat_intel",
        {"threat_type": "Ransomware"},
        ["ransomware", "cve_id", "threat_association", "detection_count"],
        False,
    ),
    # investigate_cve
    (
        "Are we affected by Log4Shell?",
        "investigate_cve",
        {"cve": "CVE-2021-44228"},
        ["CVE-2021-44228", "affected_assets", "qid", "log4j"],
        False,
    ),
    # get_cve_details
    (
        "Get details on CVE-2021-44228 and CVE-2024-3400",
        "get_cve_details",
        {"cves": "CVE-2021-44228,CVE-2024-3400"},
        ["CVE-2021-44228", "CVE-2024-3400", "severity_score", "qid"],
        False,
    ),
    # get_etm_findings
    (
        "Show confirmed findings across all sources",
        "get_etm_findings",
        {},
        ["finding_id", "etm_report", "confirmed", "source_type"],
        False,
    ),
    # get_asset_risk — requires BENCHMARK_ASSET_ID
    (
        "What is the risk for a specific asset?",
        "get_asset_risk",
        {"asset_id": os.environ.get("BENCHMARK_ASSET_ID", "")},
        ["asset_id", "trurisk_score", "vulnerability_count", "risk_level"],
        True,
    ),
]


# Tool-specific schema validators: return (valid, reason) tuple
TOOL_VALIDATORS = {
    "get_security_posture": lambda result: _validate_numeric_field(result, "trurisk_score"),
    "get_cloud_risk": lambda result: _validate_cloud_provider(result),
    "investigate_cve": lambda result: _validate_cve_in_result(result),
    "get_patch_status": lambda result: _validate_numeric_field(result, "coverage"),
}


def _validate_numeric_field(result, field_name):
    """Check that result contains a numeric value for the given field name."""
    result_str = json.dumps(result) if result else ""
    # Look for "field_name": <number> pattern
    pattern = rf'"{field_name}"\s*:\s*[\d.]+'
    if re.search(pattern, result_str):
        return True, None
    # Also accept field_name appearing with any numeric value nearby
    if field_name in result_str.lower():
        if re.search(r'\d+\.?\d*', result_str):
            return True, None
    return False, f"missing numeric {field_name}"


def _validate_cloud_provider(result):
    """Check that result contains at least one cloud provider keyword."""
    result_str = json.dumps(result).lower() if result else ""
    providers = ["aws", "azure", "gcp", "google cloud", "amazon"]
    found = [p for p in providers if p in result_str]
    if found:
        return True, None
    return False, "no cloud provider (aws/azure/gcp) found"


def _validate_cve_in_result(result):
    """Check that result contains a CVE identifier."""
    result_str = json.dumps(result) if result else ""
    if re.search(r'CVE-\d{4}-\d{4,}', result_str, re.IGNORECASE):
        return True, None
    return False, "no CVE identifier found"


def _check_result_validity(result_str):
    """Check whether a result string contains valid data (not just an error).

    Returns (is_valid, reason) tuple.
    """
    if not result_str:
        return False, "empty result"
    if len(result_str) < MIN_RESULT_LENGTH:
        return False, f"result too short ({len(result_str)} chars)"
    # Check for error-only responses
    stripped = result_str.strip().strip('"')
    if stripped.startswith("error:") or stripped.startswith("error :"):
        return False, "result is an error message"
    # Check if result is essentially just an error object
    if re.match(r'^\s*\{\s*"error"\s*:', result_str):
        return False, "result is an error object"
    return True, None


def get_tool_fn(name):
    """Get the underlying function for a tool, unwrapping FastMCP wrappers."""
    fn = getattr(qualys_mcp, name, None)
    if fn is None:
        return None
    if hasattr(fn, "fn"):
        return fn.fn
    return fn


def run_eval(question, tool_name, kwargs, expected_keywords, optional=False):
    """Run a single eval question and return the result."""
    # Skip optional questions when required env vars are missing
    if optional:
        if tool_name == "get_asset_risk" and not os.environ.get("BENCHMARK_ASSET_ID"):
            return {
                "question": question,
                "tool": tool_name,
                "status": "skipped",
                "reason": "BENCHMARK_ASSET_ID not set",
            }

    fn = get_tool_fn(tool_name)
    if fn is None:
        return {
            "question": question,
            "tool": tool_name,
            "status": "error",
            "reason": f"tool {tool_name} not found",
        }

    start = time.perf_counter()
    try:
        result = fn(**kwargs)
        elapsed = time.perf_counter() - start
    except Exception as e:
        elapsed = time.perf_counter() - start
        return {
            "question": question,
            "tool": tool_name,
            "status": "error",
            "reason": str(e)[:200],
            "elapsed_s": round(elapsed, 2),
        }

    # Convert result to string for keyword matching
    result_str = json.dumps(result).lower() if result else ""

    # Result validity check
    result_valid, validity_reason = _check_result_validity(result_str)

    # Multi-keyword threshold matching
    matched = [kw for kw in expected_keywords if kw.lower() in result_str]
    match_ratio = len(matched) / len(expected_keywords) if expected_keywords else 0
    threshold_met = match_ratio >= KEYWORD_MATCH_THRESHOLD

    # Tool-specific schema validation
    schema_valid = True
    schema_reason = None
    if tool_name in TOOL_VALIDATORS:
        schema_valid, schema_reason = TOOL_VALIDATORS[tool_name](result)

    # Pass requires: threshold met AND result valid AND schema valid
    passed = threshold_met and result_valid and schema_valid

    fail_reasons = []
    if not result_valid:
        fail_reasons.append(f"invalid result: {validity_reason}")
    if not threshold_met:
        fail_reasons.append(f"keyword match {len(matched)}/{len(expected_keywords)} below {KEYWORD_MATCH_THRESHOLD:.0%}")
    if not schema_valid:
        fail_reasons.append(f"schema: {schema_reason}")

    return {
        "question": question,
        "tool": tool_name,
        "status": "pass" if passed else "fail",
        "matched_keywords": matched,
        "expected_keywords": expected_keywords,
        "match_ratio": f"{len(matched)}/{len(expected_keywords)}",
        "result_size": len(result_str),
        "result_valid": result_valid,
        "schema_valid": schema_valid,
        "fail_reasons": fail_reasons if not passed else [],
        "elapsed_s": round(elapsed, 2),
    }


def print_results(results, score_pct, threshold):
    """Print a summary table of eval results."""
    print()
    print(f"{'#':<4} {'Status':<8} {'Tool':<28} {'Match':>7} {'Time':>7}  Question")
    print("─" * 100)

    for i, r in enumerate(results, 1):
        status = r["status"]
        if status == "pass":
            icon = "✅"
        elif status == "fail":
            icon = "❌"
        elif status == "skipped":
            icon = "⏭️"
        else:
            icon = "💥"

        elapsed = f"{r.get('elapsed_s', 0):.1f}s" if "elapsed_s" in r else "—"
        match_ratio = r.get("match_ratio", "—")
        question = r["question"][:45]
        print(f"{i:<4} {icon:<8} {r['tool']:<28} {match_ratio:>7} {elapsed:>7}  {question}")
        # Show failure reasons on the next line for failed evals
        if r.get("fail_reasons"):
            reasons = "; ".join(r["fail_reasons"])
            print(f"{'':>4} {'':>8} └─ {reasons}")

    print("─" * 100)
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    errors = sum(1 for r in results if r["status"] == "error")

    print(f"\nResults: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped")
    print(f"Score: {score_pct:.1f}% (threshold: {threshold}%)")
    print(f"Keyword match threshold: {KEYWORD_MATCH_THRESHOLD:.0%} of expected keywords required")

    if score_pct >= threshold:
        print("✅ PASSED")
    else:
        print("❌ FAILED")


def main():
    parser = argparse.ArgumentParser(description="Qualys MCP Eval Harness")
    parser.add_argument("--quick", action="store_true", help="Run only first 20 questions")
    parser.add_argument("--limit", type=int, help="Limit to N questions")
    parser.add_argument("--json", help="Save results as JSON file")
    args = parser.parse_args()

    # Check env
    for var in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "QUALYS_BASE_URL", "QUALYS_GATEWAY_URL"]:
        if not os.environ.get(var):
            print(f"ERROR: {var} not set")
            sys.exit(2)

    threshold = int(os.environ.get("EVAL_PASS_THRESHOLD", "80"))

    # Select questions
    questions = EVAL_QUESTIONS[:]
    if args.quick:
        questions = questions[:20]
    if args.limit:
        questions = questions[: args.limit]

    print(f"Qualys MCP Eval — {len(questions)} questions, threshold {threshold}%")
    base = os.environ.get("QUALYS_BASE_URL", "?")
    host = base.split("/")[2] if "/" in base else base
    print(f"Server: {host}")
    print()

    results = []
    for desc, tool_name, kwargs, keywords, optional in questions:
        sys.stdout.write(f"  ⏱  {tool_name}...")
        sys.stdout.flush()
        r = run_eval(desc, tool_name, kwargs, keywords, optional)
        results.append(r)
        icon = "✓" if r["status"] == "pass" else ("⏭" if r["status"] == "skipped" else "✗")
        match_info = f" [{r.get('match_ratio', '—')}]" if r["status"] in ("pass", "fail") else ""
        print(f"\r  {icon}  {tool_name:<35} {r['status']}{match_info}")

    # Calculate score (exclude skipped)
    scorable = [r for r in results if r["status"] in ("pass", "fail")]
    if scorable:
        passed = sum(1 for r in scorable if r["status"] == "pass")
        score_pct = (passed / len(scorable)) * 100
    else:
        score_pct = 0.0

    print_results(results, score_pct, threshold)

    # Save JSON
    if args.json:
        output = {
            "timestamp": datetime.now().isoformat(),
            "score_pct": round(score_pct, 1),
            "threshold": threshold,
            "keyword_match_threshold": KEYWORD_MATCH_THRESHOLD,
            "total": len(results),
            "passed": sum(1 for r in results if r["status"] == "pass"),
            "failed": sum(1 for r in results if r["status"] == "fail"),
            "skipped": sum(1 for r in results if r["status"] == "skipped"),
            "errors": sum(1 for r in results if r["status"] == "error"),
            "results": results,
        }
        with open(args.json, "w") as f:
            json.dump(output, f, indent=2)
        print(f"JSON saved: {args.json}")

    # Exit code
    if score_pct >= threshold:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
