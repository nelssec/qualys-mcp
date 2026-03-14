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
import sys
import time
from datetime import datetime

import qualys_mcp


# Each eval question: (description, tool_name, kwargs, expected_keywords, optional)
# optional=True means skip if required env vars are missing
EVAL_QUESTIONS = [
    # get_security_posture
    (
        "What is our overall security posture?",
        "get_security_posture",
        {},
        ["risk", "score", "vulnerability", "asset", "trurisk"],
        False,
    ),
    (
        "Show me our risk distribution",
        "get_security_posture",
        {},
        ["risk", "critical", "high", "medium"],
        False,
    ),
    # get_morning_report
    (
        "What happened overnight?",
        "get_morning_report",
        {},
        ["report", "summary", "posture", "vulnerability", "risk"],
        False,
    ),
    # get_weekly_priorities
    (
        "What are our top priorities this week?",
        "get_weekly_priorities",
        {"limit": 5},
        ["asset", "risk", "trurisk", "priority"],
        False,
    ),
    # get_patch_status
    (
        "How is our patching coverage?",
        "get_patch_status",
        {"limit": 10},
        ["patch", "coverage", "installed", "missing"],
        False,
    ),
    # get_tech_debt
    (
        "Show me end-of-life systems",
        "get_tech_debt",
        {"limit": 10},
        ["eol", "eos", "end", "life", "asset", "software"],
        False,
    ),
    # get_cloud_risk
    (
        "What is our cloud security posture?",
        "get_cloud_risk",
        {},
        ["cloud", "aws", "azure", "gcp", "resource", "risk"],
        False,
    ),
    # get_cdr_findings
    (
        "Any cloud threat detections recently?",
        "get_cdr_findings",
        {"days": 7},
        ["finding", "cloud", "detection", "threat", "resource"],
        False,
    ),
    # get_scanner_health
    (
        "Are our scanners healthy?",
        "get_scanner_health",
        {},
        ["scanner", "appliance", "status", "online"],
        False,
    ),
    # get_recommendations
    (
        "What should we improve?",
        "get_recommendations",
        {},
        ["recommendation", "gap", "module", "risk", "improvement"],
        False,
    ),
    # get_eliminate_status
    (
        "What is our remediation status?",
        "get_eliminate_status",
        {},
        ["patch", "status", "remediation", "job"],
        False,
    ),
    # get_threat_intel — ransomware
    (
        "Which vulnerabilities have ransomware associations?",
        "get_threat_intel",
        {"threat_type": "Ransomware"},
        ["vulnerability", "ransomware", "cve", "detection", "threat"],
        False,
    ),
    # investigate_cve
    (
        "Are we affected by Log4Shell?",
        "investigate_cve",
        {"cve": "CVE-2021-44228"},
        ["cve", "vulnerability", "log4j", "asset", "qid"],
        False,
    ),
    # get_cve_details
    (
        "Get details on CVE-2021-44228 and CVE-2024-3400",
        "get_cve_details",
        {"cves": "CVE-2021-44228,CVE-2024-3400"},
        ["cve", "severity", "vulnerability", "qid"],
        False,
    ),
    # get_etm_findings
    (
        "Show confirmed findings across all sources",
        "get_etm_findings",
        {},
        ["finding", "report", "etm", "confirmed"],
        False,
    ),
    # get_asset_risk — requires BENCHMARK_ASSET_ID
    (
        "What is the risk for a specific asset?",
        "get_asset_risk",
        {"asset_id": os.environ.get("BENCHMARK_ASSET_ID", "")},
        ["asset", "risk", "vulnerability", "trurisk"],
        True,
    ),
]


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

    # Check if any expected keyword appears in the response
    matched = [kw for kw in expected_keywords if kw.lower() in result_str]
    passed = len(matched) > 0

    return {
        "question": question,
        "tool": tool_name,
        "status": "pass" if passed else "fail",
        "matched_keywords": matched,
        "expected_keywords": expected_keywords,
        "result_size": len(result_str),
        "elapsed_s": round(elapsed, 2),
    }


def print_results(results, score_pct, threshold):
    """Print a summary table of eval results."""
    print()
    print(f"{'#':<4} {'Status':<8} {'Tool':<28} {'Time':>7}  Question")
    print("─" * 90)

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
        question = r["question"][:50]
        print(f"{i:<4} {icon:<8} {r['tool']:<28} {elapsed:>7}  {question}")

    print("─" * 90)
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    errors = sum(1 for r in results if r["status"] == "error")

    print(f"\nResults: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped")
    print(f"Score: {score_pct:.1f}% (threshold: {threshold}%)")

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
        print(f"\r  {icon}  {tool_name:<35} {r['status']}")

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
