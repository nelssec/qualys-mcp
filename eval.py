#!/usr/bin/env python3
"""
Qualys MCP Eval Harness — Multi-tier Quality Scoring

Scores tool responses with three tiers:
  1. Schema validation — required fields exist and are non-null/non-empty
  2. Threshold assertions — value ranges and type checks
  3. Keyword coverage — ratio of expected keywords matched (AND, not OR)

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

# Install VMDR fixture mocks when VMDR_MOCK_FIXTURES=1
from tests.fixtures import should_mock, install_vmdr_mocks
if should_mock():
    install_vmdr_mocks(qualys_mcp)


# ---------------------------------------------------------------------------
# Tier weights (must sum to 1.0)
# ---------------------------------------------------------------------------
WEIGHT_SCHEMA = 0.40
WEIGHT_THRESHOLD = 0.30
WEIGHT_KEYWORDS = 0.30

# Minimum keyword match ratio to get full marks on tier 3
MIN_KEYWORD_RATIO = 0.6


# ---------------------------------------------------------------------------
# Schema & threshold definitions per tool
# ---------------------------------------------------------------------------
# schema: list of dotted-path field names that must exist and be non-null/non-empty
# thresholds: list of (dotted_path, check_fn, description) tuples
# keywords: list of expected keywords (tier 3 uses ratio matching)

def _is_int_gte0(v):
    return isinstance(v, (int, float)) and v >= 0

def _is_int_range(lo, hi):
    def check(v):
        return isinstance(v, (int, float)) and lo <= v <= hi
    return check

def _is_nonempty_list(v):
    return isinstance(v, list) and len(v) > 0

def _is_nonempty_str(v):
    return isinstance(v, str) and len(v.strip()) > 0

def _is_float_0_100(v):
    return isinstance(v, (int, float)) and 0 <= v <= 100

def _is_dict(v):
    return isinstance(v, dict) and len(v) > 0


TOOL_SPECS = {
    "get_security_posture": {
        "schema": [
            "healthScore",
            "assets",
            "assets.total",
            "vulns",
            "vulns.critical",
            "vulns.high",
        ],
        "thresholds": [
            ("healthScore", _is_int_range(0, 100), "healthScore in 0-100"),
            ("assets.total", _is_int_gte0, "assets.total >= 0"),
            ("vulns.critical", _is_int_gte0, "vulns.critical >= 0"),
            ("vulns.high", _is_int_gte0, "vulns.high >= 0"),
        ],
        "keywords": ["risk", "score", "vulnerability", "asset", "trurisk"],
    },
    "get_morning_report": {
        "schema": [
            "report",
            "totalAssets",
            "summary",
        ],
        "thresholds": [
            ("totalAssets", _is_int_gte0, "totalAssets >= 0"),
            ("report", _is_nonempty_str, "report is non-empty string"),
            ("summary", _is_nonempty_str, "summary is non-empty string"),
        ],
        "keywords": ["report", "summary", "asset", "vulnerability", "risk"],
    },
    "get_weekly_priorities": {
        "schema": [
            "summary",
            "summary.totalAssets",
            "priorities",
            "topRiskAssets",
        ],
        "thresholds": [
            ("summary.totalAssets", _is_int_gte0, "totalAssets >= 0"),
            ("priorities", _is_nonempty_list, "priorities list non-empty"),
        ],
        "keywords": ["asset", "risk", "trurisk", "priority"],
    },
    "get_patch_status": {
        "schema": [
            "coverage",
            "assetsTotal",
            "riskDistribution",
        ],
        "thresholds": [
            ("coverage", _is_float_0_100, "coverage 0-100%"),
            ("assetsTotal", _is_int_gte0, "assetsTotal >= 0"),
            ("riskDistribution", _is_dict, "riskDistribution is non-empty dict"),
        ],
        "keywords": ["patch", "coverage", "risk", "asset"],
    },
    "get_tech_debt": {
        "schema": [
            "summary",
            "summary.osEOL",
            "summary.hardwareEOL",
        ],
        "thresholds": [
            ("summary.osEOL", _is_int_gte0, "osEOL >= 0"),
            ("summary.hardwareEOL", _is_int_gte0, "hardwareEOL >= 0"),
        ],
        "keywords": ["eol", "end", "life", "asset", "software"],
    },
    "get_cloud_risk": {
        "schema": [
            "accounts",
            "stats",
            "stats.total",
        ],
        "thresholds": [
            ("stats.total", _is_int_gte0, "stats.total >= 0"),
            ("accounts", lambda v: isinstance(v, list), "accounts is a list"),
        ],
        "keywords": ["cloud", "resource", "risk", "account"],
    },
    "get_cdr_findings": {
        "schema": [],
        "thresholds": [],
        "keywords": ["cloud", "detection", "threat", "finding"],
    },
    "get_scanner_health": {
        "schema": [
            "scanners",
            "summary",
        ],
        "thresholds": [
            ("scanners", lambda v: isinstance(v, list), "scanners is a list"),
            ("summary", _is_nonempty_str, "summary is non-empty string"),
        ],
        "keywords": ["scanner", "status", "online", "scan"],
    },
    "get_recommendations": {
        "schema": [
            "recommendations",
            "coverage",
            "summary",
        ],
        "thresholds": [
            ("recommendations", _is_nonempty_list, "recommendations non-empty"),
            ("coverage", _is_dict, "coverage is non-empty dict"),
            ("summary", _is_nonempty_str, "summary is non-empty string"),
        ],
        "keywords": ["recommendation", "gap", "risk", "improvement"],
    },
    "get_eliminate_status": {
        "schema": [
            "patchManagement",
            "summary",
        ],
        "thresholds": [
            ("summary", _is_nonempty_str, "summary is non-empty string"),
            ("patchManagement", _is_dict, "patchManagement is non-empty dict"),
        ],
        "keywords": ["patch", "status", "remediation", "job"],
    },
    "get_threat_intel": {
        "schema": [],
        "thresholds": [],
        "keywords": ["vulnerability", "ransomware", "cve", "threat"],
    },
    "investigate_cve": {
        "schema": [
            "cve",
            "qids",
            "severity",
            "title",
            "patchAvailable",
            "assets",
        ],
        "thresholds": [
            ("severity", _is_int_range(1, 5), "severity 1-5"),
            ("qids", _is_nonempty_list, "qids non-empty"),
            ("assets", _is_dict, "assets is non-empty dict"),
        ],
        "keywords": ["cve", "vulnerability", "asset", "qid"],
    },
    "get_cve_details": {
        "schema": [
            "requested",
            "found",
            "cves",
        ],
        "thresholds": [
            ("requested", _is_int_gte0, "requested >= 0"),
            ("found", _is_int_gte0, "found >= 0"),
            ("cves", _is_nonempty_list, "cves list non-empty"),
        ],
        "keywords": ["cve", "severity", "vulnerability", "qid"],
    },
    "get_etm_findings": {
        "schema": [
            "reportStatus",
            "totalFindings",
            "summary",
        ],
        "thresholds": [
            ("totalFindings", _is_int_gte0, "totalFindings >= 0"),
            ("summary", _is_dict, "summary is non-empty dict"),
        ],
        "keywords": ["finding", "report", "confirmed", "severity"],
    },
    "get_asset_risk": {
        "schema": [],
        "thresholds": [],
        "keywords": ["asset", "risk", "vulnerability", "trurisk"],
    },
}


# ---------------------------------------------------------------------------
# Eval questions: (description, tool_name, kwargs, optional)
# Scoring specs come from TOOL_SPECS above, keyed by tool_name
# ---------------------------------------------------------------------------
EVAL_QUESTIONS = [
    # get_security_posture
    (
        "What is our overall security posture?",
        "get_security_posture",
        {},
        False,
    ),
    (
        "Show me our risk distribution",
        "get_security_posture",
        {},
        False,
    ),
    # get_morning_report
    (
        "What happened overnight?",
        "get_morning_report",
        {},
        False,
    ),
    # get_weekly_priorities
    (
        "What are our top priorities this week?",
        "get_weekly_priorities",
        {"limit": 5},
        False,
    ),
    # get_patch_status
    (
        "How is our patching coverage?",
        "get_patch_status",
        {"limit": 10},
        False,
    ),
    # get_tech_debt
    (
        "Show me end-of-life systems",
        "get_tech_debt",
        {"limit": 10},
        False,
    ),
    # get_cloud_risk
    (
        "What is our cloud security posture?",
        "get_cloud_risk",
        {},
        False,
    ),
    # get_cdr_findings
    (
        "Any cloud threat detections recently?",
        "get_cdr_findings",
        {"days": 7},
        False,
    ),
    # get_scanner_health
    (
        "Are our scanners healthy?",
        "get_scanner_health",
        {},
        False,
    ),
    # get_recommendations
    (
        "What should we improve?",
        "get_recommendations",
        {},
        False,
    ),
    # get_eliminate_status
    (
        "What is our remediation status?",
        "get_eliminate_status",
        {},
        False,
    ),
    # get_threat_intel — ransomware
    (
        "Which vulnerabilities have ransomware associations?",
        "get_threat_intel",
        {"threat_type": "Ransomware"},
        False,
    ),
    # investigate_cve
    (
        "Are we affected by Log4Shell?",
        "investigate_cve",
        {"cve": "CVE-2021-44228"},
        False,
    ),
    # get_cve_details
    (
        "Get details on CVE-2021-44228 and CVE-2024-3400",
        "get_cve_details",
        {"cves": "CVE-2021-44228,CVE-2024-3400"},
        False,
    ),
    # get_etm_findings
    (
        "Show confirmed findings across all sources",
        "get_etm_findings",
        {},
        False,
    ),
    # get_asset_risk — requires BENCHMARK_ASSET_ID
    (
        "What is the risk for a specific asset?",
        "get_asset_risk",
        {"asset_id": os.environ.get("BENCHMARK_ASSET_ID", "")},
        True,
    ),
]


# ---------------------------------------------------------------------------
# Resolve a dotted path like "assets.total" on a dict
# ---------------------------------------------------------------------------
def _resolve(data, path):
    """Walk a dotted path into a dict. Returns (True, value) or (False, None)."""
    parts = path.split(".")
    cur = data
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return False, None
        cur = cur[p]
    return True, cur


def _field_is_present(value):
    """Check a resolved value is non-null and non-empty."""
    if value is None:
        return False
    if isinstance(value, str) and value.strip() == "":
        return False
    if isinstance(value, (list, dict)) and len(value) == 0:
        return False
    return True


# ---------------------------------------------------------------------------
# Tier scorers
# ---------------------------------------------------------------------------
def score_schema(result, spec):
    """Tier 1: check required fields exist and are non-null/non-empty.
    Returns (score 0.0-1.0, details list).
    """
    fields = spec.get("schema", [])
    if not fields:
        return 1.0, []  # no schema defined → auto-pass

    passed = []
    failed = []
    for path in fields:
        found, val = _resolve(result, path)
        if found and _field_is_present(val):
            passed.append(path)
        else:
            failed.append(path)

    total = len(fields)
    score = len(passed) / total if total else 1.0
    details = []
    if failed:
        details = [f"missing: {', '.join(failed)}"]
    return score, details


def score_thresholds(result, spec):
    """Tier 2: run threshold/type assertions.
    Returns (score 0.0-1.0, details list).
    """
    checks = spec.get("thresholds", [])
    if not checks:
        return 1.0, []

    passed = []
    failed = []
    for path, check_fn, desc in checks:
        found, val = _resolve(result, path)
        if found and check_fn(val):
            passed.append(desc)
        else:
            failed.append(desc)

    total = len(checks)
    score = len(passed) / total if total else 1.0
    details = []
    if failed:
        details = [f"failed: {', '.join(failed)}"]
    return score, details


def score_keywords(result, spec):
    """Tier 3: keyword coverage ratio.
    Returns (score 0.0-1.0, details dict).
    """
    keywords = spec.get("keywords", [])
    if not keywords:
        return 1.0, {}

    result_str = json.dumps(result).lower() if result else ""
    matched = [kw for kw in keywords if kw.lower() in result_str]
    ratio = len(matched) / len(keywords) if keywords else 1.0

    # Score: 1.0 if ratio >= MIN_KEYWORD_RATIO, else proportional
    if ratio >= MIN_KEYWORD_RATIO:
        score = 1.0
    else:
        score = ratio / MIN_KEYWORD_RATIO

    return score, {
        "matched": matched,
        "expected": keywords,
        "ratio": round(ratio, 2),
    }


# ---------------------------------------------------------------------------
# Main eval runner
# ---------------------------------------------------------------------------
def get_tool_fn(name):
    """Get the underlying function for a tool, unwrapping FastMCP wrappers."""
    fn = getattr(qualys_mcp, name, None)
    if fn is None:
        return None
    if hasattr(fn, "fn"):
        return fn.fn
    return fn


def run_eval(question, tool_name, kwargs, optional=False):
    """Run a single eval question and return the result with tier scores."""
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

    # Look up spec for this tool
    spec = TOOL_SPECS.get(tool_name, {"schema": [], "thresholds": [], "keywords": []})

    # If result is not a dict (e.g. deprecated tool returning a string), wrap it
    if not isinstance(result, dict):
        result_dict = {}
        result_for_keywords = result
    else:
        result_dict = result
        result_for_keywords = result

    # Tier 1: schema validation
    schema_score, schema_details = score_schema(result_dict, spec)

    # Tier 2: threshold assertions
    threshold_score, threshold_details = score_thresholds(result_dict, spec)

    # Tier 3: keyword coverage
    keyword_score, keyword_details = score_keywords(result_for_keywords, spec)

    # Weighted overall score
    overall = (
        WEIGHT_SCHEMA * schema_score
        + WEIGHT_THRESHOLD * threshold_score
        + WEIGHT_KEYWORDS * keyword_score
    )

    # Determine status: pass if overall >= 0.5
    passed = overall >= 0.5

    return {
        "question": question,
        "tool": tool_name,
        "status": "pass" if passed else "fail",
        "overall_score": round(overall, 3),
        "tiers": {
            "schema": {
                "score": round(schema_score, 3),
                "weight": WEIGHT_SCHEMA,
                "details": schema_details,
            },
            "threshold": {
                "score": round(threshold_score, 3),
                "weight": WEIGHT_THRESHOLD,
                "details": threshold_details,
            },
            "keywords": {
                "score": round(keyword_score, 3),
                "weight": WEIGHT_KEYWORDS,
                "matched": keyword_details.get("matched", []),
                "expected": keyword_details.get("expected", []),
                "ratio": keyword_details.get("ratio", 1.0),
            },
        },
        "result_size": len(json.dumps(result)) if result else 0,
        "elapsed_s": round(elapsed, 2),
    }


def print_results(results, score_pct, threshold):
    """Print a summary table of eval results."""
    print()
    print(f"{'#':<4} {'Status':<8} {'Score':>6} {'Sch':>5} {'Thr':>5} {'Kwd':>5}  {'Tool':<28} {'Time':>7}  Question")
    print("─" * 110)

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
        question = r["question"][:45]

        if "tiers" in r:
            t = r["tiers"]
            overall = f"{r['overall_score']:.0%}"
            sch = f"{t['schema']['score']:.0%}"
            thr = f"{t['threshold']['score']:.0%}"
            kwd = f"{t['keywords']['score']:.0%}"
        else:
            overall = sch = thr = kwd = "—"

        print(f"{i:<4} {icon:<8} {overall:>6} {sch:>5} {thr:>5} {kwd:>5}  {r['tool']:<28} {elapsed:>7}  {question}")

    print("─" * 110)
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    errors = sum(1 for r in results if r["status"] == "error")

    print(f"\nResults: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped")
    print(f"Score: {score_pct:.1f}% (threshold: {threshold}%)")

    # Show average tier scores
    tier_results = [r for r in results if "tiers" in r]
    if tier_results:
        avg_sch = sum(r["tiers"]["schema"]["score"] for r in tier_results) / len(tier_results)
        avg_thr = sum(r["tiers"]["threshold"]["score"] for r in tier_results) / len(tier_results)
        avg_kwd = sum(r["tiers"]["keywords"]["score"] for r in tier_results) / len(tier_results)
        print(f"Tier averages — Schema: {avg_sch:.0%}  Threshold: {avg_thr:.0%}  Keywords: {avg_kwd:.0%}")

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
    print(f"Scoring: schema {WEIGHT_SCHEMA:.0%} + threshold {WEIGHT_THRESHOLD:.0%} + keywords {WEIGHT_KEYWORDS:.0%}")
    base = os.environ.get("QUALYS_BASE_URL", "?")
    host = base.split("/")[2] if "/" in base else base
    print(f"Server: {host}")
    print()

    results = []
    for desc, tool_name, kwargs, optional in questions:
        sys.stdout.write(f"  ⏱  {tool_name}...")
        sys.stdout.flush()
        r = run_eval(desc, tool_name, kwargs, optional)
        results.append(r)
        if r["status"] in ("pass", "fail") and "overall_score" in r:
            icon = "✓" if r["status"] == "pass" else "✗"
            print(f"\r  {icon}  {tool_name:<35} {r['status']} ({r['overall_score']:.0%})")
        else:
            icon = "⏭" if r["status"] == "skipped" else "✗"
            print(f"\r  {icon}  {tool_name:<35} {r['status']}")

    # Calculate score: average of overall_score for scorable results
    scorable = [r for r in results if r["status"] in ("pass", "fail")]
    if scorable:
        score_pct = (sum(r["overall_score"] for r in scorable) / len(scorable)) * 100
    else:
        score_pct = 0.0

    print_results(results, score_pct, threshold)

    # Save JSON
    if args.json:
        output = {
            "timestamp": datetime.now().isoformat(),
            "score_pct": round(score_pct, 1),
            "threshold": threshold,
            "scoring": {
                "weights": {
                    "schema": WEIGHT_SCHEMA,
                    "threshold": WEIGHT_THRESHOLD,
                    "keywords": WEIGHT_KEYWORDS,
                },
                "min_keyword_ratio": MIN_KEYWORD_RATIO,
            },
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
