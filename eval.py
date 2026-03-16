#!/usr/bin/env python3
"""
Qualys MCP Eval Harness — Multi-layered Quality Scoring

Scores MCP tool responses using a weighted combination of three layers:

1. **Schema/Threshold Validation** (50% weight) — validates that responses
   contain expected fields with meaningful values (non-null, correct types,
   numeric ranges, non-empty lists).

2. **Multi-keyword AND Logic** (30% weight) — requires a configurable fraction
   of expected keywords to appear (default >=60%), not just any single keyword.

3. **Error Detection** (20% weight) — checks for error indicators in the
   response ("error", "failed", "exception", "not found", "unauthorized").
   Error-free responses earn the full 20%.

Overall score per eval = schema_weight + keyword_weight + error_weight.

Scoring modes (--scoring-mode):
  - combined (default): all three layers weighted as above
  - schema: only schema validation (pass/fail)
  - keywords: only keyword matching with threshold (legacy-compatible)

Usage:
    python eval.py                    # Run all evals (combined scoring)
    python eval.py --scoring-mode schema  # Schema-only scoring
    python eval.py --quick            # Run quick subset
    python eval.py --limit 50         # Limit to N questions
    python eval.py --json results.json  # Save results as JSON
    python eval.py --judge            # Enable Claude-as-judge scoring

Exit codes:
    0 = pass (score >= threshold)
    1 = fail (score < threshold)
    2 = error

Env vars:
    QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL, QUALYS_GATEWAY_URL
    EVAL_PASS_THRESHOLD (default: 80)
    EVAL_KEYWORD_THRESHOLD (default: 0.6) — fraction of keywords required
    EVAL_JUDGE (default: 0) — set to 1 to enable Claude-as-judge
    ANTHROPIC_API_KEY — required for Claude-as-judge
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
# Schema specifications per tool
# ---------------------------------------------------------------------------
# Each schema is a dict with:
#   required_fields: list of field names that must exist (dot-notation for nested)
#   non_empty: list of fields that must be non-empty (string, list, dict)
#   numeric_ranges: dict of field -> (min, max) for numeric validation
#   list_fields: list of fields that must be lists with at least one item
#   type_checks: dict of field -> expected type name ("str", "int", "float", "list", "dict", "number")
# ---------------------------------------------------------------------------
EVAL_SCHEMAS = {
    "get_security_posture": {
        "required_fields": ["trurisk_score"],
        "numeric_ranges": {"trurisk_score": (0, 1000)},
        "non_empty": ["assets", "vulnerabilities"],
    },
    "get_morning_report": {
        "non_empty": ["_root"],  # _root = the result itself must be non-empty
    },
    "get_weekly_priorities": {
        "list_fields": ["_root_or_items"],  # result is a list OR has an items-like key
    },
    "get_patch_status": {
        "numeric_ranges": {"coverage": (0, 100)},
        "non_empty": ["_root"],
    },
    "get_tech_debt": {
        "list_fields": ["_root_or_items"],
    },
    "get_cloud_risk": {
        "non_empty": ["_root"],
    },
    "get_cdr_findings": {
        "non_empty": ["_root"],
    },
    "get_cve_details": {
        "non_empty": ["_root"],
    },
    "get_etm_findings": {
        "non_empty": ["_root"],
    },
    "get_scanner_health": {
        "non_empty": ["_root"],
    },
    "get_recommendations": {
        "list_fields": ["_root_or_items"],
    },
    "get_eliminate_status": {
        "non_empty": ["_root"],
    },
    "get_threat_intel": {
        "non_empty": ["_root"],
    },
    "investigate_cve": {
        "non_empty": ["_root"],
    },
    "get_asset_risk": {
        "required_fields": ["trurisk_score"],
        "numeric_ranges": {"trurisk_score": (0, 1000)},
    },
}

# ---------------------------------------------------------------------------
# Error indicators
# ---------------------------------------------------------------------------
ERROR_INDICATORS = ["error", "failed", "exception", "not found", "unauthorized"]


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


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _resolve_field(data, field):
    """Resolve a dot-notation field path in data. Returns (found, value)."""
    if field == "_root":
        return True, data
    parts = field.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return False, None
        else:
            return False, None
    return True, current


def _find_list_content(data):
    """Check if data itself is a non-empty list, or contains a list-valued key."""
    if isinstance(data, list):
        return len(data) > 0
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and len(v) > 0:
                return True
    return False


def _is_non_empty(value):
    """Check if a value is non-empty (non-null, non-empty string/list/dict)."""
    if value is None:
        return False
    if isinstance(value, str):
        return len(value.strip()) > 0
    if isinstance(value, (list, dict)):
        return len(value) > 0
    # numbers and booleans are always "non-empty"
    return True


def validate_schema(tool_name, result):
    """
    Validate result against the schema for tool_name.
    Returns (passed: bool, checks_total: int, checks_passed: int, details: list[str]).
    """
    schema = EVAL_SCHEMAS.get(tool_name)
    if schema is None:
        return True, 0, 0, ["no schema defined — auto-pass"]

    checks_total = 0
    checks_passed = 0
    details = []

    # Normalize: if result is a JSON string, parse it
    data = result
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            pass  # keep as string

    # required_fields
    for field in schema.get("required_fields", []):
        checks_total += 1
        found, value = _resolve_field(data, field)
        if found and value is not None:
            checks_passed += 1
        else:
            details.append(f"missing required field: {field}")

    # non_empty
    for field in schema.get("non_empty", []):
        checks_total += 1
        if field == "_root":
            if _is_non_empty(data):
                checks_passed += 1
            else:
                details.append("result is empty")
        else:
            found, value = _resolve_field(data, field)
            if found and _is_non_empty(value):
                checks_passed += 1
            else:
                details.append(f"field empty or missing: {field}")

    # numeric_ranges
    for field, (lo, hi) in schema.get("numeric_ranges", {}).items():
        checks_total += 1
        found, value = _resolve_field(data, field)
        if found and isinstance(value, (int, float)) and lo <= value <= hi:
            checks_passed += 1
        elif found and isinstance(value, (int, float)):
            details.append(f"{field}={value} out of range [{lo}, {hi}]")
        else:
            details.append(f"numeric field missing or wrong type: {field}")

    # list_fields
    for field in schema.get("list_fields", []):
        checks_total += 1
        if field == "_root_or_items":
            if _find_list_content(data):
                checks_passed += 1
            else:
                details.append("expected list content not found")
        else:
            found, value = _resolve_field(data, field)
            if found and isinstance(value, list) and len(value) > 0:
                checks_passed += 1
            else:
                details.append(f"list field empty or missing: {field}")

    passed = checks_total == 0 or checks_passed == checks_total
    return passed, checks_total, checks_passed, details


# ---------------------------------------------------------------------------
# Multi-keyword scoring
# ---------------------------------------------------------------------------

def detect_errors(result_str):
    """
    Check for error indicators in the response.
    Returns (has_errors: bool, matched_indicators: list[str]).
    """
    matched = [ind for ind in ERROR_INDICATORS if ind in result_str]
    return len(matched) > 0, matched


def score_keywords(result_str, expected_keywords, threshold):
    """
    Score keyword matches. Returns (matched, total, score_frac, passed).
    score_frac is matched/total. passed is score_frac >= threshold.
    """
    matched = [kw for kw in expected_keywords if kw.lower() in result_str]
    total = len(expected_keywords)
    score_frac = len(matched) / total if total > 0 else 0.0
    return matched, total, score_frac, score_frac >= threshold


# ---------------------------------------------------------------------------
# Claude-as-judge
# ---------------------------------------------------------------------------

def judge_with_claude(question, tool_name, result_str, model="claude-3-5-haiku-20241022"):
    """
    Call the Anthropic API to score the result 1-10 for relevance and completeness.
    Returns (score: int|None, explanation: str).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None, "ANTHROPIC_API_KEY not set"
    try:
        import anthropic
    except ImportError:
        return None, "anthropic package not installed"

    # Truncate result to avoid huge prompts
    truncated = result_str[:4000] if len(result_str) > 4000 else result_str
    prompt = (
        f"You are evaluating a Qualys security tool response.\n"
        f"Question: {question}\n"
        f"Tool: {tool_name}\n"
        f"Response (may be truncated):\n{truncated}\n\n"
        f"Score the response from 1-10 on relevance and completeness.\n"
        f"Reply with ONLY a JSON object: {{\"score\": <int 1-10>, \"reason\": \"<brief reason>\"}}"
    )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=150,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        parsed = json.loads(text)
        score = int(parsed["score"])
        return max(1, min(10, score)), parsed.get("reason", "")
    except Exception as e:
        return None, f"judge error: {str(e)[:100]}"


# ---------------------------------------------------------------------------
# Run a single eval
# ---------------------------------------------------------------------------

def run_eval(question, tool_name, kwargs, expected_keywords, optional=False,
             keyword_threshold=0.6, use_judge=False, judge_model="claude-3-5-haiku-20241022",
             scoring_mode="combined"):
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

    # Schema validation
    schema_pass, schema_total, schema_passed, schema_details = validate_schema(tool_name, result)

    # Multi-keyword scoring
    kw_matched, kw_total, kw_score, kw_pass = score_keywords(
        result_str, expected_keywords, keyword_threshold
    )

    # Error detection
    has_errors, error_indicators = detect_errors(result_str)

    # Claude-as-judge (optional)
    judge_score = None
    judge_reason = ""
    if use_judge:
        judge_score, judge_reason = judge_with_claude(
            question, tool_name, result_str, model=judge_model
        )

    # Weighted scoring
    schema_frac = (schema_passed / schema_total) if schema_total > 0 else 1.0
    error_frac = 0.0 if has_errors else 1.0

    if scoring_mode == "schema":
        passed = schema_pass
        weighted_score = 1.0 if schema_pass else 0.0
    elif scoring_mode == "keywords":
        passed = kw_pass
        weighted_score = kw_score
    else:  # combined
        # Schema 50%, Keywords 30%, Error-free 20%
        weighted_score = (schema_frac * 0.5) + (kw_score * 0.3) + (error_frac * 0.2)
        passed = weighted_score >= 0.5

    score_breakdown = {
        "schema": round(schema_frac, 2),
        "keywords": round(kw_score, 2),
        "error_free": round(error_frac, 2),
        "weighted": round(weighted_score, 2),
    }

    return {
        "question": question,
        "tool": tool_name,
        "status": "pass" if passed else "fail",
        "schema_pass": schema_pass,
        "schema_checks": f"{schema_passed}/{schema_total}" if schema_total > 0 else "n/a",
        "schema_details": schema_details,
        "keyword_matched": kw_matched,
        "keyword_score": f"{len(kw_matched)}/{kw_total}",
        "keyword_pass": kw_pass,
        "has_errors": has_errors,
        "error_indicators": error_indicators,
        "score_breakdown": score_breakdown,
        "judge_score": judge_score,
        "judge_reason": judge_reason,
        "result_size": len(result_str),
        "elapsed_s": round(elapsed, 2),
        # Keep backward compat fields
        "matched_keywords": kw_matched,
        "expected_keywords": expected_keywords,
    }


def print_results(results, score_pct, threshold, judge_enabled=False):
    """Print a summary table of eval results."""
    print()
    hdr_judge = "  Judge" if judge_enabled else ""
    print(f"{'#':<4} {'Status':<8} {'Tool':<28} {'Schema':<8} {'Keywords':<10} {'Errors':<8}{hdr_judge}  {'Score':>5}  {'Time':>7}  Question")
    print("─" * (110 + (8 if judge_enabled else 0)))

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
        question = r["question"][:38]

        schema_col = "—"
        kw_col = "—"
        err_col = "—"
        score_col = "—"
        judge_col = ""
        if status not in ("skipped", "error"):
            schema_col = "✓" if r.get("schema_pass") else "✗"
            kw_col = r.get("keyword_score", "—")
            err_col = "✗" if r.get("has_errors") else "✓"
            breakdown = r.get("score_breakdown", {})
            score_col = f"{breakdown.get('weighted', 0):.0%}" if breakdown else "—"
            if judge_enabled:
                js = r.get("judge_score")
                judge_col = f"  {js}/10" if js is not None else "  —"

        print(f"{i:<4} {icon:<8} {r['tool']:<28} {schema_col:<8} {kw_col:<10} {err_col:<8}{judge_col}  {score_col:>5}  {elapsed:>7}  {question}")

    print("─" * (110 + (8 if judge_enabled else 0)))
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    errors = sum(1 for r in results if r["status"] == "error")

    print(f"\nResults: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped")
    print(f"Score: {score_pct:.1f}% (threshold: {threshold}%)")

    # Show schema detail failures
    detail_failures = [r for r in results if r.get("schema_details") and
                       r["status"] not in ("skipped", "error") and
                       any(d != "no schema defined — auto-pass" for d in r.get("schema_details", []))]
    if detail_failures:
        print("\nSchema failures:")
        for r in detail_failures:
            for d in r["schema_details"]:
                if d != "no schema defined — auto-pass":
                    print(f"  {r['tool']}: {d}")

    if score_pct >= threshold:
        print("✅ PASSED")
    else:
        print("❌ FAILED")


def main():
    parser = argparse.ArgumentParser(description="Qualys MCP Eval Harness")
    parser.add_argument("--quick", action="store_true", help="Run only first 20 questions")
    parser.add_argument("--limit", type=int, help="Limit to N questions")
    parser.add_argument("--json", help="Save results as JSON file")
    parser.add_argument(
        "--judge", action="store_true",
        help="Enable Claude-as-judge scoring (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--judge-model", default="claude-3-5-haiku-20241022",
        help="Model for Claude-as-judge (default: claude-3-5-haiku-20241022)",
    )
    parser.add_argument(
        "--scoring-mode", choices=["combined", "schema", "keywords"],
        default="combined",
        help="Scoring mode: combined (default), schema, or keywords",
    )
    args = parser.parse_args()

    # Check env
    for var in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "QUALYS_BASE_URL", "QUALYS_GATEWAY_URL"]:
        if not os.environ.get(var):
            print(f"ERROR: {var} not set")
            sys.exit(2)

    threshold = int(os.environ.get("EVAL_PASS_THRESHOLD", "80"))
    keyword_threshold = float(os.environ.get("EVAL_KEYWORD_THRESHOLD", "0.6"))
    use_judge = args.judge or os.environ.get("EVAL_JUDGE") == "1"

    if use_judge and not os.environ.get("ANTHROPIC_API_KEY"):
        print("WARNING: --judge enabled but ANTHROPIC_API_KEY not set — judge scoring will be skipped")

    # Select questions
    questions = EVAL_QUESTIONS[:]
    if args.quick:
        questions = questions[:20]
    if args.limit:
        questions = questions[: args.limit]

    print(f"Qualys MCP Eval — {len(questions)} questions, threshold {threshold}%")
    scoring_mode = args.scoring_mode
    print(f"Scoring: {scoring_mode} | Keyword threshold: {keyword_threshold:.0%} | Judge: {'on' if use_judge else 'off'}")
    base = os.environ.get("QUALYS_BASE_URL", "?")
    host = base.split("/")[2] if "/" in base else base
    print(f"Server: {host}")
    print()

    results = []
    for desc, tool_name, kwargs, keywords, optional in questions:
        sys.stdout.write(f"  ⏱  {tool_name}...")
        sys.stdout.flush()
        r = run_eval(
            desc, tool_name, kwargs, keywords, optional,
            keyword_threshold=keyword_threshold,
            use_judge=use_judge,
            judge_model=args.judge_model,
            scoring_mode=scoring_mode,
        )
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

    print_results(results, score_pct, threshold, judge_enabled=use_judge)

    # Save JSON
    if args.json:
        output = {
            "timestamp": datetime.now().isoformat(),
            "score_pct": round(score_pct, 1),
            "threshold": threshold,
            "scoring_mode": scoring_mode,
            "keyword_threshold": keyword_threshold,
            "judge_enabled": use_judge,
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
