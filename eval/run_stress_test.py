#!/usr/bin/env python3
import argparse
import json
import os
import re
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime
from pathlib import Path

from qualys.workflows.investigate import investigate
from qualys.workflows.assess_risk import assess_risk
from qualys.workflows.overview import security_overview
from qualys.workflows.compliance import check_compliance
from qualys.workflows.remediation import plan_remediation

WORKFLOW_MAP = {
    "investigate": investigate,
    "assess_risk": assess_risk,
    "security_overview": security_overview,
    "check_compliance": check_compliance,
    "plan_remediation": plan_remediation,
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_interrupted = False
_results = []


def _signal_handler(sig, frame):
    global _interrupted
    print("\n[!] Ctrl+C received — saving partial results...")
    _interrupted = True


def extract_params(question_text, workflow_name):
    q = question_text.lower()
    params = {}

    if workflow_name == "investigate":
        cve_match = CVE_RE.search(question_text)
        if cve_match:
            params["target"] = cve_match.group(0).upper()
        elif "ransomware" in q:
            params["target"] = "ransomware"
        elif "apt" in q:
            apt_match = re.search(r"apt\d+", q, re.IGNORECASE)
            params["target"] = apt_match.group(0).upper() if apt_match else "APT"
        elif "lazarus" in q:
            params["target"] = "Lazarus"
        elif "volt typhoon" in q:
            params["target"] = "Volt Typhoon"
        elif "salt typhoon" in q:
            params["target"] = "Salt Typhoon"
        else:
            params["target"] = question_text[:80]
        params["depth"] = "quick"

    elif workflow_name == "assess_risk":
        if "cloud" in q:
            params["scope"] = "cloud"
        elif "container" in q:
            params["scope"] = "containers"
        elif "web" in q or "was" in q:
            params["scope"] = "web"
        elif "cert" in q or "ssl" in q or "tls" in q:
            params["scope"] = "certs"
        elif "edr" in q or "endpoint" in q:
            params["scope"] = "edr"
        elif "fim" in q:
            params["scope"] = "fim"
        else:
            params["scope"] = "all"
        params["limit"] = 10

    elif workflow_name == "security_overview":
        params["quick"] = True
        if "week" in q:
            params["period"] = "week"
        elif "month" in q:
            params["period"] = "month"
        else:
            params["period"] = "today"
        params["scope"] = "all"

    elif workflow_name == "check_compliance":
        if "pci" in q:
            params["framework"] = "PCI"
        elif "hipaa" in q:
            params["framework"] = "HIPAA"
        elif "cis" in q:
            params["framework"] = "CIS"
        elif "stig" in q or "disa" in q:
            params["framework"] = "DISA STIG"
        elif "nist" in q:
            params["framework"] = "NIST"
        else:
            params["framework"] = ""
        params["limit"] = 10

    elif workflow_name == "plan_remediation":
        if "patch" in q:
            params["scope"] = "patches"
        elif "mitigat" in q:
            params["scope"] = "mitigations"
        else:
            params["scope"] = "all"
        cve_match = CVE_RE.search(question_text)
        if cve_match:
            params["cves"] = [cve_match.group(0).upper()]
        params["limit"] = 10

    return params


def validate_response(resp):
    if not isinstance(resp, dict):
        return False, "response is not a dict"
    summary = resp.get("summary")
    if not isinstance(summary, dict):
        return False, "missing or invalid summary"
    headline = summary.get("headline", "")
    if not headline:
        return False, "summary missing headline"
    risk_level = resp.get("risk_level") or summary.get("risk_level")
    if not risk_level:
        return False, "missing risk_level"
    data = resp.get("data")
    if data is None:
        return False, "missing data"
    if isinstance(data, dict) and not data:
        return False, "data is empty dict"
    if isinstance(data, list) and not data:
        return False, "data is empty list"

    pagination_warnings = _check_round_numbers(resp)
    if pagination_warnings:
        headline += f" [WARN: {'; '.join(pagination_warnings)}]"

    return True, headline


ROUND_NUMBERS = {50, 100, 150, 200, 250, 500, 1000, 2000, 5000, 10000}


def _check_round_numbers(obj, path="", warnings=None):
    if warnings is None:
        warnings = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{path}.{k}" if path else k
            if isinstance(v, int) and v in ROUND_NUMBERS and k.lower() not in (
                "limit", "pagesize", "page_size", "truncation_limit",
            ):
                if any(hint in k.lower() for hint in ("total", "count", "num", "size", "found")):
                    warnings.append(f"{full_key}={v} (possible pagination truncation)")
            elif isinstance(v, (dict, list)):
                _check_round_numbers(v, full_key, warnings)
    elif isinstance(obj, list) and len(obj) in ROUND_NUMBERS and len(obj) >= 50:
        warnings.append(f"{path} has exactly {len(obj)} items (possible pagination)")
    return warnings


def run_single(question_entry, timeout=120):
    qid = question_entry["id"]
    question_text = question_entry["question"]
    workflow_name = question_entry.get("expected_workflow", "investigate")
    category = question_entry.get("category", "unknown")

    fn = WORKFLOW_MAP.get(workflow_name)
    if fn is None:
        return {
            "question_id": qid,
            "workflow": workflow_name,
            "category": category,
            "passed": False,
            "response_time_ms": 0,
            "headline": "",
            "error": f"unknown workflow: {workflow_name}",
        }

    params = question_entry.get("params_hint", {}).copy()
    extracted = extract_params(question_text, workflow_name)
    for k, v in extracted.items():
        if k not in params:
            params[k] = v

    start = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fn, **params)
            resp = future.result(timeout=timeout)
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except FuturesTimeout:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "question_id": qid,
            "workflow": workflow_name,
            "category": category,
            "passed": False,
            "response_time_ms": elapsed_ms,
            "headline": "",
            "error": f"timeout after {timeout}s",
        }
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "question_id": qid,
            "workflow": workflow_name,
            "category": category,
            "passed": False,
            "response_time_ms": elapsed_ms,
            "headline": "",
            "error": str(e)[:200],
        }

    passed, info = validate_response(resp)
    return {
        "question_id": qid,
        "workflow": workflow_name,
        "category": category,
        "passed": passed,
        "response_time_ms": elapsed_ms,
        "headline": info[:120] if passed else "",
        "error": "" if passed else info,
    }


def run_conversation(conv_entry, timeout=120):
    conv_id = conv_entry["id"]
    title = conv_entry.get("title", "")
    category = conv_entry.get("category", "unknown")
    turns = conv_entry.get("turns", [])
    turn_results = []
    context = ""

    for i, turn_entry in enumerate(turns):
        if _interrupted:
            break

        if isinstance(turn_entry, dict):
            turn_text = turn_entry.get("content", turn_entry.get("question", ""))
            turn_workflow = turn_entry.get("expected_workflow", "investigate")
        else:
            turn_text = str(turn_entry)
            turn_workflow = "investigate"

        fn = WORKFLOW_MAP.get(turn_workflow, investigate)
        params = extract_params(turn_text, turn_workflow)
        if turn_workflow == "investigate" and "prior_context" not in params:
            params["prior_context"] = context

        start = time.monotonic()
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fn, **params)
                resp = future.result(timeout=timeout)
            elapsed_ms = int((time.monotonic() - start) * 1000)
        except FuturesTimeout:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            turn_results.append({
                "turn": i + 1,
                "passed": False,
                "response_time_ms": elapsed_ms,
                "error": f"timeout after {timeout}s",
            })
            continue
        except Exception as e:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            turn_results.append({
                "turn": i + 1,
                "passed": False,
                "response_time_ms": elapsed_ms,
                "error": str(e)[:200],
            })
            continue

        passed, info = validate_response(resp)
        turn_results.append({
            "turn": i + 1,
            "passed": passed,
            "response_time_ms": elapsed_ms,
            "headline": info[:120] if passed else "",
            "error": "" if passed else info,
        })

        if passed:
            if isinstance(resp, str):
                context = resp[:200]
            else:
                summary = resp.get("summary", {})
                context = summary.get("headline", turn_text[:80]) if isinstance(summary, dict) else str(summary)[:200]

    all_passed = all(t["passed"] for t in turn_results) if turn_results else False
    total_ms = sum(t["response_time_ms"] for t in turn_results)

    return {
        "conversation_id": conv_id,
        "title": title,
        "category": category,
        "num_turns": len(turns),
        "passed": all_passed,
        "total_response_time_ms": total_ms,
        "turns": turn_results,
    }


def save_results(results, conversations_results, out_path):
    total_single = len(results)
    passed_single = sum(1 for r in results if r["passed"])
    times = [r["response_time_ms"] for r in results if r["response_time_ms"] > 0]
    avg_time = int(sum(times) / len(times)) if times else 0

    failures_by_cat = {}
    for r in results:
        if not r["passed"]:
            cat = r.get("category", "unknown")
            failures_by_cat.setdefault(cat, []).append(r["question_id"])

    total_conv = len(conversations_results)
    passed_conv = sum(1 for c in conversations_results if c["passed"])

    output = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "single_turn": {
                "total": total_single,
                "passed": passed_single,
                "failed": total_single - passed_single,
                "pass_rate": round(passed_single / total_single * 100, 1) if total_single else 0,
                "avg_response_time_ms": avg_time,
            },
            "conversations": {
                "total": total_conv,
                "passed": passed_conv,
                "failed": total_conv - passed_conv,
                "pass_rate": round(passed_conv / total_conv * 100, 1) if total_conv else 0,
            },
            "failures_by_category": failures_by_cat,
        },
        "single_turn_results": results,
        "conversation_results": conversations_results,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    return output["summary"]


def print_summary(summary):
    st = summary["single_turn"]
    cv = summary["conversations"]
    print("\n" + "=" * 60)
    print("STRESS TEST RESULTS")
    print("=" * 60)
    print(f"Single-turn: {st['passed']}/{st['total']} passed ({st['pass_rate']}%)")
    print(f"  Avg response time: {st['avg_response_time_ms']}ms")
    print(f"Conversations: {cv['passed']}/{cv['total']} passed ({cv['pass_rate']}%)")
    failures = summary.get("failures_by_category", {})
    if failures:
        print("\nFailures by category:")
        for cat, ids in sorted(failures.items()):
            print(f"  {cat}: {len(ids)} failures (IDs: {ids[:5]}{'...' if len(ids) > 5 else ''})")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Qualys MCP stress test runner")
    parser.add_argument("--limit", type=int, default=0, help="Max questions to run (0=all)")
    parser.add_argument("--category", type=str, default="", help="Filter by category")
    parser.add_argument("--conversations-only", action="store_true")
    parser.add_argument("--singles-only", action="store_true")
    parser.add_argument("--timeout", type=int, default=120, help="Per-question timeout in seconds")
    parser.add_argument("--questions-file", type=str,
                        default=str(Path(__file__).parent / "v3_stress_test.json"))
    parser.add_argument("--conversations-file", type=str,
                        default=str(Path(__file__).parent / "v3_conversations.json"))
    args = parser.parse_args()

    for var in ("QUALYS_USERNAME", "QUALYS_PASSWORD", "QUALYS_POD"):
        if not os.environ.get(var):
            print(f"[ERROR] {var} not set in environment")
            sys.exit(1)

    signal.signal(signal.SIGINT, _signal_handler)

    global _results
    single_results = []
    conv_results = []

    if not args.conversations_only:
        try:
            with open(args.questions_file) as f:
                raw = json.load(f)
            questions = raw.get("single_turn", raw) if isinstance(raw, dict) else raw
        except FileNotFoundError:
            print(f"[WARN] Questions file not found: {args.questions_file}")
            questions = []

        if args.category:
            questions = [q for q in questions if q.get("category", "").lower() == args.category.lower()]

        if args.limit > 0:
            questions = questions[:args.limit]

        total = len(questions)
        print(f"[*] Running {total} single-turn questions...", flush=True)

        for i, q in enumerate(questions):
            if _interrupted:
                break
            if (i + 1) % 10 == 0:
                print(f"  [{i + 1}/{total}] progress...", flush=True)
            result = run_single(q, timeout=args.timeout)
            single_results.append(result)
            status = "PASS" if result["passed"] else "FAIL"
            if not result["passed"]:
                print(f"  [{i + 1}] {status} q={result['question_id']} err={result['error'][:60]}", flush=True)

    if not args.singles_only and not _interrupted:
        try:
            with open(args.questions_file) as f:
                raw = json.load(f)
            conversations = raw.get("conversations", []) if isinstance(raw, dict) else []
        except FileNotFoundError:
            print(f"[WARN] Questions file not found: {args.questions_file}")
            conversations = []

        if args.category:
            conversations = [c for c in conversations if c.get("category", "").lower() == args.category.lower()]

        if args.limit > 0:
            conversations = conversations[:args.limit]

        total_conv = len(conversations)
        print(f"[*] Running {total_conv} conversations...")

        for i, conv in enumerate(conversations):
            if _interrupted:
                break
            if (i + 1) % 10 == 0:
                print(f"  [{i + 1}/{total_conv}] conversations progress...")
            result = run_conversation(conv, timeout=args.timeout)
            conv_results.append(result)
            status = "PASS" if result["passed"] else "FAIL"
            print(f"  [{i + 1}] {status} conv={result['conversation_id']} \"{result['title'][:40]}\" turns={result['num_turns']}")

    _save_and_print(single_results, conv_results)


def _save_and_print(single_results, conv_results):
    ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    out_path = Path(__file__).parent.parent / "eval_results" / f"stress_test_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary = save_results(single_results, conv_results, out_path)
    print(f"\n[*] Results saved to {out_path}", flush=True)
    print_summary(summary)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL] {e}", flush=True)
        if _results:
            _save_and_print(_results, [])
        raise
