#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import re
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent
RESULTS_DIR = ROOT / "eval_results"
RESULTS_DIR.mkdir(exist_ok=True)

ALLOWED_TOOLS = "mcp__qualys__assess_risk,mcp__qualys__security_overview,mcp__qualys__plan_remediation,mcp__qualys__investigate,mcp__qualys__check_compliance,mcp__qualys__reports,mcp__qualys__cache_status"
MAX_TURNS = "8"
ROUND_NUMBERS = {50, 100, 150, 200, 250, 500, 1000, 2000, 5000, 10000}


def check_round_numbers(text):
    warnings = []
    for match in re.finditer(r'(\b\w+)[\s:=]+(\d{2,6})\b', text):
        key, val = match.group(1), int(match.group(2))
        if val in ROUND_NUMBERS and any(h in key.lower() for h in ("total", "count", "found", "assets", "images", "containers", "findings")):
            warnings.append(f"{key}={val}")
    return warnings


def run_question(question_text, timeout=180):
    start = time.time()
    try:
        result = subprocess.run(
            ["claude", "-p", "--allowedTools", ALLOWED_TOOLS, "--max-turns", MAX_TURNS],
            input=question_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ},
        )
        elapsed = time.time() - start
        output = result.stdout.strip()
        error = result.stderr.strip()

        has_data = bool(output and len(output) > 50)
        has_error = result.returncode != 0 or "reached max turns" in output.lower() or (output.lower().startswith("error") and len(output) < 100)
        round_warnings = check_round_numbers(output)

        return {
            "passed": has_data and not has_error,
            "response_time_s": round(elapsed, 1),
            "output_length": len(output),
            "output_preview": output[:300],
            "round_number_warnings": round_warnings,
            "error": error[:200] if has_error else "",
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "passed": False,
            "response_time_s": timeout,
            "output_length": 0,
            "output_preview": "",
            "round_number_warnings": [],
            "error": f"timeout after {timeout}s",
            "exit_code": -1,
        }
    except Exception as e:
        return {
            "passed": False,
            "response_time_s": time.time() - start,
            "output_length": 0,
            "output_preview": "",
            "round_number_warnings": [],
            "error": str(e)[:200],
            "exit_code": -1,
        }


def run_conversation(turns, timeout=180):
    results = []
    context = ""
    for i, turn in enumerate(turns):
        question = turn.get("content", turn.get("question", ""))
        if context:
            full_prompt = f"Previous context:\n{context[:500]}\n\nUser: {question}"
        else:
            full_prompt = question

        result = run_question(full_prompt, timeout=timeout)
        result["turn"] = i + 1
        result["question"] = question
        result["expected_workflow"] = turn.get("expected_workflow", "unknown")
        results.append(result)

        if result["passed"]:
            context = result["output_preview"]

    return results


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--questions-file", default=str(ROOT / "eval" / "v3_stress_test.json"))
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--singles-only", action="store_true")
    parser.add_argument("--conversations-only", action="store_true")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    with open(args.questions_file) as f:
        data = json.load(f)

    singles = data.get("single_turn", [])
    convos = data.get("conversations", [])

    all_results = {"single_turn": [], "conversations": [], "metadata": {}}
    passed = 0
    failed = 0
    round_warnings_total = []

    if not args.conversations_only:
        subset = singles[args.offset:args.offset + args.limit]
        print(f"[*] Running {len(subset)} single-turn questions via headless Claude...")
        for i, q in enumerate(subset):
            qtext = q.get("question", "")
            result = run_question(qtext, timeout=args.timeout)
            result["question_id"] = q.get("id", i)
            result["question"] = qtext
            result["expected_workflow"] = q.get("expected_workflow", "unknown")
            result["category"] = q.get("category", "unknown")
            all_results["single_turn"].append(result)

            if result["passed"]:
                passed += 1
            else:
                failed += 1
                print(f"  [{i+1}] FAIL: {qtext[:60]}... err={result['error'][:60]}")

            if result["round_number_warnings"]:
                round_warnings_total.extend(result["round_number_warnings"])
                print(f"  [{i+1}] ROUND NUM WARNING: {result['round_number_warnings']}")

            if (i + 1) % 5 == 0:
                print(f"  [{i+1}/{len(subset)}] {passed}P/{failed}F avg={sum(r['response_time_s'] for r in all_results['single_turn'])/len(all_results['single_turn']):.1f}s")

    if not args.singles_only:
        conv_subset = convos[:min(args.limit // 5, len(convos))]
        print(f"\n[*] Running {len(conv_subset)} conversations via headless Claude...")
        for i, conv in enumerate(conv_subset):
            turns = conv.get("turns", [])
            turn_results = run_conversation(turns, timeout=args.timeout)
            conv_passed = all(r["passed"] for r in turn_results)
            all_results["conversations"].append({
                "conv_id": conv.get("id", i),
                "title": conv.get("title", ""),
                "passed": conv_passed,
                "turns": turn_results,
            })
            if conv_passed:
                passed += 1
            else:
                failed += 1
                failed_turns = [r for r in turn_results if not r["passed"]]
                print(f"  Conv [{i+1}] FAIL at turn {failed_turns[0]['turn']}: {failed_turns[0]['error'][:60]}")
            if (i + 1) % 5 == 0:
                print(f"  [{i+1}/{len(conv_subset)}] conversations done")

    total = passed + failed
    all_results["metadata"] = {
        "date": datetime.now().isoformat(),
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / total * 100, 1) if total else 0,
        "round_number_warnings": round_warnings_total,
    }

    outfile = RESULTS_DIR / f"headless_claude_{datetime.now().strftime('%Y-%m-%d_%H%M')}.json"
    with open(outfile, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[*] Results saved to {outfile}")

    print(f"\n{'=' * 60}")
    print(f"HEADLESS CLAUDE TEST RESULTS")
    print(f"{'=' * 60}")
    print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Rate: {all_results['metadata']['pass_rate']}%")
    if round_warnings_total:
        print(f"\nROUND NUMBER WARNINGS ({len(round_warnings_total)}):")
        for w in set(round_warnings_total):
            print(f"  ! {w}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
