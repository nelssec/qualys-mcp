#!/usr/bin/env python3
"""Compare benchmark results against a baseline, fail if any tool regressed >2x."""

import json
import sys


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <baseline.json> <results.json>")
        sys.exit(1)

    baseline_path, results_path = sys.argv[1], sys.argv[2]

    with open(baseline_path) as f:
        baseline = json.load(f)
    with open(results_path) as f:
        results = json.load(f)

    baseline_by_tool = {r["tool"]: r for r in baseline["results"]}
    results_by_tool = {r["tool"]: r for r in results["results"]}

    regressions = []
    print(f"{'Tool':<40s} {'Baseline cold':>14s} {'Actual cold':>12s} {'Ratio':>7s}  {'Status'}")
    print("-" * 90)

    for tool, base in baseline_by_tool.items():
        actual = results_by_tool.get(tool)
        if actual is None:
            print(f"{tool:<40s} {'—':>14s} {'MISSING':>12s} {'—':>7s}  SKIP")
            continue

        base_cold = base["cold_s"]
        actual_cold = actual["cold_s"]
        ratio = actual_cold / base_cold if base_cold > 0 else 0
        status = "PASS" if ratio <= 2.0 else "FAIL"

        print(f"{tool:<40s} {base_cold:>13.2f}s {actual_cold:>11.2f}s {ratio:>6.1f}x  {status}")

        if ratio > 2.0:
            regressions.append(
                f"{tool}: {actual_cold:.2f}s vs baseline {base_cold:.2f}s ({ratio:.1f}x)"
            )

    print()
    if regressions:
        print(f"FAILED — {len(regressions)} tool(s) regressed >2x baseline:")
        for r in regressions:
            print(f"  - {r}")
        sys.exit(1)
    else:
        print("PASSED — all tools within 2x baseline")


if __name__ == "__main__":
    main()
