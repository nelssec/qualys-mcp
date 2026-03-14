#!/usr/bin/env python3
"""
Qualys MCP Benchmark — measures tool latency cold and warm.

Calls each MCP tool twice and reports cold and warm latency.
First call = cold (cache empty), second call = warm (cache populated).

Usage:
    python benchmark.py                          # Run all benchmarks
    python benchmark.py --tool get_morning_report  # Single tool only
    python benchmark.py --quick                  # Fast tools only (<10s expected)
    python benchmark.py --csv results.csv        # Save results to CSV
    python benchmark.py --json results.json      # Save results as JSON

Requires env vars:
    QUALYS_USERNAME
    QUALYS_PASSWORD
    QUALYS_BASE_URL       (e.g. qualysapi.qualys.com)
    QUALYS_GATEWAY_URL    (e.g. gateway.qg1.apps.qualys.com)

Optional:
    QUALYS_SSL_VERIFY=false    (for self-signed certs)
    BENCHMARK_ASSET_ID=...     (asset ID for get_asset_risk test)
    BENCHMARK_CVE=...          (CVE for investigate_cve test, default: CVE-2021-44228)
    BENCHMARK_IMAGE_ID=...     (container image ID for get_image_vulns test)
"""

import time
import json
import sys
import os
import csv
import argparse
from datetime import datetime

# ---- ensure qualys_mcp is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import qualys_mcp
except ImportError as e:
    print(f"ERROR: Could not import qualys_mcp: {e}")
    print("Run from the qualys-mcp project root directory.")
    sys.exit(1)

# ---- benchmark definitions
# (function_name, kwargs, description, quick?)
BENCHMARKS = [
    # Fast tools — CSAM-heavy, should be <5s cold, <1s warm
    ("get_security_posture",    {},                                     "Security posture (CSAM concurrent)",   True),
    ("get_weekly_priorities",   {"limit": 10},                          "Weekly priorities (9x parallel CSAM)", True),
    ("get_patch_status",        {"limit": 10},                          "Patch status",                         True),
    ("get_new_vulns",           {"days": 7},                            "New vulns (Qualys KB API)",             True),
    ("get_tech_debt",           {"limit": 20},                          "Tech debt (paginated CSAM)",            True),

    # Medium tools — mix of fast and slow APIs
    ("get_morning_report",      {},                                     "Morning report (multi-concurrent)",    False),
    ("get_scanner_health",      {},                                     "Scanner health (appliance XML)",       False),
    ("get_eliminate_status",    {},                                     "Eliminate status (PM+MTG concurrent)", False),
    ("get_cdr_findings",        {"days": 7},                            "CDR findings (TotalCloud)",            False),
    ("get_cloud_risk",          {},                                     "Cloud risk (sequential providers)",    False),
    ("get_recommendations",     {},                                     "Recommendations (cloud+CSAM)",         False),

    # Slow tools — VMDR or complex async
    ("get_threat_intel",        {"threat_type": "Ransomware"},          "Threat intel (VMDR detection API)",    False),
    ("get_etm_findings",        {},                                     "ETM findings (report API)",            False),
    ("investigate_cve",         {"cve": os.environ.get("BENCHMARK_CVE", "CVE-2021-44228")},
                                                                        "CVE investigation (KB+CSAM+QDS)",      False),
    ("get_cve_details",         {"cves": "CVE-2021-44228,CVE-2024-3400"},
                                                                        "CVE details bulk (2 CVEs)",            False),

    # Conditional — require specific IDs
    # ("get_asset_risk",        {"asset_id": os.environ.get("BENCHMARK_ASSET_ID", "0")}, ...),
    # ("get_image_vulns",       {"image_id": os.environ.get("BENCHMARK_IMAGE_ID", "0")}, ...),
]

TARGETS = {
    "cold": {
        "fast": 5.0,
        "medium": 15.0,
        "slow": 60.0,
    },
    "warm": {
        "fast": 1.0,
        "medium": 3.0,
        "slow": 5.0,
    }
}

FAST_TOOLS = {b[0] for b in BENCHMARKS if b[3]}


def get_tool_fn(name):
    fn = getattr(qualys_mcp, name, None)
    if fn is None:
        return None
    # FastMCP wraps tools — get the underlying function
    if hasattr(fn, 'fn'):
        return fn.fn
    return fn


def run_benchmark(tool_name, kwargs, description, runs=2):
    fn = get_tool_fn(tool_name)
    if fn is None:
        return {"tool": tool_name, "error": "function not found", "description": description}

    times = []
    errors = []
    result_sizes = []

    for i in range(runs):
        start = time.perf_counter()
        try:
            result = fn(**kwargs)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
            size = len(json.dumps(result)) if result else 0
            result_sizes.append(size)
        except Exception as e:
            elapsed = time.perf_counter() - start
            times.append(elapsed)
            errors.append(str(e))
            result_sizes.append(0)

    cold = times[0]
    warm = min(times[1:]) if len(times) > 1 else None
    avg_size = sum(result_sizes) / len(result_sizes) if result_sizes else 0

    return {
        "tool": tool_name,
        "description": description,
        "cold_s": round(cold, 2),
        "warm_s": round(warm, 2) if warm is not None else None,
        "runs": runs,
        "result_size_bytes": int(avg_size),
        "errors": errors,
    }


def status_icon(cold, warm, tool_name):
    is_fast = tool_name in FAST_TOOLS
    target_cold = TARGETS["cold"]["fast"] if is_fast else TARGETS["cold"]["medium"]
    target_warm = TARGETS["warm"]["fast"] if is_fast else TARGETS["warm"]["medium"]

    if warm is None:
        return "❓"
    if cold <= target_cold and warm <= target_warm:
        return "✅"
    if warm <= target_warm:
        return "⚠️ cold"
    return "🐢 slow"


def print_results(results, show_targets=True):
    print()
    print(f"{'Tool':<32} {'Cold (s)':>10} {'Warm (s)':>10} {'Size':>8}  {'Status'}")
    print("─" * 78)

    for r in results:
        if "error" in r:
            print(f"{r['tool']:<32} {'N/A':>10} {'N/A':>10} {'—':>8}  ❌ {r['error'][:20]}")
            continue

        cold_str = f"{r['cold_s']:.2f}"
        warm_str = f"{r['warm_s']:.2f}" if r['warm_s'] is not None else "N/A"
        size_str = f"{r['result_size_bytes']//1024}K" if r['result_size_bytes'] > 1024 else f"{r['result_size_bytes']}B"
        icon = status_icon(r['cold_s'], r['warm_s'], r['tool'])

        errors_str = f"  ⚠ {r['errors'][0][:40]}" if r.get('errors') else ""
        print(f"{r['tool']:<32} {cold_str:>10} {warm_str:>10} {size_str:>8}  {icon}{errors_str}")

    # Summary
    ok = sum(1 for r in results if "error" not in r and status_icon(r['cold_s'], r['warm_s'], r['tool']).startswith("✅"))
    slow = [r for r in results if "error" not in r and status_icon(r['cold_s'], r['warm_s'], r['tool']).startswith("🐢")]

    print()
    print(f"Results: {ok}/{len(results)} within targets")
    if slow:
        print(f"Slow tools needing optimization:")
        for r in slow:
            print(f"  - {r['tool']}: cold={r['cold_s']}s warm={r['warm_s']}s")

    if show_targets:
        print()
        print("Targets:")
        print(f"  Fast tools (CSAM-heavy): cold <{TARGETS['cold']['fast']}s, warm <{TARGETS['warm']['fast']}s")
        print(f"  Medium tools: cold <{TARGETS['cold']['medium']}s, warm <{TARGETS['warm']['medium']}s")


def save_csv(results, path):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["tool", "description", "cold_s", "warm_s", "result_size_bytes", "runs", "errors"])
        writer.writeheader()
        for r in results:
            row = {k: v for k, v in r.items()}
            row['errors'] = '; '.join(row.get('errors', []))
            writer.writerow(row)
    print(f"CSV saved: {path}")


def save_json(results, path):
    output = {
        "timestamp": datetime.now().isoformat(),
        "results": results,
        "targets": TARGETS,
    }
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"JSON saved: {path}")


def main():
    parser = argparse.ArgumentParser(description="Qualys MCP Benchmark")
    parser.add_argument("--tool", help="Run only this tool")
    parser.add_argument("--quick", action="store_true", help="Run fast tools only (<5s expected)")
    parser.add_argument("--csv", help="Save results to CSV file")
    parser.add_argument("--json", help="Save results as JSON file")
    parser.add_argument("--runs", type=int, default=2, help="Number of runs per tool (default: 2)")
    args = parser.parse_args()

    # Check env
    missing = [v for v in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "QUALYS_BASE_URL", "QUALYS_GATEWAY_URL"]
               if not os.environ.get(v)]
    if missing:
        print(f"ERROR: Missing environment variables: {', '.join(missing)}")
        sys.exit(1)

    # Select benchmarks
    benchmarks = BENCHMARKS
    if args.tool:
        benchmarks = [b for b in BENCHMARKS if b[0] == args.tool]
        if not benchmarks:
            print(f"ERROR: Tool '{args.tool}' not found in benchmark list")
            print("Available:", ", ".join(b[0] for b in BENCHMARKS))
            sys.exit(1)
    elif args.quick:
        benchmarks = [b for b in BENCHMARKS if b[3]]

    print(f"Qualys MCP Benchmark — {len(benchmarks)} tools, {args.runs} runs each")
    base = os.environ.get("QUALYS_BASE_URL", "?"); host = base.split("/")[2] if "/" in base else base; print(f"Server: {host}")
    print(f"CVE test: {os.environ.get('BENCHMARK_CVE', 'CVE-2021-44228')}")
    print()

    results = []
    for tool_name, kwargs, description, _ in benchmarks:
        fn = get_tool_fn(tool_name)
        if fn is None:
            print(f"  SKIP {tool_name} — not found (tool may not be exposed yet)")
            continue

        sys.stdout.write(f"  ⏱  {tool_name}...")
        sys.stdout.flush()

        r = run_benchmark(tool_name, kwargs, description, runs=args.runs)
        results.append(r)

        cold_str = f"{r['cold_s']:.2f}s"
        warm_str = f"{r['warm_s']:.2f}s" if r['warm_s'] is not None else "—"
        print(f"\r  ✓  {tool_name:<35} cold={cold_str:<8} warm={warm_str}")

    print_results(results)

    if args.csv:
        save_csv(results, args.csv)
    if args.json:
        save_json(results, args.json)


if __name__ == "__main__":
    main()
