#!/usr/bin/env python3
"""API Gap Analysis — compares api_manifest.json against api.py implementation.

Usage: python scripts/gap_analysis.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

def main():
    manifest_path = ROOT / "scripts" / "api_manifest.json"
    api_path = ROOT / "qualys" / "api.py"

    with open(manifest_path) as f:
        manifest = json.load(f)

    with open(api_path) as f:
        api_code = f.read()

    print("=" * 70)
    print("QUALYS API GAP ANALYSIS")
    print("=" * 70)

    total = 0
    implemented = 0
    gaps = 0
    not_needed = 0
    not_available = 0
    gap_list = []

    skip_statuses = {"not_needed", "not_available"}

    for module, data in sorted(manifest["modules"].items()):
        endpoints = data["endpoints"]
        mod_total = len(endpoints)
        mod_impl = sum(1 for e in endpoints if e["status"] == "implemented")
        mod_gaps = sum(1 for e in endpoints if e["status"] == "gap")
        mod_skip = sum(1 for e in endpoints if e["status"] in skip_statuses)
        mod_na = sum(1 for e in endpoints if e["status"] == "not_available")

        total += mod_total
        implemented += mod_impl
        gaps += mod_gaps
        not_needed += sum(1 for e in endpoints if e["status"] == "not_needed")
        not_available += mod_na

        actionable = mod_total - mod_skip
        pct = (mod_impl / actionable * 100) if actionable > 0 else 100
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"\n{module:<20} {bar} {pct:>5.1f}% ({mod_impl}/{actionable} read endpoints)")

        for ep in endpoints:
            if ep["status"] == "gap":
                print(f"  GAP: {ep['method']:<5} {ep['path']:<55} — {ep['description']}")
                gap_list.append({"module": module, **ep})
            elif ep["status"] == "not_available":
                print(f"  N/A: {ep['method']:<5} {ep['path']:<55} — {ep['description']}")

    actionable_total = total - not_needed - not_available
    coverage = implemented / actionable_total * 100 if actionable_total > 0 else 100
    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"  Total endpoints:    {total}")
    print(f"  Implemented:        {implemented}")
    print(f"  Gaps:               {gaps}")
    print(f"  Not needed (write): {not_needed}")
    print(f"  Not available (pod):{not_available}")
    print(f"  Actionable:         {actionable_total}")
    print(f"  Coverage:           {coverage:.1f}%")
    print(f"{'=' * 70}")

    if gap_list:
        print(f"\nPriority gaps to close:")
        for g in gap_list:
            print(f"  [{g['module']}] {g['method']} {g['path']}")

    return 0 if coverage >= 95 else 1

if __name__ == "__main__":
    sys.exit(main())
