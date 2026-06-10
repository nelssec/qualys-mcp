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

    unwired = check_wiring()
    return 0 if (coverage >= 95 and not unwired) else 1


# Infra helpers used internally by api.py / the server itself — not expected to
# be referenced from aggregators or workflows.
_WIRING_ALLOWLIST = {
    "normalize_url", "resolve_platform", "compact", "short_date", "safe_int",
    "short_host", "is_eol_stage", "get_criticality", "api_get", "etm_api",
    "etm_download", "get_bearer_token", "clear_memory_cache",
    "get_api_error_counts", "reset_api_error_counts", "get_available_modules",
    "module_status_summary", "parse_vuln_xml", "get_kb",
}

# Domain functions that exist but intentionally have no tool surface yet —
# reported for visibility but non-failing. Wire or remove before adding more.
_DORMANT_PENDING_TOOL = {
    "get_detections_by_qds",      # QDS hotlist — too slow (>70s) for dispatch timeouts on large envs
    "get_assets",                 # superseded by csam_search direct use
    "get_asset_count",            # superseded by csam_count direct use
    "get_aws_org_connector_job_summary",  # drill-down for aws_org_connectors tool
    "get_pm_job_summary",         # 404 on US2 gateway (manifest: not_available)
    "get_mtg_job_detail",         # 404 on US2 gateway (manifest: not_available)
    "get_policy_technologies",    # policy_audit drill-down
    "get_saasdr_control",         # per-control drill-down
    "get_fim_events_v2",          # candidate replacement for _fetch_fim_events_raw
    "get_fim_assets",             # fim_posture uses count; full listing pending
    "get_edr_events_v2",          # searchAfter w/ user attribution — candidate edr_events upgrade
    "get_container_detail",       # container drill-down by sha
    "get_image_detail",           # image drill-down (image_vulns uses get_image_details)
    "get_cloud_eval_resources",   # superseded by v2 per-control endpoint
    "get_patch_catalog",          # full-catalog pull too heavy for interactive use
    "get_asset_components",       # CSAM component search — returns empty on US2 software filters
    "get_cloud_control_metadata", # 404 on US2 (manifest: not_available)
    "get_cloud_mandates",         # report-mandate listing, no question maps to it yet
    "get_cloud_exceptions",       # 404 on US2 (manifest: not_available)
    "get_iac_scans",              # IaC posture — pending question demand
    "get_cloud_eval_resources_v2",# per-control drill-down pending tool surface
    "get_fim_event_detail",       # single-event drill-down
    "get_cs_centralized_policy",  # CS 1.43 by-ID drill-down
}


def check_wiring():
    """Report implemented api.py functions that nothing user-reachable calls.

    Manifest 'implemented' only proves the function exists; an aggregator or
    workflow must reference it for any MCP tool to reach it. Unwired functions
    are dormant capability and usually indicate an incomplete integration.
    """
    import re
    api_src = (ROOT / "qualys" / "api.py").read_text()
    callers = "".join(
        p.read_text() for p in
        [ROOT / "qualys" / "aggregators.py", ROOT / "qualys_mcp.py"]
        + sorted((ROOT / "qualys" / "workflows").glob("*.py"))
    )
    public_fns = re.findall(r"^def ([a-z][a-z0-9_]*)\(", api_src, re.MULTILINE)
    unreferenced = [
        fn for fn in public_fns
        if fn not in _WIRING_ALLOWLIST
        and not re.search(rf"\b{fn}\b", callers)
    ]
    dormant = [fn for fn in unreferenced if fn in _DORMANT_PENDING_TOOL]
    unwired = [fn for fn in unreferenced if fn not in _DORMANT_PENDING_TOOL]
    stale_dormant = sorted(_DORMANT_PENDING_TOOL - set(unreferenced))
    if dormant:
        print(f"\nDormant api.py functions (known, pending tool surface): {len(dormant)}")
    if stale_dormant:
        print(f"Stale dormant entries (now wired — remove from _DORMANT_PENDING_TOOL): {', '.join(stale_dormant)}")
    if unwired:
        print(f"\nUNWIRED api.py functions (new, unclassified — FAILING):")
        for fn in unwired:
            print(f"  {fn}")
        print(f"  ({len(unwired)} — wire into an aggregator/workflow, or classify as dormant/infra)")
    else:
        print(f"Wiring check: no unclassified unwired functions ✓")
    return unwired


if __name__ == "__main__":
    sys.exit(main())
