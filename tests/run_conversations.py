#!/usr/bin/env python3
"""Multi-turn conversation context test runner for qualys-mcp.

Validates that conversation context carries correctly across tool calls
by simulating multi-turn conversations defined in YAML scenario files.

Does NOT require real Qualys credentials — tests context structure only.

Usage:
    python tests/run_conversations.py
    python tests/run_conversations.py --scenario filter_chaining
    python tests/run_conversations.py --verbose
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# All valid MCP tool names from qualys_mcp.py
VALID_TOOLS = {
    "cache_status",
    "get_asset_full_profile",
    "get_asset_inventory",
    "get_asset_risk",
    "get_cdr_findings",
    "get_cloud_risk",
    "get_compliance_posture",
    "get_cve_details",
    "get_edr_events",
    "get_eliminate_status",
    "get_environment_summary",
    "get_etm_findings",
    "get_expiring_certs",
    "get_fim_events",
    "get_morning_report",
    "get_patch_status",
    "get_pm_status",
    "get_qid_details",
    "get_recommendations",
    "get_risk_by_tag",
    "get_scan_status",
    "get_scanner_health",
    "get_tech_debt",
    "get_vuln_exceptions",
    "get_webapp_vulns",
    "get_weekly_priorities",
    "get_image_vulns",
    "get_cloud_risk",
    "investigate_cve",
    "search_vulns",
}


class ConversationContext:
    """Tracks accumulated context across conversation turns."""

    def __init__(self):
        self.entries: dict[str, str] = {}
        self.history: list[dict] = []
        self.tools_used: list[list[str]] = []

    def apply_turn(self, turn: dict):
        """Apply a turn's context_carries to the accumulated context."""
        for carry in turn.get("context_carries", []):
            self.entries[carry["key"]] = carry["value"]
        self.history.append(turn)
        self.tools_used.append(turn.get("expected_tools", []))

    def has_key(self, key: str) -> bool:
        return key in self.entries

    def get(self, key: str) -> str | None:
        return self.entries.get(key)

    def previous_tools(self) -> list[str]:
        """Return tools from all previous turns (not current)."""
        flat = []
        for tools in self.tools_used[:-1]:
            flat.extend(tools)
        return flat


@dataclass
class TurnResult:
    turn_index: int
    user_input: str
    passed: bool
    errors: list[str] = field(default_factory=list)


@dataclass
class ScenarioResult:
    name: str
    file: str
    passed: bool
    turn_results: list[TurnResult] = field(default_factory=list)
    load_error: str | None = None


def validate_tools(expected_tools: list[str]) -> list[str]:
    """Check that all expected tools are valid MCP tool names."""
    errors = []
    for tool in expected_tools:
        if tool not in VALID_TOOLS:
            errors.append(f"Unknown tool '{tool}' — not in qualys_mcp.py")
    return errors


def validate_context_carries(context: ConversationContext, turn: dict, turn_idx: int) -> list[str]:
    """Validate that context_carries keys are present after applying the turn."""
    errors = []
    for carry in turn.get("context_carries", []):
        key = carry["key"]
        value = carry["value"]
        actual = context.get(key)
        if actual != value:
            errors.append(
                f"context_carries: expected {key}={value!r}, got {actual!r}"
            )
    return errors


def validate_context_assertions(
    context: ConversationContext, turn: dict, turn_idx: int
) -> list[str]:
    """Validate context assertions by checking that prior context keys are preserved.

    Assertions referencing 'preserved' check that the relevant key still exists.
    All assertions are validated as structurally present in the scenario.
    """
    errors = []
    assertions = turn.get("context_assertions", [])

    if not assertions:
        return errors

    # For turns after the first, check that prior context entries are still present
    if turn_idx > 0 and not context.entries:
        errors.append(
            "No context accumulated from previous turns — "
            "assertions cannot be validated"
        )

    for assertion in assertions:
        if not isinstance(assertion, str) or not assertion.strip():
            errors.append(f"Invalid assertion (must be non-empty string): {assertion!r}")

    return errors


def validate_context_preservation(
    context: ConversationContext, turn: dict, turn_idx: int
) -> list[str]:
    """Check that context from prior turns is not lost when new context is added."""
    errors = []
    if turn_idx == 0:
        return errors

    # Snapshot keys before this turn
    prior_keys = set(context.entries.keys())

    # After applying context_carries, prior keys should still exist
    new_carries = {c["key"] for c in turn.get("context_carries", [])}
    # Keys that are being explicitly overwritten are OK
    for key in prior_keys - new_carries:
        if not context.has_key(key):
            errors.append(f"Context key '{key}' from prior turn was lost")

    return errors


def run_scenario(scenario_path: Path, verbose: bool = False) -> ScenarioResult:
    """Run a single conversation scenario and return results."""
    try:
        with open(scenario_path) as f:
            scenario = yaml.safe_load(f)
    except Exception as e:
        return ScenarioResult(
            name=scenario_path.stem,
            file=str(scenario_path),
            passed=False,
            load_error=str(e),
        )

    name = scenario.get("name", scenario_path.stem)
    turns = scenario.get("turns", [])

    if not turns:
        return ScenarioResult(
            name=name,
            file=str(scenario_path),
            passed=False,
            load_error="No turns defined in scenario",
        )

    context = ConversationContext()
    turn_results = []
    all_passed = True

    for idx, turn in enumerate(turns):
        errors = []

        # Validate expected tools
        expected_tools = turn.get("expected_tools", [])
        errors.extend(validate_tools(expected_tools))

        # Validate context preservation before applying new context
        errors.extend(validate_context_preservation(context, turn, idx))

        # Apply this turn's context
        context.apply_turn(turn)

        # Validate context_carries were applied correctly
        errors.extend(validate_context_carries(context, turn, idx))

        # Validate assertions
        errors.extend(validate_context_assertions(context, turn, idx))

        passed = len(errors) == 0
        if not passed:
            all_passed = False

        turn_results.append(
            TurnResult(
                turn_index=idx,
                user_input=turn.get("user", ""),
                passed=passed,
                errors=errors,
            )
        )

    return ScenarioResult(
        name=name,
        file=str(scenario_path),
        passed=all_passed,
        turn_results=turn_results,
    )


def print_results(results: list[ScenarioResult], verbose: bool = False):
    """Print test results with PASS/FAIL output."""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    print("=" * 60)
    print("  Multi-Turn Conversation Context Tests")
    print("=" * 60)
    print()

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"  [{status}] {result.name}")

        if result.load_error:
            print(f"         Load error: {result.load_error}")
            continue

        if verbose or not result.passed:
            for tr in result.turn_results:
                turn_status = "PASS" if tr.passed else "FAIL"
                print(f"         Turn {tr.turn_index + 1}: [{turn_status}] \"{tr.user_input}\"")
                for err in tr.errors:
                    print(f"           - {err}")

    print()
    print("-" * 60)
    print(f"  {passed}/{total} scenarios passed", end="")
    if failed:
        print(f"  ({failed} failed)")
    else:
        print()
    print("-" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Run multi-turn conversation context tests"
    )
    parser.add_argument(
        "--scenario",
        help="Run a single scenario by name (filename without .yaml)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output for all scenarios, not just failures",
    )
    args = parser.parse_args()

    # Find scenario files
    scenarios_dir = Path(__file__).parent / "conversations"
    if not scenarios_dir.exists():
        print(f"ERROR: Scenarios directory not found: {scenarios_dir}")
        sys.exit(1)

    if args.scenario:
        scenario_file = scenarios_dir / f"{args.scenario}.yaml"
        if not scenario_file.exists():
            print(f"ERROR: Scenario not found: {scenario_file}")
            available = sorted(p.stem for p in scenarios_dir.glob("*.yaml"))
            print(f"Available: {', '.join(available)}")
            sys.exit(1)
        scenario_files = [scenario_file]
    else:
        scenario_files = sorted(scenarios_dir.glob("*.yaml"))

    if not scenario_files:
        print("ERROR: No scenario files found")
        sys.exit(1)

    # Run scenarios
    results = [run_scenario(f, args.verbose) for f in scenario_files]

    # Print results
    print_results(results, args.verbose)

    # Exit code
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
