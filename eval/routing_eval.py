#!/usr/bin/env python3
"""Tool routing eval — tests that Claude picks the correct tool for disambiguation questions.

Does NOT require Qualys credentials. Uses only the Anthropic API + tool descriptions
extracted from qualys_mcp.py.

Usage:
    python -m eval.routing_eval
    python eval/routing_eval.py
"""

from __future__ import annotations

import ast
import json
import os
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent
MCP_FILE = ROOT / "qualys_mcp.py"


def extract_tool_descriptions(path: Path) -> dict[str, str]:
    """Parse qualys_mcp.py and extract (tool_name -> docstring) for all @mcp.tool() functions."""
    source = path.read_text()
    tree = ast.parse(source)
    tools = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Check if decorated with @mcp.tool()
        for dec in node.decorator_list:
            is_mcp_tool = (
                (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                 and dec.func.attr == "tool")
                or (isinstance(dec, ast.Attribute) and dec.attr == "tool")
            )
            if is_mcp_tool:
                docstring = ast.get_docstring(node) or ""
                tools[node.name] = docstring
                break
    return tools


@dataclass
class RoutingCase:
    question: str
    expected_tool: str
    description: str = ""
    wrong_tools: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Test cases — high-priority disambiguation pairs
# ---------------------------------------------------------------------------

ROUTING_CASES: list[RoutingCase] = [
    # CVE tools
    RoutingCase(
        "Are we affected by CVE-2024-3400?",
        "investigate_cve",
        "Single CVE impact on our assets",
        wrong_tools=["get_cve_details"],
    ),
    RoutingCase(
        "What's the severity and patch info for CVE-2023-4966?",
        "investigate_cve",
        "Single CVE investigation",
        wrong_tools=["get_cve_details"],
    ),
    RoutingCase(
        "Give me a summary table for these 5 CVEs: CVE-2024-1, CVE-2024-2, CVE-2024-3, CVE-2024-4, CVE-2024-5",
        "get_cve_details",
        "Bulk CVE metadata lookup",
        wrong_tools=["investigate_cve"],
    ),
    RoutingCase(
        "Compare the severity and CVSS of CVE-2021-44228, CVE-2021-45046, and CVE-2021-45105",
        "get_cve_details",
        "Multiple CVE comparison — KB metadata only",
        wrong_tools=["investigate_cve"],
    ),

    # Asset risk tools
    RoutingCase(
        "What's the risk score on server-prod-01?",
        "get_asset",
        "Single asset risk drill-down (summary mode)",
        wrong_tools=["get_risk_by_tag"],
    ),
    RoutingCase(
        "Give me the full complete profile for this asset",
        "get_asset",
        "User explicitly requests full/complete profile (detail='full')",
        wrong_tools=["get_risk_by_tag"],
    ),
    RoutingCase(
        "What's the risk situation for our PCI assets?",
        "get_risk_by_tag",
        "Tag-scoped aggregate risk",
        wrong_tools=["get_asset"],
    ),
    RoutingCase(
        "Show me risk for the Production environment",
        "get_risk_by_tag",
        "Environment tag risk query",
        wrong_tools=["get_weekly_priorities"],
    ),

    # Vuln search vs ETM findings
    RoutingCase(
        "What new vulnerabilities were published this week?",
        "search_vulns",
        "KB / newly published vuln search",
        wrong_tools=["get_etm_findings"],
    ),
    RoutingCase(
        "Are there any ransomware-associated vulnerabilities published recently?",
        "search_vulns",
        "Threat intel KB search",
        wrong_tools=["get_etm_findings"],
    ),
    RoutingCase(
        "Show me all critical vulnerabilities detected on our assets",
        "get_etm_findings",
        "Confirmed detections in our environment",
        wrong_tools=["search_vulns"],
    ),
    RoutingCase(
        "What vulns are confirmed in our scans for Log4Shell?",
        "get_etm_findings",
        "Confirmed detections for specific vuln",
        wrong_tools=["search_vulns", "investigate_cve"],
    ),

    # Morning / weekly tools
    RoutingCase(
        "What happened overnight?",
        "get_morning_report",
        "Daily briefing",
        wrong_tools=["get_weekly_priorities"],
    ),
    RoutingCase(
        "Give me my morning security briefing",
        "get_morning_report",
        "Morning report",
        wrong_tools=["get_weekly_priorities"],
    ),
    RoutingCase(
        "What should I work on this week?",
        "get_weekly_priorities",
        "Risk-ranked weekly action list",
        wrong_tools=["get_morning_report"],
    ),
    RoutingCase(
        "What are our top priorities for remediation?",
        "get_weekly_priorities",
        "Remediation priorities",
        wrong_tools=["get_morning_report"],
    ),

    # Patch tools
    RoutingCase(
        "How is our patching going?",
        "get_patch_status",
        "Patch coverage/gaps summary",
        wrong_tools=["get_eliminate_status"],
    ),
    RoutingCase(
        "How many assets are unpatched?",
        "get_patch_status",
        "Unpatched asset count",
        wrong_tools=["get_eliminate_status"],
    ),
    RoutingCase(
        "What patches are deploying right now?",
        "get_eliminate_status",
        "Active deployment status",
        wrong_tools=["get_patch_status"],
    ),
    RoutingCase(
        "Are there active mitigation jobs running?",
        "get_eliminate_status",
        "Active job status",
        wrong_tools=["get_patch_status"],
    ),
    RoutingCase(
        "Show me Patch Management module details and per-platform job breakdown",
        "get_eliminate_status",
        "PM module details (get_pm_status deprecated, use get_eliminate_status)",
        wrong_tools=["get_patch_status"],
    ),
    RoutingCase(
        "Show me all in-progress patch jobs in Eliminate.",
        "get_eliminate_status",
        "In-progress Eliminate job status (status=Running)",
        wrong_tools=["get_patch_status"],
    ),
    RoutingCase(
        "Which vulnerabilities in our backlog have Eliminate mitigations?",
        "get_eliminate_coverage",
        "Coverage check for backlog vulns",
        wrong_tools=["get_eliminate_status"],
    ),
    RoutingCase(
        "Show me Eliminate catalog coverage for our top 50 vulns.",
        "get_eliminate_coverage",
        "Coverage check for top vulns list",
        wrong_tools=["get_eliminate_status"],
    ),
]


# ---------------------------------------------------------------------------
# Routing check via Claude
# ---------------------------------------------------------------------------

def build_tools_for_routing(tool_descriptions: dict[str, str]) -> list[dict]:
    """Build Anthropic tool definitions from extracted docstrings."""
    tools = []
    for name, doc in tool_descriptions.items():
        first_line = doc.strip().split("\n")[0] if doc else name
        tools.append({
            "name": name,
            "description": doc.strip() if doc else name,
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Query or parameters (use any reasonable values)"
                    }
                },
                "required": []
            }
        })
    return tools


def check_routing(client, tools: list[dict], case: RoutingCase) -> dict:
    """Ask Claude which tool to use for the question and check if it matches expected."""
    import anthropic

    resp = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=256,
        system=(
            "You are a security analyst assistant. "
            "Use exactly ONE tool to answer the user's question. "
            "Choose the most appropriate tool. "
            "Do not chain tools — just pick the single best one."
        ),
        tools=tools,
        messages=[{"role": "user", "content": case.question}],
    )

    tool_calls = [b.name for b in resp.content if b.type == "tool_use"]
    chosen = tool_calls[0] if tool_calls else None

    correct = chosen == case.expected_tool
    wrong_chosen = chosen in case.wrong_tools if chosen else False

    return {
        "question": case.question,
        "expected": case.expected_tool,
        "chosen": chosen,
        "correct": correct,
        "wrong_chosen": wrong_chosen,
        "description": case.description,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    print("Extracting tool descriptions from qualys_mcp.py...")
    tool_descriptions = extract_tool_descriptions(MCP_FILE)
    print(f"Found {len(tool_descriptions)} tools")
    print()

    tools = build_tools_for_routing(tool_descriptions)
    client = anthropic.Anthropic(api_key=api_key)

    results = []
    correct_count = 0
    wrong_tool_count = 0

    print(f"{'Q#':<4} {'Expected':<30} {'Chosen':<30} {'OK?'}")
    print("-" * 85)

    for i, case in enumerate(ROUTING_CASES, 1):
        try:
            result = check_routing(client, tools, case)
            results.append(result)

            ok = "✅" if result["correct"] else ("❌ WRONG PAIR" if result["wrong_chosen"] else "❌ unexpected")
            if result["correct"]:
                correct_count += 1
            elif result["wrong_chosen"]:
                wrong_tool_count += 1

            print(f"{i:<4} {result['expected']:<30} {str(result['chosen']):<30} {ok}")
            if not result["correct"]:
                print(f"     Question: {case.question}")
                print()
        except Exception as e:
            print(f"{i:<4} {case.expected_tool:<30} ERROR: {e}")
            results.append({
                "question": case.question,
                "expected": case.expected_tool,
                "chosen": None,
                "correct": False,
                "wrong_chosen": False,
                "description": case.description,
                "error": str(e),
            })

    total = len(ROUTING_CASES)
    score = correct_count / total if total else 0

    print()
    print("=" * 85)
    print(f"Routing eval results: {correct_count}/{total} correct ({score:.0%})")
    print(f"Wrong-pair errors (the kind that matter most): {wrong_tool_count}")
    print()

    # Save results
    out_path = ROOT / "eval_results" / "routing_eval_latest.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "total": total,
            "correct": correct_count,
            "wrong_pair": wrong_tool_count,
            "score": round(score, 4),
            "results": results,
        }, f, indent=2)
    print(f"Results saved to {out_path}")

    if score < 0.8:
        print(f"\nFAIL: routing score {score:.0%} < 80% threshold")
        sys.exit(1)
    else:
        print(f"PASS: routing score {score:.0%} >= 80% threshold")


if __name__ == "__main__":
    main()
