#!/usr/bin/env python3
"""Post a CI results summary comment on the PR using the gh CLI."""

import json
import os
import subprocess
import sys


def status_emoji(result: str) -> str:
    return {"success": "pass", "failure": "FAIL", "skipped": "skip"}.get(result, "?")


def main():
    pr_number = os.environ.get("PR_NUMBER")
    if not pr_number:
        print("PR_NUMBER not set, skipping comment")
        return

    smoke = os.environ.get("SMOKE_RESULT", "skipped")
    conversations = os.environ.get("CONVERSATION_RESULT", "skipped")
    benchmark = os.environ.get("BENCHMARK_RESULT", "skipped")
    eval_result = os.environ.get("EVAL_RESULT", "skipped")

    lines = [
        "## CI Results Summary",
        "",
        "| Check | Status |",
        "|-------|--------|",
        f"| Smoke Test | {status_emoji(smoke)} |",
        f"| Conversation Tests | {status_emoji(conversations)} |",
        f"| Benchmark Regression | {status_emoji(benchmark)} |",
        f"| Eval Harness | {status_emoji(eval_result)} |",
        "",
    ]

    # Benchmark details
    if os.path.isfile("benchmark_results.json"):
        with open("benchmark_results.json") as f:
            data = json.load(f)
        lines.append("### Benchmark Latencies")
        lines.append("")
        lines.append("| Tool | Cold (s) | Warm (s) |")
        lines.append("|------|----------|----------|")
        for r in data["results"]:
            lines.append(f"| {r['tool']} | {r['cold_s']:.2f} | {r['warm_s']:.2f} |")
        lines.append("")

    # Eval details
    if os.path.isfile("eval_results.json"):
        with open("eval_results.json") as f:
            data = json.load(f)
        score = data.get("score", data.get("accuracy", "N/A"))
        lines.append(f"### Eval Score: **{score}%**")
        lines.append("")

    body = "\n".join(lines)

    # Post comment via gh CLI
    subprocess.run(
        ["gh", "pr", "comment", pr_number, "--body", body],
        check=True,
    )
    print(f"Posted CI summary comment on PR #{pr_number}")


if __name__ == "__main__":
    main()
