#!/usr/bin/env python3
"""Main entry point for the eval harness.

Usage:
    python -m eval [options]
    python -m eval --quick
    python -m eval --category "Vulnerability Management" --limit 10
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone

import anthropic
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from .judge import judge_response
from .parser import QUESTIONS_PATH, parse_questions
from .reporter import (
    compute_summary,
    get_previous_run,
    print_summary,
    save_results,
)
from .runner import MODEL, get_mcp_tools, get_server_params, run_question
from .updater import update_questions_file


async def run_eval(args):
    """Main evaluation loop."""
    # Parse questions
    questions = parse_questions()
    total_parsed = len(questions)

    # Filter by category
    if args.category:
        cat_lower = args.category.lower()
        questions = [q for q in questions if cat_lower in q["category"].lower()]
        if not questions:
            print(f"No questions found for category '{args.category}'")
            print("Available categories:")
            cats = sorted(set(q["category"] for q in parse_questions()))
            for c in cats:
                print(f"  - {c}")
            sys.exit(1)

    # Apply limit
    if args.limit:
        questions = questions[: args.limit]

    print(f"Eval: {len(questions)} questions (of {total_parsed} total)")
    if args.category:
        print(f"Category filter: {args.category}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Threshold: {args.threshold}")
    print()

    # Validate env vars
    for var in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "QUALYS_BASE_URL", "ANTHROPIC_API_KEY"]:
        if not os.environ.get(var):
            print(f"Error: {var} not set")
            sys.exit(1)

    client = anthropic.Anthropic()
    server_params = get_server_params()

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await get_mcp_tools(session)
            print(f"MCP server connected: {len(tools)} tools available")
            print()

            results = []
            sem = asyncio.Semaphore(args.concurrency)

            async def process_question(q: dict) -> dict:
                async with sem:
                    prefix = f"[{q['id']:>3}/{questions[-1]['id']}]"
                    print(f"{prefix} {q['category']} — {q['question'][:60]}...")

                    try:
                        resp = await run_question(
                            client, session, tools, q["question"]
                        )
                        judgment = judge_response(
                            client,
                            q["question"],
                            resp["tool_calls"],
                            resp["response"],
                        )
                    except Exception as e:
                        resp = {"response": "", "tool_calls": []}
                        judgment = {
                            "score": "tool-error",
                            "reasoning": f"Exception: {e}",
                        }

                    result = {
                        "id": q["id"],
                        "category": q["category"],
                        "subcategory": q["subcategory"],
                        "question": q["question"],
                        "coverage_tag": q["coverage"],
                        "score": judgment["score"],
                        "reasoning": judgment["reasoning"],
                        "tool_calls": resp["tool_calls"],
                        "response": resp["response"][:2000],
                    }

                    icon = {"correct": "✅", "partial": "⚠️", "wrong": "❌", "tool-error": "💥"}.get(
                        judgment["score"], "?"
                    )
                    print(f"{prefix} {icon} {judgment['score']} — {judgment['reasoning'][:80]}")
                    return result

            # MCP stdio transport is single-connection, so questions run sequentially
            for q in questions:
                result = await process_question(q)
                results.append(result)

    # Summarize and save
    summary = compute_summary(results)
    now = datetime.now(timezone.utc)
    run_date = now.strftime("%Y-%m-%d_%H%M%S")
    result_file = save_results(results, summary, run_date, MODEL)
    print(f"\nResults saved to {result_file}")

    # Print summary
    prev_run = get_previous_run(result_file)
    if prev_run:
        prev_run["_filename"] = sorted(
            result_file.parent.glob("*.json")
        )[-2].name if len(list(result_file.parent.glob("*.json"))) > 1 else "previous"
    print_summary(summary, run_date, result_file, prev_run)

    # Update questions file if requested
    if not args.no_update:
        update_questions_file(QUESTIONS_PATH, results)
        print(f"\nUpdated coverage tags in {QUESTIONS_PATH}")

    # Threshold check
    print(f"\n{'=' * 60}")
    if summary["overall_score"] < args.threshold:
        print(f"FAIL: score {summary['overall_score']:.1%} < threshold {args.threshold:.0%}")
        sys.exit(1)
    else:
        print(f"PASS: score {summary['overall_score']:.1%} >= threshold {args.threshold:.0%}")


def main():
    parser = argparse.ArgumentParser(
        description="Eval harness for Qualys MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m eval --quick                    # Smoke test: 20 questions
  python -m eval --category "Vulnerability Management"
  python -m eval --limit 5                  # Test 5 questions
  python -m eval --threshold 0.8            # Fail if score < 80%
  python -m eval --no-update                # Don't update questions.md
  python -m eval --concurrency 10           # 10 parallel workers
""",
    )
    parser.add_argument(
        "--category",
        type=str,
        default="",
        help="Run only questions from this category",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Run only the first N questions",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Alias for --limit 20 --concurrency 10",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Parallel workers (default: 5)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.7,
        help="Exit code 1 if score below this (default: 0.7)",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="Don't auto-update coverage tags in docs/questions.md",
    )

    args = parser.parse_args()

    if args.quick:
        if not args.limit:
            args.limit = 20
        args.concurrency = max(args.concurrency, 10)

    asyncio.run(run_eval(args))


if __name__ == "__main__":
    main()
