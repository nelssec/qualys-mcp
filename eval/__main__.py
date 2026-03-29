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
import json as _json
import os
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import anthropic
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from .judge import CONV_SCORE_WEIGHTS, judge_conversation_turn, judge_response
from .parser import QUESTIONS_PATH, parse_questions
from .reporter import (
    RESULTS_DIR,
    cleanup_checkpoints,
    compute_summary,
    get_previous_run,
    load_latest_checkpoint,
    print_summary,
    save_checkpoint,
    save_results,
)
from .runner import JUDGE_MODEL, RUNNER_MODEL, get_mcp_tools, get_server_params, run_conversation, run_question
from .updater import update_questions_file


VARIANTS_PATH = Path(__file__).parent / "question_variants.json"


def _load_variants() -> dict[str, list[str]] | None:
    """Load question_variants.json if it exists."""
    if VARIANTS_PATH.exists():
        return _json.loads(VARIANTS_PATH.read_text())
    return None


async def run_eval(args):
    """Main evaluation loop."""
    # Parse questions — assign stable indices before any filtering
    questions = parse_questions()
    for i, q in enumerate(questions):
        q["_index"] = i
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

    # Load and apply variants
    variant_map: dict[str, list[str]] | None = None
    variant_rng: random.Random | None = None
    if args.variants:
        variant_map = _load_variants()
        if not variant_map:
            print("Error: --variants requires eval/question_variants.json (run: python eval/generate_variants.py)")
            sys.exit(1)
        seed = args.variant_seed if args.variant_seed is not None else random.randint(0, 2**31)
        variant_rng = random.Random(seed)
        print(f"Variants: ON (seed={seed})")

    # Generate run_id for this run
    run_id = uuid.uuid4().hex[:8]

    # Resume from checkpoint if requested
    skipped_ids: set[int] = set()
    resumed_results: list[dict] = []
    if args.resume:
        skipped_ids, resumed_results, prev_run_id = load_latest_checkpoint()
        if skipped_ids:
            run_id = prev_run_id or run_id
            print(f"Resuming: loaded {len(skipped_ids)} completed questions from checkpoint (run {run_id})")
            questions = [q for q in questions if q["id"] not in skipped_ids]
        else:
            print("Resume: no checkpoint found, starting fresh")

    print(f"Eval: {len(questions)} questions (of {total_parsed} total)")
    if args.category:
        print(f"Category filter: {args.category}")
    print(f"Runner model: {RUNNER_MODEL}")
    print(f"Judge model:  {JUDGE_MODEL}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Threshold: {args.threshold}")
    print(f"Checkpoint interval: {args.checkpoint_interval}")
    print(f"Run ID: {run_id}")
    print()

    # Validate env vars
    for var in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "ANTHROPIC_API_KEY"]:
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

            # Per-question wall-clock timeout (seconds). Heavy tools like
            # investigate_cve can take 3-5 min; 300s gives headroom while
            # preventing an infinite hang.
            QUESTION_TIMEOUT = int(os.environ.get("EVAL_QUESTION_TIMEOUT", "300"))

            async def process_question(q: dict) -> dict:
                async with sem:
                    # Pick variant if enabled
                    variant_index = 0
                    question_text = q["question"]
                    if variant_map and variant_rng:
                        sid = str(q.get("_index", q["id"]))
                        if sid in variant_map:
                            choices = variant_map[sid]
                            variant_index = variant_rng.randint(0, len(choices) - 1)
                            question_text = choices[variant_index]

                    prefix = f"[{q['id']:>3}/{questions[-1]['id']}]"
                    variant_tag = f" (v{variant_index})" if variant_index > 0 else ""
                    print(f"{prefix} {q['category']} — {question_text[:60]}...{variant_tag}")

                    try:
                        resp = await asyncio.wait_for(
                            run_question(client, session, tools, question_text),
                            timeout=QUESTION_TIMEOUT,
                        )
                        judgment = await judge_response(
                            client,
                            question_text,
                            resp["tool_calls"],
                            resp["response"],
                        )
                    except asyncio.TimeoutError:
                        print(f"{prefix} ⏱ TIMEOUT after {QUESTION_TIMEOUT}s")
                        resp = {"response": "", "tool_calls": []}
                        judgment = {
                            "score": "tool-error",
                            "reasoning": f"Question timed out after {QUESTION_TIMEOUT}s",
                        }
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
                        "question": question_text,
                        "original_question": q["question"],
                        "variant_index": variant_index,
                        "coverage_tag": q["coverage"],
                        "score": judgment["score"],
                        "reasoning": judgment["reasoning"],
                        "tool_calls": resp["tool_calls"],
                        "response": resp["response"],
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

                # Checkpoint after every N questions
                all_results = resumed_results + results
                if len(results) % args.checkpoint_interval == 0:
                    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
                    cp = save_checkpoint(all_results, now_ts, run_id, RUNNER_MODEL)
                    print(f"  💾 Checkpoint saved ({len(all_results)} questions) → {cp.name}")

    # Merge resumed results with new results for final output
    results = resumed_results + results

    # Summarize and save
    summary = compute_summary(results)
    now = datetime.now(timezone.utc)
    run_date = now.strftime("%Y-%m-%d_%H%M%S")
    result_file = save_results(results, summary, run_date, RUNNER_MODEL)
    print(f"\nResults saved to {result_file}")

    # Clean up checkpoint files from this run on success
    cleaned = cleanup_checkpoints(run_id)
    if cleaned:
        print(f"Cleaned up {cleaned} checkpoint file(s) for run {run_id}")

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


async def run_conversation_eval(args):
    """Run multi-turn conversation evaluation."""
    conv_path = Path(__file__).parent / "conversations.json"
    with open(conv_path) as f:
        conversations = _json.load(f)

    if args.limit:
        conversations = conversations[: args.limit]

    print(f"Conversation eval: {len(conversations)} scenarios")
    print(f"Threshold: {args.threshold}")
    print()

    # Validate env vars
    for var in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "ANTHROPIC_API_KEY"]:
        if not os.environ.get(var):
            print(f"Error: {var} not set")
            sys.exit(1)

    client = anthropic.Anthropic()
    server_params = get_server_params()

    all_scenario_results = []

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await get_mcp_tools(session)
            print(f"MCP server connected: {len(tools)} tools available")
            print()

            for conv in conversations:
                scenario_id = conv["id"]
                title = conv["title"]
                category = conv["category"]
                turns = conv["turns"]

                print(f"[{scenario_id:>2}/{len(conversations)}] {title} ({len(turns)} turns)")

                try:
                    turn_results = await run_conversation(
                        client, session, tools, turns
                    )
                except Exception as e:
                    print(f"  FATAL: {e}")
                    all_scenario_results.append(
                        {
                            "id": scenario_id,
                            "title": title,
                            "category": category,
                            "turns": [
                                {
                                    "turn": i + 1,
                                    "question": t,
                                    "score": "tool-error",
                                    "reasoning": f"Scenario failed: {e}",
                                    "tool_calls": [],
                                    "response": "",
                                }
                                for i, t in enumerate(turns)
                            ],
                            "scenario_score": 0.0,
                        }
                    )
                    continue

                # Score each turn
                scored_turns = []
                history_lines = []
                for tr in turn_results:
                    history_text = "\n".join(history_lines) if history_lines else "(start of conversation)"

                    try:
                        judgment = await judge_conversation_turn(
                            client,
                            history_text,
                            tr["question"],
                            tr["tool_calls"],
                            tr["response"],
                        )
                    except Exception as e:
                        judgment = {"score": "tool-error", "reasoning": f"Judge error: {e}"}

                    icon = {
                        "correct": "✅",
                        "partial": "⚠️",
                        "wrong": "❌",
                        "tool-error": "💥",
                        "context-miss": "🔄",
                        "off-track": "↗️",
                    }.get(judgment["score"], "?")

                    print(f"  T{tr['turn']}: {icon} {judgment['score']} — {judgment['reasoning'][:70]}")

                    scored_turns.append(
                        {
                            "turn": tr["turn"],
                            "question": tr["question"],
                            "score": judgment["score"],
                            "reasoning": judgment["reasoning"],
                            "tool_calls": tr["tool_calls"],
                            "response": tr["response"],
                        }
                    )

                    # Build history for next turn's judge
                    history_lines.append(f"User: {tr['question']}")
                    history_lines.append(f"Assistant: {tr['response'][:500]}")

                # Compute scenario score
                turn_weights = [CONV_SCORE_WEIGHTS.get(t["score"], 0.0) for t in scored_turns]
                scenario_score = sum(turn_weights) / len(turn_weights) if turn_weights else 0.0

                score_icon = "✅" if scenario_score >= 0.7 else "⚠️" if scenario_score >= 0.4 else "❌"
                print(f"  {score_icon} Scenario score: {scenario_score:.0%}")
                print()

                all_scenario_results.append(
                    {
                        "id": scenario_id,
                        "title": title,
                        "category": category,
                        "turns": scored_turns,
                        "scenario_score": round(scenario_score, 4),
                    }
                )

    # Aggregate results
    total_scenarios = len(all_scenario_results)
    overall_score = (
        sum(s["scenario_score"] for s in all_scenario_results) / total_scenarios
        if total_scenarios
        else 0
    )

    # Per-category
    by_category: dict[str, list[float]] = {}
    for s in all_scenario_results:
        by_category.setdefault(s["category"], []).append(s["scenario_score"])
    cat_scores = {cat: sum(scores) / len(scores) for cat, scores in by_category.items()}

    # Collect turn-level score counts
    all_scores = {"correct": 0, "partial": 0, "wrong": 0, "tool-error": 0, "context-miss": 0, "off-track": 0}
    for s in all_scenario_results:
        for t in s["turns"]:
            all_scores[t["score"]] = all_scores.get(t["score"], 0) + 1
    total_turns = sum(all_scores.values())

    # Print summary
    print(f"\n{'=' * 60}")
    now = datetime.now(timezone.utc)
    run_date = now.strftime("%Y-%m-%d_%H%M%S")
    print(f"CONVERSATION EVAL RESULTS — {run_date}")
    print(f"{'=' * 60}")
    print(f"Scenarios: {total_scenarios}  |  Turns: {total_turns}  |  Score: {overall_score:.1%}")
    print(
        f"  correct: {all_scores['correct']}  partial: {all_scores['partial']}  "
        f"wrong: {all_scores['wrong']}  tool-error: {all_scores['tool-error']}  "
        f"context-miss: {all_scores['context-miss']}  off-track: {all_scores['off-track']}"
    )
    print()

    # Per-scenario table
    print(f"{'Scenario':<40} {'Score':>6}  {'Turns':>5}")
    print("-" * 60)
    for s in all_scenario_results:
        icon = "✅" if s["scenario_score"] >= 0.7 else "⚠️" if s["scenario_score"] >= 0.4 else "❌"
        print(f"{icon} {s['title']:<38} {s['scenario_score']:>5.0%}  {len(s['turns']):>5}")

    print()
    print(f"{'Category':<35} {'Score':>6}  {'Scenarios':>9}")
    print("-" * 60)
    for cat in sorted(cat_scores.keys()):
        print(f"{cat:<35} {cat_scores[cat]:>5.0%}  {len(by_category[cat]):>9}")

    # Save results
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"conv_{run_date}.json"
    if result_file.exists():
        i = 2
        while (RESULTS_DIR / f"conv_{run_date}-{i}.json").exists():
            i += 1
        result_file = RESULTS_DIR / f"conv_{run_date}-{i}.json"

    output = {
        "run_date": run_date,
        "runner_model": RUNNER_MODEL,
        "judge_model": JUDGE_MODEL,
        "type": "conversation",
        "total_scenarios": total_scenarios,
        "total_turns": total_turns,
        "overall_score": round(overall_score, 4),
        "scored": all_scores,
        "cat_scores": {cat: round(s, 4) for cat, s in cat_scores.items()},
        "scenarios": all_scenario_results,
    }
    result_file.write_text(_json.dumps(output, indent=2))
    print(f"\nResults saved to {result_file}")

    # Threshold check
    print(f"\n{'=' * 60}")
    if overall_score < args.threshold:
        print(f"FAIL: score {overall_score:.1%} < threshold {args.threshold:.0%}")
        sys.exit(1)
    else:
        print(f"PASS: score {overall_score:.1%} >= threshold {args.threshold:.0%}")


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
  python -m eval --conversations            # Run multi-turn conversation eval
  python -m eval --conversations --limit 5  # Run first 5 conversation scenarios
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
    parser.add_argument(
        "--conversations",
        action="store_true",
        help="Run multi-turn conversation eval instead of single-question eval",
    )
    parser.add_argument(
        "--variants",
        action="store_true",
        help="Randomly replace questions with natural language variants",
    )
    parser.add_argument(
        "--variant-seed",
        type=int,
        default=None,
        help="Seed for variant selection (default: random)",
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=int,
        default=10,
        help="Save checkpoint every N questions (default: 10)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the most recent checkpoint file",
    )

    args = parser.parse_args()

    if args.conversations:
        asyncio.run(run_conversation_eval(args))
    else:
        if args.quick:
            if not args.limit:
                args.limit = 20
            args.concurrency = max(args.concurrency, 10)

        asyncio.run(run_eval(args))


if __name__ == "__main__":
    main()
