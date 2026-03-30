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
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import anthropic
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from .conversations import ConversationResult, TurnResult, parse_conversations
from .judge import CONV_SCORE_WEIGHTS, judge_conversation_turn, judge_response
from .parser import QUESTIONS_PATH, parse_questions
from .reporter import (
    RESULTS_DIR,
    cleanup_checkpoints,
    compute_summary,
    get_previous_run,
    load_latest_checkpoint,
    parse_perf_log,
    print_summary,
    print_timing_summary,
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

    # Resume from checkpoint: auto-detect today's checkpoint unless --fresh
    skipped_ids: set[int] = set()
    resumed_results: list[dict] = []
    if not args.fresh:
        if args.resume:
            skipped_ids, resumed_results, prev_run_id = load_latest_checkpoint()
        else:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            skipped_ids, resumed_results, prev_run_id = load_latest_checkpoint(date_prefix=today)
        if skipped_ids:
            run_id = prev_run_id or run_id
            auto = "" if args.resume else " (auto-detected)"
            print(f"Resuming{auto}: loaded {len(skipped_ids)} completed questions from checkpoint (run {run_id})")
            questions = [q for q in questions if q["id"] not in skipped_ids]
        elif args.resume:
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

    # Set up perf logging sidecar
    perf_log_path = f"/tmp/mcp_perf_{run_id}.jsonl"
    os.environ["MCP_PERF_LOG"] = perf_log_path

    client = anthropic.Anthropic()
    server_params = get_server_params()

    run_t0 = time.perf_counter()

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await get_mcp_tools(session)
            print(f"MCP server connected: {len(tools)} tools available")
            print()

            warmup_seconds = round(time.perf_counter() - run_t0, 2)

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

                    q_t0 = time.perf_counter()
                    timed_out = False
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
                        timed_out = True
                    except Exception as e:
                        resp = {"response": "", "tool_calls": []}
                        judgment = {
                            "score": "tool-error",
                            "reasoning": f"Exception: {e}",
                        }
                    elapsed = round(time.perf_counter() - q_t0, 2)

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
                        "elapsed_seconds": elapsed,
                        "timed_out": timed_out,
                    }

                    icon = {"correct": "✅", "partial": "⚠️", "wrong": "❌", "tool-error": "💥"}.get(
                        judgment["score"], "?"
                    )
                    print(f"{prefix} {icon} {judgment['score']} ({elapsed:.1f}s) — {judgment['reasoning'][:80]}")
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

    total_seconds = round(time.perf_counter() - run_t0, 2)

    # Merge resumed results with new results for final output
    results = resumed_results + results

    # Compute timing stats from per-question elapsed_seconds
    elapsed_list = [r["elapsed_seconds"] for r in results if "elapsed_seconds" in r]
    elapsed_sorted = sorted(elapsed_list) if elapsed_list else [0]
    timeout_count = sum(1 for r in results if r.get("timed_out"))

    def _percentile(sorted_vals, pct):
        idx = int(len(sorted_vals) * pct / 100)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]

    # Parse perf log for cache/API metrics
    perf = parse_perf_log(perf_log_path)

    timing = {
        "total_seconds": total_seconds,
        "warmup_seconds": warmup_seconds,
        "avg_per_question": round(sum(elapsed_list) / len(elapsed_list), 1) if elapsed_list else 0,
        "p50_per_question": round(_percentile(elapsed_sorted, 50), 1),
        "p95_per_question": round(_percentile(elapsed_sorted, 95), 1),
        "max_per_question": round(max(elapsed_list), 1) if elapsed_list else 0,
        "timeouts": timeout_count,
        "cache_hits_l1": perf["cache_hits_l1"],
        "cache_hits_l2": perf["cache_hits_l2"],
        "cache_misses": perf["cache_misses"],
        "api_calls": perf["api_calls"],
    }

    # Summarize and save
    summary = compute_summary(results)
    now = datetime.now(timezone.utc)
    run_date = now.strftime("%Y-%m-%d_%H%M%S")
    result_file = save_results(results, summary, run_date, RUNNER_MODEL, timing=timing)
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
    print_timing_summary(timing)

    # Update questions file if requested
    if not args.no_update:
        update_questions_file(QUESTIONS_PATH, results)
        print(f"\nUpdated coverage tags in {QUESTIONS_PATH}")

    # Clean up perf log sidecar
    try:
        os.unlink(perf_log_path)
    except OSError:
        pass
    os.environ.pop("MCP_PERF_LOG", None)

    # Threshold check
    print(f"\n{'=' * 60}")
    if summary["overall_score"] < args.threshold:
        print(f"FAIL: score {summary['overall_score']:.1%} < threshold {args.threshold:.0%}")
        sys.exit(1)
    else:
        print(f"PASS: score {summary['overall_score']:.1%} >= threshold {args.threshold:.0%}")


async def run_conversation_eval(args):
    """Run multi-turn conversation evaluation.

    Uses structured conversations from docs/questions.md (with expect /
    context_check fields) when available, falling back to the plain
    eval/conversations.json for backward compatibility.
    """
    # Parse structured conversations from questions.md
    try:
        conversations = parse_conversations()
    except Exception as e:
        print(f"Error parsing conversations from questions.md: {e}")
        sys.exit(1)

    if args.limit:
        conversations = conversations[: args.limit]

    total_turns = sum(len(c.turns) for c in conversations)
    print(f"Conversation eval: {len(conversations)} scenarios ({total_turns} turns)")
    print(f"Runner model: {RUNNER_MODEL}")
    print(f"Judge model:  {JUDGE_MODEL}")
    print(f"Threshold: {args.threshold}")
    print()

    # Validate env vars
    for var in ["QUALYS_USERNAME", "QUALYS_PASSWORD", "ANTHROPIC_API_KEY"]:
        if not os.environ.get(var):
            print(f"Error: {var} not set")
            sys.exit(1)

    client = anthropic.Anthropic()
    server_params = get_server_params()

    conv_results: list[ConversationResult] = []

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await get_mcp_tools(session)
            print(f"MCP server connected: {len(tools)} tools available")
            print()

            CONV_TIMEOUT = int(os.environ.get("EVAL_QUESTION_TIMEOUT", "300"))

            for idx, conv in enumerate(conversations, start=1):
                print(f"[{idx:>2}/{len(conversations)}] {conv.name} ({conv.category}, {len(conv.turns)} turns)")

                # Build plain turn strings for the runner
                turn_strings = [t.user for t in conv.turns]

                try:
                    raw_turns = await asyncio.wait_for(
                        run_conversation(client, session, tools, turn_strings),
                        timeout=CONV_TIMEOUT * len(conv.turns),
                    )
                except Exception as e:
                    print(f"  FATAL: {e}")
                    conv_results.append(
                        ConversationResult(
                            name=conv.name,
                            category=conv.category,
                            turn_results=[
                                TurnResult(
                                    turn_index=i,
                                    user=t.user,
                                    assistant="",
                                    pass_=False,
                                    context_ok=None,
                                    notes=f"Scenario failed: {e}",
                                )
                                for i, t in enumerate(conv.turns)
                            ],
                            score=0.0,
                        )
                    )
                    print()
                    continue

                # Judge each turn with expect / context_check
                turn_results: list[TurnResult] = []
                history_lines: list[str] = []

                for ti, (spec, raw) in enumerate(zip(conv.turns, raw_turns)):
                    history_text = "\n".join(history_lines) if history_lines else "(start of conversation)"

                    try:
                        judgment = await judge_conversation_turn(
                            client,
                            history_text,
                            raw["question"],
                            raw["tool_calls"],
                            raw["response"],
                            expect=spec.expect,
                            context_check=spec.context_check,
                        )
                    except Exception as e:
                        judgment = {"score": "tool-error", "reasoning": f"Judge error: {e}", "context_ok": None}

                    pass_ = judgment["score"] in ("correct", "partial", "context-miss")
                    context_ok = judgment.get("context_ok")

                    # Display
                    icon = {
                        "correct": "✓", "partial": "~", "wrong": "✗",
                        "tool-error": "!", "context-miss": "↺", "off-track": "→",
                    }.get(judgment["score"], "?")

                    ctx_str = ""
                    if spec.context_check:
                        ctx_str = f" context_ok={context_ok}" if context_ok is not None else " context_ok=?"
                    no_ctx = " (no context check)" if not spec.context_check else ""

                    print(f"  Turn {ti + 1}: {icon} {judgment['score']}{ctx_str}{no_ctx}")

                    turn_results.append(
                        TurnResult(
                            turn_index=ti,
                            user=spec.user,
                            assistant=raw["response"],
                            pass_=pass_,
                            context_ok=context_ok,
                            notes=judgment["reasoning"],
                            tool_calls=raw["tool_calls"],
                        )
                    )

                    history_lines.append(f"User: {raw['question']}")
                    history_lines.append(f"Assistant: {raw['response'][:500]}")

                # Compute conversation score
                turn_weights = [CONV_SCORE_WEIGHTS.get(
                    {"correct": "correct", "partial": "partial", "wrong": "wrong",
                     "tool-error": "tool-error", "context-miss": "context-miss",
                     "off-track": "off-track"}.get(
                        # Determine effective score — penalise context failures
                        "correct" if tr.pass_ and tr.context_ok is not False else
                        "wrong" if not tr.pass_ else
                        "context-miss" if tr.context_ok is False else "correct",
                        "wrong"
                    ), 0.0) for tr in turn_results]
                raw_score = sum(turn_weights) / len(turn_weights) if turn_weights else 0.0

                cr = ConversationResult(
                    name=conv.name,
                    category=conv.category,
                    turn_results=turn_results,
                    score=round(raw_score, 4),
                )
                conv_results.append(cr)

                passed_turns = sum(1 for tr in turn_results if tr.pass_)
                status = "✓" if cr.passed else "✗"
                print(f"  {status} {passed_turns}/{len(turn_results)} turns  score={cr.score:.2f}")
                print()

    # ── Aggregate & print summary ──────────────────────────────────
    _print_conversation_summary(conv_results, args.threshold)


def _print_conversation_summary(
    conv_results: list[ConversationResult],
    threshold: float,
) -> None:
    """Print and save conversation eval results."""
    now = datetime.now(timezone.utc)
    run_date = now.strftime("%Y-%m-%d_%H%M%S")

    total_scenarios = len(conv_results)
    overall_score = (
        sum(cr.score for cr in conv_results) / total_scenarios if total_scenarios else 0.0
    )
    passed_scenarios = sum(1 for cr in conv_results if cr.passed)

    # Context check stats
    context_total = 0
    context_passed = 0
    for cr in conv_results:
        for tr in cr.turn_results:
            if tr.context_ok is not None:
                context_total += 1
                if tr.context_ok:
                    context_passed += 1

    total_turns = sum(len(cr.turn_results) for cr in conv_results)

    # Per-category
    by_category: dict[str, list[ConversationResult]] = {}
    for cr in conv_results:
        by_category.setdefault(cr.category, []).append(cr)

    print(f"\n{'=' * 60}")
    print("=== Conversation Eval Results ===")
    print(f"{'=' * 60}")
    print()

    for cr in conv_results:
        passed_turns = sum(1 for tr in cr.turn_results if tr.pass_)
        status = "✓" if cr.passed else "✗"
        print(f"{cr.name} ({cr.category}): {passed_turns}/{len(cr.turn_results)} turns {status}  score={cr.score:.2f}")
        for tr in cr.turn_results:
            icon = "✓" if tr.pass_ else "✗"
            ctx = ""
            if tr.context_ok is not None:
                ctx = f" context_ok={tr.context_ok}"
            elif any(t.context_check for t in []):
                ctx = " (no context check)"
            else:
                ctx = " (no context check)" if tr.turn_index == 0 else ""
            print(f"  Turn {tr.turn_index + 1}: {icon}{ctx}")
        print()

    print("=== Summary ===")
    print(f"Conversations: {passed_scenarios}/{total_scenarios} passed ({passed_scenarios / total_scenarios * 100:.1f}%)")
    print(f"Avg score: {overall_score:.2f}")
    if context_total:
        print(f"Context checks: {context_passed}/{context_total} passed ({context_passed / context_total * 100:.1f}%)")
    print()

    # Per-category table
    print(f"{'Category':<30} {'Score':>6}  {'Passed':>8}")
    print("-" * 50)
    for cat in sorted(by_category.keys()):
        crs = by_category[cat]
        cat_score = sum(cr.score for cr in crs) / len(crs)
        cat_passed = sum(1 for cr in crs if cr.passed)
        print(f"{cat:<30} {cat_score:>5.0%}  {cat_passed}/{len(crs):>6}")

    # Save results
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"conv_{run_date}.json"
    if result_file.exists():
        i = 2
        while (RESULTS_DIR / f"conv_{run_date}-{i}.json").exists():
            i += 1
        result_file = RESULTS_DIR / f"conv_{run_date}-{i}.json"

    # Serialize ConversationResult → dict
    scenarios_out = []
    for cr in conv_results:
        scenarios_out.append({
            "name": cr.name,
            "category": cr.category,
            "score": cr.score,
            "passed": cr.passed,
            "turns": [
                {
                    "turn": tr.turn_index + 1,
                    "user": tr.user,
                    "assistant": tr.assistant[:1000],
                    "pass": tr.pass_,
                    "context_ok": tr.context_ok,
                    "notes": tr.notes,
                    "tool_calls": [
                        {"tool": tc.get("tool", ""), "input": tc.get("input", {}), "output_preview": tc.get("output_preview", "")}
                        for tc in tr.tool_calls
                    ],
                }
                for tr in cr.turn_results
            ],
        })

    output = {
        "run_date": run_date,
        "runner_model": RUNNER_MODEL,
        "judge_model": JUDGE_MODEL,
        "type": "conversation",
        "total_scenarios": total_scenarios,
        "total_turns": total_turns,
        "overall_score": round(overall_score, 4),
        "passed_scenarios": passed_scenarios,
        "context_checks": {"passed": context_passed, "total": context_total},
        "scenarios": scenarios_out,
    }
    result_file.write_text(_json.dumps(output, indent=2))
    print(f"\nResults saved to {result_file}")

    # Threshold check
    print(f"\n{'=' * 60}")
    if overall_score < threshold:
        print(f"FAIL: score {overall_score:.1%} < threshold {threshold:.0%}")
        sys.exit(1)
    else:
        print(f"PASS: score {overall_score:.1%} >= threshold {threshold:.0%}")


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
        default=1,
        help="Save checkpoint every N questions (default: 1)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the most recent checkpoint file",
    )
    parser.add_argument(
        "--fresh",
        "--no-resume",
        action="store_true",
        help="Ignore any existing checkpoints and start from scratch",
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
