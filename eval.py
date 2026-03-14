#!/usr/bin/env python3
"""Eval harness for Qualys MCP Server — sends questions from docs/questions.md
against the live MCP server via Claude API and scores response quality."""

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QUESTIONS_PATH = Path(__file__).parent / "docs" / "questions.md"
RESULTS_DIR = Path(__file__).parent / "eval_results"
MODEL = "claude-sonnet-4-20250514"

JUDGE_SYSTEM = """You are a strict but fair evaluator of security tool responses.

You will receive:
1. The original user question about their Qualys security environment
2. The tool calls that were made (if any)
3. The assistant's final response

Score the response using EXACTLY one of these labels:
- "correct": A tool was called, it returned data, and the response answered the question well.
- "partial": A tool was called but the data was incomplete, or the answer only partially addressed the question.
- "wrong": The wrong tool was called, or the answer missed the point of the question entirely.
- "tool-error": A tool raised an exception, returned an error, or no tool was called when one should have been.

Respond with JSON only:
{"score": "<label>", "reasoning": "<1-2 sentence explanation>"}"""

SCORE_WEIGHTS = {"correct": 1.0, "partial": 0.5, "wrong": 0.0, "tool-error": 0.0}

# ---------------------------------------------------------------------------
# Question parser
# ---------------------------------------------------------------------------


def parse_questions(path: Path = QUESTIONS_PATH) -> list[dict]:
    """Parse docs/questions.md into structured question dicts."""
    text = path.read_text()
    questions = []
    current_category = ""
    current_subcategory = ""

    for line in text.splitlines():
        line = line.strip()

        # Category header: ## Category Name — N questions
        if line.startswith("## ") and "—" in line:
            current_category = line.lstrip("# ").split("—")[0].strip()
            # Strip parens like (VM) (PM) etc.
            current_category = re.sub(r"\s*\(.*?\)\s*", " ", current_category).strip()
            current_subcategory = ""
            continue

        # Subcategory header: ### Subcategory
        if line.startswith("### "):
            current_subcategory = line.lstrip("# ").strip()
            continue

        # Question line: N. ✅/⚠️/❌ Question text
        m = re.match(r"^(\d+)\.\s+(✅|⚠️|❌)\s+(.+)$", line)
        if m:
            qid = int(m.group(1))
            coverage = {"✅": "full", "⚠️": "partial", "❌": "gap"}[m.group(2)]
            questions.append(
                {
                    "id": qid,
                    "category": current_category,
                    "subcategory": current_subcategory,
                    "question": m.group(3),
                    "coverage": coverage,
                }
            )

    return questions


def update_questions_file(
    path: Path, results: list[dict], score_to_tag: dict | None = None
):
    """Rewrite coverage tags in docs/questions.md based on eval scores."""
    if score_to_tag is None:
        score_to_tag = {
            "correct": "✅",
            "partial": "⚠️",
            "wrong": "❌",
            "tool-error": "❌",
        }

    score_map = {r["id"]: r["score"] for r in results}
    text = path.read_text()
    lines = text.splitlines()
    out = []

    for line in lines:
        m = re.match(r"^(\d+)\.\s+(?:✅|⚠️|❌)\s+(.+)$", line.strip())
        if m:
            qid = int(m.group(1))
            if qid in score_map:
                tag = score_to_tag.get(score_map[qid], "❌")
                # Preserve leading whitespace
                leading = len(line) - len(line.lstrip())
                out.append(f"{line[:leading]}{qid}. {tag} {m.group(2)}")
                continue
        out.append(line)

    path.write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------------------
# MCP client — connect to the live server
# ---------------------------------------------------------------------------


async def get_mcp_tools(session: ClientSession) -> list[dict]:
    """Get tool definitions from the MCP server in Anthropic API format."""
    tools_result = await session.list_tools()
    anthropic_tools = []
    for tool in tools_result.tools:
        anthropic_tools.append(
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
            }
        )
    return anthropic_tools


async def call_mcp_tool(
    session: ClientSession, name: str, arguments: dict
) -> str:
    """Call a tool on the MCP server and return the text result."""
    result = await session.call_tool(name, arguments)
    parts = []
    for content in result.content:
        if hasattr(content, "text"):
            parts.append(content.text)
        else:
            parts.append(str(content))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Agentic loop: ask Claude with tools, iterate until done
# ---------------------------------------------------------------------------


async def run_question(
    client: anthropic.Anthropic,
    session: ClientSession,
    tools: list[dict],
    question: str,
) -> dict:
    """Run a single question through Claude with MCP tools.

    Returns {"response": str, "tool_calls": list[dict]}
    """
    messages = [{"role": "user", "content": question}]
    tool_calls_log = []

    system = (
        "You are a security analyst assistant with access to Qualys security tools. "
        "Use the available tools to answer the user's question about their security environment. "
        "Be concise and data-driven."
    )

    for _ in range(10):  # max iterations
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system,
            tools=tools,
            messages=messages,
        )

        # Collect assistant content
        assistant_text = ""
        tool_use_blocks = []
        for block in resp.content:
            if block.type == "text":
                assistant_text += block.text
            elif block.type == "tool_use":
                tool_use_blocks.append(block)

        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "end_turn" or not tool_use_blocks:
            return {"response": assistant_text, "tool_calls": tool_calls_log}

        # Process tool calls
        tool_results = []
        for block in tool_use_blocks:
            try:
                result_text = await call_mcp_tool(
                    session, block.name, block.input
                )
                tool_calls_log.append(
                    {
                        "tool": block.name,
                        "input": block.input,
                        "output_preview": result_text[:500],
                        "error": None,
                    }
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    }
                )
            except Exception as e:
                tool_calls_log.append(
                    {
                        "tool": block.name,
                        "input": block.input,
                        "output_preview": None,
                        "error": str(e),
                    }
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": f"Error: {e}",
                        "is_error": True,
                    }
                )

        messages.append({"role": "user", "content": tool_results})

    return {"response": assistant_text, "tool_calls": tool_calls_log}


# ---------------------------------------------------------------------------
# Judge: score a response
# ---------------------------------------------------------------------------


def judge_response(
    client: anthropic.Anthropic,
    question: str,
    tool_calls: list[dict],
    response: str,
) -> dict:
    """Use Claude-as-judge to score a response. Returns {"score": str, "reasoning": str}."""
    tool_calls_text = json.dumps(tool_calls, indent=2) if tool_calls else "No tool calls made."

    user_msg = f"""## Question
{question}

## Tool Calls
{tool_calls_text}

## Assistant Response
{response}"""

    resp = client.messages.create(
        model=MODEL,
        max_tokens=256,
        system=JUDGE_SYSTEM,
        messages=[{"role": "user", "content": user_msg}],
    )

    text = resp.content[0].text.strip()
    # Extract JSON from response (handle markdown code blocks)
    json_match = re.search(r"\{[^}]+\}", text)
    if json_match:
        try:
            parsed = json.loads(json_match.group())
            score = parsed.get("score", "wrong")
            if score not in SCORE_WEIGHTS:
                score = "wrong"
            return {"score": score, "reasoning": parsed.get("reasoning", "")}
        except json.JSONDecodeError:
            pass

    return {"score": "wrong", "reasoning": f"Judge returned unparseable response: {text[:200]}"}


# ---------------------------------------------------------------------------
# Main eval loop
# ---------------------------------------------------------------------------


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

    # Connect to MCP server
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).parent / "qualys_mcp.py")],
        env={
            **os.environ,
            "QUALYS_USERNAME": os.environ["QUALYS_USERNAME"],
            "QUALYS_PASSWORD": os.environ["QUALYS_PASSWORD"],
            "QUALYS_BASE_URL": os.environ["QUALYS_BASE_URL"],
            "QUALYS_GATEWAY_URL": os.environ.get("QUALYS_GATEWAY_URL", ""),
            "QUALYS_SSL_VERIFY": os.environ.get("QUALYS_SSL_VERIFY", ""),
        },
    )

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

            # Run questions (sequentially through MCP but with concurrent judging)
            # MCP stdio transport is single-connection, so we run questions sequentially
            # but could parallelize the judging step
            for q in questions:
                result = await process_question(q)
                results.append(result)

    # ---------------------------------------------------------------------------
    # Summarize
    # ---------------------------------------------------------------------------
    scored = {"correct": 0, "partial": 0, "wrong": 0, "tool-error": 0}
    by_category: dict[str, dict[str, int]] = {}

    for r in results:
        scored[r["score"]] += 1
        cat = r["category"]
        if cat not in by_category:
            by_category[cat] = {"correct": 0, "partial": 0, "wrong": 0, "tool-error": 0, "total": 0}
        by_category[cat][r["score"]] += 1
        by_category[cat]["total"] += 1

    total = len(results)
    weighted = sum(SCORE_WEIGHTS[r["score"]] for r in results)
    overall_score = weighted / total if total else 0

    # Category scores
    cat_scores = {}
    for cat, counts in by_category.items():
        cat_weighted = sum(
            SCORE_WEIGHTS[s] * counts[s] for s in SCORE_WEIGHTS
        )
        cat_scores[cat] = cat_weighted / counts["total"] if counts["total"] else 0

    # Save results
    RESULTS_DIR.mkdir(exist_ok=True)
    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    result_file = RESULTS_DIR / f"{run_date}.json"

    # Handle multiple runs on same day
    if result_file.exists():
        i = 2
        while (RESULTS_DIR / f"{run_date}-{i}.json").exists():
            i += 1
        result_file = RESULTS_DIR / f"{run_date}-{i}.json"

    output = {
        "run_date": datetime.now(timezone.utc).isoformat(),
        "model": MODEL,
        "total": total,
        "overall_score": round(overall_score, 4),
        "scored": scored,
        "by_category": {
            cat: {**counts, "score": round(cat_scores[cat], 4)}
            for cat, counts in by_category.items()
        },
        "questions": results,
    }

    result_file.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {result_file}")

    # ---------------------------------------------------------------------------
    # Print summary
    # ---------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print(f"EVAL RESULTS — {run_date}")
    print(f"{'=' * 60}")
    print(f"Questions: {total}  |  Score: {overall_score:.1%}")
    print(f"  correct: {scored['correct']}  partial: {scored['partial']}  wrong: {scored['wrong']}  tool-error: {scored['tool-error']}")
    print()

    # Per-category breakdown
    print(f"{'Category':<35} {'Score':>6}  {'✅':>3} {'⚠️':>3} {'❌':>3} {'💥':>3}")
    print("-" * 60)
    for cat in sorted(by_category.keys()):
        c = by_category[cat]
        s = cat_scores[cat]
        print(
            f"{cat:<35} {s:>5.0%}  {c['correct']:>3} {c['partial']:>3} {c['wrong']:>3} {c['tool-error']:>3}"
        )

    # Compare vs previous run
    prev_files = sorted(RESULTS_DIR.glob("*.json"))
    prev_files = [f for f in prev_files if f != result_file]
    if prev_files:
        prev_data = json.loads(prev_files[-1].read_text())
        prev_score = prev_data.get("overall_score", 0)
        delta = overall_score - prev_score
        direction = "📈" if delta > 0 else "📉" if delta < 0 else "➡️"
        print(f"\nvs previous ({prev_files[-1].name}): {direction} {delta:+.1%} ({prev_score:.1%} → {overall_score:.1%})")

        # Category regressions
        regressions = []
        prev_cats = prev_data.get("by_category", {})
        for cat, score in cat_scores.items():
            prev_cat_score = prev_cats.get(cat, {}).get("score", 0)
            if score < prev_cat_score - 0.01:
                regressions.append((cat, prev_cat_score, score))
        if regressions:
            print("\n⚠️  Regressions:")
            for cat, prev_s, cur_s in regressions:
                print(f"  {cat}: {prev_s:.0%} → {cur_s:.0%}")

    # Update questions file if requested
    if args.update_questions:
        update_questions_file(QUESTIONS_PATH, results)
        print(f"\nUpdated coverage tags in {QUESTIONS_PATH}")

    # Threshold check
    print(f"\n{'=' * 60}")
    if overall_score < args.threshold:
        print(f"FAIL: score {overall_score:.1%} < threshold {args.threshold:.0%}")
        sys.exit(1)
    else:
        print(f"PASS: score {overall_score:.1%} >= threshold {args.threshold:.0%}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Eval harness for Qualys MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python eval.py --quick                    # Smoke test: 20 questions, fast
  python eval.py --category "Vulnerability Management"
  python eval.py --limit 5                  # Test 5 questions
  python eval.py --threshold 0.8            # Fail if score < 80%
  python eval.py --update-questions         # Update docs/questions.md tags
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
        "--update-questions",
        action="store_true",
        help="Auto-update coverage tags in docs/questions.md",
    )

    args = parser.parse_args()

    if args.quick:
        if not args.limit:
            args.limit = 20
        args.concurrency = max(args.concurrency, 10)

    asyncio.run(run_eval(args))


if __name__ == "__main__":
    main()
