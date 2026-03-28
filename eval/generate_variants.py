#!/usr/bin/env python3
"""Generate natural language variants for every eval question.

Reads questions via parser.parse_questions(), calls claude-haiku-4-5 to produce
3 rephrasings per question, and writes eval/question_variants.json.

Usage:
    python eval/generate_variants.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import anthropic

# Support running as `python eval/generate_variants.py` from project root
sys.path.insert(0, str(Path(__file__).parent.parent))
from eval.parser import parse_questions

VARIANTS_PATH = Path(__file__).parent / "question_variants.json"
BATCH_SIZE = 20
MODEL = "claude-haiku-4-5"


def build_batch_prompt(indexed_questions: list[tuple[int, dict]]) -> str:
    """Build a prompt asking for 3 variants of each question in a batch.

    indexed_questions: list of (global_index, question_dict) tuples.
    """
    lines = ["For each numbered question below, generate exactly 3 natural language variants."]
    lines.append("")
    lines.append("Rules:")
    lines.append("- Change wording naturally (shorter, more casual, more formal, different word order)")
    lines.append("- Never change the intent or scope of the question")
    lines.append("- Sound like real questions a security analyst or executive might ask")
    lines.append("- Do NOT add extra scope (\"and also show me...\") or remove scope")
    lines.append("- Do NOT repeat the original question as a variant")
    lines.append("")
    lines.append("Return ONLY valid JSON: an object mapping question number (string) to an array of exactly 3 variant strings.")
    lines.append("Example: {\"42\": [\"variant 1\", \"variant 2\", \"variant 3\"]}")
    lines.append("")
    lines.append("Questions:")
    for idx, q in indexed_questions:
        lines.append(f"{idx}. {q['question']}")
    return "\n".join(lines)


def parse_variants_response(text: str, question_ids: list[int]) -> dict[str, list[str]]:
    """Extract JSON from model response, handling markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        # Strip markdown code fences
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    return json.loads(text)


def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    client = anthropic.Anthropic()
    questions = parse_questions()
    print(f"Loaded {len(questions)} questions")

    # Key by list index (0-based) to avoid duplicate question IDs across categories
    indexed = list(enumerate(questions))
    variants: dict[str, list[str]] = {}

    # Process in batches
    for i in range(0, len(indexed), BATCH_SIZE):
        batch = indexed[i : i + BATCH_SIZE]
        batch_range = f"{batch[0][0]}-{batch[-1][0]}"
        print(f"  Batch {i // BATCH_SIZE + 1}: indices {batch_range} ({len(batch)} questions)...", end=" ", flush=True)

        prompt = build_batch_prompt(batch)
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )

        text = resp.content[0].text
        try:
            batch_variants = parse_variants_response(text, [idx for idx, _ in batch])
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            print(f"Response text: {text[:500]}")
            # Retry once
            print("  Retrying...", end=" ", flush=True)
            resp = client.messages.create(
                model=MODEL,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text
            batch_variants = parse_variants_response(text, [idx for idx, _ in batch])

        # Merge into main dict, keyed by string index
        for idx, q in batch:
            sid = str(idx)
            v = batch_variants.get(sid, batch_variants.get(idx, []))
            if len(v) != 3:
                print(f"\n  WARNING: index {sid} got {len(v)} variants instead of 3")
            # Store as [original, variant1, variant2, variant3]
            variants[sid] = [q["question"]] + v[:3]

        print(f"ok ({len(batch_variants)} questions)")

    # Validate
    missing = [i for i in range(len(questions)) if str(i) not in variants]
    if missing:
        print(f"\nWARNING: Missing variants for {len(missing)} questions: {missing[:10]}...")

    # Save
    VARIANTS_PATH.write_text(json.dumps(variants, indent=2, ensure_ascii=False))
    print(f"\nSaved {len(variants)} question variants to {VARIANTS_PATH}")
    print(f"Total entries: {sum(len(v) for v in variants.values())} (original + variants)")


if __name__ == "__main__":
    main()
