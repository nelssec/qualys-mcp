#!/usr/bin/env python3
"""Generate natural language variants for every eval question.

Reads questions via parser.parse_questions(), calls claude-haiku-4-5 to produce
N rephrasings per question, and writes eval/question_variants.json.

Usage:
    python eval/generate_variants.py
    python eval/generate_variants.py --new-only
    python eval/generate_variants.py --new-only --variants-per-question 4
"""

from __future__ import annotations

import argparse
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


def build_batch_prompt(indexed_questions: list[tuple[int, dict]], num_variants: int) -> str:
    """Build a prompt asking for N variants of each question in a batch.

    indexed_questions: list of (global_index, question_dict) tuples.
    """
    lines = [f"For each numbered question below, generate exactly {num_variants} natural language variants."]
    lines.append("")
    lines.append("Rules:")
    lines.append("- Change wording naturally (shorter, more casual, more formal, different word order)")
    lines.append("- Never change the intent or scope of the question")
    lines.append("- Sound like real questions a security analyst or executive might ask")
    lines.append("- Do NOT add extra scope (\"and also show me...\") or remove scope")
    lines.append("- Do NOT repeat the original question as a variant")
    lines.append("")
    lines.append(
        f"Return ONLY valid JSON: an object mapping question number (string) to an array of exactly {num_variants} variant strings."
    )
    lines.append(f'Example: {{"42": ["variant 1", "variant 2", "variant 3"{", ..." if num_variants > 3 else ""}]}}')
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


def compute_consistency_metadata(variants: dict[str, list[str]]) -> dict:
    """Compute variant consistency metadata.

    Returns a dict with:
      - total_questions: number of questions with variants
      - questions_with_expected_count: number with the expected variant count
      - variant_counts: distribution of variant counts
    """
    counts: dict[int, int] = {}
    for v in variants.values():
        # v is [original, variant1, variant2, ...]
        n = len(v) - 1  # subtract original
        counts[n] = counts.get(n, 0) + 1

    return {
        "total_questions": len(variants),
        "questions_with_variants": sum(1 for v in variants.values() if len(v) > 1),
        "variant_count_distribution": {str(k): v for k, v in sorted(counts.items())},
    }


def main():
    parser = argparse.ArgumentParser(description="Generate NL variants for eval questions")
    parser.add_argument(
        "--new-only",
        action="store_true",
        help="Only generate variants for questions not already in question_variants.json",
    )
    parser.add_argument(
        "--variants-per-question",
        type=int,
        default=3,
        help="Number of variants to generate per question (default: 3)",
    )
    args = parser.parse_args()

    num_variants = args.variants_per_question

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    client = anthropic.Anthropic()
    questions = parse_questions()
    print(f"Loaded {len(questions)} questions")

    # Load existing variants if --new-only
    existing_variants: dict[str, list[str]] = {}
    if args.new_only and VARIANTS_PATH.exists():
        existing_variants = json.loads(VARIANTS_PATH.read_text())
        print(f"Loaded {len(existing_variants)} existing variant entries")

    # Key by list index (0-based) to avoid duplicate question IDs across categories
    indexed = list(enumerate(questions))

    # Filter to new-only if requested
    if args.new_only:
        indexed = [(i, q) for i, q in indexed if str(i) not in existing_variants]
        print(f"Generating variants for {len(indexed)} new questions (skipping {len(existing_variants)} existing)")

    if not indexed:
        print("No new questions to process.")
        # Still save metadata
        if existing_variants:
            meta = compute_consistency_metadata(existing_variants)
            existing_variants["_metadata"] = meta
            VARIANTS_PATH.write_text(json.dumps(existing_variants, indent=2, ensure_ascii=False))
            print(f"Updated metadata: {json.dumps(meta, indent=2)}")
        return

    variants: dict[str, list[str]] = dict(existing_variants)
    # Remove old metadata before processing
    variants.pop("_metadata", None)

    # Process in batches
    for i in range(0, len(indexed), BATCH_SIZE):
        batch = indexed[i : i + BATCH_SIZE]
        batch_range = f"{batch[0][0]}-{batch[-1][0]}"
        print(f"  Batch {i // BATCH_SIZE + 1}: indices {batch_range} ({len(batch)} questions)...", end=" ", flush=True)

        prompt = build_batch_prompt(batch, num_variants)
        resp = client.messages.create(
            model=MODEL,
            max_tokens=8192,
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
                max_tokens=8192,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text
            batch_variants = parse_variants_response(text, [idx for idx, _ in batch])

        # Merge into main dict, keyed by string index
        for idx, q in batch:
            sid = str(idx)
            v = batch_variants.get(sid, batch_variants.get(idx, []))
            if len(v) != num_variants:
                print(f"\n  WARNING: index {sid} got {len(v)} variants instead of {num_variants}")
            # Store as [original, variant1, variant2, ...]
            variants[sid] = [q["question"]] + v[:num_variants]

        print(f"ok ({len(batch_variants)} questions)")

    # Validate
    all_questions = parse_questions()
    missing = [i for i in range(len(all_questions)) if str(i) not in variants]
    if missing:
        print(f"\nWARNING: Missing variants for {len(missing)} questions: {missing[:10]}...")

    # Compute and attach consistency metadata
    meta = compute_consistency_metadata(variants)
    print(f"\nVariant consistency: {json.dumps(meta, indent=2)}")
    variants["_metadata"] = meta

    # Save
    VARIANTS_PATH.write_text(json.dumps(variants, indent=2, ensure_ascii=False))
    print(f"\nSaved {len(variants) - 1} question variants to {VARIANTS_PATH}")  # -1 for _metadata
    print(f"Total entries: {sum(len(v) for v in variants.values() if isinstance(v, list))} (original + variants)")


if __name__ == "__main__":
    main()
