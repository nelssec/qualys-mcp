"""Summary report generation and regression detection."""

from __future__ import annotations

import json
from pathlib import Path

from .judge import SCORE_WEIGHTS

RESULTS_DIR = Path(__file__).parent.parent / "eval_results"


def compute_summary(results: list[dict]) -> dict:
    """Compute overall and per-category scores from result list."""
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

    cat_scores = {}
    for cat, counts in by_category.items():
        cat_weighted = sum(SCORE_WEIGHTS[s] * counts[s] for s in SCORE_WEIGHTS)
        cat_scores[cat] = cat_weighted / counts["total"] if counts["total"] else 0

    return {
        "total": total,
        "overall_score": round(overall_score, 4),
        "scored": scored,
        "by_category": by_category,
        "cat_scores": cat_scores,
    }


def detect_regressions(cat_scores: dict[str, float], result_file: Path) -> list[tuple]:
    """Compare against most recent prior JSON in eval_results/.

    Returns list of (category, prev_score, cur_score) tuples for regressions,
    and (prev_file, prev_overall_score, overall_delta) as metadata.
    """
    prev_files = sorted(RESULTS_DIR.glob("*.json"))
    prev_files = [f for f in prev_files if f != result_file]
    if not prev_files:
        return []

    prev_data = json.loads(prev_files[-1].read_text())
    prev_score = prev_data.get("overall_score", 0)
    prev_cats = prev_data.get("by_category", {})

    regressions = []
    for cat, score in cat_scores.items():
        prev_cat_score = prev_cats.get(cat, {}).get("score", 0)
        if score < prev_cat_score - 0.01:
            regressions.append((cat, prev_cat_score, score))

    return regressions


def get_previous_run(result_file: Path) -> dict | None:
    """Load the most recent prior run for comparison."""
    prev_files = sorted(RESULTS_DIR.glob("*.json"))
    prev_files = [f for f in prev_files if f != result_file]
    if not prev_files:
        return None
    return json.loads(prev_files[-1].read_text())


def print_summary(
    summary: dict, run_date: str, result_file: Path, prev_run: dict | None
):
    """Print formatted summary report to stdout."""
    scored = summary["scored"]
    by_category = summary["by_category"]
    cat_scores = summary["cat_scores"]
    overall_score = summary["overall_score"]

    print(f"\n{'=' * 60}")
    print(f"EVAL RESULTS — {run_date}")
    print(f"{'=' * 60}")
    print(f"Questions: {summary['total']}  |  Score: {overall_score:.1%}")
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
    if prev_run:
        prev_score = prev_run.get("overall_score", 0)
        delta = overall_score - prev_score
        direction = "📈" if delta > 0 else "📉" if delta < 0 else "➡️"
        prev_name = prev_run.get("_filename", "previous")
        print(f"\nvs previous ({prev_name}): {direction} {delta:+.1%} ({prev_score:.1%} → {overall_score:.1%})")

        regressions = detect_regressions(cat_scores, result_file)
        if regressions:
            print("\n⚠️  Regressions:")
            for cat, prev_s, cur_s in regressions:
                print(f"  {cat}: {prev_s:.0%} → {cur_s:.0%}")


def save_checkpoint(
    results: list[dict], run_date: str, run_id: str, model: str
) -> Path:
    """Save a partial checkpoint file to eval_results/."""
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"checkpoint_{run_date}_{run_id}.json"

    output = {
        "partial": True,
        "checkpoint_at": len(results),
        "run_date": run_date,
        "run_id": run_id,
        "model": model,
        "questions": results,
    }

    result_file.write_text(json.dumps(output, indent=2))
    return result_file


def load_latest_checkpoint(
    run_id: str | None = None, date_prefix: str | None = None
) -> tuple[set[int], list[dict], str | None]:
    """Find and load the most recent checkpoint file.

    If run_id is given, only consider checkpoints for that run.
    If date_prefix is given (e.g. "2026-03-29"), only consider checkpoints
    whose filename starts with ``checkpoint_{date_prefix}``.
    Returns (set of completed question IDs, results list, run_id or None).
    """
    if not RESULTS_DIR.exists():
        return set(), [], None

    if run_id:
        pattern = f"checkpoint_*_{run_id}.json"
    elif date_prefix:
        pattern = f"checkpoint_{date_prefix}_*.json"
    else:
        pattern = "checkpoint_*.json"
    checkpoint_files = sorted(RESULTS_DIR.glob(pattern))
    if not checkpoint_files:
        return set(), [], None

    latest = checkpoint_files[-1]
    data = json.loads(latest.read_text())
    completed_ids = {q["id"] for q in data.get("questions", [])}
    loaded_run_id = data.get("run_id")
    return completed_ids, data.get("questions", []), loaded_run_id


def cleanup_checkpoints(run_id: str) -> int:
    """Delete checkpoint files for the given run_id. Returns count deleted."""
    if not RESULTS_DIR.exists():
        return 0
    count = 0
    for f in RESULTS_DIR.glob(f"checkpoint_*_{run_id}.json"):
        f.unlink()
        count += 1
    return count


def save_results(
    results: list[dict], summary: dict, run_date: str, model: str
) -> Path:
    """Save results to eval_results/YYYY-MM-DD.json. Returns the file path."""
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"{run_date}.json"

    # Handle multiple runs on same day
    if result_file.exists():
        i = 2
        while (RESULTS_DIR / f"{run_date}-{i}.json").exists():
            i += 1
        result_file = RESULTS_DIR / f"{run_date}-{i}.json"

    output = {
        "run_date": run_date,
        "model": model,
        "total": summary["total"],
        "overall_score": summary["overall_score"],
        "scored": summary["scored"],
        "by_category": {
            cat: {**counts, "score": round(summary["cat_scores"][cat], 4)}
            for cat, counts in summary["by_category"].items()
        },
        "questions": results,
    }

    result_file.write_text(json.dumps(output, indent=2))
    return result_file
