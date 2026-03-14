"""Update coverage tags in docs/questions.md based on eval scores."""

from __future__ import annotations

import re
from pathlib import Path


def update_questions_file(
    path: Path, results: list[dict], score_to_tag: dict | None = None
):
    """Rewrite coverage tags in docs/questions.md based on eval scores.

    Maps eval scores to coverage tags:
        correct  -> ✅
        partial  -> ⚠️
        wrong    -> ❌
        tool-error -> ❌
    """
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
