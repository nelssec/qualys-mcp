"""Parse docs/questions.md into structured question dicts."""

import re
from pathlib import Path

QUESTIONS_PATH = Path(__file__).parent.parent / "docs" / "questions.md"


def parse_questions(path: Path = QUESTIONS_PATH) -> list[dict]:
    """Parse docs/questions.md into structured question dicts.

    Returns a list of dicts with keys:
        id, category, subcategory, question, coverage
    """
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
