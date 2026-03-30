"""Parse and run multi-turn conversation evaluations.

Conversations are defined in a YAML code-block inside docs/questions.md
between the ``conversations: BEGIN`` and ``conversations: END`` markers.
"""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path

from .parser import QUESTIONS_PATH


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ConversationTurn:
    user: str
    expect: str
    context_check: str | None = None


@dataclass
class Conversation:
    name: str
    category: str
    turns: list[ConversationTurn]


@dataclass
class TurnResult:
    turn_index: int
    user: str
    assistant: str
    pass_: bool
    context_ok: bool | None
    notes: str
    tool_calls: list[dict] = field(default_factory=list)


@dataclass
class ConversationResult:
    name: str
    category: str
    turn_results: list[TurnResult]
    score: float  # avg of per-turn, bonus for context

    @property
    def passed(self) -> bool:
        return self.score >= 0.65


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_BEGIN_MARKER = "conversations: BEGIN"
_END_MARKER = "conversations: END"


def parse_conversations(path: Path = QUESTIONS_PATH) -> list[Conversation]:
    """Parse the ``conversations:`` YAML block from *path*.

    Returns a list of :class:`Conversation` objects.
    """
    text = path.read_text()

    # Extract the YAML code-block between the markers
    begin_idx = text.find(_BEGIN_MARKER)
    end_idx = text.find(_END_MARKER)
    if begin_idx == -1 or end_idx == -1:
        raise ValueError(
            f"Could not find conversation markers in {path}. "
            f"Expected '<!-- {_BEGIN_MARKER} ...' and '<!-- {_END_MARKER} -->'."
        )

    block = text[begin_idx:end_idx]

    # Extract content inside ```yaml ... ```
    m = re.search(r"```yaml\s*\n(.*?)```", block, re.DOTALL)
    if not m:
        raise ValueError(f"No ```yaml code block found between conversation markers in {path}")

    yaml_text = m.group(1)
    data = yaml.safe_load(yaml_text)

    if not data or "conversations" not in data:
        raise ValueError("YAML block does not contain a 'conversations' key")

    conversations: list[Conversation] = []
    for entry in data["conversations"]:
        turns = []
        for t in entry["turns"]:
            turns.append(
                ConversationTurn(
                    user=t["user"],
                    expect=t["expect"],
                    context_check=t.get("context_check"),
                )
            )
        conversations.append(
            Conversation(
                name=entry["name"],
                category=entry["category"],
                turns=turns,
            )
        )

    return conversations
