"""Claude-as-judge scoring logic."""

import json
import re

import anthropic

from .runner import MODEL

SCORE_WEIGHTS = {"correct": 1.0, "partial": 0.5, "wrong": 0.0, "tool-error": 0.0}

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


def judge_response(
    client: anthropic.Anthropic,
    question: str,
    tool_calls: list[dict],
    response: str,
) -> dict:
    """Use Claude-as-judge to score a response.

    Returns {"score": str, "reasoning": str}.
    """
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
