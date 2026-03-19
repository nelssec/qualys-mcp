"""Claude-as-judge scoring logic."""

import json
import re

import anthropic

from .runner import MODEL

SCORE_WEIGHTS = {"correct": 1.0, "partial": 0.5, "wrong": 0.0, "tool-error": 0.0}

CONV_SCORE_WEIGHTS = {
    "correct": 1.0,
    "partial": 0.5,
    "wrong": 0.0,
    "tool-error": 0.0,
    "context-miss": 0.5,
    "off-track": 0.0,
}

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


CONV_JUDGE_SYSTEM = """You are a strict but fair evaluator of multi-turn security tool conversations.

You will receive:
1. The conversation history so far (previous turns and responses)
2. The current turn's user message
3. The tool calls made for this turn (if any)
4. The assistant's response for this turn

Score this turn using EXACTLY one of these labels:
- "correct": The response correctly answered the question using appropriate tools or conversation context.
- "partial": The response partially addressed the question, or used incomplete data.
- "wrong": The wrong tool was called, or the answer missed the point entirely.
- "tool-error": A tool raised an exception, returned an error, or no tool was called when one should have been.
- "context-miss": The assistant re-called a tool to fetch data that was ALREADY available in the conversation history. The answer itself may be fine, but the redundant tool call wastes resources.
- "off-track": The response ignored the conversational context or went on a tangent unrelated to what the user was asking about.

Important: For follow-up questions that reference prior context (e.g., "which of those", "tell me more", "any of these"), the assistant should use data already in the conversation when possible, not re-fetch it.

Respond with JSON only:
{"score": "<label>", "reasoning": "<1-2 sentence explanation>"}"""


def judge_conversation_turn(
    client: anthropic.Anthropic,
    conversation_history: str,
    current_question: str,
    tool_calls: list[dict],
    response: str,
) -> dict:
    """Use Claude-as-judge to score a single turn within a conversation.

    Returns {"score": str, "reasoning": str}.
    """
    tool_calls_text = json.dumps(tool_calls, indent=2) if tool_calls else "No tool calls made."

    user_msg = f"""## Conversation History
{conversation_history}

## Current Turn Question
{current_question}

## Tool Calls (this turn)
{tool_calls_text}

## Assistant Response (this turn)
{response}"""

    resp = client.messages.create(
        model=MODEL,
        max_tokens=256,
        system=CONV_JUDGE_SYSTEM,
        messages=[{"role": "user", "content": user_msg}],
    )

    text = resp.content[0].text.strip()
    json_match = re.search(r"\{[^}]+\}", text)
    if json_match:
        try:
            parsed = json.loads(json_match.group())
            score = parsed.get("score", "wrong")
            if score not in CONV_SCORE_WEIGHTS:
                score = "wrong"
            return {"score": score, "reasoning": parsed.get("reasoning", "")}
        except json.JSONDecodeError:
            pass

    return {"score": "wrong", "reasoning": f"Judge returned unparseable response: {text[:200]}"}
