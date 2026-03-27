"""Send questions to the MCP server via Claude API with tools enabled."""

import os
import sys
import time
from pathlib import Path

import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_DEFAULT_MODEL = "claude-haiku-4-5"

RUNNER_MODEL = os.environ.get("EVAL_RUNNER_MODEL") or os.environ.get("EVAL_MODEL") or _DEFAULT_MODEL
JUDGE_MODEL = os.environ.get("EVAL_JUDGE_MODEL") or os.environ.get("EVAL_MODEL") or _DEFAULT_MODEL

def _create_message_with_retry(client: anthropic.Anthropic, **kwargs):
    """Wrap client.messages.create with retry logic for transient 401/429 errors."""
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            return client.messages.create(**kwargs)
        except anthropic.AuthenticationError:
            if attempt == max_attempts - 1:
                raise
            wait = 2 * (2 ** attempt)
            print(f"[retry] 401 AuthenticationError (transient), waiting {wait}s (attempt {attempt + 1}/{max_attempts})")
            time.sleep(wait)
        except anthropic.RateLimitError:
            if attempt == max_attempts - 1:
                raise
            wait = 5 * (2 ** attempt)
            print(f"[retry] 429 RateLimitError, waiting {wait}s (attempt {attempt + 1}/{max_attempts})")
            time.sleep(wait)


SYSTEM_PROMPT = (
    "You are a security analyst assistant with access to Qualys security tools. "
    "Use the available tools to answer the user's question about their security environment. "
    "Be concise and data-driven."
)


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
    assistant_text = ""

    for _ in range(10):  # max iterations
        resp = _create_message_with_retry(client,
            model=RUNNER_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
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
                        "output": result_text,
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


async def run_conversation(
    client: anthropic.Anthropic,
    session: ClientSession,
    tools: list[dict],
    turns: list[str],
) -> list[dict]:
    """Run a multi-turn conversation, maintaining message history across turns.

    Returns a list of per-turn results:
        [{"turn": int, "question": str, "response": str, "tool_calls": list[dict]}, ...]
    """
    messages: list[dict] = []
    turn_results = []

    for turn_idx, user_msg in enumerate(turns, start=1):
        messages.append({"role": "user", "content": user_msg})
        tool_calls_log = []
        assistant_text = ""

        for _ in range(10):  # max iterations per turn
            resp = _create_message_with_retry(client,
                model=RUNNER_MODEL,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=messages,
            )

            assistant_text = ""
            tool_use_blocks = []
            for block in resp.content:
                if block.type == "text":
                    assistant_text += block.text
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason == "end_turn" or not tool_use_blocks:
                break

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
                            "output": result_text,
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

        turn_results.append(
            {
                "turn": turn_idx,
                "question": user_msg,
                "response": assistant_text,
                "tool_calls": tool_calls_log,
            }
        )

    return turn_results


def get_server_params() -> StdioServerParameters:
    """Build MCP server parameters from environment."""
    return StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).parent.parent / "qualys_mcp.py")],
        env={
            **os.environ,
            "QUALYS_USERNAME": os.environ["QUALYS_USERNAME"],
            "QUALYS_PASSWORD": os.environ["QUALYS_PASSWORD"],
            "QUALYS_BASE_URL": os.environ["QUALYS_BASE_URL"],
            "QUALYS_GATEWAY_URL": os.environ.get("QUALYS_GATEWAY_URL", ""),
            "QUALYS_SSL_VERIFY": os.environ.get("QUALYS_SSL_VERIFY", ""),
        },
    )
