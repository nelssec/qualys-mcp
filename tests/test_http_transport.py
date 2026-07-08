"""End-to-end: real server subprocess over Streamable HTTP + stdio regression."""
import asyncio
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport

REPO = Path(__file__).resolve().parent.parent
SCRIPT = str(REPO / "qualys_mcp.py")
DUMMY_CREDS = {
    "QUALYS_POD": "US2",
    "QUALYS_USERNAME": "dummy",
    "QUALYS_PASSWORD": "dummy",
}
EXPECTED_TOOLS = {"investigate", "assess_risk", "check_compliance",
                  "plan_remediation", "security_overview", "reports",
                  "cache_status", "aws_org_connectors"}


def _clean_env(**overrides):
    """Inherited env minus any ambient MCP_* vars, plus dummy creds/overrides."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("MCP_TRANSPORT", "MCP_HOST", "MCP_PORT", "MCP_AUTH_TOKEN")}
    return {**env, **DUMMY_CREDS, **overrides}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_server(port, token=""):
    env = _clean_env(MCP_TRANSPORT="http", MCP_HOST="127.0.0.1", MCP_PORT=str(port))
    if token:
        env["MCP_AUTH_TOKEN"] = token
    proc = subprocess.Popen([sys.executable, SCRIPT], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server died:\n{proc.stdout.read().decode()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("server did not open port in 20s")


def _list_tool_names(url, token=None):
    async def go():
        async with Client(url, auth=token) as client:
            return {t.name for t in await client.list_tools()}
    return asyncio.run(go())


def test_http_serves_all_tools():
    port = _free_port()
    proc = _start_server(port)
    try:
        names = _list_tool_names(f"http://127.0.0.1:{port}/mcp/")
        assert EXPECTED_TOOLS <= names
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_http_rejects_missing_token_and_accepts_valid_one():
    port = _free_port()
    proc = _start_server(port, token="s3cret-token")
    try:
        # NOTE: FastMCP's streamable-http app is actually mounted at "/mcp"
        # (no trailing slash); "/mcp/" 307-redirects to "/mcp" at the ASGI
        # router level, before auth is evaluated. urllib.request does not
        # auto-follow POST 307s (by design, per RFC 7231 body-replay
        # semantics), so it raises the 307 as an HTTPError instead of
        # reaching the auth-enforcing endpoint. Hit "/mcp" directly here to
        # exercise the real auth check. fastmcp's Client (used below and in
        # test_http_serves_all_tools) already tolerates the trailing slash.
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/mcp", data=b"{}", method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"})
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(req, timeout=5)
        assert excinfo.value.code == 401

        names = _list_tool_names(f"http://127.0.0.1:{port}/mcp/", token="s3cret-token")
        assert EXPECTED_TOOLS <= names
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_stdio_default_unchanged():
    transport = PythonStdioTransport(SCRIPT, env=_clean_env(),
                                     python_cmd=sys.executable)

    async def go():
        async with Client(transport) as client:
            return {t.name for t in await client.list_tools()}

    assert EXPECTED_TOOLS <= asyncio.run(go())
