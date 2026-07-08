"""Concurrency soak for the Streamable HTTP transport (issue #213 class).

Usage: .venv/bin/python scripts/soak_http.py
Env: SOAK_URL (default http://127.0.0.1:8000/mcp/), SOAK_CLIENTS (10),
     SOAK_MINUTES (5), MCP_AUTH_TOKEN (optional).
Exit 0 = zero errors across all clients.
"""
import asyncio
import os
import sys
import time

from fastmcp import Client

URL = os.environ.get("SOAK_URL", "http://127.0.0.1:8000/mcp/")
CLIENTS = int(os.environ.get("SOAK_CLIENTS", "10"))
MINUTES = float(os.environ.get("SOAK_MINUTES", "5"))
TOKEN = os.environ.get("MCP_AUTH_TOKEN") or None

# Rotate through cheap + heavier tools to stress both fast and slow paths.
CALLS = [
    ("cache_status", {"clear": False}),
    ("security_overview", {"quick": True}),
]


async def worker(idx, stop_at, stats):
    async with Client(URL, auth=TOKEN) as client:
        i = 0
        while time.monotonic() < stop_at:
            tool, params = CALLS[i % len(CALLS)]
            i += 1
            started = time.monotonic()
            try:
                await client.call_tool(tool, params)
                stats["ok"] += 1
                stats["latency"].append(time.monotonic() - started)
            except Exception as exc:
                stats["errors"].append(f"client{idx} {tool}: {exc!r}")


async def main():
    stop_at = time.monotonic() + MINUTES * 60
    stats = {"ok": 0, "errors": [], "latency": []}
    await asyncio.gather(*(worker(i, stop_at, stats) for i in range(CLIENTS)))
    lat = sorted(stats["latency"])
    p95 = lat[int(len(lat) * 0.95)] if lat else 0
    print(f"calls ok: {stats['ok']}  errors: {len(stats['errors'])}  p95: {p95:.2f}s")
    for err in stats["errors"][:20]:
        print("  ", err)
    return 1 if stats["errors"] else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
