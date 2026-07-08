"""Reproduce issue #229: per-asset vulnerability queries returning no detections.

Usage:
    .venv/bin/python scripts/repro_229.py [hostname-or-ip]
    .venv/bin/python scripts/repro_229.py --url http://127.0.0.1:8000/mcp/ [hostname-or-ip]

Requires live QUALYS_* env vars (QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_POD).
Non-interactive: if no target is given it auto-discovers one from a quick
security_overview (falling back to assess_risk asset listing), parses a hostname
or IP out of the returned text, and uses it.

Exit 0 = per-asset detections present with CVE/severity data (SHIP GATE PASS).
Exit 1 = #229 reproduced (per-asset query returned no detection data).
Exit 2 = could not obtain a target / harness error (inconclusive).

The pass/fail heuristic is deliberately strict: generic prose that merely
contains the word "severity" must NOT false-pass. We require BOTH a QID token
AND either a CVE id or an explicit numeric severity next to it, AND the absence
of the workflow's own "no detection data" sentinel.
"""
import asyncio
import os
import re
import sys

from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport, StreamableHttpTransport

# A hostname candidate: dotted DNS name (label.label[.label...]) that is not a
# bare version string. An IPv4 candidate: four dotted octets.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

# Detection-data markers. QID plus (CVE or explicit "severity N") is real data.
_QID_RE = re.compile(r"\bQID[\s:#-]*\d{3,}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_SEV_RE = re.compile(r"severity['\"\s:]*[1-5]\b", re.IGNORECASE)
_EMPTY_SENTINELS = (
    "no results found",
    "no detection data",
    "no detections",
    "0 detections",
    "no vulnerabilities",
    "not found in csam",
)


_TOP_ASSET_RE = re.compile(
    r"Top risk assets?:\s*([A-Za-z0-9][A-Za-z0-9._-]*)", re.IGNORECASE)


def _extract_target(text: str) -> str | None:
    """Pull a plausible hostname or IP out of overview/risk text."""
    m = _TOP_ASSET_RE.search(text)
    if m:
        return m.group(1)
    for m in _HOST_RE.finditer(text):
        cand = m.group(0)
        # Skip obvious non-hosts (docs domains, qualys endpoints).
        if cand.lower().endswith(("qualys.com", "example.com")):
            continue
        return cand
    m = _IP_RE.search(text)
    return m.group(0) if m else None


async def _discover_target(client) -> str | None:
    # Try a quick overview first (per task brief).
    try:
        ov = await client.call_tool("security_overview", {"quick": True})
        text = str(ov.content[0].text)
        print("--- overview (for asset discovery) ---")
        print(text[:2000])
        t = _extract_target(text)
        if t:
            return t
    except Exception as e:  # noqa: BLE001
        print(f"security_overview discovery failed: {e}")

    # Fall back to the risk-ranked asset listing, which names hosts.
    try:
        risk = await client.call_tool(
            "assess_risk", {"scope": "assets", "limit": 10})
        text = str(risk.content[0].text)
        print("--- assess_risk assets (fallback discovery) ---")
        print(text[:2000])
        return _extract_target(text)
    except Exception as e:  # noqa: BLE001
        print(f"assess_risk discovery failed: {e}")
        return None


def _looks_empty(text: str) -> bool:
    low = text.lower()
    if any(s in low for s in _EMPTY_SENTINELS):
        return True
    has_qid = bool(_QID_RE.search(text))
    has_cve = bool(_CVE_RE.search(text))
    has_sev = bool(_SEV_RE.search(text))
    # Real per-asset detection data = a QID together with a CVE or an explicit
    # 1-5 severity. Anything less is treated as empty (no false-pass on prose).
    has_detection_data = has_qid and (has_cve or has_sev)
    return not has_detection_data


async def main(target=None, url=None):
    if url:
        transport = StreamableHttpTransport(url)
    else:
        # The MCP stdio client spawns the server with a scrubbed default
        # environment; QUALYS_* must be forwarded explicitly or the server
        # exits with "Qualys platform not configured".
        child_env = {k: v for k, v in os.environ.items() if k.startswith("QUALYS_")}
        transport = PythonStdioTransport("qualys_mcp.py", env=child_env)

    async with Client(transport) as client:
        if target is None:
            target = await _discover_target(client)
            if not target:
                print("Could not auto-discover a target asset; pass one as argv.")
                return 2
            print(f"\nauto-discovered target: {target}")

        # Hostnames use the documented per-asset syntax ("asset:" prefix) so
        # the query exercises the per-asset detection path — bare names would
        # otherwise be routed as a general/software topic.
        if not _IP_RE.fullmatch(target) and not target.lower().startswith("asset:"):
            target = f"asset:{target}"
            print(f"using per-asset target syntax: {target}")

        result = await client.call_tool(
            "investigate", {"target": target, "depth": "deep", "detail": "detailed"},
            timeout=360)
        text = str(result.content[0].text)
        print("--- investigate result ---")
        print(text[:5000])

        empty = _looks_empty(text)
        qids = _QID_RE.findall(text)
        cves = sorted(set(_CVE_RE.findall(text)))
        print(f"\nQIDs seen: {len(qids)}  CVEs seen: {len(cves)}  "
              f"looks_empty: {empty}")
        if cves:
            print(f"sample CVEs: {cves[:8]}")
        return 1 if empty else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    url = None
    if "--url" in args:
        i = args.index("--url")
        url = args[i + 1]
        del args[i:i + 2]
    target = args[0] if args else None
    sys.exit(asyncio.run(main(target, url)))
