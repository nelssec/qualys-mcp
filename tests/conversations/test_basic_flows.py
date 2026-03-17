"""
Basic conversation flow tests for Qualys MCP tools.

These tests verify that tool functions are callable, return non-empty results,
and contain expected structure in their responses.

Requires QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL, QUALYS_GATEWAY_URL
environment variables to be set. Tests are skipped if credentials are missing.
"""

import json
import os

import pytest

import qualys_mcp

# Install VMDR fixture mocks when VMDR_MOCK_FIXTURES=1
from tests.fixtures import should_mock, install_vmdr_mocks
if should_mock():
    install_vmdr_mocks(qualys_mcp)

skip_no_creds = pytest.mark.skipif(
    not os.getenv("QUALYS_USERNAME"),
    reason="QUALYS_USERNAME not set — skipping live API tests",
)


def get_tool_fn(name):
    """Get the underlying function for a tool, unwrapping FastMCP wrappers."""
    fn = getattr(qualys_mcp, name, None)
    if fn is None:
        pytest.skip(f"Tool {name} not found")
    if hasattr(fn, "fn"):
        return fn.fn
    return fn


def call_tool(name, **kwargs):
    """Call a tool and return the result as a dict."""
    fn = get_tool_fn(name)
    result = fn(**kwargs)
    assert result is not None, f"{name} returned None"
    # Result should be serializable
    result_str = json.dumps(result)
    assert len(result_str) > 2, f"{name} returned empty result"
    return result


@skip_no_creds
class TestSecurityPosture:
    """Test get_security_posture tool responses."""

    def test_returns_non_empty(self):
        result = call_tool("get_security_posture")
        assert isinstance(result, dict)

    def test_contains_risk_data(self):
        result = call_tool("get_security_posture")
        result_str = json.dumps(result).lower()
        assert any(
            kw in result_str for kw in ["risk", "asset", "vulnerability", "trurisk"]
        ), "Response missing expected risk-related keywords"


@skip_no_creds
class TestMorningReport:
    """Test get_morning_report tool responses."""

    def test_returns_non_empty(self):
        result = call_tool("get_morning_report")
        assert isinstance(result, dict)

    def test_contains_summary_data(self):
        result = call_tool("get_morning_report")
        result_str = json.dumps(result).lower()
        assert any(
            kw in result_str for kw in ["report", "summary", "vulnerability", "risk", "posture"]
        ), "Response missing expected summary keywords"


@skip_no_creds
class TestListVulnerabilities:
    """Test vulnerability listing via search_vulns."""

    def test_returns_non_empty(self):
        result = call_tool("search_vulns", threat_type="Ransomware")
        assert isinstance(result, dict)

    def test_contains_vuln_data(self):
        result = call_tool("search_vulns", threat_type="Ransomware")
        result_str = json.dumps(result).lower()
        assert any(
            kw in result_str for kw in ["vulnerability", "cve", "vuln", "ransomware", "threat"]
        ), "Response missing expected vulnerability keywords"


@skip_no_creds
class TestTopVulnerabilities:
    """Test get_weekly_priorities tool responses."""

    def test_returns_non_empty(self):
        result = call_tool("get_weekly_priorities", limit=5)
        assert isinstance(result, dict)

    def test_contains_priority_data(self):
        result = call_tool("get_weekly_priorities", limit=5)
        result_str = json.dumps(result).lower()
        assert any(
            kw in result_str for kw in ["asset", "risk", "trurisk", "priority"]
        ), "Response missing expected priority keywords"


@skip_no_creds
class TestCVEInvestigation:
    """Test investigate_cve tool responses."""

    def test_returns_non_empty(self):
        result = call_tool("investigate_cve", cve="CVE-2021-44228")
        assert isinstance(result, dict)

    def test_contains_cve_data(self):
        result = call_tool("investigate_cve", cve="CVE-2021-44228")
        result_str = json.dumps(result).lower()
        assert any(
            kw in result_str for kw in ["cve", "vulnerability", "qid", "log4j"]
        ), "Response missing expected CVE keywords"
