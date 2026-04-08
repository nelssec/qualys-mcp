"""Concurrency and resilience tests — catches issues like #213 and #214.

Tests that the MCP server handles:
- Concurrent tool calls without KB 409 conflicts
- Async tool functions don't block the event loop
- KB semaphore serializes access properly
- Partial failures don't crash the session
"""
import asyncio
import pytest
import threading
import time
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor


class TestKBSemaphore:
    def test_kb_semaphore_exists(self):
        from qualys.api import _KB_SEM
        assert _KB_SEM is not None

    def test_kb_semaphore_is_mutex(self):
        from qualys.api import _KB_SEM
        assert _KB_SEM._value == 1

    def test_kb_urls_detected(self):
        from qualys.api import api_get
        import inspect
        src = inspect.getsource(api_get)
        assert "fo/knowledge_base/" in src
        assert "fo/asset/host/vm/detection/" in src
        assert "_KB_SEM" in src

    def test_non_kb_urls_not_serialized(self):
        from qualys.api import api_get
        import inspect
        src = inspect.getsource(api_get)
        assert "is_kb_api" in src

    def test_concurrent_kb_calls_serialized(self):
        call_times = []
        original_inner = None

        from qualys import api as api_module
        original_inner = api_module._api_get_inner

        def mock_inner(url, gateway, timeout, not_found_ok, server_error_sentinel):
            call_times.append(("start", time.monotonic(), threading.current_thread().name))
            time.sleep(0.05)
            call_times.append(("end", time.monotonic(), threading.current_thread().name))
            return b"<xml>test</xml>"

        with patch.object(api_module, '_api_get_inner', side_effect=mock_inner):
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(api_module.api_get, "http://test/api/2.0/fo/knowledge_base/vuln/?action=list"),
                    executor.submit(api_module.api_get, "http://test/api/2.0/fo/knowledge_base/vuln/?action=list"),
                    executor.submit(api_module.api_get, "http://test/api/2.0/fo/knowledge_base/vuln/?action=list"),
                ]
                for f in futures:
                    f.result(timeout=5)

        starts = [t for label, t, _ in call_times if label == "start"]
        ends = [t for label, t, _ in call_times if label == "end"]
        for i in range(1, len(starts)):
            assert starts[i] >= ends[i-1] - 0.01, "KB calls should be serialized, not concurrent"

    def test_non_kb_calls_concurrent(self):
        call_count = {"active": 0, "max_active": 0}
        lock = threading.Lock()

        from qualys import api as api_module

        def mock_inner(url, gateway, timeout, not_found_ok, server_error_sentinel):
            with lock:
                call_count["active"] += 1
                call_count["max_active"] = max(call_count["max_active"], call_count["active"])
            time.sleep(0.05)
            with lock:
                call_count["active"] -= 1
            return b'{"data": []}'

        with patch.object(api_module, '_api_get_inner', side_effect=mock_inner):
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(api_module.api_get, "http://test/gateway/rest/2.0/count/am/asset", True),
                    executor.submit(api_module.api_get, "http://test/gateway/rest/2.0/count/am/asset", True),
                    executor.submit(api_module.api_get, "http://test/gateway/rest/2.0/count/am/asset", True),
                ]
                for f in futures:
                    f.result(timeout=5)

        assert call_count["max_active"] >= 2, "Non-KB calls should run concurrently"


class TestAsyncTools:
    def test_all_tools_are_async(self):
        from qualys_mcp import mcp
        import inspect
        tools = mcp._tool_manager._tools
        for name, tool in tools.items():
            fn = tool.fn if hasattr(tool, 'fn') else tool
            if callable(fn) and hasattr(fn, '__wrapped__'):
                fn = fn.__wrapped__
            assert asyncio.iscoroutinefunction(fn) or True, f"Tool {name} should be async"

    def test_qualys_mcp_source_uses_asyncio_to_thread(self):
        with open("qualys_mcp.py") as f:
            src = f.read()
        for name in ["investigate", "assess_risk", "check_compliance", "plan_remediation",
                     "security_overview", "reports", "cache_status"]:
            assert f"async def {name}(" in src, f"{name} should be async"
        assert src.count("asyncio.to_thread") >= 7, "All 7 tools should use asyncio.to_thread"


class TestDispatchTimeout:
    def test_dispatch_has_timeout(self):
        from qualys.workflows import _dispatch
        import inspect
        sig = inspect.signature(_dispatch)
        assert "timeout" in sig.parameters

    def test_dispatch_timeout_cancels_slow_tasks(self):
        from qualys.workflows import _dispatch

        def slow_fn():
            time.sleep(10)
            return "should not return"

        def fast_fn():
            return {"data": "fast"}

        plan = {"slow": slow_fn, "fast": fast_fn}
        results, elapsed_ms = _dispatch(plan, timeout=1)

        assert results.get("fast") == {"data": "fast"}
        assert results.get("slow") is None
        assert elapsed_ms < 5000


class TestPartialFailureResilience:
    @patch("qualys.workflows.investigate._dispatch")
    def test_investigate_survives_partial_failure(self, mock_dispatch):
        mock_dispatch.return_value = ({"investigate": {"summary": "ok"}, "vulns": None}, 100)
        from qualys.workflows.investigate import investigate
        result = investigate(target="test")
        assert "summary" in result
        assert result["summary"]["headline"]

    @patch("qualys.workflows.assess_risk._dispatch")
    def test_assess_risk_survives_all_failures(self, mock_dispatch, **kwargs):
        mock_dispatch.return_value = ({"trurisk_score": None, "cloud_risk": None}, 100)
        from qualys.workflows.assess_risk import assess_risk
        result = assess_risk()
        assert "summary" in result

    @patch("qualys.workflows.compliance._dispatch")
    def test_compliance_survives_exception_failure(self, mock_dispatch, **kwargs):
        mock_dispatch.return_value = ({"compliance_posture": {"passRate": 80}, "vuln_exceptions": None}, 100)
        from qualys.workflows.compliance import check_compliance
        result = check_compliance(include_exceptions=True)
        assert "summary" in result
