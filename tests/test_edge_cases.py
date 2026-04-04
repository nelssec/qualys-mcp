"""Tests for edge cases: partial failures, empty inputs, scope conflicts.

These tests verify that workflow orchestrators handle error conditions
gracefully — aggregator failures are captured as None, empty plans
return sensible defaults, and conflicting scopes don't crash.
"""

import pytest
from unittest.mock import patch, MagicMock


# ===========================================================================
# _dispatch edge cases (from __init__.py)
# ===========================================================================

class TestDispatchEdgeCases:
    """Test the shared _dispatch function handles edge cases."""

    def test_empty_plan_returns_empty_dict(self):
        from qualys.workflows import _dispatch
        results, elapsed = _dispatch({})
        assert results == {}
        assert elapsed == 0

    def test_single_success(self):
        from qualys.workflows import _dispatch
        with patch("qualys.workflows._run_concurrent", return_value={"key": "value"}):
            results, elapsed = _dispatch({"key": lambda: "value"})
        assert results == {"key": "value"}

    def test_partial_failure_captured_as_none(self):
        """_safe_call wraps each fn; if it raises, result is None."""
        from qualys.workflows import _safe_call
        result = _safe_call("test_agg", lambda: 1 / 0)
        assert result is None

    def test_safe_call_success_returns_value(self):
        from qualys.workflows import _safe_call
        result = _safe_call("test_agg", lambda: {"data": 42})
        assert result == {"data": 42}

    def test_safe_call_exception_does_not_propagate(self):
        from qualys.workflows import _safe_call
        # Should not raise
        result = _safe_call("agg", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        assert result is None


# ===========================================================================
# _build_envelope edge cases (from __init__.py)
# ===========================================================================

class TestBuildEnvelopeEdgeCases:
    """Test _build_envelope handles all-failure and empty scenarios."""

    def test_all_failures_produces_error_key(self):
        from qualys.workflows import _build_envelope
        results = {"agg1": None, "agg2": None}
        env = _build_envelope(
            workflow="test",
            aggregators_called=["agg1", "agg2"],
            results=results,
            execution_time_ms=0,
        )
        assert "_errors" in env
        assert set(env["_errors"]) == {"agg1", "agg2"}

    def test_all_failures_summary_is_unknown(self):
        from qualys.workflows import _build_envelope
        results = {"agg1": None}
        env = _build_envelope(
            workflow="test",
            aggregators_called=["agg1"],
            results=results,
            execution_time_ms=0,
        )
        assert env["summary"]["risk_level"] == "unknown"

    def test_partial_failure_data_excludes_nones(self):
        from qualys.workflows import _build_envelope
        results = {"ok": {"score": 100}, "bad": None}
        env = _build_envelope(
            workflow="test",
            aggregators_called=["ok", "bad"],
            results=results,
            execution_time_ms=100,
        )
        assert "ok" in env["data"]
        assert "bad" not in env["data"]
        assert "bad" in env["_errors"]

    def test_no_failures_no_error_key(self):
        from qualys.workflows import _build_envelope
        results = {"agg": {"score": 500}}
        env = _build_envelope(
            workflow="test",
            aggregators_called=["agg"],
            results=results,
            execution_time_ms=50,
        )
        assert "_errors" not in env

    def test_empty_results_produces_valid_envelope(self):
        from qualys.workflows import _build_envelope
        env = _build_envelope(
            workflow="test",
            aggregators_called=[],
            results={},
            execution_time_ms=0,
        )
        assert env["workflow"] == "test"
        assert isinstance(env["data"], dict)
        assert isinstance(env["summary"], dict)

    def test_summary_fn_exception_does_not_crash(self):
        from qualys.workflows import _build_envelope
        def bad_summary(data):
            raise ValueError("summary broken")
        env = _build_envelope(
            workflow="test",
            aggregators_called=["agg"],
            results={"agg": {"x": 1}},
            execution_time_ms=0,
            summary_fn=bad_summary,
        )
        # Should fall back to default summary
        assert env["summary"] is not None

    def test_correlate_fn_exception_does_not_crash(self):
        from qualys.workflows import _build_envelope
        def bad_correlate(data):
            raise RuntimeError("correlate broken")
        env = _build_envelope(
            workflow="test",
            aggregators_called=["agg"],
            results={"agg": {"x": 1}},
            execution_time_ms=0,
            correlate_fn=bad_correlate,
        )
        assert env["correlations"] == []

    def test_actions_fn_exception_does_not_crash(self):
        from qualys.workflows import _build_envelope
        def bad_actions(data):
            raise RuntimeError("actions broken")
        env = _build_envelope(
            workflow="test",
            aggregators_called=["agg"],
            results={"agg": {"x": 1}},
            execution_time_ms=0,
            actions_fn=bad_actions,
        )
        assert env["actions"] == []


# ===========================================================================
# _apply_detail edge cases
# ===========================================================================

class TestApplyDetailEdgeCases:
    """Test _apply_detail handles all levels and missing keys."""

    def _make_envelope(self):
        return {
            "workflow": "test",
            "summary": {
                "headline": "test",
                "key_findings": ["f1", "f2", "f3", "f4", "f5", "f6", "f7"],
            },
            "data": {"key": "value"},
            "correlations": [{"type": "x"}],
            "actions": [],
        }

    def test_summary_level_removes_data(self):
        from qualys.workflows import _apply_detail
        result = _apply_detail(self._make_envelope(), "summary")
        assert "data" not in result

    def test_summary_level_removes_correlations(self):
        from qualys.workflows import _apply_detail
        result = _apply_detail(self._make_envelope(), "summary")
        assert "correlations" not in result

    def test_summary_level_caps_key_findings_at_5(self):
        from qualys.workflows import _apply_detail
        result = _apply_detail(self._make_envelope(), "summary")
        assert len(result["summary"]["key_findings"]) <= 5

    def test_standard_level_no_changes(self):
        from qualys.workflows import _apply_detail
        env = self._make_envelope()
        result = _apply_detail(env, "standard")
        assert "data" in result
        assert "correlations" in result

    def test_detailed_level_no_changes_to_normal_keys(self):
        from qualys.workflows import _apply_detail
        env = self._make_envelope()
        result = _apply_detail(env, "detailed")
        assert "data" in result

    def test_detailed_level_moves_raw_results(self):
        from qualys.workflows import _apply_detail
        env = self._make_envelope()
        env["_raw_results"] = {"some": "raw"}
        result = _apply_detail(env, "detailed")
        assert "_raw" in result
        assert "_raw_results" not in result

    def test_unknown_detail_level_no_crash(self):
        from qualys.workflows import _apply_detail
        env = self._make_envelope()
        result = _apply_detail(env, "bogus_level")
        assert result is not None


# ===========================================================================
# investigate: empty target validation
# ===========================================================================

class TestInvestigateEmptyTarget:
    """Test that investigate() validates empty targets."""

    def test_empty_string_returns_error(self):
        with patch("qualys.workflows.investigate._dispatch", return_value=({}, 0)):
            from qualys.workflows.investigate import investigate
            result = investigate("")
        assert "error" in result

    def test_whitespace_only_returns_error(self):
        with patch("qualys.workflows.investigate._dispatch", return_value=({}, 0)):
            from qualys.workflows.investigate import investigate
            result = investigate("   ")
        assert "error" in result

    def test_error_includes_summary(self):
        with patch("qualys.workflows.investigate._dispatch", return_value=({}, 0)):
            from qualys.workflows.investigate import investigate
            result = investigate("")
        assert "summary" in result


# ===========================================================================
# investigate: invalid depth normalization
# ===========================================================================

class TestInvestigateDepthNormalization:
    """Test that invalid depth values are normalized to 'standard'."""

    def _run_investigate(self, target, depth):
        import sys
        agg_mock = MagicMock()
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}), \
             patch("qualys.workflows.investigate._dispatch", return_value=({}, 0)), \
             patch("qualys.workflows.investigate._build_envelope", return_value={
                 "workflow": "investigate",
                 "aggregators_called": [],
                 "execution_time_ms": 0,
                 "summary": {},
                 "data": {},
                 "correlations": [],
                 "actions": [],
             }), \
             patch("qualys.workflows.investigate._apply_detail", side_effect=lambda e, d: e):
            from qualys.workflows.investigate import investigate
            return investigate(target=target, depth=depth)

    def test_invalid_depth_does_not_crash(self):
        result = self._run_investigate("CVE-2024-12345", depth="extreme")
        assert result is not None

    def test_empty_depth_does_not_crash(self):
        result = self._run_investigate("CVE-2024-12345", depth="")
        assert result is not None


# ===========================================================================
# _vuln_identity edge cases
# ===========================================================================

class TestVulnIdentityEdgeCases:
    """Test _vuln_identity fills missing fields and coerces numeric types."""

    def test_all_fields_filled_when_missing(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"qid": 12345})
        for field in ("qid", "cve", "qvs", "cvss", "severity", "title", "patch_available", "threat_intel"):
            assert field in result

    def test_missing_fields_default_to_none(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"qid": 12345})
        assert result["cve"] is None
        assert result["title"] is None

    def test_string_qvs_coerced_to_int(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"qvs": "90"})
        assert result["qvs"] == 90
        assert isinstance(result["qvs"], int)

    def test_float_cvss_preserved(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"cvss": "7.5"})
        assert result["cvss"] == 7.5

    def test_string_cvss_int_value_coerced_to_int(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"cvss": "9.0"})
        assert result["cvss"] == 9

    def test_invalid_qvs_left_as_is(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"qvs": "not-a-number"})
        assert result["qvs"] == "not-a-number"

    def test_none_qvs_stays_none(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"qvs": None})
        assert result["qvs"] is None

    def test_existing_numeric_qvs_unchanged(self):
        from qualys.workflows import _vuln_identity
        result = _vuln_identity({"qvs": 85})
        assert result["qvs"] == 85


# ===========================================================================
# _determine_risk_level edge cases
# ===========================================================================

class TestDetermineRiskLevelEdgeCases:
    """Test risk level boundary conditions."""

    def test_no_data_returns_unknown(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({}) == "unknown"

    def test_none_value_returns_unknown(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": None}) == "unknown"

    def test_score_900_is_critical(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 900}}) == "critical"

    def test_score_899_is_high(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 899}}) == "high"

    def test_score_700_is_high(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 700}}) == "high"

    def test_score_699_is_medium(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 699}}) == "medium"

    def test_score_300_is_medium(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 300}}) == "medium"

    def test_score_299_is_low(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 299}}) == "low"

    def test_score_zero_is_low(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": 0}}) == "low"

    def test_trurisk_score_key_recognized(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"truriskScore": 950}}) == "critical"

    def test_risk_score_key_recognized(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"riskScore": 750}}) == "high"

    def test_invalid_score_value_returns_unknown(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": {"score": "not-a-number"}}) == "unknown"

    def test_non_dict_agg_value_skipped(self):
        from qualys.workflows import _determine_risk_level
        assert _determine_risk_level({"agg": "just a string"}) == "unknown"


# ===========================================================================
# assess_risk: scope conflict / empty results
# ===========================================================================

class TestAssessRiskScopeEdgeCases:
    """Test assess_risk handles unusual scope values and empty data."""

    def test_unknown_scope_returns_no_cloud_or_certs(self):
        """Unknown scope: cloud/cert/container/web plan keys should be absent."""
        captured = {}

        def fake_dispatch(plan):
            captured["plan"] = plan
            return {}, 0

        with patch("qualys.workflows.assess_risk._dispatch", side_effect=fake_dispatch), \
             patch("qualys.workflows.assess_risk._build_envelope", return_value={
                 "workflow": "assess_risk", "data": {}, "summary": {}, "correlations": [], "actions": []
             }), \
             patch("qualys.workflows.assess_risk._apply_detail", side_effect=lambda e, d: e):
            from qualys.workflows.assess_risk import assess_risk
            assess_risk(scope="unknown_scope")

        plan = captured.get("plan", {})
        assert "cloud_risk" not in plan
        assert "webapp_vulns" not in plan
        assert "expiring_certs" not in plan

    def test_empty_scope_string(self):
        """Empty scope string: no plan keys should trigger."""
        captured = {}

        def fake_dispatch(plan):
            captured["plan"] = plan
            return {}, 0

        with patch("qualys.workflows.assess_risk._dispatch", side_effect=fake_dispatch), \
             patch("qualys.workflows.assess_risk._build_envelope", return_value={
                 "workflow": "assess_risk", "data": {}, "summary": {}, "correlations": [], "actions": []
             }), \
             patch("qualys.workflows.assess_risk._apply_detail", side_effect=lambda e, d: e):
            from qualys.workflows.assess_risk import assess_risk
            assess_risk(scope="")

        plan = captured.get("plan", {})
        # Empty scope string is not "all" and not a named scope — no broad queries
        assert "trurisk_score" not in plan
        assert "cloud_risk" not in plan


# ===========================================================================
# compliance: exception correlation edge cases
# ===========================================================================

class TestComplianceCorrelateEdgeCases:
    """Test compliance._correlate handles missing/malformed exception data."""

    def test_no_exceptions_data_returns_empty(self):
        from qualys.workflows.compliance import _correlate
        result = _correlate({})
        assert result == []

    def test_non_dict_exceptions_returns_empty(self):
        from qualys.workflows.compliance import _correlate
        result = _correlate({"vuln_exceptions": "not-a-dict"})
        assert result == []

    def test_exceptions_with_no_expiring_soon(self):
        from qualys.workflows.compliance import _correlate
        data = {
            "vuln_exceptions": {
                "exceptions": [
                    {"id": "e1", "daysUntilExpiry": 30},
                    {"id": "e2", "daysUntilExpiry": 14},
                ]
            }
        }
        result = _correlate(data)
        assert result == []

    def test_expiring_soon_threshold_is_7_days(self):
        from qualys.workflows.compliance import _correlate
        data = {
            "vuln_exceptions": {
                "exceptions": [
                    {"id": "e1", "daysUntilExpiry": 7},
                    {"id": "e2", "daysUntilExpiry": 8},
                    {"id": "e3", "daysUntilExpiry": 0},
                ]
            }
        }
        result = _correlate(data)
        # e1 (7 <= 7) and e3 (0 <= 7) are expiring soon → one correlation entry
        assert len(result) == 1


# ===========================================================================
# remediation: partial failures in plan
# ===========================================================================

class TestRemediationPartialFailures:
    """Test remediation workflow handles aggregator failures gracefully."""

    def test_summarize_with_empty_data_no_crash(self):
        from qualys.workflows.remediation import _summarize
        result = _summarize({})
        assert isinstance(result, dict)

    def test_summarize_with_none_values_no_crash(self):
        from qualys.workflows.remediation import _summarize
        result = _summarize({"patch_status": None, "outstanding_patches": None})
        assert isinstance(result, dict)

    def test_correlate_with_no_patches_returns_empty(self):
        from qualys.workflows.remediation import _correlate
        result = _correlate({})
        assert result == []

    def test_build_actions_with_empty_data_returns_list(self):
        from qualys.workflows.remediation import _build_actions
        result = _build_actions({}, {})
        assert isinstance(result, list)


# ===========================================================================
# overview: partial failures
# ===========================================================================

class TestOverviewPartialFailures:
    """Test overview workflow synthesizers handle missing data."""

    def test_summarize_with_empty_data(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({})
        assert isinstance(result, dict)
        assert result["total_assets"] == 0
        assert result["health_score"] is None

    def test_correlate_with_no_scanner_data(self):
        from qualys.workflows.overview import _correlate
        result = _correlate({})
        assert result == []

    def test_build_actions_with_empty_data(self):
        from qualys.workflows.overview import _build_actions
        result = _build_actions({}, [])
        assert isinstance(result, list)

    def test_summarize_handles_error_key_in_morning_report(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"morning_report": {"error": "API failure"}})
        assert result["total_assets"] == 0
