import pytest
from qualys.workflows import _build_envelope, _apply_detail, _vuln_identity, _determine_risk_level


class TestBuildEnvelope:
    def test_basic_envelope(self):
        result = _build_envelope(
            workflow="assess_risk",
            aggregators_called=["trurisk_score", "weekly_priorities"],
            results={"trurisk_score": {"score": 720}, "weekly_priorities": {"topRiskAssets": []}},
            execution_time_ms=1500,
        )
        assert result["workflow"] == "assess_risk"
        assert result["aggregators_called"] == ["trurisk_score", "weekly_priorities"]
        assert result["execution_time_ms"] == 1500
        assert "summary" in result
        assert "data" in result
        assert "correlations" in result
        assert "actions" in result
        assert "_meta" in result

    def test_envelope_excludes_none_results(self):
        result = _build_envelope(
            workflow="investigate",
            aggregators_called=["cve_details", "edr_events"],
            results={"cve_details": {"qid": 12345}, "edr_events": None},
            execution_time_ms=800,
        )
        assert "cve_details" in result["data"]
        assert "edr_events" not in result["data"]

    def test_envelope_all_failures(self):
        result = _build_envelope(
            workflow="assess_risk",
            aggregators_called=["trurisk_score"],
            results={"trurisk_score": None},
            execution_time_ms=500,
        )
        assert result["data"] == {}
        assert result["summary"]["risk_level"] == "unknown"
        assert "error" in result["summary"]["headline"].lower() or "no data" in result["summary"]["headline"].lower()


class TestDetermineRiskLevel:
    def test_critical(self):
        assert _determine_risk_level({"trurisk_score": {"score": 950}}) == "critical"

    def test_high(self):
        assert _determine_risk_level({"trurisk_score": {"score": 750}}) == "high"

    def test_medium(self):
        assert _determine_risk_level({"trurisk_score": {"score": 400}}) == "medium"

    def test_low(self):
        assert _determine_risk_level({"trurisk_score": {"score": 50}}) == "low"

    def test_empty(self):
        assert _determine_risk_level({}) == "unknown"


class TestApplyDetail:
    def test_summary_strips_data(self):
        envelope = {
            "workflow": "assess_risk",
            "summary": {"headline": "test", "risk_level": "high", "key_findings": ["a", "b", "c"], "stats": {}},
            "data": {"trurisk": {"score": 720}},
            "correlations": [{"finding": "x", "severity": "high", "sources": ["trurisk"]}],
            "actions": [{"priority": 1, "action": "patch"}],
            "_meta": {"total_results": 10, "returned": 10, "truncated": False},
            "aggregators_called": ["trurisk_score"],
            "execution_time_ms": 500,
        }
        result = _apply_detail(envelope, "summary")
        assert "data" not in result
        assert "correlations" not in result
        assert "summary" in result
        assert "actions" in result

    def test_summary_caps_findings_at_5(self):
        envelope = {
            "workflow": "test",
            "summary": {"headline": "t", "risk_level": "low", "key_findings": list(range(10)), "stats": {}},
            "data": {},
            "correlations": [],
            "actions": [],
            "_meta": {"total_results": 0, "returned": 0, "truncated": False},
            "aggregators_called": [],
            "execution_time_ms": 0,
        }
        result = _apply_detail(envelope, "summary")
        assert len(result["summary"]["key_findings"]) <= 5

    def test_standard_keeps_everything(self):
        envelope = {
            "workflow": "test",
            "summary": {"headline": "t", "risk_level": "low", "key_findings": [], "stats": {}},
            "data": {"trurisk": {"score": 100}},
            "correlations": [],
            "actions": [],
            "_meta": {"total_results": 0, "returned": 0, "truncated": False},
            "aggregators_called": [],
            "execution_time_ms": 0,
        }
        result = _apply_detail(envelope, "standard")
        assert "data" in result
        assert "correlations" in result

    def test_detailed_includes_raw(self):
        raw_results = {"trurisk_score": {"score": 100}}
        envelope = {
            "workflow": "test",
            "summary": {"headline": "t", "risk_level": "low", "key_findings": [], "stats": {}},
            "data": {"trurisk": {"score": 100}},
            "correlations": [],
            "actions": [],
            "_meta": {"total_results": 0, "returned": 0, "truncated": False},
            "aggregators_called": [],
            "execution_time_ms": 0,
            "_raw_results": raw_results,
        }
        result = _apply_detail(envelope, "detailed")
        assert "_raw" in result
        assert result["_raw"] == raw_results


class TestVulnIdentity:
    def test_preserves_all_fields(self):
        item = {"qid": 12345, "cve": "CVE-2024-3400", "qvs": 95, "cvss": 9.8, "severity": 5, "title": "Test", "patch_available": True, "threat_intel": ["Ransomware"]}
        result = _vuln_identity(item)
        assert result["qid"] == 12345
        assert result["cve"] == "CVE-2024-3400"
        assert result["qvs"] == 95
        assert result["cvss"] == 9.8

    def test_missing_fields_get_none(self):
        item = {"qid": 12345, "title": "Test"}
        result = _vuln_identity(item)
        assert result["cve"] is None
        assert result["qvs"] is None
        assert result["cvss"] is None
        assert result["patch_available"] is None
        assert result["threat_intel"] is None

    def test_numeric_types_preserved(self):
        item = {"qid": "12345", "qvs": "95", "cvss": "9.8"}
        result = _vuln_identity(item)
        assert isinstance(result["qvs"], (int, float))
        assert isinstance(result["cvss"], (int, float))
