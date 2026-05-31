import pytest
from qualys.workflows import _build_envelope, _apply_detail, _vuln_identity, _determine_risk_level, _envelope_to_markdown


class TestEnvelopeToMarkdown:
    def _envelope(self, **over):
        env = {
            "workflow": "assess_risk",
            "aggregators_called": ["trurisk_score", "cloud_risk"],
            "execution_time_ms": 1234,
            "summary": {
                "headline": "89031 assets, 173 critical-risk",
                "risk_level": "high",
                "key_findings": ["173 critical-risk assets", "316 CDR threats"],
                "stats": {"totalAssets": 89031, "criticalRiskAssets": 173},
            },
            "actions": [{"priority": 1, "action": "Patch top vulns", "module": "VMDR"}],
            "correlations": [{"type": "x", "finding": "compounding risk"}],
        }
        env.update(over)
        return env

    def test_returns_string(self):
        assert isinstance(_envelope_to_markdown(self._envelope()), str)

    def test_includes_title_risk_and_headline(self):
        md = _envelope_to_markdown(self._envelope())
        assert "# Assess Risk" in md
        assert "**Risk Level:** high" in md
        assert "89031 assets, 173 critical-risk" in md

    def test_includes_findings_stats_actions_correlations(self):
        md = _envelope_to_markdown(self._envelope())
        assert "## Key Findings" in md and "- 173 critical-risk assets" in md
        assert "## Stats" in md and "**totalAssets:** 89031" in md
        assert "## Recommended Actions" in md and "**[P1]** Patch top vulns" in md
        assert "Module: VMDR" in md
        assert "## Correlations" in md and "compounding risk" in md
        assert "1234ms" in md and "Sources: 2" in md

    def test_more_compact_than_json(self):
        import json
        env = self._envelope()
        assert len(_envelope_to_markdown(env)) < len(json.dumps(env))

    def test_omits_empty_sections(self):
        md = _envelope_to_markdown(self._envelope(actions=[], correlations=[], summary={
            "headline": "", "risk_level": "low", "key_findings": [], "stats": {}}))
        assert "## Key Findings" not in md
        assert "## Recommended Actions" not in md
        assert "## Correlations" not in md
        assert "**Risk Level:** low" in md

    def test_surfaces_unavailable_sources(self):
        md = _envelope_to_markdown(self._envelope(_errors=["cloud_risk", "fim"]))
        assert "2 data source(s) unavailable" in md
        assert "cloud_risk" in md and "fim" in md

    def test_missing_summary_defaults_unknown(self):
        md = _envelope_to_markdown({"workflow": "investigate", "aggregators_called": []})
        assert "# Investigate" in md
        assert "**Risk Level:** unknown" in md


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


class TestCacheStatusMode:
    def test_cache_status_includes_mode(self):
        from qualys.aggregators import cache_status_agg
        result = cache_status_agg()
        assert "cacheMode" in result

    def test_cache_mode_is_string(self):
        from qualys.aggregators import cache_status_agg
        result = cache_status_agg()
        assert isinstance(result["cacheMode"], str)
        assert result["cacheMode"] in ("lazy", "aggressive", "none")


class TestAssessExposure:
    def test_assess_exposure_signature(self):
        from qualys.aggregators import assess_exposure
        import inspect
        sig = inspect.signature(assess_exposure)
        assert "cve" in sig.parameters
        assert "detail" in sig.parameters

    def test_assess_exposure_unknown_cve(self, monkeypatch):
        import qualys.aggregators as agg
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [])
        result = agg.assess_exposure(cve="CVE-9999-99999")
        assert isinstance(result, dict)
        assert "exposure" in result
        assert "summary" in result
        assert result["exposure"]["status"] == "unknown"

    def test_assess_exposure_with_kb_hit(self, monkeypatch):
        import qualys.aggregators as agg
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [12345])
        monkeypatch.setattr(agg, "get_kb_batch", lambda qids: {
            12345: {
                "qid": 12345,
                "title": "OpenSSH Remote Code Execution",
                "severity": 5,
                "qds": 95,
                "cvss_v3": 9.8,
                "cves": ["CVE-2024-6387"],
                "patch_available": True,
                "has_exploit": True,
                "ransomware": False,
                "threat_intel": ["Exploit_Public"],
                "diagnosis": "OpenSSH is vulnerable.",
                "solution": "Upgrade OpenSSH to 9.8p1.",
            }
        })
        monkeypatch.setattr(agg, "csam_count", lambda filters=None: 100 if filters else 5000)
        result = agg.assess_exposure(cve="CVE-2024-6387")
        assert result["exposure"]["potentialAssets"] == 100
        assert result["exposure"]["status"] == "likely_exposed"
        assert result["exposure"]["riskContext"]["risk"] == "critical"
        assert result["kb"]["qid"] == 12345
        assert len(result["exposure"]["softwareMatches"]) > 0

    def test_assess_exposure_no_software_match(self, monkeypatch):
        import qualys.aggregators as agg
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [99999])
        monkeypatch.setattr(agg, "get_kb_batch", lambda qids: {
            99999: {
                "qid": 99999,
                "title": "Obscure Widget Buffer Overflow",
                "severity": 3,
                "qds": 40,
                "cves": ["CVE-2024-0001"],
                "patch_available": False,
                "has_exploit": False,
                "ransomware": False,
                "threat_intel": [],
                "diagnosis": "",
                "solution": "",
            }
        })
        monkeypatch.setattr(agg, "csam_count", lambda filters=None: 0)
        result = agg.assess_exposure(cve="CVE-2024-0001")
        assert result["exposure"]["potentialAssets"] == 0
        assert result["exposure"]["status"] == "not_exposed"
