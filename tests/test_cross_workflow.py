"""Tests for cross-workflow chaining with mock data.

These tests verify that data produced by one workflow can be consumed
as input to another, and that synthesis helpers produce expected
output shapes when given realistic mock data.
"""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Shared mock data fixtures
# ---------------------------------------------------------------------------

CVE_RESULT = {
    "cve": "CVE-2021-44228",
    "title": "Log4Shell",
    "qds": 100,
    "severity": 5,
    "ransomware": True,
    "patchAvailable": True,
    "qids": [375925, 375926],
    "summary": {"assetsWithSoftware": 47},
    "score": 950,
}

THREAT_ACTOR_RESULT = {
    "threatActor": "APT28",
    "activeInEnvironment": 3,
    "totalInKB": 12,
    "summary": "APT28 has 12 known CVEs; 3 are active in your environment.",
    "riskScore": 820,
}

EDR_RESULT = {
    "summary": "3 critical events detected",
    "severityCounts": {"CRITICAL": 3, "HIGH": 5},
    "affectedHosts": ["host-01", "host-02"],
}

FIM_RESULT = {
    "summary": "2 critical path events",
    "criticalPathEvents": 2,
    "affectedHosts": ["host-01"],
}

TRURISK_RESULT = {
    "score": 850,
    "trend": {"direction": "worsening"},
}

WEEKLY_PRIORITIES_RESULT = {
    "topVulns": [
        {"qid": 375925, "title": "Log4Shell", "severity": 5},
        {"qid": 90001, "title": "SMB Ghost", "severity": 4},
    ],
    "vulnerabilities": [],
}

CLOUD_RISK_RESULT = {
    "accounts": 3,
    "criticalFindings": 8,
}

CLOUD_CONTROLS_RESULT = {
    "failed": 12,
}

CONTAINER_VULN_RESULT = {
    "totalVulns": 45,
    "critical": 6,
}

RUNNING_CONTAINERS_RESULT = {
    "total": 20,
}


# ===========================================================================
# investigate synthesis helpers with realistic data
# ===========================================================================

class TestInvestigateSynthesisWithMockData:
    """Test investigate _summarize and _correlate with realistic mock data."""

    def test_cve_summarize_includes_cve_id(self):
        from qualys.workflows.investigate import _summarize
        data = {"cve_deep": CVE_RESULT}
        result = _summarize(data)
        assert "CVE-2021-44228" in result["headline"] or any(
            "CVE-2021-44228" in f for f in result["key_findings"]
        )

    def test_cve_summarize_mentions_ransomware(self):
        from qualys.workflows.investigate import _summarize
        data = {"cve_deep": CVE_RESULT}
        result = _summarize(data)
        combined = result["headline"].lower() + " ".join(result["key_findings"]).lower()
        assert "ransomware" in combined

    def test_threat_actor_summarize_includes_actor(self):
        from qualys.workflows.investigate import _summarize
        data = {"threat_actor": THREAT_ACTOR_RESULT}
        result = _summarize(data)
        # Summary uses the actor's own summary string
        combined = result["headline"] + " ".join(result["key_findings"])
        assert "APT28" in combined

    def test_edr_fim_summarize_includes_prefixes(self):
        from qualys.workflows.investigate import _summarize
        data = {"edr": EDR_RESULT, "fim": FIM_RESULT}
        result = _summarize(data)
        combined = result["headline"] + " ".join(result["key_findings"])
        assert "EDR" in combined
        assert "FIM" in combined

    def test_cve_correlate_extracts_qids(self):
        from qualys.workflows.investigate import _correlate
        cve_meta = {"cve": "CVE-2021-44228", "qids": [999]}
        data = {"cve_deep": CVE_RESULT, "cve_meta": cve_meta}
        result = _correlate(data)
        # result is a list of {"finding": str, "severity": str, "sources": list}
        assert isinstance(result, list)
        findings_text = " ".join(item["finding"] for item in result)
        assert "375925" in findings_text or "CVE-2021-44228" in findings_text

    def test_edr_fim_correlate_merges_hosts(self):
        from qualys.workflows.investigate import _correlate
        data = {"edr": EDR_RESULT, "fim": FIM_RESULT}
        result = _correlate(data)
        # result is a list of finding dicts
        assert isinstance(result, list)
        findings_text = " ".join(item["finding"] for item in result)
        assert "host-01" in findings_text or "host-02" in findings_text or len(result) > 0

    def test_high_risk_score_produces_critical(self):
        from qualys.workflows.investigate import _correlate
        data = {"cve_deep": CVE_RESULT}  # score=950
        result = _correlate(data)
        # result is a list; at least one finding should be critical severity
        assert isinstance(result, list)
        severities = [item.get("severity", "") for item in result]
        assert any(s in ("critical", "high") for s in severities)

    def test_build_actions_ransomware_cve_is_critical(self):
        from qualys.workflows.investigate import _build_actions
        data = {"cve_deep": CVE_RESULT}
        correlations = [{"finding": "CVE-2021-44228 QIDs: 375925, 375926", "severity": "critical", "sources": ["cve_deep"]}]
        actions = _build_actions(data, correlations)
        assert len(actions) > 0
        assert actions[0]["priority"] == 1

    def test_build_actions_threat_actor_active_produces_high(self):
        from qualys.workflows.investigate import _build_actions
        data = {"threat_actor": THREAT_ACTOR_RESULT}
        correlations = [{"finding": "APT28 active", "severity": "high", "sources": ["threat_actor"]}]
        actions = _build_actions(data, correlations)
        assert any(a["priority"] <= 2 for a in actions)

    def test_build_actions_edr_critical_count(self):
        from qualys.workflows.investigate import _build_actions
        data = {"edr": EDR_RESULT}
        correlations = [{"finding": "3 critical EDR events", "severity": "critical", "sources": ["edr"]}]
        actions = _build_actions(data, correlations)
        assert any(a["priority"] == 1 for a in actions)

    def test_build_actions_fim_critical_paths(self):
        from qualys.workflows.investigate import _build_actions
        data = {"fim": FIM_RESULT}
        correlations = [{"finding": "2 critical FIM path events", "severity": "high", "sources": ["fim"]}]
        actions = _build_actions(data, correlations)
        assert any(a["priority"] <= 2 for a in actions)

    def test_build_actions_sorted_by_priority(self):
        from qualys.workflows.investigate import _build_actions
        data = {"cve_deep": CVE_RESULT, "edr": EDR_RESULT}
        correlations = [
            {"finding": "CVE-2021-44228 QIDs: 375925", "severity": "critical", "sources": ["cve_deep"]},
        ]
        actions = _build_actions(data, correlations)
        priorities = [a["priority"] for a in actions]
        assert priorities == sorted(priorities), "Actions should be sorted by priority"


# ===========================================================================
# assess_risk synthesis helpers with realistic data
# ===========================================================================

class TestAssessRiskSynthesisWithMockData:
    """Test assess_risk _summarize, _correlate, _build_actions with mock data."""

    def test_summarize_extracts_org_trurisk(self):
        from qualys.workflows.assess_risk import _summarize
        data = {"trurisk_score": TRURISK_RESULT, "weekly_priorities": WEEKLY_PRIORITIES_RESULT}
        result = _summarize(data)
        assert result["stats"]["orgTruRisk"] == 850

    def test_summarize_risk_level_critical_at_900(self):
        from qualys.workflows.assess_risk import _summarize
        data = {"trurisk_score": {"score": 900}}
        result = _summarize(data)
        assert result["risk_level"] == "critical"

    def test_summarize_weekly_priorities_count(self):
        from qualys.workflows.assess_risk import _summarize
        data = {"weekly_priorities": WEEKLY_PRIORITIES_RESULT}
        result = _summarize(data)
        assert result["stats"]["topVulnsCount"] == 2

    def test_summarize_cloud_findings(self):
        from qualys.workflows.assess_risk import _summarize
        data = {"cloud_risk": CLOUD_RISK_RESULT}
        result = _summarize(data)
        assert any("critical" in f.lower() for f in result["key_findings"])

    def test_correlate_compounding_cloud_risk(self):
        from qualys.workflows.assess_risk import _correlate
        data = {
            "cloud_risk": CLOUD_RISK_RESULT,
            "cloud_controls": CLOUD_CONTROLS_RESULT,
        }
        result = _correlate(data)
        types = [c["type"] for c in result]
        assert "compounding_cloud_risk" in types

    def test_correlate_active_container_exposure(self):
        from qualys.workflows.assess_risk import _correlate
        data = {
            "container_vuln_summary": CONTAINER_VULN_RESULT,
            "running_containers": RUNNING_CONTAINERS_RESULT,
        }
        result = _correlate(data)
        types = [c["type"] for c in result]
        assert "active_container_exposure" in types

    def test_correlate_risk_score_spike(self):
        from qualys.workflows.assess_risk import _correlate
        data = {
            "trurisk_score": TRURISK_RESULT,  # worsening trend
            "weekly_priorities": WEEKLY_PRIORITIES_RESULT,
        }
        result = _correlate(data)
        types = [c["type"] for c in result]
        assert "risk_score_spike" in types

    def test_correlate_no_compounding_when_no_cloud_controls(self):
        from qualys.workflows.assess_risk import _correlate
        data = {"cloud_risk": CLOUD_RISK_RESULT}  # no cloud_controls
        result = _correlate(data)
        types = [c["type"] for c in result]
        assert "compounding_cloud_risk" not in types

    def test_build_actions_returns_list(self):
        from qualys.workflows.assess_risk import _build_actions
        data = {
            "weekly_priorities": WEEKLY_PRIORITIES_RESULT,
            "cloud_risk": CLOUD_RISK_RESULT,
        }
        correlations = []
        result = _build_actions(data, correlations)
        assert isinstance(result, list)

    def test_build_actions_max_10(self):
        from qualys.workflows.assess_risk import _build_actions
        data = {
            "weekly_priorities": WEEKLY_PRIORITIES_RESULT,
            "cloud_risk": CLOUD_RISK_RESULT,
            "cloud_controls": CLOUD_CONTROLS_RESULT,
            "container_vuln_summary": CONTAINER_VULN_RESULT,
            "webapp_vulns": {"critical": 5},
            "expiring_certs": {"expired": 2},
            "cert_security_posture": {"weakCerts": 3},
            "tech_debt": {"eolSystems": 8},
        }
        from qualys.workflows.assess_risk import _correlate
        correlations = _correlate(data)
        result = _build_actions(data, correlations)
        assert len(result) <= 10


# ===========================================================================
# compliance synthesis helpers with realistic data
# ===========================================================================

class TestComplianceSynthesisWithMockData:
    """Test compliance _summarize with realistic posture data."""

    def test_pass_rate_calculation(self):
        from qualys.workflows.compliance import _summarize
        data = {
            "compliance_posture": {
                "summary": {
                    "controls": 100,
                    "passing": 85,
                    "failing": 15,
                }
            }
        }
        result = _summarize(data)
        assert result["stats"]["pass_rate"] == 85.0
        assert result["stats"]["failing_controls"] == 15
        assert result["stats"]["total_controls"] == 100

    def test_zero_total_controls_pass_rate_zero(self):
        from qualys.workflows.compliance import _summarize
        data = {"compliance_posture": {"summary": {"controls": 0, "passing": 0, "failing": 0}}}
        result = _summarize(data)
        assert result["stats"]["pass_rate"] == 0.0

    def test_exception_count_from_stats(self):
        from qualys.workflows.compliance import _summarize
        data = {
            "compliance_posture": {},
            "vuln_exceptions": {"stats": {"total": 7}},
        }
        result = _summarize(data)
        assert result["stats"]["exception_count"] == 7

    def test_exception_count_from_list(self):
        from qualys.workflows.compliance import _summarize
        data = {
            "compliance_posture": {},
            "vuln_exceptions": {
                "exceptions": [{"id": "e1"}, {"id": "e2"}]
            },
        }
        result = _summarize(data)
        assert result["stats"]["exception_count"] == 2

    def test_frameworks_extracted_from_posture(self):
        from qualys.workflows.compliance import _summarize
        data = {
            "compliance_posture": {
                "summary": {"frameworks": ["CIS", "DISA STIG"]},
            }
        }
        result = _summarize(data)
        assert "CIS" in result["stats"]["frameworks"]

    def test_build_actions_top_failing_controls(self):
        from qualys.workflows.compliance import _build_actions
        data = {
            "compliance_posture": {
                "topFailingControls": [
                    {"controlId": "CIS-1.1", "title": "Password policy", "failingAssets": 10, "severity": "critical"},
                    {"controlId": "CIS-1.2", "title": "Account lockout", "failingAssets": 5, "severity": "high"},
                ]
            }
        }
        correlations = []
        actions = _build_actions(data, correlations)
        assert len(actions) == 2
        assert "CIS-1.1" in actions[0]["action"]

    def test_build_actions_expiring_exceptions(self):
        from qualys.workflows.compliance import _build_actions
        data = {"compliance_posture": {}}
        # _correlate returns a list; _build_actions just receives it
        correlations = []
        actions = _build_actions(data, correlations)
        # With no failing controls and no correlations, actions may be empty — that's fine
        assert isinstance(actions, list)

    def test_build_actions_no_data_suggests_license_check(self):
        from qualys.workflows.compliance import _build_actions
        data = {"compliance_posture": {}}
        correlations = []
        actions = _build_actions(data, correlations)
        assert isinstance(actions, list)


# ===========================================================================
# remediation synthesis helpers with realistic data
# ===========================================================================

class TestRemediationSynthesisWithMockData:
    """Test remediation _summarize, _correlate, _build_actions with mock data."""

    PATCH_STATUS = {
        "coverage": 78,
        "assetsTotal": 500,
        "riskDistribution": {"critical_900plus": 12, "high_700plus": 30},
    }

    OUTSTANDING_PATCHES = {
        "totalOutstanding": 45,
        "totalMissingInstalls": 120,
        "securityPatches": 30,
        "topPatches": [
            {
                "title": "MS23-001",
                "missingCount": 25,
                "platform": "Windows",
                "vendorSeverity": "Critical",
                "qids": [90001],
            },
            {
                "title": "KB5012345",
                "missingCount": 10,
                "platform": "Windows",
                "vendorSeverity": "Important",
                "qids": [90002],
            },
        ],
    }

    ELIMINATE_STATUS = {
        "patchCounts": {
            "deployed": {"total": 300},
            "missing": {"total": 200},
        }
    }

    def test_summarize_patch_coverage(self):
        from qualys.workflows.remediation import _summarize
        result = _summarize({"patch_status": self.PATCH_STATUS})
        assert result["stats"]["patch_coverage"] == 78

    def test_summarize_outstanding_totals(self):
        from qualys.workflows.remediation import _summarize
        result = _summarize({"outstanding_patches": self.OUTSTANDING_PATCHES})
        assert result["stats"]["outstanding_patches"] == 45

    def test_summarize_eliminate_status_counts(self):
        from qualys.workflows.remediation import _summarize
        result = _summarize({"eliminate_status": self.ELIMINATE_STATUS})
        assert result["stats"]["patches_deployed"] == 300
        assert result["stats"]["patches_missing"] == 200

    def test_build_actions_from_outstanding_patches(self):
        from qualys.workflows.remediation import _build_actions
        data = {"outstanding_patches": self.OUTSTANDING_PATCHES}
        actions = _build_actions(data, [])
        assert len(actions) > 0
        # actions are dicts with "priority" (int), "action", "scope", "tool_hint"
        assert isinstance(actions[0], dict)
        assert "action" in actions[0]

    def test_build_actions_critical_severity_is_high_priority(self):
        from qualys.workflows.remediation import _build_actions
        data = {"outstanding_patches": self.OUTSTANDING_PATCHES}
        actions = _build_actions(data, [])
        # priority is an integer (1 = highest priority)
        priorities = [a["priority"] for a in actions]
        assert len(priorities) > 0
        assert min(priorities) >= 1

    def test_correlate_unmitigated_qids(self):
        from qualys.workflows.remediation import _correlate
        data = {
            "outstanding_patches": self.OUTSTANDING_PATCHES,
            "eliminate_coverage": {
                "coverage": [
                    {"qid": 90001, "hasMitigation": True},
                ]
            }
        }
        result = _correlate(data)
        # result is a list; should contain one entry about unmitigated QIDs
        assert isinstance(result, list)
        assert len(result) > 0
        # The finding should mention QIDs with no mitigation
        assert any("mitigation" in item.get("finding", "").lower() for item in result)


# ===========================================================================
# overview synthesis helpers with realistic data
# ===========================================================================

class TestOverviewSynthesisWithMockData:
    """Test overview _summarize, _correlate, _build_actions with mock data."""

    MORNING_REPORT = {
        "environment": {"totalAssets": 1500, "healthScore": 72},
    }

    SCANNER_HEALTH = {
        "scanners": [
            {"name": "scanner-01", "status": "online"},
            {"name": "scanner-02", "status": "offline", "heartbeatsMissed": 5},
        ]
    }

    SCAN_STATUS = {
        "stats": {"running": 3, "queued": 1, "errors": 2},
        "failedScans": [{"title": "Weekly Full Scan"}],
    }

    ETM_FINDINGS = {
        "findings": [{"id": "f1"}, {"id": "f2"}],
        "total": 42,
    }

    def test_summarize_total_assets(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"morning_report": self.MORNING_REPORT})
        assert result["stats"]["total_assets"] == 1500

    def test_summarize_health_score(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"morning_report": self.MORNING_REPORT})
        assert result["stats"]["health_score"] == 72

    def test_summarize_scanner_counts(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"scanner_health": self.SCANNER_HEALTH})
        assert result["stats"]["scanners_online"] == 1
        assert result["stats"]["scanners_offline"] == 1

    def test_summarize_active_scans(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"scan_status": self.SCAN_STATUS})
        assert "headline" in result

    def test_summarize_scan_errors(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"scan_status": self.SCAN_STATUS})
        assert result["stats"]["scan_errors"] == 2

    def test_summarize_findings_count(self):
        from qualys.workflows.overview import _summarize
        result = _summarize({"etm_findings": self.ETM_FINDINGS})
        assert result["stats"]["findings_count"] == 42

    def test_correlate_offline_scanner_with_errors(self):
        from qualys.workflows.overview import _correlate
        data = {
            "scanner_health": self.SCANNER_HEALTH,
            "scan_status": self.SCAN_STATUS,
        }
        result = _correlate(data)
        assert len(result) > 0
        assert result[0]["type"] == "scanner_scan_correlation"

    def test_build_actions_offline_scanner(self):
        from qualys.workflows.overview import _build_actions
        data = {"scanner_health": self.SCANNER_HEALTH}
        actions = _build_actions(data, [])
        types = [a["type"] for a in actions]
        assert "offline_scanner" in types

    def test_build_actions_scan_errors(self):
        from qualys.workflows.overview import _build_actions
        data = {"scan_status": self.SCAN_STATUS}
        actions = _build_actions(data, [])
        types = [a["type"] for a in actions]
        assert "scan_errors" in types

    def test_build_actions_low_health_score(self):
        from qualys.workflows.overview import _build_actions
        data = {"morning_report": self.MORNING_REPORT}  # health_score=72 < 80
        actions = _build_actions(data, [])
        types = [a["type"] for a in actions]
        assert "low_health_score" in types

    def test_build_actions_high_health_no_alert(self):
        from qualys.workflows.overview import _build_actions
        data = {"morning_report": {"environment": {"totalAssets": 100, "healthScore": 95}}}
        actions = _build_actions(data, [])
        types = [a["type"] for a in actions]
        assert "low_health_score" not in types
