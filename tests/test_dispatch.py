"""Tests for dispatch plan construction across all 5 workflows.

These tests verify that each workflow's _build_plan function returns
the correct set of dispatch keys for various input combinations,
without making any real API calls.
"""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers: patch _dispatch to return controlled results
# ---------------------------------------------------------------------------

def _make_dispatch_mock(return_data=None):
    """Return a mock for _dispatch that yields (return_data, 0)."""
    if return_data is None:
        return_data = {}
    mock = MagicMock(return_value=(return_data, 0))
    return mock


# ===========================================================================
# investigate._build_plan
# ===========================================================================

class TestInvestigateBuildPlan:
    """Test investigate._build_plan dispatch key selection."""

    def _call_build_plan(self, target, target_type, **kwargs):
        from qualys.workflows.investigate import _build_plan
        defaults = dict(
            depth="standard",
            scope=[],
            tag="",
            asset_group="",
            threat_type="",
            software="",
            days=7,
            limit=50,
            detail="standard",
            prior_context="",
        )
        defaults.update(kwargs)

        # Patch all aggregator imports so _build_plan doesn't need real API
        with patch("qualys.workflows.investigate._build_plan.__globals__", {}):
            pass

        # We need to patch the aggregators inside the function
        agg_mock = MagicMock()
        with patch.dict("sys.modules", {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target=target,
                target_type=target_type,
                **defaults,
            )
        return plan

    def test_cve_target_keys(self):
        """CVE target type should produce cve_deep key (cve_meta removed to avoid redundant API calls).

        Note: empty scope defaults to scope_all=True which also adds 'investigate'
        for the general/all path — so we only assert the CVE-specific keys are present.
        """
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="CVE-2024-12345",
                target_type="cve",
                depth="standard",
                scope=[],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "cve_deep" in plan
        assert "cve_deep" in plan
        assert "threat_actor" not in plan

    def test_threat_actor_target_keys(self):
        """Threat actor target type should produce threat_actor key."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="russia",
                target_type="threat_actor",
                depth="standard",
                scope=[],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "threat_actor" in plan
        assert "cve_deep" not in plan
        assert "cve_meta" not in plan

    def test_ip_target_keys(self):
        """IP target type should produce investigate, edr, and fim keys."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="192.168.1.1",
                target_type="ip",
                depth="standard",
                scope=[],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "investigate" in plan
        assert "edr" in plan
        assert "fim" in plan

    def test_hostname_target_keys(self):
        """Hostname target type should produce investigate, edr, and fim keys."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="asset:myserver.corp",
                target_type="hostname",
                depth="standard",
                scope=[],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "investigate" in plan
        assert "edr" in plan
        assert "fim" in plan

    def test_general_target_keys(self):
        """General target type should produce investigate key."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="log4j",
                target_type="general",
                depth="standard",
                scope=[],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "investigate" in plan

    def test_scope_edr_added_to_cve(self):
        """Adding 'edr' to scope on a CVE target should include edr key."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="CVE-2024-12345",
                target_type="cve",
                depth="standard",
                scope=["edr"],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "cve_deep" in plan
        assert "cve_deep" in plan
        assert "edr" in plan

    def test_scope_vulns_adds_vulns_key(self):
        """Adding 'vulns' to scope should include vulns key."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="log4j",
                target_type="general",
                depth="standard",
                scope=["vulns"],
                tag="",
                asset_group="",
                threat_type="",
                software="",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "vulns" in plan

    def test_software_filter_adds_vulns(self):
        """Setting software= triggers vulns key in dispatch plan."""
        from qualys.workflows.investigate import _build_plan
        agg_mock = MagicMock()
        import sys
        with patch.dict(sys.modules, {"qualys.aggregators": agg_mock}):
            plan = _build_plan(
                target="apache",
                target_type="general",
                depth="standard",
                scope=[],
                tag="",
                asset_group="",
                threat_type="",
                software="apache",
                days=7,
                limit=50,
                detail="standard",
                prior_context="",
            )
        assert "vulns" in plan


# ===========================================================================
# investigate._detect_target_type
# ===========================================================================

class TestDetectTargetType:
    """Test target type detection logic."""

    def test_valid_cve(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("CVE-2024-12345") == "cve"

    def test_valid_cve_lowercase(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("cve-2021-44228") == "cve"

    def test_malformed_cve_returns_general(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("CVE-invalid") == "general"

    def test_ip_address(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("10.0.0.1") == "ip"

    def test_hostname_prefix(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("asset:server01") == "hostname"

    def test_threat_actor_russia(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("russia") == "threat_actor"

    def test_threat_actor_ransomware(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("ransomware") == "threat_actor"

    def test_general_keyword(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("log4j vulnerability") == "general"

    def test_apt_group_exact(self):
        from qualys.workflows.investigate import _detect_target_type
        assert _detect_target_type("APT28") == "threat_actor"


# ===========================================================================
# assess_risk dispatch plan keys
# ===========================================================================

class TestAssessRiskDispatchPlan:
    """Test that assess_risk builds the right plan dict for each scope."""

    def _get_plan(self, **kwargs):
        """Call assess_risk with _dispatch mocked and capture the plan."""
        from qualys.workflows import assess_risk as ar_module

        captured = {}

        def fake_dispatch(plan, **kwargs):
            captured["plan"] = plan
            return {}, 0

        defaults = dict(
            scope="all",
            tag="",
            asset_group="",
            asset_id="",
            os="",
            query="",
            days_since_seen=0,
            days_since_scan=0,
            eol_only=False,
            provider="",
            service="",
            account_id="",
            per_account=False,
            image_id="",
            app_name="",
            owasp_category="",
            protocol_filter="",
            weak_ciphers=False,
            weak_only=False,
            insecure_renegotiation=False,
            include_expired=True,
            days=30,
            limit=20,
            detail="standard",
            sort_by="trurisk",
            breakdown_by="tag",
        )
        defaults.update(kwargs)

        with patch("qualys.workflows.assess_risk._dispatch", side_effect=fake_dispatch), \
             patch("qualys.workflows.assess_risk._build_envelope", return_value={"workflow": "assess_risk", "data": {}, "summary": {}, "correlations": [], "actions": []}), \
             patch("qualys.workflows.assess_risk._apply_detail", side_effect=lambda e, d: e):
            from qualys.workflows.assess_risk import assess_risk
            assess_risk(**defaults)

        return captured.get("plan", {})

    def test_scope_all_includes_trurisk_and_cloud(self):
        plan = self._get_plan(scope="all")
        assert "trurisk_score" in plan
        assert "weekly_priorities" in plan
        assert "cloud_risk" in plan
        assert "cloud_account_summary" in plan
        assert "cloud_controls" in plan

    def test_scope_all_includes_containers(self):
        plan = self._get_plan(scope="all")
        assert "container_vuln_summary" in plan
        assert "running_containers" in plan

    def test_scope_all_includes_web(self):
        plan = self._get_plan(scope="all")
        assert "webapp_vulns" in plan

    def test_scope_all_includes_certs(self):
        plan = self._get_plan(scope="all")
        assert "expiring_certs" in plan
        assert "cert_security_posture" in plan

    def test_scope_assets_only(self):
        plan = self._get_plan(scope="assets")
        assert "trurisk_score" in plan
        assert "weekly_priorities" in plan
        assert "cloud_risk" not in plan
        assert "webapp_vulns" not in plan

    def test_scope_cloud_only(self):
        plan = self._get_plan(scope="cloud")
        assert "cloud_risk" in plan
        assert "cloud_account_summary" in plan
        assert "cloud_controls" in plan
        assert "trurisk_score" not in plan

    def test_scope_containers_only(self):
        plan = self._get_plan(scope="containers")
        assert "container_security_posture" in plan
        assert "running_containers" in plan
        assert "trurisk_score" not in plan

    def test_scope_web_only(self):
        plan = self._get_plan(scope="web")
        assert "webapp_vulns" in plan
        assert "cloud_risk" not in plan

    def test_scope_certs_only(self):
        plan = self._get_plan(scope="certs")
        assert "expiring_certs" in plan
        assert "cert_security_posture" in plan
        assert "webapp_vulns" not in plan

    def test_tag_adds_risk_by_tag(self):
        plan = self._get_plan(scope="assets", tag="production")
        assert "risk_by_tag" in plan

    def test_no_tag_no_risk_by_tag(self):
        plan = self._get_plan(scope="assets", tag="")
        assert "risk_by_tag" not in plan

    def test_image_id_adds_image_vulns(self):
        plan = self._get_plan(scope="containers", image_id="sha256:abc123")
        assert "image_vulns" in plan

    def test_eol_only_adds_tech_debt_and_inventory(self):
        plan = self._get_plan(scope="assets", eol_only=True)
        assert "tech_debt" in plan
        assert "asset_inventory" in plan

    def test_staleness_param_adds_tech_debt_and_inventory(self):
        plan = self._get_plan(scope="assets", days_since_seen=30)
        assert "tech_debt" in plan
        assert "asset_inventory" in plan

    def test_asset_id_skips_broad_queries(self):
        """Single-asset fast path: only asset_detail in plan."""
        captured = {}

        def fake_dispatch(plan, **kwargs):
            captured["plan"] = plan
            return {}, 0

        with patch("qualys.workflows.assess_risk._dispatch", side_effect=fake_dispatch), \
             patch("qualys.workflows.assess_risk._build_envelope", return_value={"workflow": "assess_risk", "data": {}, "summary": {}, "correlations": [], "actions": []}), \
             patch("qualys.workflows.assess_risk._apply_detail", side_effect=lambda e, d: e):
            from qualys.workflows.assess_risk import assess_risk
            assess_risk(asset_id="12345")

        plan = captured.get("plan", {})
        assert "asset_detail" in plan
        assert "trurisk_score" not in plan
        assert "cloud_risk" not in plan


# ===========================================================================
# compliance._build_plan
# ===========================================================================

class TestComplianceBuildPlan:
    """Test compliance._build_plan list construction."""

    def _call(self, **kwargs):
        from qualys.workflows.compliance import _build_plan
        defaults = dict(
            framework="",
            platform="",
            include_exceptions=False,
            exception_status="Active",
            vuln_type="",
            days_to_expiry=30,
            limit=20,
            detail="standard",
        )
        defaults.update(kwargs)
        return _build_plan(**defaults)

    def _keys(self, plan):
        return list(plan.keys())

    def test_no_framework_includes_posture_and_frameworks(self):
        plan = self._call(framework="")
        keys = self._keys(plan)
        assert "compliance_posture" in keys
        assert "list_compliance_frameworks" in keys

    def test_list_framework_includes_frameworks(self):
        plan = self._call(framework="list")
        keys = self._keys(plan)
        assert "list_compliance_frameworks" in keys

    def test_specific_framework_skips_frameworks(self):
        plan = self._call(framework="CIS")
        keys = self._keys(plan)
        assert "compliance_posture" in keys
        assert "list_compliance_frameworks" not in keys

    def test_include_exceptions_adds_exceptions(self):
        plan = self._call(include_exceptions=True)
        keys = self._keys(plan)
        assert "vuln_exceptions" in keys

    def test_no_exceptions_by_default(self):
        plan = self._call()
        keys = self._keys(plan)
        assert "vuln_exceptions" not in keys

    def test_all_keys_present_when_no_framework_and_exceptions(self):
        plan = self._call(framework="", include_exceptions=True)
        keys = self._keys(plan)
        assert "compliance_posture" in keys
        assert "list_compliance_frameworks" in keys
        assert "vuln_exceptions" in keys

    def test_plan_is_list_of_dicts(self):
        plan = self._call()
        assert isinstance(plan, dict)
        for key, fn in plan.items():
            assert isinstance(key, str)
            assert callable(fn)


# ===========================================================================
# remediation._build_plan
# ===========================================================================

class TestRemediationBuildPlan:
    """Test remediation._build_plan list construction."""

    def _call(self, **kwargs):
        from qualys.workflows.remediation import _build_plan
        defaults = dict(
            scope="all",
            tag="",
            asset_group="",
            platform="",
            severity="",
            status="",
            qids=None,
            cves=None,
            limit=20,
            detail="standard",
        )
        defaults.update(kwargs)
        return _build_plan(**defaults)

    def _names(self, plan):
        return list(plan.keys())

    def test_scope_all_keys(self):
        names = self._names(self._call(scope="all"))
        assert "patch_status" in names
        assert "eliminate_status" in names
        assert "outstanding_patches" in names

    def test_scope_patches_keys(self):
        names = self._names(self._call(scope="patches"))
        assert "patch_status" in names
        assert "outstanding_patches" in names
        assert "eliminate_status" not in names

    def test_scope_mitigations_keys(self):
        names = self._names(self._call(scope="mitigations"))
        assert "eliminate_coverage" in names
        assert "patch_status" not in names

    def test_scope_program_keys(self):
        names = self._names(self._call(scope="program"))
        assert "recommendations" in names
        assert "patch_status" not in names

    def test_qids_triggers_mitigations_path(self):
        names = self._names(self._call(scope="all", qids=[12345]))
        assert "eliminate_coverage" in names

    def test_cves_triggers_mitigations_path(self):
        names = self._names(self._call(scope="all", cves=["CVE-2021-44228"]))
        assert "eliminate_coverage" in names

    def test_fallback_scope_returns_patch_and_eliminate(self):
        names = self._names(self._call(scope="unknown"))
        assert "patch_status" in names
        assert "eliminate_status" in names

    def test_plan_is_list_of_tuples(self):
        plan = self._call(scope="all")
        assert isinstance(plan, dict)
        for key, fn in plan.items():
            assert isinstance(key, str)
            assert callable(fn)


# ===========================================================================
# overview._build_plan
# ===========================================================================

class TestOverviewBuildPlan:
    """Test overview._build_plan list construction."""

    def _call(self, **kwargs):
        from qualys.workflows.overview import _build_plan
        defaults = dict(
            period="today",
            scope="all",
            quick=False,
            qql="",
            scan_state="Running",
            limit=50,
            detail="standard",
        )
        defaults.update(kwargs)
        return _build_plan(**defaults)

    def _keys(self, plan):
        return list(plan.keys())

    def test_always_includes_morning_report(self):
        keys = self._keys(self._call(scope="all"))
        assert "morning_report" in keys

    def test_scope_all_includes_infrastructure(self):
        keys = self._keys(self._call(scope="all"))
        assert "scanner_health" in keys
        assert "scan_status" in keys

    def test_scope_all_includes_scheduled_scans(self):
        keys = self._keys(self._call(scope="all"))
        assert "scheduled_scans" in keys

    def test_scope_infrastructure_includes_scanners(self):
        keys = self._keys(self._call(scope="infrastructure"))
        assert "scanner_health" in keys
        assert "scan_status" in keys

    def test_scope_findings_no_scanner(self):
        keys = self._keys(self._call(scope="findings"))
        assert "scanner_health" not in keys

    def test_quick_mode_no_scheduled_scans(self):
        keys = self._keys(self._call(scope="all", quick=True))
        assert "scheduled_scans" not in keys

    def test_plan_is_list_of_dicts_with_key_and_fn(self):
        plan = self._call(scope="all")
        assert isinstance(plan, dict)
        for key, fn in plan.items():
            assert isinstance(key, str)
            assert callable(fn)

    def test_period_today(self):
        """Period 'today' should be accepted without error."""
        plan = self._call(period="today")
        assert len(plan) > 0

    def test_period_week(self):
        plan = self._call(period="week")
        assert len(plan) > 0

    def test_period_month(self):
        plan = self._call(period="month")
        assert len(plan) > 0
