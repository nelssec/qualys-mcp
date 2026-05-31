"""Unit coverage for functions added in the v0.2.x reconciliation work:
error counters, bearer-token invalidation, module availability + prewarm,
vuln-listing intent, and the TC 2.24 / PM 3.14 aggregators."""
import pytest
from unittest.mock import patch


class TestApiErrorCounters:
    def test_reset_zeroes_all(self):
        from qualys.api import get_api_error_counts, reset_api_error_counts, _count_api_error
        _count_api_error(503)
        reset_api_error_counts()
        assert all(v == 0 for v in get_api_error_counts().values())

    def test_count_increments_by_code(self):
        from qualys.api import get_api_error_counts, reset_api_error_counts, _count_api_error
        reset_api_error_counts()
        _count_api_error(503)
        _count_api_error(503)
        _count_api_error(429)
        c = get_api_error_counts()
        assert c["503"] == 2
        assert c["429"] == 1

    def test_gateway_401_uses_distinct_key(self):
        from qualys.api import get_api_error_counts, reset_api_error_counts, _count_api_error
        reset_api_error_counts()
        _count_api_error(401, gateway=True)
        _count_api_error(401, gateway=False)
        c = get_api_error_counts()
        assert c["401_gw"] == 1
        assert c.get("401") == 1

    def test_snapshot_is_a_copy(self):
        from qualys.api import get_api_error_counts, _count_api_error
        snap = get_api_error_counts()
        snap["503"] = 9999
        assert get_api_error_counts()["503"] != 9999


class TestBearerTokenInvalidation:
    @pytest.fixture(autouse=True)
    def _restore_token_state(self):
        import qualys.api as api
        saved_t, saved_tt = api.BEARER_TOKEN, api.BEARER_TOKEN_TIME
        yield
        api.BEARER_TOKEN, api.BEARER_TOKEN_TIME = saved_t, saved_tt

    def test_clears_only_when_token_matches(self):
        import qualys.api as api
        from datetime import datetime, timezone
        api.BEARER_TOKEN = "tok-A"
        api.BEARER_TOKEN_TIME = datetime.now(timezone.utc)
        api._invalidate_bearer_token("tok-A")
        assert api.BEARER_TOKEN is None
        assert api.BEARER_TOKEN_TIME is None

    def test_does_not_clear_a_different_token(self):
        import qualys.api as api
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        api.BEARER_TOKEN = "tok-fresh"
        api.BEARER_TOKEN_TIME = now
        # a stale handler tries to clear the OLD token — must be a no-op
        api._invalidate_bearer_token("tok-stale")
        assert api.BEARER_TOKEN == "tok-fresh"
        assert api.BEARER_TOKEN_TIME == now


class TestModuleAvailability:
    def test_unknown_module_assumed_available(self):
        from qualys.api import module_available
        assert module_available("does-not-exist") is True

    def test_no_creds_mode_short_circuits_true(self):
        # tests run without QUALYS_USERNAME/PASSWORD set, so every known module
        # must report available without probing or touching the disk cache.
        from qualys.api import module_available, MODULES
        for name in MODULES:
            assert module_available(name) is True

    def test_no_creds_mode_ignores_stale_disk_false(self):
        from qualys.api import module_available, _MODULE_AVAILABLE
        from qualys.cache import disk_cache
        _MODULE_AVAILABLE.pop("vmdr", None)
        disk_cache.set("module_avail_vmdr", False, 3600)
        try:
            assert module_available("vmdr") is True
        finally:
            disk_cache.clear("module_avail_vmdr")

    def test_status_summary_shape(self):
        from qualys.api import module_status_summary
        s = module_status_summary()
        assert set(["available", "unavailable", "total", "enabled"]) <= set(s)
        assert s["total"] == len(s["available"]) + len(s["unavailable"])

    def test_prewarm_is_noop_when_all_cached(self):
        from qualys.api import prewarm_modules, _MODULE_AVAILABLE
        _MODULE_AVAILABLE["cs"] = True
        _MODULE_AVAILABLE["was"] = True
        # already-cached names => no probing should occur
        with patch("qualys.api._probe_module") as probe:
            prewarm_modules(["cs", "was"])
            probe.assert_not_called()


class TestVulnListingIntent:
    @pytest.mark.parametrize("q,threat", [
        ("list exploitable vulnerabilities", "Active_Attacks"),
        ("what is actively exploited", "Active_Attacks"),
        ("ransomware vulnerabilities", "Ransomware"),
        ("show me CISA KEV vulns", "Cisa_Known_Exploited_Vulns"),
    ])
    def test_threat_mapping(self, q, threat):
        from qualys.workflows.investigate import _vuln_listing_intent
        t, listing = _vuln_listing_intent(q)
        assert t == threat
        assert listing is True

    @pytest.mark.parametrize("q", [
        "top critical vulnerabilities", "list all sev 5 QIDs",
        "unpatched vulnerabilities", "recent CVEs",
    ])
    def test_generic_listing_detected_without_threat(self, q):
        from qualys.workflows.investigate import _vuln_listing_intent
        t, listing = _vuln_listing_intent(q)
        assert listing is True
        assert t == ""

    @pytest.mark.parametrize("q", ["OpenSSH", "10.0.0.1", "Lazarus Group", "Apache"])
    def test_non_listing_targets(self, q):
        from qualys.workflows.investigate import _vuln_listing_intent
        _, listing = _vuln_listing_intent(q)
        assert listing is False


class TestNewAggregators:
    def test_cloud_resources_v1_agg_shape(self):
        from qualys.aggregators import cloud_resources_v1_agg
        fake = {"content": [
            {"resourceId": "i-1", "name": "web", "region": "us-east-1",
             "uuid": "u1", "criticality": "HIGH"}], "totalHits": 1}
        with patch("qualys.aggregators.get_cloud_resources_v1", return_value=fake):
            r = cloud_resources_v1_agg(provider="aws", resource_type="EC2_INSTANCE")
        assert r["totalResources"] == 1
        assert r["provider"] == "AWS"
        assert r["resources"][0]["resourceId"] == "i-1"
        assert "1 AWS" in r["summary"]

    def test_cloud_resources_v1_agg_empty(self):
        from qualys.aggregators import cloud_resources_v1_agg
        with patch("qualys.aggregators.get_cloud_resources_v1",
                   return_value={"content": [], "totalHits": 0}):
            r = cloud_resources_v1_agg()
        assert r["totalResources"] == 0
        # compact() drops the empty resources list from the envelope
        assert r.get("resources", []) == []

    def test_pm_remediation_insights_agg_counts(self):
        from qualys.aggregators import pm_remediation_insights_agg
        fake = {"patches": [
            {"id": "p1", "title": "KB1", "isVendorAcquired": True, "isCustomizedDownloadUrl": True},
            {"id": "p2", "title": "KB2", "vendorAcquired": False},
        ]}
        with patch("qualys.aggregators.get_pm_remediation_insights", return_value=fake):
            r = pm_remediation_insights_agg(platform="Windows")
        assert r["totalPatches"] == 2
        assert r["vendorAcquired"] == 1
        assert r["customizedDownloadUrl"] == 1

    def test_pm_remediation_insights_agg_empty(self):
        from qualys.aggregators import pm_remediation_insights_agg
        with patch("qualys.aggregators.get_pm_remediation_insights", return_value={}):
            r = pm_remediation_insights_agg()
        assert r["totalPatches"] == 0
