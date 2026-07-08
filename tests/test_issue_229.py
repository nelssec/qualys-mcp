"""Regression tests for issue #229 — per-asset vulnerability queries returning
no detection data.

Root cause (confirmed live): the per-asset path funnels hostname/IP targets
into get_asset_by_id(), which filtered CSAM with `asset.id EQUALS <value>`.
A non-numeric identifier makes the CSAM API return HTTP 400, the asset is
"not found", and the VMDR detection fetch never runs. Two secondary gaps kept
detections invisible even for numeric ids: investigate_agg's asset branch read
the wrong result keys ('vulns'/'hostname' instead of 'vmdrDetections'/'csam'),
and the workflow summary dropped the aggregator's key_facts.

Mock payloads mirror live CSAM v2 / VMDR shapes (sanitized — fake names/IPs).
"""
from unittest.mock import patch


FAKE_ASSET = {
    "assetId": 12345678,
    "hostId": 987654,
    "address": "10.0.0.99",
    "dnsName": "testhost01",
    "assetName": "testhost01",
    "operatingSystem": {"osName": "Windows Server 2012 R2"},
    "riskScore": 1000,
    "criticality": {"score": 3},
    "lastModifiedDate": "2026-07-01T00:00:00Z",
    "softwareListData": {"software": []},
    "tags": {},
}


class TestGetAssetByIdResolution:
    """get_asset_by_id must resolve hostnames and IPs, not just numeric ids.

    Live behavior on US2: `asset.id EQUALS <hostname>` -> HTTP 400 -> None,
    while `asset.name EQUALS <hostname>` and `interfaces.address EQUALS <ip>`
    both resolve the asset (hostId populated).
    """

    def _capturing_search(self, responses):
        """Return (calls, fake) where fake pops canned responses per call."""
        calls = []

        def fake(filters=None, limit=100, fields=None, fetch_all=False):
            calls.append({"filters": filters, "fields": fields})
            return responses.pop(0) if responses else []

        return calls, fake

    def test_numeric_id_uses_asset_id_filter(self):
        from qualys.api import get_asset_by_id
        calls, fake = self._capturing_search([[FAKE_ASSET]])
        with patch("qualys.api.csam_search", side_effect=fake):
            asset = get_asset_by_id("12345678")
        assert asset is not None
        f = calls[0]["filters"][0]
        assert f["field"] == "asset.id"
        assert f["value"] == "12345678"

    def test_hostname_uses_asset_name_filter(self):
        from qualys.api import get_asset_by_id
        calls, fake = self._capturing_search([[FAKE_ASSET]])
        with patch("qualys.api.csam_search", side_effect=fake):
            asset = get_asset_by_id("testhost01")
        assert asset is not None, "hostname lookup must resolve the asset"
        f = calls[0]["filters"][0]
        assert f["field"] == "asset.name", (
            "non-numeric identifier must not be sent as asset.id "
            "(CSAM returns HTTP 400 and the asset is never found)")
        assert f["operator"] == "EQUALS"
        assert f["value"] == "testhost01"

    def test_ip_uses_interfaces_address_filter(self):
        from qualys.api import get_asset_by_id
        calls, fake = self._capturing_search([[FAKE_ASSET]])
        with patch("qualys.api.csam_search", side_effect=fake):
            asset = get_asset_by_id("10.0.0.99")
        assert asset is not None, "IP lookup must resolve the asset"
        f = calls[0]["filters"][0]
        assert f["field"] == "interfaces.address"
        assert f["value"] == "10.0.0.99"

    def test_fqdn_falls_back_to_short_name(self):
        from qualys.api import get_asset_by_id
        calls, fake = self._capturing_search([[], [FAKE_ASSET]])
        with patch("qualys.api.csam_search", side_effect=fake):
            asset = get_asset_by_id("testhost01.corp.example")
        assert asset is not None, "FQDN must fall back to the short hostname"
        assert calls[0]["filters"][0]["value"] == "testhost01.corp.example"
        assert calls[1]["filters"][0]["field"] == "asset.name"
        assert calls[1]["filters"][0]["value"] == "testhost01"

    def test_lookup_requests_hostid_projection(self):
        """Every resolution path must request hostId (v0.2.6 regression)."""
        from qualys.api import get_asset_by_id
        calls, fake = self._capturing_search([[FAKE_ASSET]])
        with patch("qualys.api.csam_search", side_effect=fake):
            get_asset_by_id("testhost01")
        assert "hostId" in (calls[0]["fields"] or "")

    def test_unresolvable_returns_none(self):
        from qualys.api import get_asset_by_id
        with patch("qualys.api.csam_search", return_value=[]):
            assert get_asset_by_id("no-such-host") is None


# Shape of asset_detail(detail_level='full') as observed live (sanitized):
# detections live under 'vmdrDetections', identity under 'csam'.
FULL_ASSET_DETAIL = {
    "assetId": "12345678",
    "riskScore": 1000,
    "truriskScore": 1000,
    "csam": {
        "hostname": "testhost01",
        "ip": "10.0.0.99",
        "os": "Windows Server 2012 R2",
        "hostId": "987654",
        "riskScore": 1000,
        "criticality": 3,
    },
    "etmFindings": [],
    "vmdrDetections": [
        {"qid": 13360, "title": "Example Remote Code Execution", "severity": 4,
         "qds": 72, "cves": ["CVE-2020-0001", "CVE-2020-0002"],
         "patchAvailable": True, "status": "Active"},
        {"qid": 38863, "title": "Example TLS Weakness", "severity": 4,
         "qds": 60, "cves": [], "patchAvailable": False, "status": "Active"},
    ],
    "summary": {"riskScore": 1000, "vmdrDetections": 2, "etmFindings": 0},
}


class TestInvestigateAggAssetBranch:
    """The asset branch must surface VMDR detections in its key facts."""

    def _run(self):
        import qualys.aggregators as agg
        with patch.object(agg, "asset_detail", return_value=FULL_ASSET_DETAIL):
            return agg.investigate_agg("asset:testhost01", depth="quick")

    def test_detection_facts_include_qid_severity_cve(self):
        facts = " | ".join(self._run().get("key_facts") or [])
        assert "QID 13360" in facts, f"top detection QID missing from: {facts}"
        assert "severity 4" in facts
        assert "CVE-2020-0001" in facts

    def test_vuln_count_reads_vmdr_detections_key(self):
        facts = " | ".join(self._run().get("key_facts") or [])
        assert "2 vulnerabilities detected" in facts, (
            "count must come from 'vmdrDetections' (full detail), "
            f"got: {facts}")

    def test_hostname_read_from_csam_block(self):
        facts = " | ".join(self._run().get("key_facts") or [])
        assert "testhost01" in facts


class TestAssetBranchAvoidsSubscriptionWideFetch:
    """The asset branch must not pull subscription-wide ETM findings.

    Live evidence: etm_findings() cold fetches every sev 3-5 detection in the
    subscription (>10 min on large tenants), exceeding the workflow dispatch
    budget so the entire per-asset investigation was dropped — the visible
    #229 symptom. asset_detail(full) already returns the asset's own
    etmFindings and vmdrDetections.
    """

    def test_deep_asset_investigation_skips_global_etm(self):
        import qualys.aggregators as agg
        from unittest.mock import MagicMock
        etm_mock = MagicMock(return_value={"findings": []})
        with patch.object(agg, "asset_detail", return_value=FULL_ASSET_DETAIL), \
             patch.object(agg, "etm_findings", etm_mock), \
             patch.object(agg, "patch_status", return_value={}), \
             patch.object(agg, "vuln_exceptions", return_value={}):
            res = agg.investigate_agg("asset:testhost01", depth="deep")
        etm_mock.assert_not_called()
        facts = " | ".join(res.get("key_facts") or [])
        assert "QID 13360" in facts

    def test_deep_asset_branch_runs_concurrently(self):
        """asset_detail + patch_status + vuln_exceptions must run in one
        concurrent batch, not sequentially — cold per-host VMDR fetches are
        ~60-90s and the sequential sum blew the dispatch budget (issue #229)."""
        import time
        import qualys.aggregators as agg

        def slow(delay, value):
            def _f(*a, **k):
                time.sleep(delay)
                return value
            return _f

        with patch.object(agg, "asset_detail", side_effect=slow(0.2, FULL_ASSET_DETAIL)), \
             patch.object(agg, "patch_status", side_effect=slow(0.2, {})), \
             patch.object(agg, "vuln_exceptions", side_effect=slow(0.2, {})):
            t0 = time.time()
            res = agg.investigate_agg("asset:testhost01", depth="deep")
            elapsed = time.time() - t0
        assert elapsed < 0.35, (
            f"deep asset branch took {elapsed:.2f}s for three 0.2s calls — "
            "all three must run in one concurrent batch (asset_detail must "
            "not be a serial phase before the deep tasks)")
        assert "QID 13360" in " | ".join(res.get("key_facts") or [])

    def test_deep_dispatch_budget_covers_cold_vmdr_fetch(self):
        """The deep dispatch timeout must exceed a cold per-host VMDR
        detection fetch (~60-90s) plus KB enrichment; 120s was routinely
        exceeded on large tenants, dropping all per-asset data."""
        from unittest.mock import MagicMock
        captured = {}

        def fake_dispatch(plan, timeout=None):
            captured["timeout"] = timeout
            return {}, 1

        with patch("qualys.workflows.investigate._dispatch",
                   side_effect=fake_dispatch), \
             patch("qualys.api.module_available", return_value=False), \
             patch("qualys.api.prewarm_modules", return_value=None), \
             patch("qualys.aggregators.summarize_investigation_agg",
                   MagicMock(return_value=""), create=True):
            from qualys.workflows.investigate import investigate
            investigate(target="asset:testhost01", depth="deep")
        assert captured["timeout"] >= 240, (
            f"deep dispatch timeout {captured['timeout']}s cannot cover a "
            "cold per-host VMDR detection fetch")


class TestWorkflowSummaryPropagatesAssetFacts:
    """The investigate workflow summary must not drop the asset key_facts —
    they are the only place QID/CVE/severity data reaches the rendered
    markdown output."""

    def test_key_facts_reach_key_findings(self):
        from qualys.workflows.investigate import investigate

        inv_result = {
            "summary": "Asset investigation on 'asset:testhost01' (quick depth).",
            "key_facts": [
                "Asset TruRisk: 1000",
                "Hostname: testhost01, OS: Windows Server 2012 R2",
                "2 vulnerabilities detected",
                "QID 13360 severity 4 (CVE-2020-0001, CVE-2020-0002)",
            ],
        }

        def fake_dispatch(plan, timeout=None):
            return {"investigate": inv_result}, 5

        with patch("qualys.workflows.investigate._dispatch",
                   side_effect=fake_dispatch), \
             patch("qualys.api.module_available", return_value=False), \
             patch("qualys.api.prewarm_modules", return_value=None):
            env = investigate(target="asset:testhost01", depth="quick")

        findings = " | ".join(env["summary"]["key_findings"])
        assert "QID 13360" in findings, (
            f"detection facts dropped from workflow summary: {findings}")
        assert "CVE-2020-0001" in findings

    def test_aggregator_risk_level_adopted(self):
        from qualys.workflows.investigate import investigate

        inv_result = {
            "summary": "Asset investigation on 'asset:testhost01' (quick depth).",
            "key_facts": ["Asset TruRisk: 1000"],
            "risk_level": "critical",
        }

        def fake_dispatch(plan, timeout=None):
            return {"investigate": inv_result}, 5

        with patch("qualys.workflows.investigate._dispatch",
                   side_effect=fake_dispatch), \
             patch("qualys.api.module_available", return_value=False), \
             patch("qualys.api.prewarm_modules", return_value=None):
            env = investigate(target="asset:testhost01", depth="quick")

        assert env["summary"]["risk_level"] == "critical", (
            "a TruRisk-1000 asset must not surface as low/unknown")
