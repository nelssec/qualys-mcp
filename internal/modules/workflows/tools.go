package workflows

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-mcp/internal/common"
	"github.com/nelssec/qualys-mcp/internal/modules/activitylog"
	"github.com/nelssec/qualys-mcp/internal/modules/car"
	"github.com/nelssec/qualys-mcp/internal/modules/compliance"
	"github.com/nelssec/qualys-mcp/internal/modules/container"
	"github.com/nelssec/qualys-mcp/internal/modules/gav"
	"github.com/nelssec/qualys-mcp/internal/modules/knowledgebase"
	"github.com/nelssec/qualys-mcp/internal/modules/patch"
	"github.com/nelssec/qualys-mcp/internal/modules/totalcloud"
	"github.com/nelssec/qualys-mcp/internal/modules/vmdr"
	"github.com/nelssec/qualys-mcp/internal/modules/was"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var newToolResultError = common.NewToolResultError

type Module struct {
	client *Client
}

func New(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client) *Module {
	return &Module{
		client: NewClient(gavClient, vmdrClient, kbClient, pmClient, carClient),
	}
}

func NewWithWAS(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client) *Module {
	return &Module{
		client: NewClientWithWAS(gavClient, vmdrClient, kbClient, pmClient, carClient, wasClient),
	}
}

func NewFull(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client, containerClient *container.Client) *Module {
	return &Module{
		client: NewClientFull(gavClient, vmdrClient, kbClient, pmClient, carClient, wasClient, containerClient),
	}
}

func NewComplete(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client, containerClient *container.Client, tcClient *totalcloud.Client, pcClient *compliance.Client, alClient *activitylog.Client) *Module {
	return &Module{
		client: NewClientComplete(gavClient, vmdrClient, kbClient, pmClient, carClient, wasClient, containerClient, tcClient, pcClient, alClient),
	}
}

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("get_asset_risk_summary",
			mcp.WithDescription("[ASSET RISK] Get a comprehensive risk summary for a single asset combining TruRisk, top vulns, patches, and remediation steps.\n\nUSE WHEN: user asks 'why is this asset risky', 'what's wrong with asset X', drilling into one specific asset's risk profile\nDO NOT USE WHEN: user wants aggregate risk for a group/tag (use gav_get_assets_by_tag or gav_get_high_risk_assets), user wants full asset profile with all metadata (use gav_get_asset_details)\nPREFER INSTEAD: gav_get_asset_details when user wants hardware/software/network info without risk focus; gav_get_high_risk_assets when user wants to find the riskiest assets across the environment\n\nParameters:\n  asset_id: (required) the asset ID to analyze\n\nReturns: TruRisk score, top vulnerabilities with severity, available patches, remediation steps from KB\n\nPerformance: ~5s cold / ~0.5s warm (multi-source aggregation)"),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID to get the risk summary for")),
		),
		m.getAssetRiskSummary,
	)

	s.AddTool(
		mcp.NewTool("get_remediation_plan",
			mcp.WithDescription("[REMEDIATION] Get a remediation plan for a specific vulnerability across your environment.\n\nUSE WHEN: user asks 'how do I fix CVE-X', 'what's the blast radius of this vuln', 'remediation plan for QID 12345'\nDO NOT USE WHEN: user just wants CVE metadata (use kb_search_vulns or kb_get_cve_mapping), user wants to know if they are affected without a fix plan (use investigate_cve)\nPREFER INSTEAD: investigate_cve when user asks 'are we affected by CVE-X' without needing a fix plan; kb_get_qid when user just wants vuln details for a single QID\n\nParameters:\n  identifier: (required) CVE ID (e.g., 'CVE-2024-1234') or QID number (e.g., '12345')\n\nReturns: affected assets, vulnerability details, manual remediation steps, available patches, remediation scripts\n\nPerformance: ~8s cold / ~0.5s warm (multi-source aggregation)"),
			mcp.WithString("identifier", mcp.Required(), mcp.Description("CVE ID (e.g., 'CVE-2024-1234') or QID number (e.g., '12345')")),
		),
		m.getRemediationPlan,
	)

	s.AddTool(
		mcp.NewTool("prioritize_external_risk",
			mcp.WithDescription("[EXTERNAL RISK] Get a prioritized remediation list for internet-facing assets (~2-3k tokens).\n\nUSE WHEN: user asks 'what's exposed externally', 'attack surface priorities', 'internet-facing risks', 'what should we fix on our perimeter'\nDO NOT USE WHEN: user asks about internal assets only (use get_weekly_priorities), user wants cloud-specific posture (use get_cloud_risk_summary)\nPREFER INSTEAD: get_weekly_priorities when user wants general weekly action items not limited to external assets\n\nParameters:\n  tag_name: tag identifying external assets (default: 'Internet Facing Assets')\n  min_severity: minimum severity 1-5, where 4=High, 5=Critical (default: 4)\n  limit: max findings per category (default: 20)\n  include_web_apps: include WAS findings (default: true)\n\nReturns: external asset inventory, critical/high web app vulns with URLs, infrastructure vulns with KB enrichment, top risk assets\n\nPerformance: ~10s cold / ~0.5s warm (multi-source aggregation)"),
			mcp.WithString("tag_name", mcp.Description("Tag name identifying external assets (default: 'Internet Facing Assets')")),
			mcp.WithNumber("min_severity", mcp.Description("Minimum severity to include: 4=High, 5=Critical (default: 4)")),
			mcp.WithNumber("limit", mcp.Description("Maximum findings per category (default: 20)")),
			mcp.WithBoolean("include_web_apps", mcp.Description("Include WAS findings (default: true)")),
		),
		m.prioritizeExternalRisk,
	)

	s.AddTool(
		mcp.NewTool("get_tech_debt_summary",
			mcp.WithDescription("[TECH DEBT] Analyze End-of-Life/End-of-Support software across your environment with a reduction plan.\n\nUSE WHEN: user asks 'reduce tech debt', 'EOL software', 'end of life', 'unsupported software', 'tech debt by 30%'\nDO NOT USE WHEN: user asks about active vulnerabilities (use get_weekly_priorities or vmdr_get_detection_summary), user asks about compliance (use get_compliance_gaps)\nPREFER INSTEAD: get_weekly_priorities when user wants actionable vulnerability fixes, not software lifecycle issues\n\nParameters:\n  reduction_target: target reduction percentage (default: 30) — returns plan showing which software to upgrade first\n  limit: max assets to analyze (default: 100)\n\nReturns: EOL/EOS stats, affected software by type with asset counts, EOL container images, top affected assets, prioritized reduction plan\n\nPerformance: ~8s cold / ~0.5s warm (multi-source aggregation)"),
			mcp.WithNumber("reduction_target", mcp.Description("Target reduction percentage (default: 30). Returns a plan showing which software to upgrade first to hit this target.")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to analyze (default: 100)")),
		),
		m.getTechDebtSummary,
	)

	s.AddTool(
		mcp.NewTool("get_weekly_priorities",
			mcp.WithDescription("[PRIORITIZATION] Get risk-ranked security action list for the week combining vulns, containers, and patches.\n\nUSE WHEN: user asks 'what should I work on this week', 'top priorities', 'weekly report', 'what should my team fix'\nDO NOT USE WHEN: user asks about last 24 hours / overnight changes (use get_notable_changes), user wants external-only priorities (use prioritize_external_risk)\nPREFER INSTEAD: get_notable_changes when user asks 'what happened overnight' or 'morning report'; prioritize_external_risk when focus is internet-facing assets only\n\nParameters:\n  limit: max priority items to return (default: 10)\n\nReturns: critical items ranked by severity and asset impact, infra vs container breakdown, effort classification (patch/config/upgrade)\n\nPerformance: ~8s cold / ~0.5s warm (multi-source aggregation)"),
			mcp.WithNumber("limit", mcp.Description("Maximum priority items to return (default: 10)")),
		),
		m.getWeeklyPriorities,
	)

	s.AddTool(
		mcp.NewTool("investigate_cve",
			mcp.WithDescription("[CVE INVESTIGATION] Investigate a specific CVE across your entire environment — single CVE, full asset search, slow.\n\nUSE WHEN: user asks 'are we affected by CVE-X', 'investigate CVE-X', 'find CVE-X in our environment'\nDO NOT USE WHEN: user wants CVE metadata without asset search (use kb_get_cve_mapping or kb_search_vulns), user wants to fix a CVE (use get_remediation_plan), user wants bulk CVE lookup for 2+ CVEs (use kb_search_vulns)\nPREFER INSTEAD: kb_get_cve_mapping when user just wants QID mapping for a CVE; kb_search_vulns when user wants CVE metadata for multiple CVEs without asset search; get_remediation_plan when user needs a fix plan\n\nParameters:\n  cve: (required) CVE ID (e.g., 'CVE-2024-1234')\n\nReturns: CVE details from KB, detecting QIDs, all affected hosts from VMDR, affected container images, available patches, remediation scripts, manual fix steps\n\nPerformance: ~12s cold / ~0.5s warm (full environment scan)"),
			mcp.WithString("cve", mcp.Required(), mcp.Description("The CVE ID to investigate (e.g., 'CVE-2024-1234')")),
		),
		m.investigateCVE,
	)

	s.AddTool(
		mcp.NewTool("get_security_posture",
			mcp.WithDescription("[EXECUTIVE OVERVIEW] Get an executive overview of overall security posture with health score.\n\nUSE WHEN: user asks 'how secure are we', 'security overview', 'executive summary', 'overall posture', 'dashboard'\nDO NOT USE WHEN: user asks about specific vulns (use vmdr_get_detection_summary), specific assets (use get_asset_risk_summary), or specific modules\nPREFER INSTEAD: get_weekly_priorities when user wants actionable items; get_cloud_risk_summary when user wants cloud-specific posture\n\nParameters: none\n\nReturns: health score (0-100), asset inventory stats, vuln counts by severity, container security stats, cloud posture (failed controls by provider), compliance status\n\nPerformance: ~10s cold / ~0.5s warm (aggregates all modules)"),
		),
		m.getSecurityPosture,
	)

	s.AddTool(
		mcp.NewTool("get_patch_status",
			mcp.WithDescription("[PATCHING] Get patching coverage/gaps analysis across your environment.\n\nUSE WHEN: user asks 'how is our patching going', 'patch coverage', 'missing patches', 'what needs patching'\nDO NOT USE WHEN: user asks about active patch deployment jobs (use pm_list_jobs), user wants patches for one specific asset (use pm_get_asset_patches), user asks about Patch Management module directly (use pm_list_patches)\nPREFER INSTEAD: pm_list_jobs when user asks 'what patches are deploying right now'; pm_get_asset_patches when user asks about patches for a specific asset; pm_list_patches when user wants to browse available patches\n\nParameters:\n  limit: max items per category (default: 20)\n\nReturns: patch coverage percentage, missing critical patches (count + list), assets missing patches by criticality, recent job status, patchable vs non-patchable breakdown\n\nPerformance: ~5s cold / ~0.3s warm (multi-source aggregation)"),
			mcp.WithNumber("limit", mcp.Description("Maximum items to return per category (default: 20)")),
		),
		m.getPatchStatus,
	)

	s.AddTool(
		mcp.NewTool("get_compliance_gaps",
			mcp.WithDescription("[COMPLIANCE] Identify compliance gaps that may fail audits.\n\nUSE WHEN: user asks 'what will fail our audit', 'compliance gaps', 'policy violations', 'audit readiness'\nDO NOT USE WHEN: user wants raw policy list (use pc_list_policies), user wants compliance scan status (use pc_list_scans), user wants cloud compliance (use get_cloud_risk_summary)\nPREFER INSTEAD: pc_list_policies when user wants to browse policies; pc_get_policy_details when user wants details on one policy; get_cloud_risk_summary when compliance question is cloud-specific\n\nParameters:\n  limit: max items per category (default: 20)\n\nReturns: policy compliance summary with pass/fail rates, top failing controls, assets with most compliance issues, critical gaps with remediation guidance\n\nPerformance: ~5s cold / ~0.3s warm (multi-source aggregation)"),
			mcp.WithNumber("limit", mcp.Description("Maximum items to return per category (default: 20)")),
		),
		m.getComplianceGaps,
	)

	s.AddTool(
		mcp.NewTool("get_cloud_risk_summary",
			mcp.WithDescription("[CLOUD SECURITY] Get cloud security posture across AWS, Azure, and GCP.\n\nUSE WHEN: user asks 'cloud security posture', 'cloud risks', 'AWS/Azure/GCP security', 'cloud misconfigurations'\nDO NOT USE WHEN: user wants specific cloud resource details (use tc_list_resources), specific control evaluations (use tc_get_control_evaluations), CDR threat findings only (use tc_list_cdr_findings)\nPREFER INSTEAD: tc_list_resources when user asks about specific cloud resource types; tc_list_cdr_findings when user asks about cloud threats/detections specifically\n\nParameters:\n  limit: max items per category (default: 20)\n\nReturns: cloud accounts overview, failed controls by severity, misconfigs by resource type, container risks in cloud (EKS/GKE/AKS), recent CDR findings, top risky cloud resources\n\nPerformance: ~8s cold / ~0.5s warm (multi-source aggregation)"),
			mcp.WithNumber("limit", mcp.Description("Maximum items to return per category (default: 20)")),
		),
		m.getCloudRiskSummary,
	)
}

func (m *Module) getAssetRiskSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	assetID, ok := req.Params.Arguments["asset_id"].(string)
	if !ok || assetID == "" {
		return newToolResultError("asset_id is required"), nil
	}

	summary, err := m.client.GetAssetRiskSummary(ctx, assetID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get asset risk summary: %v", err)), nil
	}

	data, _ := json.MarshalIndent(summary, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getRemediationPlan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	identifier, ok := req.Params.Arguments["identifier"].(string)
	if !ok || identifier == "" {
		return newToolResultError("identifier (CVE or QID) is required"), nil
	}

	plan, err := m.client.GetRemediationPlan(ctx, identifier)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get remediation plan: %v", err)), nil
	}

	data, _ := json.MarshalIndent(plan, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) prioritizeExternalRisk(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tagName := ""
	if t, ok := req.Params.Arguments["tag_name"].(string); ok {
		tagName = t
	}

	minSeverity := 4
	if s, ok := req.Params.Arguments["min_severity"].(float64); ok {
		minSeverity = int(s)
	}

	limit := 20
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	includeWebApps := true
	if w, ok := req.Params.Arguments["include_web_apps"].(bool); ok {
		includeWebApps = w
	}

	result, err := m.client.PrioritizeExternalRisk(ctx, tagName, minSeverity, limit, includeWebApps)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to prioritize external risk: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getTechDebtSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	reductionTarget := 30.0
	if r, ok := req.Params.Arguments["reduction_target"].(float64); ok {
		reductionTarget = r
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	result, err := m.client.GetTechDebtSummary(ctx, reductionTarget, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get tech debt summary: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getWeeklyPriorities(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 10
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	result, err := m.client.GetWeeklyPriorities(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get weekly priorities: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) investigateCVE(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cve, ok := req.Params.Arguments["cve"].(string)
	if !ok || cve == "" {
		return newToolResultError("cve is required"), nil
	}

	result, err := m.client.InvestigateCVE(ctx, cve)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to investigate CVE: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getSecurityPosture(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result, err := m.client.GetSecurityPosture(ctx)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get security posture: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getPatchStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 20
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	result, err := m.client.GetPatchStatus(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get patch status: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getComplianceGaps(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 20
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	result, err := m.client.GetComplianceGaps(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get compliance gaps: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getCloudRiskSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 20
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	result, err := m.client.GetCloudRiskSummary(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get cloud risk summary: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
