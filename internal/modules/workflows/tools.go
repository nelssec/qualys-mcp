package workflows

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-mcp/internal/common"
	"github.com/nelssec/qualys-mcp/internal/modules/car"
	"github.com/nelssec/qualys-mcp/internal/modules/container"
	"github.com/nelssec/qualys-mcp/internal/modules/gav"
	"github.com/nelssec/qualys-mcp/internal/modules/knowledgebase"
	"github.com/nelssec/qualys-mcp/internal/modules/patch"
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

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("get_asset_risk_summary",
			mcp.WithDescription("Get a comprehensive risk summary for an asset. Combines data from multiple sources: TruRisk score from Global AssetView, top vulnerabilities from VMDR, available patches from Patch Management, and remediation steps from the KnowledgeBase. Use this to understand why an asset is risky and how to fix it."),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID to get the risk summary for")),
		),
		m.getAssetRiskSummary,
	)

	s.AddTool(
		mcp.NewTool("get_remediation_plan",
			mcp.WithDescription("Get a remediation plan for a specific vulnerability. Given a CVE or QID, returns: all affected assets, vulnerability details, manual remediation steps, available patches, and remediation scripts. Use this to understand the blast radius of a vulnerability and plan remediation."),
			mcp.WithString("identifier", mcp.Required(), mcp.Description("CVE ID (e.g., 'CVE-2024-1234') or QID number (e.g., '12345')")),
		),
		m.getRemediationPlan,
	)

	s.AddTool(
		mcp.NewTool("prioritize_external_risk",
			mcp.WithDescription("Get a prioritized remediation list for internet-facing assets. Returns a token-optimized summary (~2-3k tokens) combining: external asset inventory from a tag, critical/high web application vulnerabilities with URLs, critical/high infrastructure vulnerabilities with KB enrichment, and top risk assets. Use this to quickly understand what to fix first on your attack surface."),
			mcp.WithString("tag_name", mcp.Description("Tag name identifying external assets (default: 'Internet Facing Assets')")),
			mcp.WithNumber("min_severity", mcp.Description("Minimum severity to include: 4=High, 5=Critical (default: 4)")),
			mcp.WithNumber("limit", mcp.Description("Maximum findings per category (default: 20)")),
			mcp.WithBoolean("include_web_apps", mcp.Description("Include WAS findings (default: true)")),
		),
		m.prioritizeExternalRisk,
	)

	s.AddTool(
		mcp.NewTool("get_tech_debt_summary",
			mcp.WithDescription("RECOMMENDED for tech debt reduction. Analyze End-of-Life (EOL) and End-of-Support (EOS) software across your environment. Returns: stats on affected assets, EOL/EOS software by type with asset counts, EOL container images, top affected assets, and a prioritized reduction plan. Ask 'reduce tech debt by 30%' to get an actionable plan."),
			mcp.WithNumber("reduction_target", mcp.Description("Target reduction percentage (default: 30). Returns a plan showing which software to upgrade first to hit this target.")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to analyze (default: 100)")),
		),
		m.getTechDebtSummary,
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
