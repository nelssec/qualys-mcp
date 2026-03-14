package patch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-mcp/internal/common"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var newToolResultError = common.NewToolResultError

type Module struct {
	client *Client
}

func New(http *common.HTTPClient, gatewayURL string) *Module {
	return &Module{
		client: NewClient(http, gatewayURL),
	}
}

func NewWithClient(client *Client) *Module {
	return &Module{
		client: client,
	}
}

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("pm_list_patches",
			mcp.WithDescription("[PATCH MANAGEMENT] List available patches from Qualys Patch Management with severity and CVE info.\n\nUSE WHEN: user asks 'available patches', 'what patches exist', 'browse patches', specifically asks about Patch Management module\nDO NOT USE WHEN: user wants patching coverage summary (use get_patch_status), user wants patches for a specific asset (use pm_get_asset_patches)\nPREFER INSTEAD: get_patch_status for overall patching coverage analysis; pm_get_asset_patches when user asks about one asset's missing patches\n\nParameters:\n  filter: filter expression for patches\n  severity: filter by severity — Critical, Important, Moderate, Low\n  limit: max patches to return (default: 100)\n\nReturns: patch list with IDs, titles, severity, CVEs, release date, applicable OS\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter expression for patches")),
			mcp.WithString("severity", mcp.Description("Filter by severity: Critical, Important, Moderate, Low")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of patches to return (default 100)")),
		),
		m.listPatches,
	)

	s.AddTool(
		mcp.NewTool("pm_list_assets",
			mcp.WithDescription("[PATCH MANAGEMENT] List assets with patch status from Qualys Patch Management.\n\nUSE WHEN: user asks 'which assets need patches', 'patch status by asset', browsing PM asset inventory\nDO NOT USE WHEN: user wants overall patch coverage (use get_patch_status), user wants GAV asset inventory (use gav_list_assets)\nPREFER INSTEAD: get_patch_status for coverage summary; pm_get_asset_patches when user wants patches for one specific asset\n\nParameters:\n  filter: filter expression for assets\n  limit: max assets to return (default: 100)\n\nReturns: assets with patch status, missing patch counts, last patch date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("pm_list_jobs",
			mcp.WithDescription("[PATCH MANAGEMENT] List patch deployment jobs with status and progress.\n\nUSE WHEN: user asks 'what patches are deploying right now', 'patch job status', 'deployment progress', 'running patch jobs'\nDO NOT USE WHEN: user wants patching coverage analysis (use get_patch_status), user wants to browse available patches (use pm_list_patches)\nPREFER INSTEAD: get_patch_status for coverage/gaps analysis; pm_get_job_details when user wants details on a specific job\n\nParameters:\n  status: filter by job status — Running, Completed, Failed\n  limit: max jobs to return (default: 100)\n\nReturns: jobs with IDs, status, progress percentage, success/failure counts, start/end times\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("status", mcp.Description("Filter by job status (e.g., 'Running', 'Completed', 'Failed')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of jobs to return (default 100)")),
		),
		m.listJobs,
	)

	s.AddTool(
		mcp.NewTool("pm_get_job_details",
			mcp.WithDescription("[PATCH MANAGEMENT] Get detailed information about a specific patch deployment job.\n\nUSE WHEN: user asks 'details on patch job X', 'what happened in job X', has a specific job ID\nDO NOT USE WHEN: user wants to list all jobs (use pm_list_jobs), user wants overall patch status (use get_patch_status)\n\nParameters:\n  job_id: (required) the job ID to get details for\n\nReturns: job details with status, targeted assets, patches applied, success/failure per asset, timing\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("The job ID to get details for")),
		),
		m.getJobDetails,
	)

	s.AddTool(
		mcp.NewTool("pm_get_asset_patches",
			mcp.WithDescription("[PATCH MANAGEMENT] Get missing patches for a specific asset.\n\nUSE WHEN: user asks 'what patches does asset X need', 'missing patches for this host', drilling into one asset's patch status\nDO NOT USE WHEN: user wants environment-wide patch coverage (use get_patch_status), user wants to browse all patches (use pm_list_patches)\nPREFER INSTEAD: get_patch_status for environment-wide patching analysis; get_asset_risk_summary when user wants full risk view including patches\n\nParameters:\n  asset_id: (required) the asset ID to get patches for\n  limit: max patches to return (default: 100)\n\nReturns: missing patches for the asset with patch IDs, titles, severity, CVEs\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID to get patches for")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of patches to return (default 100)")),
		),
		m.getAssetPatches,
	)
}

func (m *Module) listPatches(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	severity, _ := req.Params.Arguments["severity"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	if severity != "" {
		sevFilter := fmt.Sprintf("severity:%s", severity)
		if filter != "" {
			filter = filter + " and " + sevFilter
		} else {
			filter = sevFilter
		}
	}

	patches, err := m.client.ListPatches(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list patches: %v", err)), nil
	}

	data, _ := json.MarshalIndent(patches, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listAssets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	assets, err := m.client.ListAssets(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list assets: %v", err)), nil
	}

	data, _ := json.MarshalIndent(assets, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listJobs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, _ := req.Params.Arguments["status"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	jobs, err := m.client.ListJobs(ctx, status, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list jobs: %v", err)), nil
	}

	data, _ := json.MarshalIndent(jobs, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getJobDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	jobID, ok := req.Params.Arguments["job_id"].(string)
	if !ok || jobID == "" {
		return newToolResultError("job_id is required"), nil
	}

	job, err := m.client.GetJobDetails(ctx, jobID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get job details: %v", err)), nil
	}

	data, _ := json.MarshalIndent(job, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getAssetPatches(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	assetID, ok := req.Params.Arguments["asset_id"].(string)
	if !ok || assetID == "" {
		return newToolResultError("asset_id is required"), nil
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	patches, err := m.client.GetAssetPatches(ctx, assetID, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get asset patches: %v", err)), nil
	}

	data, _ := json.MarshalIndent(patches, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
