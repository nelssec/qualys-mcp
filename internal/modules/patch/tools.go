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
			mcp.WithDescription("List available patches from Qualys Patch Management. Shows patches with severity and CVE information."),
			mcp.WithString("filter", mcp.Description("Filter expression for patches")),
			mcp.WithString("severity", mcp.Description("Filter by severity: Critical, Important, Moderate, Low")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of patches to return (default 100)")),
		),
		m.listPatches,
	)

	s.AddTool(
		mcp.NewTool("pm_list_assets",
			mcp.WithDescription("List assets with patch status from Qualys Patch Management."),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("pm_list_jobs",
			mcp.WithDescription("List patch deployment jobs. Shows job status, progress, and results."),
			mcp.WithString("status", mcp.Description("Filter by job status (e.g., 'Running', 'Completed', 'Failed')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of jobs to return (default 100)")),
		),
		m.listJobs,
	)

	s.AddTool(
		mcp.NewTool("pm_get_job_details",
			mcp.WithDescription("Get detailed information about a specific patch deployment job."),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("The job ID to get details for")),
		),
		m.getJobDetails,
	)

	s.AddTool(
		mcp.NewTool("pm_get_asset_patches",
			mcp.WithDescription("Get missing patches for a specific asset."),
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
