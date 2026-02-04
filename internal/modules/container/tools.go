package container

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

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("cs_list_images",
			mcp.WithDescription("List container images from Qualys Container Security. Shows image metadata and vulnerability counts."),
			mcp.WithString("filter", mcp.Description("QQL filter expression (e.g., 'repo:nginx')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of images to return (default 100)")),
		),
		m.listImages,
	)

	s.AddTool(
		mcp.NewTool("cs_get_image_vulnerabilities",
			mcp.WithDescription("Get vulnerabilities for a specific container image. Use output_mode to control response size: 'summary' for stats + top vulns (~1k tokens), 'full' for all data."),
			mcp.WithString("image_id", mcp.Required(), mcp.Description("The SHA256 image ID")),
			mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (stats + top 15 vulns), 'full' (all data, default)")),
		),
		m.getImageVulnerabilities,
	)

	s.AddTool(
		mcp.NewTool("cs_list_containers",
			mcp.WithDescription("List running containers from Qualys Container Security."),
			mcp.WithString("filter", mcp.Description("QQL filter expression (e.g., 'state:RUNNING')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of containers to return (default 100)")),
		),
		m.listContainers,
	)

	s.AddTool(
		mcp.NewTool("cs_search_images",
			mcp.WithDescription("Search container images using Qualys Query Language (QQL). Supports complex queries."),
			mcp.WithString("query", mcp.Required(), mcp.Description("QQL query (e.g., 'vulnerabilities.severity:5 and repo:nginx')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results (default 100)")),
		),
		m.searchImages,
	)

	s.AddTool(
		mcp.NewTool("cs_get_image_details",
			mcp.WithDescription("Get detailed information about a specific container image including layers and metadata."),
			mcp.WithString("image_id", mcp.Required(), mcp.Description("The SHA256 image ID")),
		),
		m.getImageDetails,
	)

	s.AddTool(
		mcp.NewTool("cs_list_vulnerable_containers",
			mcp.WithDescription("RECOMMENDED for container risk. List running containers with vulnerabilities. Default severity:5 (critical). Returns focused list."),
			mcp.WithNumber("severity", mcp.Description("Severity (1-5). Default: 5 (critical only)")),
			mcp.WithNumber("qds", mcp.Description("Minimum QDS (1-100). Recommended: 90+")),
			mcp.WithString("qds_severity", mcp.Description("QDS level: CRITICAL, HIGH, MEDIUM, LOW")),
			mcp.WithNumber("trurisk", mcp.Description("Minimum TruRisk (1-1000). Recommended: 700+")),
			mcp.WithString("cve", mcp.Description("Specific CVE ID (e.g., 'CVE-2024-1234')")),
			mcp.WithString("filter", mcp.Description("Custom QQL filter")),
			mcp.WithNumber("limit", mcp.Description("Maximum containers (default 25)")),
		),
		m.listVulnerableContainers,
	)
}

func (m *Module) listImages(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	images, err := m.client.ListImages(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list images: %v", err)), nil
	}

	data, _ := json.MarshalIndent(images, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getImageVulnerabilities(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	imageID, ok := req.Params.Arguments["image_id"].(string)
	if !ok || imageID == "" {
		return newToolResultError("image_id is required"), nil
	}
	outputMode, _ := req.Params.Arguments["output_mode"].(string)

	vulns, err := m.client.GetImageVulnerabilities(ctx, imageID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get vulnerabilities: %v", err)), nil
	}

	var data []byte
	switch outputMode {
	case "summary":
		stats := GetImageVulnStats(vulns, 15)
		data, _ = json.MarshalIndent(stats, "", "  ")
	default:
		data, _ = json.MarshalIndent(vulns, "", "  ")
	}

	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listContainers(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	containers, err := m.client.ListContainers(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list containers: %v", err)), nil
	}

	data, _ := json.MarshalIndent(containers, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) searchImages(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, ok := req.Params.Arguments["query"].(string)
	if !ok || query == "" {
		return newToolResultError("query is required"), nil
	}

	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	images, err := m.client.SearchImages(ctx, query, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to search images: %v", err)), nil
	}

	data, _ := json.MarshalIndent(images, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getImageDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	imageID, ok := req.Params.Arguments["image_id"].(string)
	if !ok || imageID == "" {
		return newToolResultError("image_id is required"), nil
	}

	image, err := m.client.GetImageDetails(ctx, imageID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get image details: %v", err)), nil
	}

	data, _ := json.MarshalIndent(image, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listVulnerableContainers(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter := VulnContainerFilter{
		Severity: 5,
	}

	if severity, ok := req.Params.Arguments["severity"].(float64); ok {
		filter.Severity = int(severity)
	}
	if qds, ok := req.Params.Arguments["qds"].(float64); ok {
		filter.QDS = int(qds)
	}
	if qdsSeverity, ok := req.Params.Arguments["qds_severity"].(string); ok {
		filter.QDSSeverity = qdsSeverity
	}
	if trurisk, ok := req.Params.Arguments["trurisk"].(float64); ok {
		filter.TruRisk = int(trurisk)
	}
	if cve, ok := req.Params.Arguments["cve"].(string); ok {
		filter.CVE = cve
	}
	if customFilter, ok := req.Params.Arguments["filter"].(string); ok {
		filter.CustomQQL = customFilter
	}

	limit := 25
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	containers, err := m.client.ListVulnerableContainers(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list vulnerable containers: %v", err)), nil
	}

	data, _ := json.MarshalIndent(containers, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
