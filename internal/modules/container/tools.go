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

func NewWithClient(client *Client) *Module {
	return &Module{
		client: client,
	}
}

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("cs_list_images",
			mcp.WithDescription("[CONTAINER IMAGES] List container images from Qualys Container Security with metadata and vuln counts.\n\nUSE WHEN: user asks 'container images', 'list images', 'image inventory'\nDO NOT USE WHEN: user wants vulnerable containers specifically (use cs_list_vulnerable_containers), user wants image vulns (use cs_get_image_vulnerabilities)\nPREFER INSTEAD: cs_list_vulnerable_containers for risk-focused container queries; cs_search_images when user has a QQL query\n\nParameters:\n  filter: QQL filter expression (e.g., 'repo:nginx')\n  limit: max images to return (default: 100)\n\nReturns: images with SHA256 IDs, repo, tag, size, vuln counts by severity, created date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("QQL filter expression (e.g., 'repo:nginx')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of images to return (default 100)")),
		),
		m.listImages,
	)

	s.AddTool(
		mcp.NewTool("cs_get_image_vulnerabilities",
			mcp.WithDescription("[CONTAINER VULNS] Get vulnerabilities for a specific container image.\n\nUSE WHEN: user asks 'vulns in image X', 'image vulnerabilities', drilling into one image's security findings\nDO NOT USE WHEN: user wants to find vulnerable containers across the environment (use cs_list_vulnerable_containers)\nPREFER INSTEAD: cs_list_vulnerable_containers when user wants to find the most vulnerable containers environment-wide\n\nParameters:\n  image_id: (required) the SHA256 image ID\n  output_mode: 'summary' (stats + top 15 vulns ~1k tokens), 'full' (all data, default)\n\nReturns: vulnerabilities with QID, CVE, severity, CVSS, package name, fixed version\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("image_id", mcp.Required(), mcp.Description("The SHA256 image ID")),
			mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (stats + top 15 vulns), 'full' (all data, default)")),
		),
		m.getImageVulnerabilities,
	)

	s.AddTool(
		mcp.NewTool("cs_list_containers",
			mcp.WithDescription("[CONTAINER INVENTORY] List running containers from Qualys Container Security.\n\nUSE WHEN: user asks 'running containers', 'container inventory', 'list containers'\nDO NOT USE WHEN: user wants vulnerable containers (use cs_list_vulnerable_containers), user wants image details (use cs_list_images)\nPREFER INSTEAD: cs_list_vulnerable_containers for security-focused container list\n\nParameters:\n  filter: QQL filter expression (e.g., 'state:RUNNING')\n  limit: max containers to return (default: 100)\n\nReturns: containers with IDs, names, image, state, host, created date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("QQL filter expression (e.g., 'state:RUNNING')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of containers to return (default 100)")),
		),
		m.listContainers,
	)

	s.AddTool(
		mcp.NewTool("cs_search_images",
			mcp.WithDescription("[CONTAINER SEARCH] Search container images using QQL. Supports complex queries.\n\nUSE WHEN: user has a specific QQL query for images like 'critical vulns in nginx images'\nDO NOT USE WHEN: user wants a simple image list (use cs_list_images), user wants vulnerable containers (use cs_list_vulnerable_containers)\n\nParameters:\n  query: (required) QQL query (e.g., 'vulnerabilities.severity:5 and repo:nginx')\n  limit: max results (default: 100)\n\nReturns: matching images with SHA256 IDs, repo, tag, vuln counts\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("query", mcp.Required(), mcp.Description("QQL query (e.g., 'vulnerabilities.severity:5 and repo:nginx')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results (default 100)")),
		),
		m.searchImages,
	)

	s.AddTool(
		mcp.NewTool("cs_get_image_details",
			mcp.WithDescription("[CONTAINER IMAGE DETAIL] Get detailed information about a specific container image including layers and metadata.\n\nUSE WHEN: user asks 'image details', 'layers of image X', 'image metadata'\nDO NOT USE WHEN: user wants vulnerabilities (use cs_get_image_vulnerabilities), user wants to list images (use cs_list_images)\n\nParameters:\n  image_id: (required) the SHA256 image ID\n\nReturns: image details with layers, labels, entrypoint, environment vars, size, created date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("image_id", mcp.Required(), mcp.Description("The SHA256 image ID")),
		),
		m.getImageDetails,
	)

	s.AddTool(
		mcp.NewTool("cs_list_vulnerable_containers",
			mcp.WithDescription("[CONTAINER RISK] List running containers with vulnerabilities — risk-focused view. Default: severity 5 (critical only).\n\nUSE WHEN: user asks 'vulnerable containers', 'container risks', 'which containers have critical vulns', 'container security posture'\nDO NOT USE WHEN: user wants general container inventory (use cs_list_containers), user wants image-level vulns (use cs_get_image_vulnerabilities)\nPREFER INSTEAD: cs_list_containers for general inventory; cs_get_image_vulnerabilities for one image's vulns\n\nParameters:\n  severity: severity filter 1-5 (default: 5 = critical only)\n  qds: minimum QDS 1-100 (recommended: 90+)\n  qds_severity: QDS level — CRITICAL, HIGH, MEDIUM, LOW\n  trurisk: minimum TruRisk 1-1000 (recommended: 700+)\n  cve: specific CVE ID (e.g., 'CVE-2024-1234')\n  filter: custom QQL filter\n  limit: max containers (default: 25)\n\nReturns: vulnerable containers with image, vulns, severity, QDS, TruRisk, host\n\nPerformance: ~3s cold / ~0.3s warm (cached)"),
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
