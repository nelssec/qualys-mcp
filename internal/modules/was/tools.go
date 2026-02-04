package was

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

func New(http *common.HTTPClient, baseURL string) *Module {
	return &Module{
		client: NewClient(http, baseURL),
	}
}

func NewWithClient(client *Client) *Module {
	return &Module{
		client: client,
	}
}

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("was_list_webapps",
			mcp.WithDescription("List web applications from Qualys Web Application Scanning."),
			mcp.WithString("filter", mcp.Description("Filter by web app name (contains search)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of web apps to return (default 100)")),
		),
		m.listWebApps,
	)

	s.AddTool(
		mcp.NewTool("was_list_scans",
			mcp.WithDescription("List WAS scans. Shows scan status, type, and results."),
			mcp.WithString("status", mcp.Description("Filter by scan status (e.g., 'SUBMITTED', 'RUNNING', 'FINISHED', 'ERROR')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scans to return (default 100)")),
		),
		m.listScans,
	)

	s.AddTool(
		mcp.NewTool("was_list_findings",
			mcp.WithDescription("List vulnerability findings from WAS scans. Use output_mode to control response size: 'stats' for counts only (~500 tokens), 'summary' for stats + top findings (~2k tokens), 'full' for all data."),
			mcp.WithNumber("severity", mcp.Description("Minimum severity filter (1-5, where 5 is critical)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of findings to return (default 100)")),
			mcp.WithString("output_mode", mcp.Description("Output mode: 'stats' (counts only), 'summary' (stats + top 20 findings), 'full' (all data, default)")),
		),
		m.listFindings,
	)

	s.AddTool(
		mcp.NewTool("was_get_webapp_findings",
			mcp.WithDescription("Get vulnerability findings for a specific web application."),
			mcp.WithString("webapp_id", mcp.Required(), mcp.Description("The web application ID")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of findings to return (default 100)")),
		),
		m.getWebAppFindings,
	)

	s.AddTool(
		mcp.NewTool("was_list_reports",
			mcp.WithDescription("List WAS reports. Shows generated scan reports."),
			mcp.WithNumber("limit", mcp.Description("Maximum number of reports to return (default 100)")),
		),
		m.listReports,
	)
}

func (m *Module) listWebApps(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	webapps, err := m.client.ListWebApps(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list web apps: %v", err)), nil
	}

	data, _ := json.MarshalIndent(webapps, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listScans(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, _ := req.Params.Arguments["status"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	scans, err := m.client.ListScans(ctx, status, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list scans: %v", err)), nil
	}

	data, _ := json.MarshalIndent(scans, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	severity := 0
	if s, ok := req.Params.Arguments["severity"].(float64); ok {
		severity = int(s)
	}
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}
	outputMode, _ := req.Params.Arguments["output_mode"].(string)

	findings, err := m.client.ListFindings(ctx, severity, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list findings: %v", err)), nil
	}

	var data []byte
	switch outputMode {
	case "stats":
		stats := m.client.GetFindingStats(ctx, findings)
		data, _ = json.MarshalIndent(stats, "", "  ")
	case "summary":
		summary := m.client.GetFindingSummary(ctx, findings, 20)
		data, _ = json.MarshalIndent(summary, "", "  ")
	default:
		data, _ = json.MarshalIndent(findings, "", "  ")
	}

	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getWebAppFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	webAppID, ok := req.Params.Arguments["webapp_id"].(string)
	if !ok || webAppID == "" {
		return newToolResultError("webapp_id is required"), nil
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	findings, err := m.client.GetWebAppFindings(ctx, webAppID, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get web app findings: %v", err)), nil
	}

	data, _ := json.MarshalIndent(findings, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listReports(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	reports, err := m.client.ListReports(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list reports: %v", err)), nil
	}

	data, _ := json.MarshalIndent(reports, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
