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
			mcp.WithDescription("[WAS INVENTORY] List web applications from Qualys Web Application Scanning.\n\nUSE WHEN: user asks 'web apps', 'web application inventory', 'list web applications'\nDO NOT USE WHEN: user wants web app findings (use was_list_findings or was_get_webapp_findings), user wants WAS scan status (use was_list_scans)\n\nParameters:\n  filter: filter by web app name (contains search)\n  limit: max web apps to return (default: 100)\n\nReturns: web apps with IDs, names, URLs, tags, last scan date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter by web app name (contains search)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of web apps to return (default 100)")),
		),
		m.listWebApps,
	)

	s.AddTool(
		mcp.NewTool("was_list_scans",
			mcp.WithDescription("[WAS SCANS] List WAS scans with status, type, and results.\n\nUSE WHEN: user asks 'WAS scans', 'web app scan status', 'when did web scans run'\nDO NOT USE WHEN: user wants vulnerability scans (use vmdr_list_scans), user wants compliance scans (use pc_list_scans)\n\nParameters:\n  status: filter by scan status — SUBMITTED, RUNNING, FINISHED, ERROR\n  limit: max scans to return (default: 100)\n\nReturns: WAS scans with IDs, status, type, web app reference, launch date, vuln counts\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("status", mcp.Description("Filter by scan status (e.g., 'SUBMITTED', 'RUNNING', 'FINISHED', 'ERROR')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scans to return (default 100)")),
		),
		m.listScans,
	)

	s.AddTool(
		mcp.NewTool("was_list_findings",
			mcp.WithDescription("[WAS FINDINGS] List vulnerability findings from WAS scans with configurable output modes.\n\nUSE WHEN: user asks 'web app vulnerabilities', 'WAS findings', 'web application security findings'\nDO NOT USE WHEN: user wants findings for one specific web app (use was_get_webapp_findings), user wants infrastructure vulns (use vmdr_get_detection_summary)\nPREFER INSTEAD: was_get_webapp_findings when user asks about a specific web app; prioritize_external_risk for combined infra+web external risk view\n\nParameters:\n  severity: minimum severity filter 1-5 (5=critical)\n  limit: max findings to return (default: 100)\n  output_mode: 'stats' (counts only ~500 tokens), 'summary' (stats + top 20 findings ~2k tokens), 'full' (all data, default)\n\nReturns: WAS findings with type (XSS, SQLi, etc.), severity, URL, web app, remediation\n\nPerformance: ~3s cold / ~0.3s warm (cached)"),
			mcp.WithNumber("severity", mcp.Description("Minimum severity filter (1-5, where 5 is critical)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of findings to return (default 100)")),
			mcp.WithString("output_mode", mcp.Description("Output mode: 'stats' (counts only), 'summary' (stats + top 20 findings), 'full' (all data, default)")),
		),
		m.listFindings,
	)

	s.AddTool(
		mcp.NewTool("was_get_webapp_findings",
			mcp.WithDescription("[WAS APP FINDINGS] Get vulnerability findings for a specific web application.\n\nUSE WHEN: user asks 'findings for web app X', 'vulns on this web app', drilling into one web app's security\nDO NOT USE WHEN: user wants findings across all web apps (use was_list_findings)\n\nParameters:\n  webapp_id: (required) the web application ID\n  limit: max findings to return (default: 100)\n\nReturns: findings for the web app with type, severity, URL, parameter, remediation\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("webapp_id", mcp.Required(), mcp.Description("The web application ID")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of findings to return (default 100)")),
		),
		m.getWebAppFindings,
	)

	s.AddTool(
		mcp.NewTool("was_list_reports",
			mcp.WithDescription("[WAS REPORTS] List WAS reports — generated scan reports.\n\nUSE WHEN: user asks 'WAS reports', 'web scan reports', 'generated reports'\nDO NOT USE WHEN: user wants findings data (use was_list_findings), user wants scan status (use was_list_scans)\n\nParameters:\n  limit: max reports to return (default: 100)\n\nReturns: reports with IDs, names, format, creation date, web app reference\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
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
