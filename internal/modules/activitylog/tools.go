package activitylog

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
		mcp.NewTool("get_activity_log",
			mcp.WithDescription("Get the Qualys activity log for audit trail and compliance. Shows who ran scans, changed policies, acknowledged exceptions, and modified configuration. Useful for change management, compliance audits, and detecting config drift."),
			mcp.WithNumber("days", mcp.Description("Number of days to look back (default: 7)")),
			mcp.WithString("user", mcp.Description("Filter by username/login")),
			mcp.WithString("action", mcp.Description("Filter by action type (e.g., 'scan', 'policy', 'user')")),
		),
		m.getActivityLog,
	)

	s.AddTool(
		mcp.NewTool("get_notable_changes",
			mcp.WithDescription("Get notable changes since yesterday for morning report. Categorizes recent activity into: config drift (new scanners, option profile changes), policy changes, scan launches/completions, user additions/removals, and exception acknowledgements. Use for daily briefings and change management."),
			mcp.WithNumber("hours", mcp.Description("Number of hours to look back (default: 24)")),
		),
		m.getNotableChanges,
	)
}

func (m *Module) getActivityLog(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	days := 7
	if d, ok := req.Params.Arguments["days"].(float64); ok && d > 0 {
		days = int(d)
	}

	user, _ := req.Params.Arguments["user"].(string)
	action, _ := req.Params.Arguments["action"].(string)

	result, err := m.client.GetActivityLog(ctx, days, user, action)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get activity log: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getNotableChanges(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	hours := 24
	if h, ok := req.Params.Arguments["hours"].(float64); ok && h > 0 {
		hours = int(h)
	}

	result, err := m.client.GetNotableChanges(ctx, hours)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get notable changes: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
