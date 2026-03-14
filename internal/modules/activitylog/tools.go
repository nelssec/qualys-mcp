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
			mcp.WithDescription("[AUDIT TRAIL] Get the Qualys activity log for audit trail and compliance — who did what and when.\n\nUSE WHEN: user asks 'activity log', 'audit trail', 'who ran scans', 'who changed config', 'change management log'\nDO NOT USE WHEN: user wants overnight changes summary (use get_notable_changes), user wants vulnerability data (use vmdr_get_detection_summary)\nPREFER INSTEAD: get_notable_changes when user asks 'what happened overnight' or 'morning report'\n\nParameters:\n  days: number of days to look back (default: 7)\n  user: filter by username/login\n  action: filter by action type — 'scan', 'policy', 'user'\n\nReturns: activity log entries with timestamp, user, action, module, details\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithNumber("days", mcp.Description("Number of days to look back (default: 7)")),
			mcp.WithString("user", mcp.Description("Filter by username/login")),
			mcp.WithString("action", mcp.Description("Filter by action type (e.g., 'scan', 'policy', 'user')")),
		),
		m.getActivityLog,
	)

	s.AddTool(
		mcp.NewTool("get_notable_changes",
			mcp.WithDescription("[MORNING REPORT] Get notable changes since yesterday — categorized daily briefing of recent activity.\n\nUSE WHEN: user asks 'what happened overnight', 'morning report', 'daily briefing', 'notable changes', 'what changed today'\nDO NOT USE WHEN: user wants full audit log (use get_activity_log), user wants weekly priorities (use get_weekly_priorities)\nPREFER INSTEAD: get_activity_log when user wants raw log with filters; get_weekly_priorities when user wants action items not change summary\n\nParameters:\n  hours: hours to look back (default: 24)\n\nReturns: categorized changes — config drift (scanners, profiles), policy changes, scan activity, user changes, exception acknowledgements\n\nPerformance: ~3s cold / ~0.3s warm"),
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
