package remediation

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
		mcp.NewTool("get_remediation_tickets",
			mcp.WithDescription("List remediation tickets with filtering. Shows ticket status, assignee, QID, severity, and due dates. Use to track remediation progress and find overdue items."),
			mcp.WithString("status", mcp.Description("Filter by ticket status: OPEN, CLOSED, RESOLVED, FIXED")),
			mcp.WithString("assignee", mcp.Description("Filter by assignee username")),
			mcp.WithBoolean("overdue", mcp.Description("If true, return only overdue tickets (past due date and not resolved)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of tickets to return (default 100)")),
		),
		m.getRemediationTickets,
	)

	s.AddTool(
		mcp.NewTool("create_remediation_ticket",
			mcp.WithDescription("Create a new remediation ticket for a vulnerability on an asset. Links a QID to an asset with an optional assignee."),
			mcp.WithString("qid", mcp.Required(), mcp.Description("The QID (vulnerability ID) to create a ticket for")),
			mcp.WithString("asset_id", mcp.Description("The asset ID to associate with the ticket")),
			mcp.WithString("assignee", mcp.Description("Username to assign the ticket to")),
		),
		m.createRemediationTicket,
	)

	s.AddTool(
		mcp.NewTool("get_sla_status",
			mcp.WithDescription("Get SLA compliance summary with MTTR metrics. Shows open/closed/overdue ticket counts, compliance rate, mean time to remediate by severity, and overdue ticket details."),
			mcp.WithNumber("limit", mcp.Description("Maximum tickets to analyze for SLA metrics (default 500)")),
		),
		m.getSLAStatus,
	)
}

func (m *Module) getRemediationTickets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, _ := req.Params.Arguments["status"].(string)
	assignee, _ := req.Params.Arguments["assignee"].(string)

	overdue := false
	if o, ok := req.Params.Arguments["overdue"].(bool); ok {
		overdue = o
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	tickets, err := m.client.ListTickets(ctx, status, assignee, overdue, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list remediation tickets: %v", err)), nil
	}

	data, _ := json.MarshalIndent(tickets, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) createRemediationTicket(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	qid, ok := req.Params.Arguments["qid"].(string)
	if !ok || qid == "" {
		return newToolResultError("qid is required"), nil
	}

	assetID, _ := req.Params.Arguments["asset_id"].(string)
	assignee, _ := req.Params.Arguments["assignee"].(string)

	result, err := m.client.CreateTicket(ctx, qid, assetID, assignee)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to create remediation ticket: %v", err)), nil
	}

	response := map[string]string{
		"status":  "created",
		"message": result,
		"qid":     qid,
	}
	if assetID != "" {
		response["assetId"] = assetID
	}
	if assignee != "" {
		response["assignee"] = assignee
	}

	data, _ := json.MarshalIndent(response, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getSLAStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 500
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	sla, err := m.client.GetSLAStatus(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get SLA status: %v", err)), nil
	}

	data, _ := json.MarshalIndent(sla, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
