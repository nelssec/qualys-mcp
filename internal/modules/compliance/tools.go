package compliance

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
		mcp.NewTool("pc_list_policies",
			mcp.WithDescription("List compliance policies from Qualys Policy Compliance. Shows policy names, status, and control counts."),
			mcp.WithNumber("limit", mcp.Description("Maximum number of policies to return (default 100)")),
		),
		m.listPolicies,
	)

	s.AddTool(
		mcp.NewTool("pc_list_scans",
			mcp.WithDescription("List compliance scans. Shows scan status, launch date, and targets."),
			mcp.WithString("status", mcp.Description("Filter by scan status (e.g., 'Running', 'Finished', 'Error')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scans to return (default 100)")),
		),
		m.listScans,
	)

	s.AddTool(
		mcp.NewTool("pc_get_policy_details",
			mcp.WithDescription("Get detailed information about a specific compliance policy."),
			mcp.WithString("policy_id", mcp.Required(), mcp.Description("The policy ID to get details for")),
		),
		m.getPolicyDetails,
	)

	s.AddTool(
		mcp.NewTool("pc_list_exceptions",
			mcp.WithDescription("List compliance exceptions. Shows approved deviations from policy controls."),
			mcp.WithNumber("limit", mcp.Description("Maximum number of exceptions to return (default 100)")),
		),
		m.listExceptions,
	)
}

func (m *Module) listPolicies(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	policies, err := m.client.ListPolicies(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list policies: %v", err)), nil
	}

	data, _ := json.MarshalIndent(policies, "", "  ")
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

func (m *Module) getPolicyDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	policyID, ok := req.Params.Arguments["policy_id"].(string)
	if !ok || policyID == "" {
		return newToolResultError("policy_id is required"), nil
	}

	policy, err := m.client.GetPolicyDetails(ctx, policyID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get policy details: %v", err)), nil
	}

	data, _ := json.MarshalIndent(policy, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listExceptions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	exceptions, err := m.client.ListExceptions(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list exceptions: %v", err)), nil
	}

	data, _ := json.MarshalIndent(exceptions, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
