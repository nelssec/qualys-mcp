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
			mcp.WithDescription("[COMPLIANCE POLICIES] List compliance policies from Qualys Policy Compliance with names, status, and control counts.\n\nUSE WHEN: user asks 'compliance policies', 'list policies', 'what policies do we have'\nDO NOT USE WHEN: user wants compliance gaps/failures (use get_compliance_gaps), user wants cloud compliance (use get_cloud_risk_summary)\nPREFER INSTEAD: get_compliance_gaps when user asks about failing controls or audit readiness; pc_get_policy_details when user wants details on one policy\n\nParameters:\n  limit: max policies to return (default: 100)\n\nReturns: policies with IDs, names, status, control count, last evaluation date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithNumber("limit", mcp.Description("Maximum number of policies to return (default 100)")),
		),
		m.listPolicies,
	)

	s.AddTool(
		mcp.NewTool("pc_list_scans",
			mcp.WithDescription("[COMPLIANCE SCANS] List compliance scans with status, launch date, and targets.\n\nUSE WHEN: user asks 'compliance scans', 'PC scan status', 'when did compliance scans run'\nDO NOT USE WHEN: user wants vulnerability scans (use vmdr_list_scans), user wants WAS scans (use was_list_scans)\n\nParameters:\n  status: filter by scan status — Running, Finished, Error\n  limit: max scans to return (default: 100)\n\nReturns: compliance scans with IDs, status, launch date, targets, policy references\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("status", mcp.Description("Filter by scan status (e.g., 'Running', 'Finished', 'Error')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scans to return (default 100)")),
		),
		m.listScans,
	)

	s.AddTool(
		mcp.NewTool("pc_get_policy_details",
			mcp.WithDescription("[COMPLIANCE POLICY DETAIL] Get detailed information about a specific compliance policy.\n\nUSE WHEN: user asks 'details on policy X', 'what controls does policy X check', drilling into one policy\nDO NOT USE WHEN: user wants to list all policies (use pc_list_policies), user wants compliance gaps across all policies (use get_compliance_gaps)\n\nParameters:\n  policy_id: (required) the policy ID to get details for\n\nReturns: policy details with controls, control descriptions, expected values, severity\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("policy_id", mcp.Required(), mcp.Description("The policy ID to get details for")),
		),
		m.getPolicyDetails,
	)

	s.AddTool(
		mcp.NewTool("pc_list_exceptions",
			mcp.WithDescription("[COMPLIANCE EXCEPTIONS] List compliance exceptions — approved deviations from policy controls.\n\nUSE WHEN: user asks 'compliance exceptions', 'approved deviations', 'exception list', 'waivers'\nDO NOT USE WHEN: user wants failing controls (use get_compliance_gaps), user wants policy details (use pc_get_policy_details)\n\nParameters:\n  limit: max exceptions to return (default: 100)\n\nReturns: exceptions with control reference, asset, reason, approval status, expiry date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
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
