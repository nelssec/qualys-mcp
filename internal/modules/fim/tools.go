package fim

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
		mcp.NewTool("fim_list_events",
			mcp.WithDescription("List file integrity monitoring events. Shows file changes, creations, deletions, and modifications."),
			mcp.WithString("action", mcp.Description("Filter by action type (e.g., 'Create', 'Modify', 'Delete', 'Rename')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.listEvents,
	)

	s.AddTool(
		mcp.NewTool("fim_list_profiles",
			mcp.WithDescription("List FIM monitoring profiles. Shows configured file monitoring rules and policies."),
			mcp.WithNumber("limit", mcp.Description("Maximum number of profiles to return (default 100)")),
		),
		m.listProfiles,
	)

	s.AddTool(
		mcp.NewTool("fim_list_assets",
			mcp.WithDescription("List assets monitored by FIM with their event counts."),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("fim_list_incidents",
			mcp.WithDescription("List FIM security incidents. Shows grouped file change events that may indicate security issues."),
			mcp.WithString("status", mcp.Description("Filter by incident status (e.g., 'Open', 'Closed', 'InProgress')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of incidents to return (default 100)")),
		),
		m.listIncidents,
	)

	s.AddTool(
		mcp.NewTool("fim_get_asset_events",
			mcp.WithDescription("Get FIM events for a specific asset."),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID to get events for")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.getAssetEvents,
	)
}

func (m *Module) listEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	action, _ := req.Params.Arguments["action"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	events, err := m.client.ListEvents(ctx, action, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list events: %v", err)), nil
	}

	data, _ := json.MarshalIndent(events, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listProfiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	profiles, err := m.client.ListProfiles(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list profiles: %v", err)), nil
	}

	data, _ := json.MarshalIndent(profiles, "", "  ")
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

func (m *Module) listIncidents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, _ := req.Params.Arguments["status"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	incidents, err := m.client.ListIncidents(ctx, status, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list incidents: %v", err)), nil
	}

	data, _ := json.MarshalIndent(incidents, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getAssetEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	assetID, ok := req.Params.Arguments["asset_id"].(string)
	if !ok || assetID == "" {
		return newToolResultError("asset_id is required"), nil
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	events, err := m.client.GetAssetEvents(ctx, assetID, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get asset events: %v", err)), nil
	}

	data, _ := json.MarshalIndent(events, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
