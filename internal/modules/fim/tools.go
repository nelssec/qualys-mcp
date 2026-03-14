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
			mcp.WithDescription("[FIM EVENTS] List file integrity monitoring events — file changes, creations, deletions, and modifications.\n\nUSE WHEN: user asks 'file changes', 'FIM events', 'what files changed', 'integrity monitoring events'\nDO NOT USE WHEN: user wants FIM events for a specific asset (use fim_get_asset_events), user wants FIM incidents (use fim_list_incidents)\nPREFER INSTEAD: fim_get_asset_events when user asks about one asset; fim_list_incidents for security-relevant grouped events\n\nParameters:\n  action: filter by action type — Create, Modify, Delete, Rename\n  limit: max events to return (default: 100)\n\nReturns: FIM events with file path, action type, timestamp, asset, user, old/new hash\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("action", mcp.Description("Filter by action type (e.g., 'Create', 'Modify', 'Delete', 'Rename')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.listEvents,
	)

	s.AddTool(
		mcp.NewTool("fim_list_profiles",
			mcp.WithDescription("[FIM CONFIG] List FIM monitoring profiles — configured file monitoring rules and policies.\n\nUSE WHEN: user asks 'FIM profiles', 'monitoring rules', 'what files are monitored', 'FIM configuration'\nDO NOT USE WHEN: user wants FIM events (use fim_list_events), user wants FIM assets (use fim_list_assets)\n\nParameters:\n  limit: max profiles to return (default: 100)\n\nReturns: profiles with IDs, names, monitored paths, rules, assigned assets\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
			mcp.WithNumber("limit", mcp.Description("Maximum number of profiles to return (default 100)")),
		),
		m.listProfiles,
	)

	s.AddTool(
		mcp.NewTool("fim_list_assets",
			mcp.WithDescription("[FIM ASSETS] List assets monitored by FIM with their event counts.\n\nUSE WHEN: user asks 'FIM-monitored assets', 'which assets have FIM', 'FIM coverage'\nDO NOT USE WHEN: user wants GAV asset inventory (use gav_list_assets), user wants FIM events for one asset (use fim_get_asset_events)\n\nParameters:\n  filter: filter expression for assets\n  limit: max assets to return (default: 100)\n\nReturns: FIM assets with IDs, hostnames, event counts, last event time\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("fim_list_incidents",
			mcp.WithDescription("[FIM INCIDENTS] List FIM security incidents — grouped file change events that may indicate security issues.\n\nUSE WHEN: user asks 'FIM incidents', 'file integrity incidents', 'suspicious file changes', 'FIM alerts'\nDO NOT USE WHEN: user wants raw FIM events (use fim_list_events), user wants EDR incidents (use edr_list_indicators)\n\nParameters:\n  status: filter by incident status — Open, Closed, InProgress\n  limit: max incidents to return (default: 100)\n\nReturns: incidents with IDs, status, severity, affected files, asset, timeline\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("status", mcp.Description("Filter by incident status (e.g., 'Open', 'Closed', 'InProgress')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of incidents to return (default 100)")),
		),
		m.listIncidents,
	)

	s.AddTool(
		mcp.NewTool("fim_get_asset_events",
			mcp.WithDescription("[FIM ASSET EVENTS] Get FIM events for a specific asset.\n\nUSE WHEN: user asks 'file changes on asset X', 'FIM events for this host', drilling into one asset's file changes\nDO NOT USE WHEN: user wants events across all assets (use fim_list_events)\n\nParameters:\n  asset_id: (required) the asset ID to get events for\n  limit: max events to return (default: 100)\n\nReturns: FIM events for the asset with file path, action, timestamp, user, hash changes\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
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
