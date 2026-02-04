package edr

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
		mcp.NewTool("edr_list_events",
			mcp.WithDescription("List EDR events from Qualys Endpoint Detection & Response. Shows file, process, and network events."),
			mcp.WithString("type", mcp.Description("Event type filter (e.g., 'file', 'process', 'network')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.listEvents,
	)

	s.AddTool(
		mcp.NewTool("edr_list_indicators",
			mcp.WithDescription("List indicators of compromise (IOCs) from EDR."),
			mcp.WithString("severity", mcp.Description("Filter by severity (e.g., 'Critical', 'High', 'Medium', 'Low')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of indicators to return (default 100)")),
		),
		m.listIndicators,
	)

	s.AddTool(
		mcp.NewTool("edr_list_assets",
			mcp.WithDescription("List assets monitored by EDR with their detection status."),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("edr_get_asset_events",
			mcp.WithDescription("Get EDR events for a specific asset."),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID to get events for")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.getAssetEvents,
	)

	s.AddTool(
		mcp.NewTool("edr_search_events",
			mcp.WithDescription("Search EDR events using advanced hunting queries."),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query for events")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.searchEvents,
	)
}

func (m *Module) listEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	eventType, _ := req.Params.Arguments["type"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	events, err := m.client.ListEvents(ctx, eventType, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list events: %v", err)), nil
	}

	data, _ := json.MarshalIndent(events, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listIndicators(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	severity, _ := req.Params.Arguments["severity"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	indicators, err := m.client.ListIndicators(ctx, severity, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list indicators: %v", err)), nil
	}

	data, _ := json.MarshalIndent(indicators, "", "  ")
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

func (m *Module) searchEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, ok := req.Params.Arguments["query"].(string)
	if !ok || query == "" {
		return newToolResultError("query is required"), nil
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	events, err := m.client.SearchEvents(ctx, query, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to search events: %v", err)), nil
	}

	data, _ := json.MarshalIndent(events, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
