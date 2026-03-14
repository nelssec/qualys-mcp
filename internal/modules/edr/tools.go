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
			mcp.WithDescription("[EDR EVENTS] List EDR events from Qualys Endpoint Detection & Response.\n\nUSE WHEN: user asks 'EDR events', 'endpoint events', 'file/process/network events', wants to browse recent endpoint activity\nDO NOT USE WHEN: user wants IOCs (use edr_list_indicators), user wants events for a specific asset (use edr_get_asset_events)\nPREFER INSTEAD: edr_get_asset_events when user asks about one specific asset; edr_search_events when user has a specific query\n\nParameters:\n  type: event type filter — 'file', 'process', 'network'\n  limit: max events to return (default: 100)\n\nReturns: EDR events with type, timestamp, asset, process name, file path, network details\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("type", mcp.Description("Event type filter (e.g., 'file', 'process', 'network')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.listEvents,
	)

	s.AddTool(
		mcp.NewTool("edr_list_indicators",
			mcp.WithDescription("[EDR THREAT] List indicators of compromise (IOCs) from EDR.\n\nUSE WHEN: user asks 'IOCs', 'indicators of compromise', 'threat indicators', 'suspicious activity'\nDO NOT USE WHEN: user wants raw events (use edr_list_events), user wants vulnerability detections (use vmdr_get_detection_summary)\nPREFER INSTEAD: edr_list_events when user wants to browse raw endpoint events; tc_list_cdr_findings when user wants cloud-based threat detections\n\nParameters:\n  severity: filter by severity — Critical, High, Medium, Low\n  limit: max indicators to return (default: 100)\n\nReturns: IOCs with severity, type, description, affected assets, detection time\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("severity", mcp.Description("Filter by severity (e.g., 'Critical', 'High', 'Medium', 'Low')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of indicators to return (default 100)")),
		),
		m.listIndicators,
	)

	s.AddTool(
		mcp.NewTool("edr_list_assets",
			mcp.WithDescription("[EDR ASSETS] List assets monitored by EDR with their detection status.\n\nUSE WHEN: user asks 'EDR-monitored assets', 'which endpoints have EDR', 'EDR coverage'\nDO NOT USE WHEN: user wants GAV asset inventory (use gav_list_assets), user wants VMDR hosts (use vmdr_list_hosts)\nPREFER INSTEAD: gav_list_assets for general asset inventory; edr_get_asset_events when user wants events for a specific EDR asset\n\nParameters:\n  filter: filter expression for assets\n  limit: max assets to return (default: 100)\n\nReturns: EDR assets with IDs, hostnames, detection status, agent version, last seen\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("edr_get_asset_events",
			mcp.WithDescription("[EDR ASSET EVENTS] Get EDR events for a specific asset.\n\nUSE WHEN: user asks 'what happened on asset X', 'endpoint activity for this host', drilling into one asset's EDR events\nDO NOT USE WHEN: user wants events across all assets (use edr_list_events), user wants IOCs (use edr_list_indicators)\n\nParameters:\n  asset_id: (required) the asset ID to get events for\n  limit: max events to return (default: 100)\n\nReturns: EDR events for the asset with type, timestamp, process, file, network details\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID to get events for")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of events to return (default 100)")),
		),
		m.getAssetEvents,
	)

	s.AddTool(
		mcp.NewTool("edr_search_events",
			mcp.WithDescription("[EDR HUNT] Search EDR events using advanced hunting queries.\n\nUSE WHEN: user asks to 'hunt for', 'search EDR', 'find process X', 'look for lateral movement', advanced threat hunting\nDO NOT USE WHEN: user wants to browse events (use edr_list_events), user wants IOC summary (use edr_list_indicators)\nPREFER INSTEAD: edr_list_events for simple event browsing; edr_list_indicators for IOC-focused view\n\nParameters:\n  query: (required) search query for events\n  limit: max events to return (default: 100)\n\nReturns: matching EDR events with full details\n\nPerformance: ~3s cold / ~0.3s warm"),
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
