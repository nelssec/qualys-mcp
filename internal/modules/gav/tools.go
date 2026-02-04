package gav

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

func New(gatewayHTTP *common.HTTPClient, gatewayURL string, classicHTTP *common.HTTPClient, classicURL string) *Module {
	return &Module{
		client: NewClient(gatewayHTTP, gatewayURL, classicHTTP, classicURL),
	}
}

func NewWithClient(client *Client) *Module {
	return &Module{
		client: client,
	}
}

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("gav_list_assets",
			mcp.WithDescription("List assets from Global AssetView. For risk-focused queries, use gav_get_high_risk_assets instead."),
			mcp.WithString("filter", mcp.Description("QQL filter expression")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to return (default 50)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("gav_search_assets",
			mcp.WithDescription("Search assets using QQL. For risk-focused queries, use gav_get_high_risk_assets instead."),
			mcp.WithString("query", mcp.Required(), mcp.Description("QQL query (e.g., 'operatingSystem:Windows and tags.name:Production')")),
			mcp.WithNumber("limit", mcp.Description("Maximum results (default 50)")),
		),
		m.searchAssets,
	)

	s.AddTool(
		mcp.NewTool("gav_get_asset_details",
			mcp.WithDescription("Get detailed information about a specific asset including network interfaces, software inventory, and open ports."),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID")),
		),
		m.getAssetDetails,
	)

	s.AddTool(
		mcp.NewTool("gav_list_tags",
			mcp.WithDescription("List all asset tags defined in Global AssetView. Tags are used to organize and categorize assets."),
		),
		m.listTags,
	)

	s.AddTool(
		mcp.NewTool("gav_get_assets_by_tag",
			mcp.WithDescription("Get assets with a specific tag assigned."),
			mcp.WithString("tag_id", mcp.Required(), mcp.Description("The tag ID to filter by")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to return (default 50)")),
		),
		m.getAssetsByTag,
	)

	s.AddTool(
		mcp.NewTool("gav_get_high_risk_assets",
			mcp.WithDescription("RECOMMENDED for risk queries. Get assets with high TruRisk scores. Returns focused list of truly high-risk assets. Default: TruRisk 700+, limit 25."),
			mcp.WithNumber("min_trurisk", mcp.Description("Minimum TruRisk score (default 700). Use 850+ for critical only.")),
			mcp.WithNumber("min_criticality", mcp.Description("Minimum asset criticality (1-5, where 5 is most critical)")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to return (default 25)")),
		),
		m.getHighRiskAssets,
	)
}

func (m *Module) listAssets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 50
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

func (m *Module) searchAssets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, ok := req.Params.Arguments["query"].(string)
	if !ok || query == "" {
		return newToolResultError("query is required"), nil
	}

	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	assets, err := m.client.SearchAssets(ctx, query, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to search assets: %v", err)), nil
	}

	data, _ := json.MarshalIndent(assets, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getAssetDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	assetID, ok := req.Params.Arguments["asset_id"].(string)
	if !ok || assetID == "" {
		return newToolResultError("asset_id is required"), nil
	}

	asset, err := m.client.GetAssetDetails(ctx, assetID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get asset details: %v", err)), nil
	}

	data, _ := json.MarshalIndent(asset, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listTags(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tags, err := m.client.ListTags(ctx)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list tags: %v", err)), nil
	}

	data, _ := json.MarshalIndent(tags, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getAssetsByTag(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tagID, ok := req.Params.Arguments["tag_id"].(string)
	if !ok || tagID == "" {
		return newToolResultError("tag_id is required"), nil
	}

	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	assets, err := m.client.GetAssetsByTag(ctx, tagID, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get assets by tag: %v", err)), nil
	}

	data, _ := json.MarshalIndent(assets, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getHighRiskAssets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	minTruRisk := 700
	if t, ok := req.Params.Arguments["min_trurisk"].(float64); ok {
		minTruRisk = int(t)
	}

	minCriticality := 0
	if c, ok := req.Params.Arguments["min_criticality"].(float64); ok {
		minCriticality = int(c)
	}

	limit := 25
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	assets, err := m.client.GetHighRiskAssets(ctx, minTruRisk, minCriticality, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get high risk assets: %v", err)), nil
	}

	data, _ := json.MarshalIndent(assets, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
