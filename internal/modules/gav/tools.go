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
			mcp.WithDescription("[ASSET INVENTORY] List assets from Global AssetView with optional QQL filtering.\n\nUSE WHEN: user asks 'list assets', 'show me our assets', wants to browse asset inventory with filters\nDO NOT USE WHEN: user wants risk-ranked assets (use gav_get_high_risk_assets), user wants assets by tag (use gav_get_assets_by_tag), user wants VMDR host data (use vmdr_list_hosts)\nPREFER INSTEAD: gav_get_high_risk_assets for risk-focused queries; gav_search_assets when user has a specific QQL query\n\nParameters:\n  filter: QQL filter expression\n  limit: max assets to return (default: 50)\n\nReturns: asset list with IDs, hostnames, IPs, OS, TruRisk score, tags, last scan date\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("QQL filter expression")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to return (default 50)")),
		),
		m.listAssets,
	)

	s.AddTool(
		mcp.NewTool("gav_search_assets",
			mcp.WithDescription("[ASSET SEARCH] Search assets using QQL (Qualys Query Language).\n\nUSE WHEN: user has a specific search query like 'Windows servers in production', 'assets with specific software', complex QQL expressions\nDO NOT USE WHEN: user wants risk-ranked assets (use gav_get_high_risk_assets), user wants a simple asset list (use gav_list_assets)\nPREFER INSTEAD: gav_get_high_risk_assets for risk-focused queries; gav_list_assets for simple browsing\n\nParameters:\n  query: (required) QQL query (e.g., 'operatingSystem:Windows and tags.name:Production')\n  limit: max results (default: 50)\n\nReturns: matching assets with IDs, hostnames, IPs, OS, TruRisk, tags\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("query", mcp.Required(), mcp.Description("QQL query (e.g., 'operatingSystem:Windows and tags.name:Production')")),
			mcp.WithNumber("limit", mcp.Description("Maximum results (default 50)")),
		),
		m.searchAssets,
	)

	s.AddTool(
		mcp.NewTool("gav_get_asset_details",
			mcp.WithDescription("[ASSET DETAILS] Get detailed information about a specific asset including network interfaces, software inventory, and open ports.\n\nUSE WHEN: user asks 'tell me about asset X', 'asset details', wants software/hardware/network info for one asset\nDO NOT USE WHEN: user wants risk-focused analysis (use get_asset_risk_summary), user wants vulnerability detections (use vmdr_get_host_detections)\nPREFER INSTEAD: get_asset_risk_summary when user asks 'why is this asset risky'; vmdr_get_host_detections when user wants vuln findings on the asset\n\nParameters:\n  asset_id: (required) the asset ID\n\nReturns: full asset profile — hostname, IPs, OS, hardware, software inventory, open ports, network interfaces, tags, TruRisk\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("asset_id", mcp.Required(), mcp.Description("The asset ID")),
		),
		m.getAssetDetails,
	)

	s.AddTool(
		mcp.NewTool("gav_list_tags",
			mcp.WithDescription("[ASSET ORGANIZATION] List all asset tags defined in Global AssetView.\n\nUSE WHEN: user asks 'what tags exist', 'list tags', 'how are assets organized', needs tag IDs for filtering\nDO NOT USE WHEN: user wants VMDR asset groups (use vmdr_list_asset_groups), user wants assets with a specific tag (use gav_get_assets_by_tag)\n\nParameters: none\n\nReturns: tag list with IDs, names, tag types, asset counts\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
		),
		m.listTags,
	)

	s.AddTool(
		mcp.NewTool("gav_get_assets_by_tag",
			mcp.WithDescription("[ASSET GROUP] Get assets with a specific tag assigned — aggregate view for a team, environment, or tag segment.\n\nUSE WHEN: user asks about a team's assets, environment segment, 'production assets', 'assets tagged X'\nDO NOT USE WHEN: user wants risk-ranked assets across all tags (use gav_get_high_risk_assets), user wants to search by QQL (use gav_search_assets)\nPREFER INSTEAD: gav_list_tags when user needs to find the tag ID first\n\nParameters:\n  tag_id: (required) the tag ID to filter by\n  limit: max assets to return (default: 50)\n\nReturns: assets in the tag group with IDs, hostnames, IPs, OS, TruRisk\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("tag_id", mcp.Required(), mcp.Description("The tag ID to filter by")),
			mcp.WithNumber("limit", mcp.Description("Maximum assets to return (default 50)")),
		),
		m.getAssetsByTag,
	)

	s.AddTool(
		mcp.NewTool("gav_get_high_risk_assets",
			mcp.WithDescription("[ASSET RISK] Get assets with high TruRisk scores — risk-ranked view of your most vulnerable assets.\n\nUSE WHEN: user asks 'riskiest assets', 'high risk assets', 'what needs attention', 'top risk', wants risk-sorted asset list\nDO NOT USE WHEN: user wants a specific asset's full risk breakdown (use get_asset_risk_summary), user wants assets by tag (use gav_get_assets_by_tag)\nPREFER INSTEAD: get_asset_risk_summary when drilling into one specific asset's risk; gav_get_assets_by_tag when user wants assets for a specific team/environment\n\nParameters:\n  min_trurisk: minimum TruRisk score (default: 700). Use 850+ for critical only\n  min_criticality: minimum asset criticality 1-5 (5=most critical)\n  limit: max assets to return (default: 25)\n\nReturns: assets sorted by TruRisk score with IDs, hostnames, IPs, OS, TruRisk, criticality\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
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
