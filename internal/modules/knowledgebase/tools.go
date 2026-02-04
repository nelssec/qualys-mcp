package knowledgebase

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
		mcp.NewTool("kb_get_qid",
			mcp.WithDescription("Get detailed information about a specific Qualys ID (QID) from the KnowledgeBase. Returns vulnerability details including CVEs, CVSS scores, solutions, and remediation guidance."),
			mcp.WithNumber("qid", mcp.Required(), mcp.Description("The Qualys ID (QID) number")),
		),
		m.getQID,
	)

	s.AddTool(
		mcp.NewTool("kb_search_vulns",
			mcp.WithDescription("Search the Qualys KnowledgeBase for vulnerabilities by keyword or CVE. Returns matching vulnerability entries."),
			mcp.WithString("keyword", mcp.Required(), mcp.Description("Search term: vulnerability title keyword or CVE ID (e.g., 'Log4j' or 'CVE-2021-44228')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results (default 50)")),
		),
		m.searchVulns,
	)

	s.AddTool(
		mcp.NewTool("kb_get_cve_mapping",
			mcp.WithDescription("Map a CVE to its corresponding Qualys IDs (QIDs). Useful for finding which Qualys detections cover a specific CVE."),
			mcp.WithString("cve", mcp.Required(), mcp.Description("The CVE ID (e.g., 'CVE-2021-44228')")),
		),
		m.getCVEMapping,
	)

	s.AddTool(
		mcp.NewTool("kb_list_recent_vulns",
			mcp.WithDescription("List recently added or modified vulnerabilities in the Qualys KnowledgeBase."),
			mcp.WithNumber("days", mcp.Description("Number of days to look back (default 7)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results (default 50)")),
		),
		m.listRecentVulns,
	)
}

func (m *Module) getQID(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	qidFloat, ok := req.Params.Arguments["qid"].(float64)
	if !ok {
		return newToolResultError("qid is required and must be a number"), nil
	}
	qid := int(qidFloat)

	info, err := m.client.GetQID(ctx, qid)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get QID: %v", err)), nil
	}

	data, _ := json.MarshalIndent(info, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) searchVulns(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	keyword, ok := req.Params.Arguments["keyword"].(string)
	if !ok || keyword == "" {
		return newToolResultError("keyword is required"), nil
	}

	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	vulns, err := m.client.SearchVulns(ctx, keyword, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to search vulnerabilities: %v", err)), nil
	}

	data, _ := json.MarshalIndent(vulns, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getCVEMapping(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cve, ok := req.Params.Arguments["cve"].(string)
	if !ok || cve == "" {
		return newToolResultError("cve is required"), nil
	}

	mapping, err := m.client.GetCVEMapping(ctx, cve)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get CVE mapping: %v", err)), nil
	}

	data, _ := json.MarshalIndent(mapping, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listRecentVulns(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	days := 7
	if d, ok := req.Params.Arguments["days"].(float64); ok {
		days = int(d)
	}

	limit := 50
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	vulns, err := m.client.ListRecentVulns(ctx, days, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list recent vulnerabilities: %v", err)), nil
	}

	data, _ := json.MarshalIndent(vulns, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
