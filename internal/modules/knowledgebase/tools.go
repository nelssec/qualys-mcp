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
			mcp.WithDescription("[KB LOOKUP] Get detailed information about a specific Qualys ID (QID) from the KnowledgeBase.\n\nUSE WHEN: user asks about a specific QID number, wants vuln details for a known QID, needs CVSS score or remediation steps for a QID\nDO NOT USE WHEN: user asks about a CVE (use kb_get_cve_mapping to find QIDs first), user wants to search by keyword (use kb_search_vulns)\nPREFER INSTEAD: kb_search_vulns when user has a keyword or CVE rather than a QID number; kb_get_cve_mapping when user has a CVE and wants to find matching QIDs\n\nParameters:\n  qid: (required) the Qualys ID number\n\nReturns: vulnerability details including CVEs, CVSS scores, severity, solutions, and remediation guidance\n\nPerformance: ~1s cold / ~0.1s warm (single KB lookup, cached)"),
			mcp.WithNumber("qid", mcp.Required(), mcp.Description("The Qualys ID (QID) number")),
		),
		m.getQID,
	)

	s.AddTool(
		mcp.NewTool("kb_search_vulns",
			mcp.WithDescription("[KB SEARCH] Search the Qualys KnowledgeBase for published vulnerabilities by keyword or CVE — no asset search, fast.\n\nUSE WHEN: user wants vulnerability metadata, asks about vuln details, searches for newly published CVEs, wants CVE info for 1-20 CVEs without needing asset lists\nDO NOT USE WHEN: user wants to know which assets are affected (use investigate_cve for single CVE or vmdr_search_detections for detections in your environment)\nPREFER INSTEAD: investigate_cve when user asks 'are we affected by CVE-X' (needs asset search); vmdr_search_detections when user wants confirmed detections on their hosts\n\nParameters:\n  keyword: (required) search term — vulnerability title keyword or CVE ID (e.g., 'Log4j' or 'CVE-2021-44228')\n  limit: max results (default: 50)\n\nReturns: matching KB entries with QID, title, CVEs, severity, CVSS, published date\n\nPerformance: ~2s cold / ~0.1s warm (KB search, cached)"),
			mcp.WithString("keyword", mcp.Required(), mcp.Description("Search term: vulnerability title keyword or CVE ID (e.g., 'Log4j' or 'CVE-2021-44228')")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results (default 50)")),
		),
		m.searchVulns,
	)

	s.AddTool(
		mcp.NewTool("kb_get_cve_mapping",
			mcp.WithDescription("[KB MAPPING] Map a CVE to its corresponding Qualys IDs (QIDs) — fast metadata lookup, no asset search.\n\nUSE WHEN: user wants to know which QIDs detect a specific CVE, needs CVE-to-QID mapping for scan configuration\nDO NOT USE WHEN: user wants to know if their environment is affected (use investigate_cve), user wants full CVE details (use kb_search_vulns)\nPREFER INSTEAD: investigate_cve when user asks 'are we affected by CVE-X'; kb_search_vulns when user wants full vulnerability details beyond just QID mapping\n\nParameters:\n  cve: (required) CVE ID (e.g., 'CVE-2021-44228')\n\nReturns: list of QIDs that detect this CVE with severity and title\n\nPerformance: ~1s cold / ~0.1s warm (KB lookup, cached)"),
			mcp.WithString("cve", mcp.Required(), mcp.Description("The CVE ID (e.g., 'CVE-2021-44228')")),
		),
		m.getCVEMapping,
	)

	s.AddTool(
		mcp.NewTool("kb_list_recent_vulns",
			mcp.WithDescription("[KB RECENT] List recently added or modified vulnerabilities in the Qualys KnowledgeBase.\n\nUSE WHEN: user asks 'what new vulns were published', 'recent vulnerabilities', 'new CVEs this week'\nDO NOT USE WHEN: user wants detections in their environment (use vmdr_get_detection_summary), user wants to search for a specific vuln (use kb_search_vulns)\nPREFER INSTEAD: vmdr_get_detection_summary when user wants recent detections on their assets, not published KB entries\n\nParameters:\n  days: number of days to look back (default: 7)\n  limit: max results (default: 50)\n\nReturns: recently published/modified KB entries with QID, title, CVEs, severity, published date\n\nPerformance: ~2s cold / ~0.1s warm (KB search, cached)"),
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
