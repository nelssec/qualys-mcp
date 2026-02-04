package vmdr

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
		mcp.NewTool("vmdr_list_hosts",
			mcp.WithDescription("List hosts from VMDR with vulnerability counts. Use to get an overview of hosts and their security posture."),
			mcp.WithString("filter", mcp.Description("Optional filter by host ID or IP range")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of hosts to return (default 100)")),
		),
		m.listHosts,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_host_detections",
			mcp.WithDescription("Get vulnerability detections for a specific host. Returns detailed vulnerability information including QIDs, CVEs, severity, and QDS scores."),
			mcp.WithString("host_id", mcp.Required(), mcp.Description("The host ID to get detections for")),
			mcp.WithNumber("severity", mcp.Description("Filter by minimum severity (1-5, where 5 is critical)")),
			mcp.WithNumber("qds_min", mcp.Description("Filter by minimum QDS (Qualys Detection Score) from 1-100")),
		),
		m.getHostDetections,
	)

	s.AddTool(
		mcp.NewTool("vmdr_search_detections",
			mcp.WithDescription("Search vulnerability detections across all hosts. Auto-selects output mode based on query: QID specified=full, severity/status filter=brief, no filters=stats. Override with output_mode parameter."),
			mcp.WithString("qids", mcp.Description("QID or comma-separated list of QIDs to search for")),
			mcp.WithNumber("severity", mcp.Description("Filter by minimum severity (1-5, where 5 is critical)")),
			mcp.WithNumber("qds_min", mcp.Description("Filter by minimum QDS (Qualys Detection Score) from 1-100")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results (default 100)")),
			mcp.WithString("status", mcp.Description("Filter by detection status: Active, Fixed, New")),
			mcp.WithString("output_mode", mcp.Description("Override auto mode: 'full' (all data), 'brief' (minimal fields), 'stats' (counts only)")),
		),
		m.searchDetections,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_detection_stats",
			mcp.WithDescription("FAST: Get aggregated detection statistics. Returns counts by severity, top QIDs, and QDS metrics. Use this first for overview queries. Always filter by severity:5 for critical-only."),
			mcp.WithString("qids", mcp.Description("QID or comma-separated list of QIDs to filter")),
			mcp.WithNumber("severity", mcp.Description("Filter by minimum severity (1-5, where 5 is critical). Recommended: 5")),
			mcp.WithNumber("qds_min", mcp.Description("Filter by minimum QDS from 1-100")),
			mcp.WithString("status", mcp.Description("Filter by detection status: Active, Fixed, New")),
			mcp.WithNumber("limit", mcp.Description("Maximum detections to analyze (default 200)")),
		),
		m.getDetectionStats,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_detection_summary",
			mcp.WithDescription("RECOMMENDED: Get summarized view with stats, top 10 risk hosts, and top 20 findings. Faster than full search. Always filter by severity:5 for critical-only."),
			mcp.WithString("qids", mcp.Description("QID or comma-separated list of QIDs to filter")),
			mcp.WithNumber("severity", mcp.Description("Filter by minimum severity (1-5, where 5 is critical). Recommended: 5")),
			mcp.WithNumber("qds_min", mcp.Description("Filter by minimum QDS from 1-100")),
			mcp.WithString("status", mcp.Description("Filter by detection status: Active, Fixed, New")),
			mcp.WithNumber("limit", mcp.Description("Maximum detections to analyze (default 200)")),
		),
		m.getDetectionSummary,
	)

	s.AddTool(
		mcp.NewTool("vmdr_list_scans",
			mcp.WithDescription("List recent vulnerability scans. Shows scan status, launch date, and targets."),
			mcp.WithString("status", mcp.Description("Filter by scan status: Running, Paused, Canceled, Finished, Error")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scans to return")),
		),
		m.listScans,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_scan_results",
			mcp.WithDescription("Get detailed results from a specific vulnerability scan."),
			mcp.WithString("scan_ref", mcp.Required(), mcp.Description("The scan reference ID (e.g., scan/1234567890.12345)")),
		),
		m.getScanResults,
	)

	s.AddTool(
		mcp.NewTool("vmdr_list_asset_groups",
			mcp.WithDescription("List all asset groups defined in VMDR. Asset groups organize hosts for scanning and reporting."),
		),
		m.listAssetGroups,
	)
}

func (m *Module) listHosts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	hosts, err := m.client.ListHosts(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list hosts: %v", err)), nil
	}

	data, _ := json.MarshalIndent(hosts, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getHostDetections(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	hostID, ok := req.Params.Arguments["host_id"].(string)
	if !ok || hostID == "" {
		return newToolResultError("host_id is required"), nil
	}

	severity := 0
	if s, ok := req.Params.Arguments["severity"].(float64); ok {
		severity = int(s)
	}

	qdsMin := 0
	if q, ok := req.Params.Arguments["qds_min"].(float64); ok {
		qdsMin = int(q)
	}

	detections, err := m.client.GetHostDetections(ctx, hostID, severity, qdsMin)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get detections: %v", err)), nil
	}

	data, _ := json.MarshalIndent(detections, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) searchDetections(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	qids, _ := req.Params.Arguments["qids"].(string)
	status, _ := req.Params.Arguments["status"].(string)
	outputMode, _ := req.Params.Arguments["output_mode"].(string)

	severity := 0
	if s, ok := req.Params.Arguments["severity"].(float64); ok {
		severity = int(s)
	}

	qdsMin := 0
	if q, ok := req.Params.Arguments["qds_min"].(float64); ok {
		qdsMin = int(q)
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	if outputMode == "" {
		if qids != "" {
			outputMode = "full"
		} else if severity > 0 || qdsMin > 0 || status != "" {
			outputMode = "brief"
		} else {
			outputMode = "stats"
		}
	}

	if outputMode == "stats" {
		stats, err := m.client.GetDetectionStats(ctx, qids, severity, qdsMin, status, limit)
		if err != nil {
			return newToolResultError(fmt.Sprintf("Failed to get detection stats: %v", err)), nil
		}
		data, _ := json.MarshalIndent(stats, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}

	detections, err := m.client.SearchDetectionsWithStatus(ctx, qids, severity, qdsMin, limit, status)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to search detections: %v", err)), nil
	}

	if outputMode == "brief" {
		type BriefDetection struct {
			QID      int    `json:"qid"`
			Severity int    `json:"severity"`
			Status   string `json:"status"`
		}
		type BriefHost struct {
			HostID     string           `json:"hostId"`
			IP         string           `json:"ip"`
			Detections []BriefDetection `json:"detections"`
		}
		var brief []BriefHost
		for _, h := range detections {
			bh := BriefHost{
				HostID: h.Host.ID,
				IP:     h.Host.IP,
			}
			for _, d := range h.Detections {
				bh.Detections = append(bh.Detections, BriefDetection{
					QID:      d.QID,
					Severity: d.Severity,
					Status:   d.Status,
				})
			}
			brief = append(brief, bh)
		}
		data, _ := json.MarshalIndent(brief, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}

	data, _ := json.MarshalIndent(detections, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getDetectionStats(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	qids, _ := req.Params.Arguments["qids"].(string)
	status, _ := req.Params.Arguments["status"].(string)

	severity := 0
	if s, ok := req.Params.Arguments["severity"].(float64); ok {
		severity = int(s)
	}

	qdsMin := 0
	if q, ok := req.Params.Arguments["qds_min"].(float64); ok {
		qdsMin = int(q)
	}

	limit := 200
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	stats, err := m.client.GetDetectionStats(ctx, qids, severity, qdsMin, status, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get detection stats: %v", err)), nil
	}

	data, _ := json.MarshalIndent(stats, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getDetectionSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	qids, _ := req.Params.Arguments["qids"].(string)
	status, _ := req.Params.Arguments["status"].(string)

	severity := 0
	if s, ok := req.Params.Arguments["severity"].(float64); ok {
		severity = int(s)
	}

	qdsMin := 0
	if q, ok := req.Params.Arguments["qds_min"].(float64); ok {
		qdsMin = int(q)
	}

	limit := 200
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	summary, err := m.client.GetDetectionSummary(ctx, qids, severity, qdsMin, status, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get detection summary: %v", err)), nil
	}

	data, _ := json.MarshalIndent(summary, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listScans(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, _ := req.Params.Arguments["status"].(string)
	limit := 50
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

func (m *Module) getScanResults(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	scanRef, ok := req.Params.Arguments["scan_ref"].(string)
	if !ok || scanRef == "" {
		return newToolResultError("scan_ref is required"), nil
	}

	detections, err := m.client.GetScanResults(ctx, scanRef)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get scan results: %v", err)), nil
	}

	data, _ := json.MarshalIndent(detections, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listAssetGroups(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	groups, err := m.client.ListAssetGroups(ctx)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list asset groups: %v", err)), nil
	}

	data, _ := json.MarshalIndent(groups, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
