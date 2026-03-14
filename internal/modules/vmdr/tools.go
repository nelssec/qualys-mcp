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
			mcp.WithDescription("[VMDR HOSTS] List hosts from VMDR with vulnerability counts.\n\nUSE WHEN: user asks 'list hosts', 'show me our hosts', 'host inventory from VMDR', wants to browse hosts\nDO NOT USE WHEN: user wants asset details from Global AssetView (use gav_list_assets), user wants risk-ranked assets (use gav_get_high_risk_assets)\nPREFER INSTEAD: gav_list_assets when user wants richer asset metadata (software, tags, TruRisk); gav_get_high_risk_assets when user wants risk-sorted assets\n\nParameters:\n  filter: optional filter by host ID or IP range\n  limit: max hosts to return (default: 100)\n\nReturns: host list with IDs, IPs, OS, last scan date, vuln counts by severity\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Optional filter by host ID or IP range")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of hosts to return (default 100)")),
		),
		m.listHosts,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_host_detections",
			mcp.WithDescription("[VMDR DETECTIONS] Get vulnerability detections for a specific host — confirmed findings in YOUR environment.\n\nUSE WHEN: user asks 'what vulns are on host X', 'detections for this host', drilling into one host's vulnerabilities\nDO NOT USE WHEN: user wants detections across all hosts (use vmdr_get_detection_summary or vmdr_search_detections), user wants KB info about a vuln (use kb_get_qid)\nPREFER INSTEAD: vmdr_get_detection_summary when user wants environment-wide detection overview; get_asset_risk_summary when user wants a complete risk view of one asset\n\nParameters:\n  host_id: (required) the VMDR host ID\n  severity: filter by minimum severity 1-5 (5=critical)\n  qds_min: filter by minimum QDS (Qualys Detection Score) 1-100\n\nReturns: detections with QID, CVEs, severity, QDS, status, first/last found dates\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("host_id", mcp.Required(), mcp.Description("The host ID to get detections for")),
			mcp.WithNumber("severity", mcp.Description("Filter by minimum severity (1-5, where 5 is critical)")),
			mcp.WithNumber("qds_min", mcp.Description("Filter by minimum QDS (Qualys Detection Score) from 1-100")),
		),
		m.getHostDetections,
	)

	s.AddTool(
		mcp.NewTool("vmdr_search_detections",
			mcp.WithDescription("[VMDR SEARCH] Search detections across hosts with auto-selected output mode — confirmed findings in YOUR environment.\n\nUSE WHEN: user wants to find specific QIDs across hosts, search detections by severity/status, 'which hosts have QID 12345'\nDO NOT USE WHEN: user wants an overview (use vmdr_get_detection_summary), user wants stats only (use vmdr_get_detection_stats), user wants KB info (use kb_search_vulns)\nPREFER INSTEAD: vmdr_get_detection_summary for overview queries; vmdr_get_detection_stats for stats-only; investigate_cve for CVE-based environment search\n\nParameters:\n  qids: QID or comma-separated QIDs to search\n  severity: minimum severity 1-5 (recommended: 5 for critical)\n  qds_min: minimum QDS 1-100 (recommended: 90+ for high risk)\n  limit: max results (default: 50)\n  status: filter by status — Active, Fixed, New\n  output_mode: override auto-select — 'full' (QID search), 'brief' (severity filter), 'stats' (no filters)\n\nReturns: host detections with QID, severity, CVEs, status; format varies by output_mode\n\nPerformance: ~3s cold / ~0.3s warm (cached)"),
			mcp.WithString("qids", mcp.Description("QID or comma-separated list of QIDs to search for")),
			mcp.WithNumber("severity", mcp.Description("Minimum severity (1-5). Recommended: 5 for critical only")),
			mcp.WithNumber("qds_min", mcp.Description("Minimum QDS (1-100). Recommended: 90+ for high risk")),
			mcp.WithNumber("limit", mcp.Description("Maximum results (default 50)")),
			mcp.WithString("status", mcp.Description("Filter by status: Active, Fixed, New")),
			mcp.WithString("output_mode", mcp.Description("Override: 'full', 'brief', 'stats'")),
		),
		m.searchDetections,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_detection_stats",
			mcp.WithDescription("[VMDR STATS] Get aggregated detection statistics — fastest VMDR query.\n\nUSE WHEN: user asks 'how many critical vulns', 'detection counts', 'vulnerability statistics', wants numbers not details\nDO NOT USE WHEN: user wants to see actual detections (use vmdr_search_detections), user wants top hosts + findings (use vmdr_get_detection_summary)\nPREFER INSTEAD: vmdr_get_detection_summary when user wants top hosts and findings alongside stats; vmdr_search_detections when user needs full detection details\n\nParameters:\n  qids: QID or comma-separated QIDs to filter\n  severity: minimum severity 1-5 (recommended: 5)\n  qds_min: minimum QDS 1-100\n  status: filter by status — Active, Fixed, New\n  limit: max detections to analyze (default: 200)\n\nReturns: counts by severity, top QIDs by frequency, QDS distribution metrics\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
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
			mcp.WithDescription("[VMDR SUMMARY] Get summarized detection view with stats, top 10 risk hosts, and top 20 findings — confirmed findings in YOUR environment.\n\nUSE WHEN: user asks 'what vulns exist on our assets', 'vulnerability overview', 'detection summary', 'show me our findings'\nDO NOT USE WHEN: user wants KB info about published vulns (use kb_search_vulns), user wants to search for specific QIDs (use vmdr_search_detections)\nPREFER INSTEAD: kb_search_vulns when user asks about published vulnerability details without needing asset context; vmdr_search_detections when user needs to search by specific QID/severity\n\nParameters:\n  qids: QID or comma-separated QIDs to filter\n  severity: minimum severity 1-5 (recommended: 5 for critical)\n  qds_min: minimum QDS 1-100\n  status: filter by status — Active, Fixed, New\n  limit: max detections to analyze (default: 200)\n\nReturns: detection stats, top 10 riskiest hosts, top 20 most impactful findings\n\nPerformance: ~3s cold / ~0.3s warm (cached)"),
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
			mcp.WithDescription("[VMDR SCANS] List recent vulnerability scans with status and targets.\n\nUSE WHEN: user asks 'recent scans', 'scan history', 'what scans ran', 'scan status'\nDO NOT USE WHEN: user wants compliance scans (use pc_list_scans), user wants WAS scans (use was_list_scans), user wants scan coverage gaps (use vmdr_get_scan_coverage)\nPREFER INSTEAD: vmdr_get_scan_coverage when user asks about scan gaps or assets not being scanned\n\nParameters:\n  status: filter by scan status — Running, Paused, Canceled, Finished, Error\n  limit: max scans to return\n\nReturns: scan list with reference ID, title, status, launch date, targets, duration\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("status", mcp.Description("Filter by scan status: Running, Paused, Canceled, Finished, Error")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scans to return")),
		),
		m.listScans,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_scan_results",
			mcp.WithDescription("[VMDR SCAN RESULTS] Get detailed results from a specific vulnerability scan.\n\nUSE WHEN: user asks 'results of scan X', 'what did scan X find', has a specific scan reference ID\nDO NOT USE WHEN: user wants environment-wide detections (use vmdr_get_detection_summary), user wants to find scans first (use vmdr_list_scans)\nPREFER INSTEAD: vmdr_list_scans when user needs to find a scan first; vmdr_get_detection_summary for environment-wide detection view\n\nParameters:\n  scan_ref: (required) scan reference ID (e.g., 'scan/1234567890.12345')\n\nReturns: scan findings with host IPs, QIDs, severity, detection details\n\nPerformance: ~3s cold / ~0.3s warm"),
			mcp.WithString("scan_ref", mcp.Required(), mcp.Description("The scan reference ID (e.g., scan/1234567890.12345)")),
		),
		m.getScanResults,
	)

	s.AddTool(
		mcp.NewTool("vmdr_list_asset_groups",
			mcp.WithDescription("[VMDR CONFIG] List all asset groups defined in VMDR.\n\nUSE WHEN: user asks 'asset groups', 'how are hosts organized', needs group IDs for scanning\nDO NOT USE WHEN: user wants asset tags from GAV (use gav_list_tags), user wants to browse assets (use gav_list_assets)\nPREFER INSTEAD: gav_list_tags when user wants tag-based asset organization; gav_get_assets_by_tag when user wants assets in a tag group\n\nParameters: none\n\nReturns: asset groups with IDs, names, IPs/ranges, owner\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
		),
		m.listAssetGroups,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_scan_schedules",
			mcp.WithDescription("[VMDR CONFIG] List all scheduled vulnerability scans with next run time.\n\nUSE WHEN: user asks 'scan schedules', 'when do scans run', 'scheduled scans', auditing scan scheduling\nDO NOT USE WHEN: user wants scan results (use vmdr_list_scans), user wants scan coverage gaps (use vmdr_get_scan_coverage)\n\nParameters: none\n\nReturns: schedules with title, frequency, next run time, last launch, targets\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
		),
		m.listScanSchedules,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_option_profiles",
			mcp.WithDescription("[VMDR CONFIG] List all VM scan option profiles.\n\nUSE WHEN: user asks 'option profiles', 'scan configurations', needs profile name for vmdr_launch_scan\nDO NOT USE WHEN: user wants scan results (use vmdr_list_scans), user wants compliance policies (use pc_list_policies)\n\nParameters: none\n\nReturns: option profiles with names, IDs, scan settings (ports, authentication, QID selection)\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
		),
		m.listOptionProfiles,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_ip_list",
			mcp.WithDescription("[VMDR CONFIG] List tracked IPs and IP ranges in the Qualys subscription.\n\nUSE WHEN: user asks 'tracked IPs', 'what IPs are we monitoring', 'IP inventory'\nDO NOT USE WHEN: user wants full asset details (use gav_list_assets), user wants host vulnerability data (use vmdr_list_hosts)\n\nParameters:\n  network: optional filter by network or IP range (e.g., '192.168.1.0/24')\n\nReturns: IP addresses and ranges being monitored in the subscription\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
			mcp.WithString("network", mcp.Description("Optional: filter by network or IP range (e.g. 192.168.1.0/24)")),
		),
		m.listTrackedIPs,
	)

	s.AddTool(
		mcp.NewTool("vmdr_launch_scan",
			mcp.WithDescription("[VMDR ACTION] Launch an on-demand vulnerability scan.\n\nUSE WHEN: user asks to 'run a scan', 'scan these IPs', 'launch vulnerability scan'\nDO NOT USE WHEN: user wants scan results (use vmdr_list_scans + vmdr_get_scan_results), user wants to check scan coverage (use vmdr_get_scan_coverage)\n\nParameters:\n  title: (required) title for the scan\n  option_profile: (required) name of the option profile (use vmdr_get_option_profiles to find)\n  targets: comma-separated IPs or CIDR ranges (e.g., '192.168.1.0/24,10.0.0.1')\n  asset_groups: comma-separated asset group IDs (at least one of targets or asset_groups required)\n\nReturns: scan reference ID for tracking progress\n\nPerformance: ~3s (launches asynchronously)"),
			mcp.WithString("title", mcp.Required(), mcp.Description("Title for the scan")),
			mcp.WithString("option_profile", mcp.Required(), mcp.Description("Name of the option profile to use for scanning")),
			mcp.WithString("targets", mcp.Description("Comma-separated IPs or CIDR ranges to scan (e.g. 192.168.1.0/24,10.0.0.1)")),
			mcp.WithString("asset_groups", mcp.Description("Comma-separated asset group IDs to scan")),
		),
		m.launchScan,
	)

	s.AddTool(
		mcp.NewTool("vmdr_get_scan_coverage",
			mcp.WithDescription("[VMDR COVERAGE] Show scan coverage gaps — assets not scanned within threshold days.\n\nUSE WHEN: user asks 'scan coverage', 'assets not scanned', 'scan gaps', 'stale assets'\nDO NOT USE WHEN: user wants scan results (use vmdr_list_scans), user wants to run a scan (use vmdr_launch_scan)\n\nParameters:\n  threshold_days: days since last scan to consider stale (default: 7)\n\nReturns: coverage report with never-scanned assets, stale assets, coverage percentage\n\nPerformance: ~3s cold / ~0.3s warm"),
			mcp.WithNumber("threshold_days", mcp.Description("Days since last scan to consider an asset stale (default: 7)")),
		),
		m.getScanCoverage,
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

	limit := 50
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

func (m *Module) listScanSchedules(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	schedules, err := m.client.ListScanSchedules(ctx)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list scan schedules: %v", err)), nil
	}

	data, _ := json.MarshalIndent(schedules, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listOptionProfiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	profiles, err := m.client.ListOptionProfiles(ctx)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list option profiles: %v", err)), nil
	}

	data, _ := json.MarshalIndent(profiles, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listTrackedIPs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	network, _ := req.Params.Arguments["network"].(string)

	result, err := m.client.ListTrackedIPs(ctx, network)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list tracked IPs: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) launchScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	title, ok := req.Params.Arguments["title"].(string)
	if !ok || title == "" {
		return newToolResultError("title is required"), nil
	}

	optionProfile, ok := req.Params.Arguments["option_profile"].(string)
	if !ok || optionProfile == "" {
		return newToolResultError("option_profile is required"), nil
	}

	targets, _ := req.Params.Arguments["targets"].(string)
	assetGroups, _ := req.Params.Arguments["asset_groups"].(string)

	if targets == "" && assetGroups == "" {
		return newToolResultError("at least one of targets or asset_groups is required"), nil
	}

	result, err := m.client.LaunchScan(ctx, title, optionProfile, targets, assetGroups)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to launch scan: %v", err)), nil
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getScanCoverage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	thresholdDays := 7
	if t, ok := req.Params.Arguments["threshold_days"].(float64); ok && t > 0 {
		thresholdDays = int(t)
	}

	report, err := m.client.GetScanCoverageGaps(ctx, thresholdDays)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get scan coverage: %v", err)), nil
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
