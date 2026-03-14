package car

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

func NewWithClient(client *Client) *Module {
	return &Module{
		client: client,
	}
}

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("car_list_scripts",
			mcp.WithDescription("[CAR SCRIPTS] List custom assessment and remediation scripts.\n\nUSE WHEN: user asks 'custom scripts', 'CAR scripts', 'assessment scripts', 'what scripts are available'\nDO NOT USE WHEN: user wants remediation scripts specifically (use car_list_remediation_scripts), user wants to see script details (use car_get_script)\nPREFER INSTEAD: car_list_remediation_scripts when user specifically asks about remediation/fix scripts\n\nParameters:\n  platform: filter by platform — WINDOWS, LINUX, UNIX\n  type: filter by type — DETECTION (assess issues), REMEDIATION (fix issues)\n  limit: max scripts to return (default: 100)\n\nReturns: scripts with IDs, names, platform, type, description, last modified\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("platform", mcp.Description("Filter by platform: WINDOWS, LINUX, or UNIX")),
			mcp.WithString("type", mcp.Description("Filter by script type: DETECTION (assess issues) or REMEDIATION (fix issues)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scripts to return (default 100)")),
		),
		m.listScripts,
	)

	s.AddTool(
		mcp.NewTool("car_get_script",
			mcp.WithDescription("[CAR SCRIPT DETAIL] Get details of a specific custom script including description, platform, and configuration.\n\nUSE WHEN: user asks 'show me script X', 'script details', wants to review a script before execution\nDO NOT USE WHEN: user wants to list all scripts (use car_list_scripts), user wants to run a script (use car_execute_script)\n\nParameters:\n  script_id: (required) the script ID to retrieve\n\nReturns: script details with name, description, platform, content, configuration\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
			mcp.WithString("script_id", mcp.Required(), mcp.Description("The script ID to retrieve")),
		),
		m.getScript,
	)

	s.AddTool(
		mcp.NewTool("car_execute_script",
			mcp.WithDescription("[CAR ACTION] Execute a custom script on specified assets. Defaults to test mode for safety.\n\nUSE WHEN: user asks 'run script X', 'execute remediation', 'apply fix to assets'\nDO NOT USE WHEN: user wants to review the script first (use car_get_script), user wants to check job results (use car_get_job_results)\n\nParameters:\n  script_id: (required) the script ID to execute\n  asset_ids: comma-separated asset IDs to run on\n  tag_ids: comma-separated tag IDs — runs on all assets with these tags\n  test_mode: run in test/validation mode (default: true for safety)\n\nReturns: correlation UUID for tracking job status\n\nPerformance: ~3s (launches asynchronously)"),
			mcp.WithString("script_id", mcp.Required(), mcp.Description("The script ID to execute")),
			mcp.WithString("asset_ids", mcp.Description("Comma-separated list of asset IDs to run the script on")),
			mcp.WithString("tag_ids", mcp.Description("Comma-separated list of asset tag IDs - script runs on all assets with these tags")),
			mcp.WithBoolean("test_mode", mcp.Description("Run in test mode to validate without making changes (default: true for safety)")),
		),
		m.executeScript,
	)

	s.AddTool(
		mcp.NewTool("car_list_jobs",
			mcp.WithDescription("[CAR JOBS] List script execution jobs with status and results.\n\nUSE WHEN: user asks 'script job status', 'what scripts ran', 'CAR job history'\nDO NOT USE WHEN: user wants patch deployment jobs (use pm_list_jobs), user wants detailed job results (use car_get_job_results)\nPREFER INSTEAD: car_get_job_results when user wants per-asset details on a specific job\n\nParameters:\n  status: filter by status — RUNNING, COMPLETED, FAILED, QUEUED\n  limit: max jobs to return (default: 100)\n\nReturns: jobs with IDs, status, success/failure counts, timing, script reference\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("status", mcp.Description("Filter by job status: RUNNING, COMPLETED, FAILED, QUEUED")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of jobs to return (default 100)")),
		),
		m.listJobs,
	)

	s.AddTool(
		mcp.NewTool("car_get_job_results",
			mcp.WithDescription("[CAR JOB RESULTS] Get detailed results from a script execution job.\n\nUSE WHEN: user asks 'what happened in job X', 'script results', 'per-asset status for job X'\nDO NOT USE WHEN: user wants to list all jobs (use car_list_jobs)\n\nParameters:\n  job_id: (required) the job ID to get results for\n  limit: max results to return (default: 100)\n\nReturns: per-asset results with status, output text, exit codes, timing\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("job_id", mcp.Required(), mcp.Description("The job ID to get results for")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of results to return (default 100)")),
		),
		m.getJobResults,
	)

	s.AddTool(
		mcp.NewTool("car_list_remediation_scripts",
			mcp.WithDescription("[CAR REMEDIATION] List available remediation scripts that fix vulnerabilities or misconfigurations.\n\nUSE WHEN: user asks 'remediation scripts', 'fix scripts', 'what can we auto-remediate'\nDO NOT USE WHEN: user wants all script types (use car_list_scripts with type filter), user wants KB remediation guidance (use kb_get_qid)\nPREFER INSTEAD: car_list_scripts with type=REMEDIATION for the same result with more filter options\n\nParameters:\n  limit: max scripts to return (default: 100)\n\nReturns: remediation scripts with IDs, names, platform, description\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithNumber("limit", mcp.Description("Maximum number of scripts to return (default 100)")),
		),
		m.listRemediationScripts,
	)
}

func (m *Module) listScripts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	platform, _ := req.Params.Arguments["platform"].(string)
	scriptType, _ := req.Params.Arguments["type"].(string)

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	scripts, err := m.client.ListScripts(ctx, platform, scriptType, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list scripts: %v", err)), nil
	}

	data, _ := json.MarshalIndent(scripts, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getScript(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	scriptID, ok := req.Params.Arguments["script_id"].(string)
	if !ok || scriptID == "" {
		return newToolResultError("script_id is required"), nil
	}

	script, err := m.client.GetScript(ctx, scriptID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get script: %v", err)), nil
	}

	data, _ := json.MarshalIndent(script, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) executeScript(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	scriptID, ok := req.Params.Arguments["script_id"].(string)
	if !ok || scriptID == "" {
		return newToolResultError("script_id is required"), nil
	}

	var assetIDs []string
	if ids, ok := req.Params.Arguments["asset_ids"].(string); ok && ids != "" {
		assetIDs = splitAndTrim(ids)
	}

	var tagIDs []string
	if ids, ok := req.Params.Arguments["tag_ids"].(string); ok && ids != "" {
		tagIDs = splitAndTrim(ids)
	}

	if len(assetIDs) == 0 && len(tagIDs) == 0 {
		return newToolResultError("either asset_ids or tag_ids is required"), nil
	}

	testMode := true
	if tm, ok := req.Params.Arguments["test_mode"].(bool); ok {
		testMode = tm
	}

	resp, err := m.client.ExecuteScript(ctx, scriptID, assetIDs, tagIDs, testMode)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to execute script: %v", err)), nil
	}

	data, _ := json.MarshalIndent(resp, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listJobs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, _ := req.Params.Arguments["status"].(string)

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	jobs, err := m.client.ListJobs(ctx, status, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list jobs: %v", err)), nil
	}

	data, _ := json.MarshalIndent(jobs, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getJobResults(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	jobID, ok := req.Params.Arguments["job_id"].(string)
	if !ok || jobID == "" {
		return newToolResultError("job_id is required"), nil
	}

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	results, err := m.client.GetJobResults(ctx, jobID, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get job results: %v", err)), nil
	}

	data, _ := json.MarshalIndent(results, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listRemediationScripts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	scripts, err := m.client.ListRemediationScripts(ctx, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list remediation scripts: %v", err)), nil
	}

	data, _ := json.MarshalIndent(scripts, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func splitAndTrim(s string) []string {
	var result []string
	for _, part := range split(s, ",") {
		trimmed := trim(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func split(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
