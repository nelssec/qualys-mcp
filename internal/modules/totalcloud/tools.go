package totalcloud

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
		mcp.NewTool("tc_list_connectors",
			mcp.WithDescription("[CLOUD CONNECTORS] List cloud connectors from TotalCloud/CSPM showing account connections and sync status.\n\nUSE WHEN: user asks 'cloud accounts', 'connected accounts', 'cloud connectors', 'sync status'\nDO NOT USE WHEN: user wants cloud security posture (use get_cloud_risk_summary), user wants cloud resources (use tc_list_resources)\n\nParameters:\n  provider: cloud provider — aws, azure, gcp, oci (default: aws)\n  limit: max connectors to return (default: 100)\n\nReturns: connectors with IDs, account names, provider, sync status, last sync time\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of connectors to return (default 100)")),
		),
		m.listConnectors,
	)

	s.AddTool(
		mcp.NewTool("tc_list_resources",
			mcp.WithDescription("[CLOUD RESOURCES] List cloud resources from TotalCloud/CSPM inventory.\n\nUSE WHEN: user asks 'cloud resources', 'EC2 instances', 'S3 buckets', 'list our cloud assets by type'\nDO NOT USE WHEN: user wants security posture summary (use get_cloud_risk_summary), user wants evaluations for a resource (use tc_get_resource_evaluations)\nPREFER INSTEAD: get_cloud_risk_summary for security-focused cloud overview; tc_get_resource_evaluations when user wants compliance status of one resource\n\nParameters:\n  provider: cloud provider — AWS, AZURE, GCP, OCI (default: AWS)\n  resource_type: resource type (default: EC2_INSTANCE). AWS: EC2_INSTANCE, BUCKET, RDS_INSTANCE, LAMBDA_FUNCTION, VPC, SECURITY_GROUP, IAM_USER, IAM_ROLE, EBS_VOLUME, EKS_CLUSTER. Azure: VM_INSTANCE, STORAGE_ACCOUNT, SQL_DATABASE, NETWORK, NSG, KEY_VAULT. GCP: VM_INSTANCE, BUCKET, CLOUD_FUNCTION, K8S_CLUSTER, NETWORK, FIREWALL_RULES\n  limit: max resources to return (default: 100)\n\nReturns: cloud resources with IDs, names, type, region, account, tags\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("provider", mcp.Description("Cloud provider: AWS, AZURE, GCP, or OCI (default: AWS)")),
			mcp.WithString("resource_type", mcp.Description("Resource type (e.g., EC2_INSTANCE, BUCKET, VM_INSTANCE). Default: EC2_INSTANCE")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of resources to return (default 100)")),
		),
		m.listResources,
	)

	s.AddTool(
		mcp.NewTool("tc_list_controls",
			mcp.WithDescription("[CLOUD CONTROLS] List security controls from TotalCloud/CSPM with pass/fail status.\n\nUSE WHEN: user asks 'cloud controls', 'CSPM controls', 'what controls are checked', browsing security controls\nDO NOT USE WHEN: user wants evaluations for a specific control (use tc_get_control_evaluations), user wants overall cloud posture (use get_cloud_risk_summary)\nPREFER INSTEAD: tc_get_control_evaluations when user asks about results for a specific control\n\nParameters:\n  provider: cloud provider — aws, azure, gcp, oci (default: aws)\n  limit: max controls to return (default: 100)\n\nReturns: controls with IDs, names, description, severity, pass/fail counts\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of controls to return (default 100)")),
		),
		m.listControls,
	)

	s.AddTool(
		mcp.NewTool("tc_list_evaluations",
			mcp.WithDescription("[CLOUD EVALUATIONS] List all control evaluations for a cloud account with configurable output modes.\n\nUSE WHEN: user asks 'evaluation results for account X', 'what failed in this account', 'cloud compliance for account'\nDO NOT USE WHEN: user wants evaluations for one specific control (use tc_get_control_evaluations), user wants evaluations for one resource (use tc_get_resource_evaluations)\nPREFER INSTEAD: tc_get_control_evaluations for one control's results; tc_get_resource_evaluations for one resource's results\n\nParameters:\n  account_id: (required) cloud account ID (AWS account, Azure subscription, GCP project, OCI tenant)\n  provider: cloud provider — aws, azure, gcp, oci (default: aws)\n  output_mode: 'summary' (stats + top 20 failures ~1k tokens), 'failed_only' (only FAIL results), 'full' (all data, default)\n  limit: max evaluations to return (default: 100)\n\nReturns: control evaluations with control name, resource, status (PASS/FAIL), severity\n\nPerformance: ~3s cold / ~0.3s warm (cached)"),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Cloud account ID (AWS account ID, Azure subscription ID, GCP project ID, or OCI tenant ID)")),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (stats + top 20 failures), 'failed_only' (only FAIL results), 'full' (all data, default)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of evaluations to return (default 100)")),
		),
		m.listEvaluations,
	)

	s.AddTool(
		mcp.NewTool("tc_get_control_evaluations",
			mcp.WithDescription("[CLOUD CONTROL DETAIL] Get evaluation results for a specific security control showing which resources passed or failed.\n\nUSE WHEN: user asks 'which resources failed control X', 'control results', drilling into one control's evaluations\nDO NOT USE WHEN: user wants all evaluations for an account (use tc_list_evaluations), user wants evaluations for a resource (use tc_get_resource_evaluations)\n\nParameters:\n  control_id: (required) the control ID to get evaluations for\n  account_id: (required) cloud account ID\n  provider: cloud provider — aws, azure, gcp, oci (default: aws)\n  limit: max evaluations to return (default: 100)\n\nReturns: resources evaluated against this control with PASS/FAIL status, resource details\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("control_id", mcp.Required(), mcp.Description("The control ID to get evaluations for")),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Cloud account ID")),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of evaluations to return (default 100)")),
		),
		m.getControlEvaluations,
	)

	s.AddTool(
		mcp.NewTool("tc_get_resource_evaluations",
			mcp.WithDescription("[CLOUD RESOURCE DETAIL] Get all control evaluations for a specific cloud resource.\n\nUSE WHEN: user asks 'is this resource compliant', 'what controls failed on resource X', drilling into one resource's posture\nDO NOT USE WHEN: user wants all evaluations for an account (use tc_list_evaluations), user wants evaluations for a control (use tc_get_control_evaluations)\n\nParameters:\n  resource_id: (required) the resource ID to get evaluations for\n  account_id: (required) cloud account ID\n  provider: cloud provider — aws, azure, gcp, oci (default: aws)\n  limit: max evaluations to return (default: 100)\n\nReturns: all controls evaluated against this resource with PASS/FAIL status\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("resource_id", mcp.Required(), mcp.Description("The resource ID to get evaluations for")),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Cloud account ID")),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of evaluations to return (default 100)")),
		),
		m.getResourceEvaluations,
	)

	s.AddTool(
		mcp.NewTool("tc_list_cdr_findings",
			mcp.WithDescription("[CLOUD THREATS] List Cloud Detection and Response (CDR) findings — security threats and anomalies across cloud environments.\n\nUSE WHEN: user asks 'cloud threats', 'CDR findings', 'cloud detections', 'suspicious cloud activity', 'cryptominers', 'container escapes'\nDO NOT USE WHEN: user wants compliance/posture (use get_cloud_risk_summary or tc_list_evaluations), user wants EDR endpoint detections (use edr_list_indicators)\nPREFER INSTEAD: get_cloud_risk_summary for overall cloud posture including CDR; edr_list_indicators for endpoint-level threat detection\n\nParameters:\n  provider: filter by cloud provider — AWS, AZURE, GCP\n  severity: filter by severity — LOW, MEDIUM, HIGH, CRITICAL\n  days: days to look back (default: 7)\n  limit: max findings to return (default: 100)\n\nReturns: CDR findings with type (container escape, cryptominer, fileless malware, etc.), severity, resource, timestamp\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("provider", mcp.Description("Cloud provider filter: AWS, AZURE, or GCP")),
			mcp.WithString("severity", mcp.Description("Filter by severity: LOW, MEDIUM, HIGH, or CRITICAL")),
			mcp.WithNumber("days", mcp.Description("Number of days to look back for findings (default: 7)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of findings to return (default 100)")),
		),
		m.listCDRFindings,
	)
}

func (m *Module) listConnectors(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	provider, _ := req.Params.Arguments["provider"].(string)
	if provider == "" {
		provider = "aws"
	}
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	connectors, err := m.client.ListConnectors(ctx, provider, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list connectors: %v", err)), nil
	}

	data, _ := json.MarshalIndent(connectors, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listResources(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	provider, _ := req.Params.Arguments["provider"].(string)
	resourceType, _ := req.Params.Arguments["resource_type"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	resources, err := m.client.ListResources(ctx, provider, resourceType, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list resources: %v", err)), nil
	}

	data, _ := json.MarshalIndent(resources, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listControls(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	provider, _ := req.Params.Arguments["provider"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	controls, err := m.client.ListControls(ctx, provider, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list controls: %v", err)), nil
	}

	data, _ := json.MarshalIndent(controls, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listEvaluations(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	accountID, ok := req.Params.Arguments["account_id"].(string)
	if !ok || accountID == "" {
		return newToolResultError("account_id is required"), nil
	}
	provider, _ := req.Params.Arguments["provider"].(string)
	outputMode, _ := req.Params.Arguments["output_mode"].(string)

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	evaluations, err := m.client.ListEvaluations(ctx, accountID, provider, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list evaluations: %v", err)), nil
	}

	var data []byte
	switch outputMode {
	case "summary":
		stats := GetEvaluationStats(evaluations, 20)
		data, _ = json.MarshalIndent(stats, "", "  ")
	case "failed_only":
		var failures []Evaluation
		for _, e := range evaluations {
			if e.Status == "FAIL" || e.Status == "FAILED" {
				failures = append(failures, e)
			}
		}
		data, _ = json.MarshalIndent(failures, "", "  ")
	default:
		data, _ = json.MarshalIndent(evaluations, "", "  ")
	}

	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getControlEvaluations(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	controlID, ok := req.Params.Arguments["control_id"].(string)
	if !ok || controlID == "" {
		return newToolResultError("control_id is required"), nil
	}

	accountID, ok := req.Params.Arguments["account_id"].(string)
	if !ok || accountID == "" {
		return newToolResultError("account_id is required"), nil
	}

	provider, _ := req.Params.Arguments["provider"].(string)

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	evaluations, err := m.client.GetControlEvaluations(ctx, controlID, accountID, provider, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get control evaluations: %v", err)), nil
	}

	data, _ := json.MarshalIndent(evaluations, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getResourceEvaluations(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	resourceID, ok := req.Params.Arguments["resource_id"].(string)
	if !ok || resourceID == "" {
		return newToolResultError("resource_id is required"), nil
	}

	accountID, ok := req.Params.Arguments["account_id"].(string)
	if !ok || accountID == "" {
		return newToolResultError("account_id is required"), nil
	}

	provider, _ := req.Params.Arguments["provider"].(string)

	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	evaluations, err := m.client.GetResourceEvaluations(ctx, resourceID, accountID, provider, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get resource evaluations: %v", err)), nil
	}

	data, _ := json.MarshalIndent(evaluations, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listCDRFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	provider, _ := req.Params.Arguments["provider"].(string)
	severity, _ := req.Params.Arguments["severity"].(string)
	days := 7
	if d, ok := req.Params.Arguments["days"].(float64); ok {
		days = int(d)
	}
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	findings, err := m.client.ListCDRFindings(ctx, provider, severity, days, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list CDR findings: %v", err)), nil
	}

	data, _ := json.MarshalIndent(findings, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}
