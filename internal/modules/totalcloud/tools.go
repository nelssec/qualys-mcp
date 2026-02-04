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

func (m *Module) RegisterTools(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("tc_list_connectors",
			mcp.WithDescription("List cloud connectors from TotalCloud/CSPM. Shows AWS, Azure, GCP, and OCI account connections and sync status."),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of connectors to return (default 100)")),
		),
		m.listConnectors,
	)

	s.AddTool(
		mcp.NewTool("tc_list_resources",
			mcp.WithDescription("List cloud resources from TotalCloud/CSPM. Shows inventory of cloud assets. AWS types: EC2_INSTANCE, BUCKET, RDS_INSTANCE, LAMBDA_FUNCTION, VPC, SECURITY_GROUP, IAM_USER, IAM_ROLE, EBS_VOLUME, EKS_CLUSTER. Azure types: VM_INSTANCE, STORAGE_ACCOUNT, SQL_DATABASE, NETWORK, NSG, KEY_VAULT. GCP types: VM_INSTANCE, BUCKET, CLOUD_FUNCTION, K8S_CLUSTER, NETWORK, FIREWALL_RULES."),
			mcp.WithString("provider", mcp.Description("Cloud provider: AWS, AZURE, GCP, or OCI (default: AWS)")),
			mcp.WithString("resource_type", mcp.Description("Resource type (e.g., EC2_INSTANCE, BUCKET, VM_INSTANCE). Default: EC2_INSTANCE")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of resources to return (default 100)")),
		),
		m.listResources,
	)

	s.AddTool(
		mcp.NewTool("tc_list_controls",
			mcp.WithDescription("List security controls from TotalCloud/CSPM. Shows compliance controls and their pass/fail status."),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of controls to return (default 100)")),
		),
		m.listControls,
	)

	s.AddTool(
		mcp.NewTool("tc_list_evaluations",
			mcp.WithDescription("List all control evaluations for a cloud account. Use output_mode to control response size: 'summary' for stats + top failures (~1k tokens), 'failed_only' for only failed evaluations, 'full' for all data."),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Cloud account ID (AWS account ID, Azure subscription ID, GCP project ID, or OCI tenant ID)")),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (stats + top 20 failures), 'failed_only' (only FAIL results), 'full' (all data, default)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of evaluations to return (default 100)")),
		),
		m.listEvaluations,
	)

	s.AddTool(
		mcp.NewTool("tc_get_control_evaluations",
			mcp.WithDescription("Get evaluation results for a specific security control. Shows which resources passed or failed."),
			mcp.WithString("control_id", mcp.Required(), mcp.Description("The control ID to get evaluations for")),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Cloud account ID")),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of evaluations to return (default 100)")),
		),
		m.getControlEvaluations,
	)

	s.AddTool(
		mcp.NewTool("tc_get_resource_evaluations",
			mcp.WithDescription("Get all control evaluations for a specific cloud resource."),
			mcp.WithString("resource_id", mcp.Required(), mcp.Description("The resource ID to get evaluations for")),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Cloud account ID")),
			mcp.WithString("provider", mcp.Description("Cloud provider: aws, azure, gcp, or oci (default: aws)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of evaluations to return (default 100)")),
		),
		m.getResourceEvaluations,
	)

	s.AddTool(
		mcp.NewTool("tc_list_cdr_findings",
			mcp.WithDescription("List Cloud Detection and Response (CDR) findings. Shows security threats, anomalies, and detections across cloud environments including container escapes, cryptominers, fileless malware, and suspicious network activity."),
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
