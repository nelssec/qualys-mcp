package certview

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
		mcp.NewTool("cert_list_certificates",
			mcp.WithDescription("List SSL/TLS certificates from Qualys CertView. Shows certificate details, expiration, and grades."),
			mcp.WithString("filter", mcp.Description("Filter expression for certificates")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of certificates to return (default 100)")),
		),
		m.listCertificates,
	)

	s.AddTool(
		mcp.NewTool("cert_get_expiring",
			mcp.WithDescription("Get certificates expiring within a specified number of days."),
			mcp.WithNumber("days", mcp.Description("Number of days to check for expiring certificates (default 30)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of certificates to return (default 100)")),
		),
		m.getExpiringCertificates,
	)

	s.AddTool(
		mcp.NewTool("cert_list_endpoints",
			mcp.WithDescription("List SSL/TLS endpoints. Shows hosts, ports, and certificate associations."),
			mcp.WithString("filter", mcp.Description("Filter expression for endpoints")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of endpoints to return (default 100)")),
		),
		m.listEndpoints,
	)

	s.AddTool(
		mcp.NewTool("cert_get_details",
			mcp.WithDescription("Get detailed information about a specific certificate."),
			mcp.WithString("cert_id", mcp.Required(), mcp.Description("The certificate ID")),
		),
		m.getCertificateDetails,
	)

	s.AddTool(
		mcp.NewTool("cert_list_assets",
			mcp.WithDescription("List assets with their certificate counts and expiration status."),
			mcp.WithString("filter", mcp.Description("Filter expression for assets")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of assets to return (default 100)")),
		),
		m.listAssets,
	)
}

func (m *Module) listCertificates(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	certs, err := m.client.ListCertificates(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list certificates: %v", err)), nil
	}

	data, _ := json.MarshalIndent(certs, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getExpiringCertificates(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	days := 30
	if d, ok := req.Params.Arguments["days"].(float64); ok {
		days = int(d)
	}
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	certs, err := m.client.GetExpiringCertificates(ctx, days, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get expiring certificates: %v", err)), nil
	}

	data, _ := json.MarshalIndent(certs, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) listEndpoints(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, _ := req.Params.Arguments["filter"].(string)
	limit := 100
	if l, ok := req.Params.Arguments["limit"].(float64); ok {
		limit = int(l)
	}

	endpoints, err := m.client.ListEndpoints(ctx, filter, limit)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to list endpoints: %v", err)), nil
	}

	data, _ := json.MarshalIndent(endpoints, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (m *Module) getCertificateDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	certID, ok := req.Params.Arguments["cert_id"].(string)
	if !ok || certID == "" {
		return newToolResultError("cert_id is required"), nil
	}

	cert, err := m.client.GetCertificateDetails(ctx, certID)
	if err != nil {
		return newToolResultError(fmt.Sprintf("Failed to get certificate details: %v", err)), nil
	}

	data, _ := json.MarshalIndent(cert, "", "  ")
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
