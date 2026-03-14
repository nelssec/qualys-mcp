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
			mcp.WithDescription("[CERTVIEW INVENTORY] List SSL/TLS certificates from Qualys CertView with details, expiration, and grades.\n\nUSE WHEN: user asks 'certificates', 'SSL certs', 'TLS certificates', 'certificate inventory'\nDO NOT USE WHEN: user wants expiring certs specifically (use cert_get_expiring), user wants cert details for one cert (use cert_get_details)\nPREFER INSTEAD: cert_get_expiring when user asks about expiring or soon-to-expire certificates\n\nParameters:\n  filter: filter expression for certificates\n  limit: max certificates to return (default: 100)\n\nReturns: certificates with IDs, subject, issuer, expiration date, grade, key size\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter expression for certificates")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of certificates to return (default 100)")),
		),
		m.listCertificates,
	)

	s.AddTool(
		mcp.NewTool("cert_get_expiring",
			mcp.WithDescription("[CERTVIEW EXPIRING] Get certificates expiring within a specified number of days.\n\nUSE WHEN: user asks 'expiring certificates', 'certs about to expire', 'certificate renewal needed', 'SSL expiry'\nDO NOT USE WHEN: user wants full cert inventory (use cert_list_certificates), user wants details on one cert (use cert_get_details)\n\nParameters:\n  days: days to check for expiring certificates (default: 30)\n  limit: max certificates to return (default: 100)\n\nReturns: expiring certificates with subject, issuer, expiration date, days remaining, associated endpoints\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithNumber("days", mcp.Description("Number of days to check for expiring certificates (default 30)")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of certificates to return (default 100)")),
		),
		m.getExpiringCertificates,
	)

	s.AddTool(
		mcp.NewTool("cert_list_endpoints",
			mcp.WithDescription("[CERTVIEW ENDPOINTS] List SSL/TLS endpoints — hosts, ports, and certificate associations.\n\nUSE WHEN: user asks 'SSL endpoints', 'TLS endpoints', 'which hosts have certificates', 'certificate endpoints'\nDO NOT USE WHEN: user wants certificate details (use cert_list_certificates), user wants asset inventory (use gav_list_assets)\n\nParameters:\n  filter: filter expression for endpoints\n  limit: max endpoints to return (default: 100)\n\nReturns: endpoints with host, port, protocol, associated certificate, grade\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
			mcp.WithString("filter", mcp.Description("Filter expression for endpoints")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of endpoints to return (default 100)")),
		),
		m.listEndpoints,
	)

	s.AddTool(
		mcp.NewTool("cert_get_details",
			mcp.WithDescription("[CERTVIEW DETAIL] Get detailed information about a specific certificate.\n\nUSE WHEN: user asks 'certificate details', 'cert info for X', drilling into one certificate\nDO NOT USE WHEN: user wants to list certificates (use cert_list_certificates)\n\nParameters:\n  cert_id: (required) the certificate ID\n\nReturns: full certificate details — subject, issuer, validity, SANs, key info, chain, grade\n\nPerformance: ~1s cold / ~0.1s warm (cached)"),
			mcp.WithString("cert_id", mcp.Required(), mcp.Description("The certificate ID")),
		),
		m.getCertificateDetails,
	)

	s.AddTool(
		mcp.NewTool("cert_list_assets",
			mcp.WithDescription("[CERTVIEW ASSETS] List assets with their certificate counts and expiration status.\n\nUSE WHEN: user asks 'assets with certificates', 'certificate coverage', 'which assets have SSL'\nDO NOT USE WHEN: user wants GAV asset inventory (use gav_list_assets), user wants expiring certs (use cert_get_expiring)\n\nParameters:\n  filter: filter expression for assets\n  limit: max assets to return (default: 100)\n\nReturns: assets with certificate count, expiring cert count, hostnames\n\nPerformance: ~2s cold / ~0.1s warm (cached)"),
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
