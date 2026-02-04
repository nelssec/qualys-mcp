package certview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/common"
)

type Client struct {
	http       *common.HTTPClient
	gatewayURL string
}

func NewClient(http *common.HTTPClient, gatewayURL string) *Client {
	return &Client{
		http:       http,
		gatewayURL: gatewayURL,
	}
}

type Certificate struct {
	ID              interface{} `json:"id,omitempty"`
	SerialNumber    string      `json:"serialNumber,omitempty"`
	Subject         string      `json:"subject,omitempty"`
	Issuer          string      `json:"issuer,omitempty"`
	ValidFrom       string      `json:"validFrom,omitempty"`
	ValidTo         string      `json:"validTo,omitempty"`
	KeyAlgorithm    string      `json:"keyAlgorithm,omitempty"`
	KeySize         int         `json:"keySize,omitempty"`
	SignatureAlgo   string      `json:"signatureAlgorithm,omitempty"`
	SHA256          string      `json:"sha256Fingerprint,omitempty"`
	IsExpired       bool        `json:"isExpired,omitempty"`
	DaysToExpire    int         `json:"daysToExpire,omitempty"`
	Grade           string      `json:"grade,omitempty"`
	InstanceCount   int         `json:"instanceCount,omitempty"`
}

type Endpoint struct {
	ID          interface{} `json:"id,omitempty"`
	Host        string      `json:"host,omitempty"`
	Port        int         `json:"port,omitempty"`
	Protocol    string      `json:"protocol,omitempty"`
	Grade       string      `json:"grade,omitempty"`
	IP          string      `json:"ipAddress,omitempty"`
	LastScanned string      `json:"lastScanned,omitempty"`
	CertID      interface{} `json:"certificateId,omitempty"`
}

type Asset struct {
	ID           interface{} `json:"id,omitempty"`
	Name         string      `json:"name,omitempty"`
	FQDN         string      `json:"fqdn,omitempty"`
	IP           string      `json:"ipAddress,omitempty"`
	CertCount    int         `json:"certificateCount,omitempty"`
	ExpiredCount int         `json:"expiredCertCount,omitempty"`
	ExpiringCount int        `json:"expiringCertCount,omitempty"`
}

type CertificatesResponse struct {
	Data       []Certificate `json:"data"`
	Count      int           `json:"count,omitempty"`
	TotalCount int           `json:"totalCount,omitempty"`
}

type EndpointsResponse struct {
	Data       []Endpoint `json:"data"`
	Count      int        `json:"count,omitempty"`
	TotalCount int        `json:"totalCount,omitempty"`
}

type AssetsResponse struct {
	Data       []Asset `json:"data"`
	Count      int     `json:"count,omitempty"`
	TotalCount int     `json:"totalCount,omitempty"`
}

func (c *Client) ListCertificates(ctx context.Context, filter string, limit int) ([]Certificate, error) {
	endpoint := fmt.Sprintf("%s/certview/v2.1/certificates", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	var body string
	if filter != "" {
		body = fmt.Sprintf(`{"filter":"%s"}`, filter)
	} else {
		body = `{}`
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Certificate{}, nil
	}

	var resp CertificatesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var certs []Certificate
		if err2 := json.Unmarshal(data, &certs); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return certs, nil
	}

	return resp.Data, nil
}

func (c *Client) GetExpiringCertificates(ctx context.Context, days int, limit int) ([]Certificate, error) {
	filter := fmt.Sprintf("instance.daysToExpire:[0 TO %d]", days)
	return c.ListCertificates(ctx, filter, limit)
}

func (c *Client) ListEndpoints(ctx context.Context, filter string, limit int) ([]Endpoint, error) {
	endpoint := fmt.Sprintf("%s/certview/v1/getEndpointData", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	var body string
	if filter != "" {
		body = fmt.Sprintf(`{"filter":"%s"}`, filter)
	} else {
		body = `{}`
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Endpoint{}, nil
	}

	var resp EndpointsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var endpoints []Endpoint
		if err2 := json.Unmarshal(data, &endpoints); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return endpoints, nil
	}

	return resp.Data, nil
}

func (c *Client) GetCertificateDetails(ctx context.Context, certID string) (*Certificate, error) {
	endpoint := fmt.Sprintf("%s/certview/v1/certificates/%s", c.gatewayURL, certID)

	data, err := c.http.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var cert Certificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &cert, nil
}

func (c *Client) ListAssets(ctx context.Context, filter string, limit int) ([]Asset, error) {
	endpoint := fmt.Sprintf("%s/certview/v1/assets", c.gatewayURL)

	params := url.Values{}
	if filter != "" {
		params.Set("filter", filter)
	}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Asset{}, nil
	}

	var resp AssetsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var assets []Asset
		if err2 := json.Unmarshal(data, &assets); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return assets, nil
	}

	return resp.Data, nil
}
