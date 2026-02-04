package compliance

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"

	"github.com/nelssec/qualys-mcp/internal/common"
)

type Client struct {
	http    *common.HTTPClient
	baseURL string
}

func NewClient(http *common.HTTPClient, baseURL string) *Client {
	return &Client{
		http:    http,
		baseURL: baseURL,
	}
}

type Policy struct {
	ID          int    `xml:"ID" json:"id,omitempty"`
	Title       string `xml:"TITLE" json:"title,omitempty"`
	Status      string `xml:"STATUS" json:"status,omitempty"`
	Created     string `xml:"CREATED" json:"created,omitempty"`
	Modified    string `xml:"MODIFIED" json:"modified,omitempty"`
	ControlCount int   `xml:"CONTROL_COUNT" json:"controlCount,omitempty"`
}

type Control struct {
	ID          int    `xml:"ID" json:"id,omitempty"`
	Statement   string `xml:"STATEMENT" json:"statement,omitempty"`
	Criticality string `xml:"CRITICALITY" json:"criticality,omitempty"`
	Category    string `xml:"CATEGORY" json:"category,omitempty"`
}

type PostureInfo struct {
	HostID       int    `json:"hostId,omitempty"`
	ControlID    int    `json:"controlId,omitempty"`
	Status       string `json:"status,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	FirstFailed  string `json:"firstFailed,omitempty"`
	LastEvaluated string `json:"lastEvaluated,omitempty"`
}

type Scan struct {
	ID          string `xml:"ID" json:"id,omitempty"`
	Reference   string `xml:"REF" json:"reference,omitempty"`
	Title       string `xml:"TITLE" json:"title,omitempty"`
	Status      string `xml:"STATUS>STATE" json:"status,omitempty"`
	LaunchDate  string `xml:"LAUNCH_DATETIME" json:"launchDate,omitempty"`
	Duration    string `xml:"DURATION" json:"duration,omitempty"`
	Target      string `xml:"TARGET" json:"target,omitempty"`
}

type PolicyListResponse struct {
	XMLName  xml.Name `xml:"POLICY_LIST_OUTPUT"`
	Response struct {
		PolicyList []Policy `xml:"POLICY_LIST>POLICY"`
	} `xml:"RESPONSE"`
}

type ScanListResponse struct {
	XMLName  xml.Name `xml:"COMPLIANCE_SCAN_LIST_OUTPUT"`
	Response struct {
		ScanList []Scan `xml:"SCAN_LIST>SCAN"`
	} `xml:"RESPONSE"`
}

func (c *Client) ListPolicies(ctx context.Context, limit int) ([]Policy, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/compliance/policy/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	if limit > 0 {
		params.Set("truncation_limit", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp PolicyListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Response.PolicyList, nil
}

func (c *Client) ListScans(ctx context.Context, status string, limit int) ([]Scan, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/scan/compliance/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	if status != "" {
		params.Set("state", status)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp ScanListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if limit > 0 && len(resp.Response.ScanList) > limit {
		return resp.Response.ScanList[:limit], nil
	}

	return resp.Response.ScanList, nil
}

func (c *Client) GetPolicyDetails(ctx context.Context, policyID string) (*Policy, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/compliance/policy/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("id", policyID)

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp PolicyListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(resp.Response.PolicyList) == 0 {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	return &resp.Response.PolicyList[0], nil
}

func (c *Client) ListExceptions(ctx context.Context, limit int) ([]Policy, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/compliance/exception/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	if limit > 0 {
		params.Set("truncation_limit", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp PolicyListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Response.PolicyList, nil
}
