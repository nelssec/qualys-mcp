package totalcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

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

type Connector struct {
	ID              interface{} `json:"id,omitempty"`
	Name            string      `json:"name,omitempty"`
	Description     string      `json:"description,omitempty"`
	Provider        string      `json:"provider,omitempty"`
	State           string      `json:"state,omitempty"`
	LastSyncedOn    string      `json:"lastSyncedOn,omitempty"`
	TotalAssets     int         `json:"totalAssets,omitempty"`
	AwsAccountID    string      `json:"awsAccountId,omitempty"`
	AzureSubID      string      `json:"azureSubscriptionId,omitempty"`
	GcpProjectID    string      `json:"gcpProjectId,omitempty"`
}

type Resource struct {
	ResourceID   string      `json:"resourceId,omitempty"`
	Name         string      `json:"name,omitempty"`
	Type         string      `json:"resourceType,omitempty"`
	Region       string      `json:"region,omitempty"`
	AccountID    string      `json:"accountId,omitempty"`
	Provider     string      `json:"cloudType,omitempty"`
	Created      string      `json:"created,omitempty"`
	Tags         interface{} `json:"tags,omitempty"`
}

type Control struct {
	ControlID    string      `json:"cid,omitempty"`
	Name         string      `json:"controlName,omitempty"`
	Criticality  string      `json:"criticality,omitempty"`
	Service      string      `json:"service,omitempty"`
	Category     string      `json:"controlCategoryName,omitempty"`
	Provider     string      `json:"provider,omitempty"`
	ControlType  string      `json:"controlType,omitempty"`
	CreatedDate  string      `json:"createdDate,omitempty"`
	ModifiedDate string      `json:"modifiedDate,omitempty"`
}

type Evaluation struct {
	ResourceID  string `json:"resourceId,omitempty"`
	ControlID   string `json:"controlId,omitempty"`
	Status      string `json:"result,omitempty"`
	Reason      string `json:"reason,omitempty"`
	EvaluatedOn string `json:"evaluatedOn,omitempty"`
}

type ConnectorsResponse struct {
	Content []Connector `json:"content"`
	Count   int         `json:"count,omitempty"`
}

type ResourcesResponse struct {
	Content []Resource `json:"content"`
	Count   int        `json:"count,omitempty"`
}

type ControlsResponse struct {
	Content []Control `json:"content"`
	Count   int       `json:"count,omitempty"`
}

type EvaluationsResponse struct {
	Content []Evaluation `json:"content"`
	Count   int          `json:"count,omitempty"`
}

type CDRFinding struct {
	CustomerUUID     string      `json:"customerUuid,omitempty"`
	CloudType        string      `json:"cloudType,omitempty"`
	CloudAccount     string      `json:"cloudAccount,omitempty"`
	ResourceID       string      `json:"resourceId,omitempty"`
	ResourceType     string      `json:"resourceType,omitempty"`
	Region           string      `json:"region,omitempty"`
	Severity         interface{} `json:"severity,omitempty"`
	Category         string      `json:"category,omitempty"`
	AlertClass       string      `json:"alertClass,omitempty"`
	EventMessage     string      `json:"eventMessage,omitempty"`
	Timestamp        string      `json:"timestamp,omitempty"`
	Hash             string      `json:"hash,omitempty"`
	RemoteIP         string      `json:"remoteResource,omitempty"`
	RemoteCountry    string      `json:"remote.country,omitempty"`
	RemoteCity       string      `json:"remote.city,omitempty"`
	CloudIdentifier  string      `json:"cloudIdentifier,omitempty"`
}

type CDRFindingsResponse struct {
	Content  []CDRFinding `json:"content"`
	Pageable struct {
		PageNumber    int `json:"pageNumber,omitempty"`
		PageSize      int `json:"pageSize,omitempty"`
		TotalPages    int `json:"totalPages,omitempty"`
		TotalElements int `json:"totalElements,omitempty"`
	} `json:"pageable,omitempty"`
}

func (c *Client) ListConnectors(ctx context.Context, provider string, limit int) ([]Connector, error) {
	p := strings.ToLower(provider)
	if p == "" {
		p = "aws"
	}
	endpoint := fmt.Sprintf("%s/cloudview-api/rest/v1/%s/connectors", c.gatewayURL, p)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp ConnectorsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Content, nil
}

func (c *Client) ListResources(ctx context.Context, provider string, resourceType string, limit int) ([]Resource, error) {
	p := strings.ToUpper(provider)
	if p == "" {
		p = "AWS"
	}

	rt := resourceType
	if rt == "" {
		rt = "EC2_INSTANCE"
	}

	endpoint := fmt.Sprintf("%s/cloudview-api/rest/v1/resource/%s/%s", c.gatewayURL, rt, p)

	params := url.Values{}
	params.Set("pageNo", "0")
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	} else {
		params.Set("pageSize", "100")
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Resource{}, nil
	}

	var resp ResourcesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var resources []Resource
		if err2 := json.Unmarshal(data, &resources); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return resources, nil
	}

	return resp.Content, nil
}

func (c *Client) ListControls(ctx context.Context, provider string, limit int) ([]Control, error) {
	p := strings.ToUpper(provider)
	if p == "" {
		p = "AWS"
	}

	endpoint := fmt.Sprintf("%s/cloudview-api/rest/v1/controls/metadata/list", c.gatewayURL)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("provider:%s", p))
	params.Set("pageNo", "0")
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	} else {
		params.Set("pageSize", "100")
	}

	fullURL := endpoint + "?" + params.Encode()
	data, err := c.http.Get(ctx, fullURL)
	if err != nil {
		return nil, fmt.Errorf("API error at %s: %w", fullURL, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty response from %s", fullURL)
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(data, &rawResp); err == nil {
		controlList, ok := rawResp["control"].([]interface{})
		if !ok {
			if content, ok := rawResp["content"].([]interface{}); ok {
				controlList = content
			}
		}
		if controlList != nil {
			controls := make([]Control, 0, len(controlList))
			for _, item := range controlList {
				if m, ok := item.(map[string]interface{}); ok {
					ctrl := Control{}
					if v, ok := m["cid"].(float64); ok {
						ctrl.ControlID = fmt.Sprintf("%.0f", v)
					} else if v, ok := m["cid"].(string); ok {
						ctrl.ControlID = v
					}
					if v, ok := m["controlName"].(string); ok {
						ctrl.Name = v
					}
					if v, ok := m["criticality"].(string); ok {
						ctrl.Criticality = v
					}
					if v, ok := m["service"].(string); ok {
						ctrl.Service = v
					}
					if v, ok := m["controlCategoryName"].(string); ok {
						ctrl.Category = v
					}
					if v, ok := m["provider"].(string); ok {
						ctrl.Provider = v
					}
					if v, ok := m["controlType"].(string); ok {
						ctrl.ControlType = v
					}
					controls = append(controls, ctrl)
				}
			}
			return controls, nil
		}
		return nil, fmt.Errorf("unexpected response structure: %s", string(data[:min(len(data), 500)]))
	}

	return nil, fmt.Errorf("parse response: (raw: %s)", string(data[:min(len(data), 500)]))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *Client) GetControlEvaluations(ctx context.Context, controlID string, accountID string, provider string, limit int) ([]Evaluation, error) {
	p := strings.ToLower(provider)
	if p == "" {
		p = "aws"
	}
	endpoint := fmt.Sprintf("%s/cloudview-api/rest/v1/%s/evaluations/%s", c.gatewayURL, p, accountID)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("controlId:%s", controlID))
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Evaluation{}, nil
	}

	var resp EvaluationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var evals []Evaluation
		if err2 := json.Unmarshal(data, &evals); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return evals, nil
	}

	return resp.Content, nil
}

func (c *Client) GetResourceEvaluations(ctx context.Context, resourceID string, accountID string, provider string, limit int) ([]Evaluation, error) {
	p := strings.ToLower(provider)
	if p == "" {
		p = "aws"
	}
	endpoint := fmt.Sprintf("%s/cloudview-api/rest/v1/%s/evaluations/%s", c.gatewayURL, p, accountID)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("resourceId:%s", resourceID))
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Evaluation{}, nil
	}

	var resp EvaluationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var evals []Evaluation
		if err2 := json.Unmarshal(data, &evals); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return evals, nil
	}

	return resp.Content, nil
}

type EvaluationStats struct {
	TotalEvaluations int            `json:"totalEvaluations"`
	ByStatus         map[string]int `json:"byStatus"`
	FailedControls   int            `json:"failedControls"`
	PassedControls   int            `json:"passedControls"`
	TopFailures      []Evaluation   `json:"topFailures,omitempty"`
}

func GetEvaluationStats(evals []Evaluation, topN int) *EvaluationStats {
	stats := &EvaluationStats{
		TotalEvaluations: len(evals),
		ByStatus:         make(map[string]int),
	}

	failedControls := make(map[string]bool)
	passedControls := make(map[string]bool)
	var failures []Evaluation

	for _, e := range evals {
		stats.ByStatus[e.Status]++
		if e.Status == "FAIL" || e.Status == "FAILED" {
			failedControls[e.ControlID] = true
			failures = append(failures, e)
		} else if e.Status == "PASS" || e.Status == "PASSED" {
			passedControls[e.ControlID] = true
		}
	}

	stats.FailedControls = len(failedControls)
	stats.PassedControls = len(passedControls)

	for i := 0; i < len(failures) && i < topN; i++ {
		stats.TopFailures = append(stats.TopFailures, failures[i])
	}

	return stats
}

func (c *Client) ListEvaluations(ctx context.Context, accountID string, provider string, limit int) ([]Evaluation, error) {
	p := strings.ToLower(provider)
	if p == "" {
		p = "aws"
	}
	endpoint := fmt.Sprintf("%s/cloudview-api/rest/v1/%s/evaluations/%s", c.gatewayURL, p, accountID)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Evaluation{}, nil
	}

	var resp EvaluationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var evals []Evaluation
		if err2 := json.Unmarshal(data, &evals); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return evals, nil
	}

	return resp.Content, nil
}

func (c *Client) ListCDRFindings(ctx context.Context, provider string, severity string, days int, limit int) ([]CDRFinding, error) {
	endpoint := fmt.Sprintf("%s/cdr-api/rest/v1/findings/", c.gatewayURL)

	now := time.Now().UTC()
	if days <= 0 {
		days = 7
	}
	startTime := now.AddDate(0, 0, -days)

	params := url.Values{}
	params.Set("startAt", startTime.Format(time.RFC3339))
	params.Set("endAt", now.Format(time.RFC3339))

	if provider != "" {
		params.Set("cloudProvider", strings.ToUpper(provider))
	}
	if severity != "" {
		params.Set("severity", strings.ToUpper(severity))
	}
	if limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", limit))
	} else {
		params.Set("limit", "100")
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []CDRFinding{}, nil
	}

	var resp CDRFindingsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var findings []CDRFinding
		if err2 := json.Unmarshal(data, &findings); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return findings, nil
	}

	return resp.Content, nil
}
