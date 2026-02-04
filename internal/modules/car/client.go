package car

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

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

type Script struct {
	ID            interface{} `json:"id,omitempty"`
	Title         string      `json:"title,omitempty"`
	Description   string      `json:"description,omitempty"`
	Platform      string      `json:"platform,omitempty"`
	Language      string      `json:"language,omitempty"`
	Type          string      `json:"type,omitempty"`
	Subtype       string      `json:"subtype,omitempty"`
	Category      string      `json:"category,omitempty"`
	Severity      int         `json:"severity,omitempty"`
	Status        string      `json:"status,omitempty"`
	CreatedDate   string      `json:"createdDate,omitempty"`
	ModifiedDate  string      `json:"modifiedDate,omitempty"`
	CreatedBy     string      `json:"createdBy,omitempty"`
}

type ScriptJob struct {
	JobID           interface{} `json:"jobId,omitempty"`
	CorrelationUUID string      `json:"correlationUuid,omitempty"`
	ScriptID        interface{} `json:"scriptId,omitempty"`
	ScriptTitle     string      `json:"scriptTitle,omitempty"`
	Status          string      `json:"status,omitempty"`
	AssetCount      int         `json:"assetCount,omitempty"`
	SuccessCount    int         `json:"successCount,omitempty"`
	FailedCount     int         `json:"failedCount,omitempty"`
	StartTime       string      `json:"startTime,omitempty"`
	EndTime         string      `json:"endTime,omitempty"`
}

type JobResult struct {
	AssetID     interface{} `json:"assetId,omitempty"`
	AssetName   string      `json:"assetName,omitempty"`
	Status      string      `json:"status,omitempty"`
	Output      string      `json:"output,omitempty"`
	ExitCode    int         `json:"exitCode,omitempty"`
	ExecutedAt  string      `json:"executedAt,omitempty"`
}

type ScriptsResponse struct {
	Scripts []Script `json:"scripts,omitempty"`
	Content []Script `json:"content,omitempty"`
	Count   int      `json:"count,omitempty"`
}

type JobsResponse struct {
	Jobs    []ScriptJob `json:"jobs,omitempty"`
	Content []ScriptJob `json:"content,omitempty"`
	Count   int         `json:"count,omitempty"`
}

type JobResultsResponse struct {
	Results []JobResult `json:"results,omitempty"`
	Content []JobResult `json:"content,omitempty"`
	Count   int         `json:"count,omitempty"`
}

type ExecuteResponse struct {
	CorrelationUUID string `json:"correlationUuid,omitempty"`
	Message         string `json:"message,omitempty"`
}

func (c *Client) ListScripts(ctx context.Context, platform string, scriptType string, limit int) ([]Script, error) {
	endpoint := fmt.Sprintf("%s/sm/v1/scripts/search", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	} else {
		params.Set("pageSize", "100")
	}

	filters := make(map[string]interface{})
	if platform != "" {
		filters["platform"] = platform
	}
	if scriptType != "" {
		filters["type"] = scriptType
	}

	var data []byte
	var err error

	if len(filters) > 0 {
		body, _ := json.Marshal(filters)
		data, err = c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "application/json")
		if err != nil {
			data, err = c.http.Get(ctx, endpoint+"?"+params.Encode())
		}
		_ = body
	} else {
		data, err = c.http.Get(ctx, endpoint+"?"+params.Encode())
	}

	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Script{}, nil
	}

	var resp ScriptsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var scripts []Script
		if err2 := json.Unmarshal(data, &scripts); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return scripts, nil
	}

	if len(resp.Content) > 0 {
		return resp.Content, nil
	}
	return resp.Scripts, nil
}

func (c *Client) GetScript(ctx context.Context, scriptID string) (*Script, error) {
	endpoint := fmt.Sprintf("%s/sm/v1/scripts/%s", c.gatewayURL, scriptID)

	data, err := c.http.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var script Script
	if err := json.Unmarshal(data, &script); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &script, nil
}

func (c *Client) ExecuteScript(ctx context.Context, scriptID string, assetIDs []string, assetTagIDs []string, testMode bool) (*ExecuteResponse, error) {
	endpoint := fmt.Sprintf("%s/sm/v1/scripts/%s/execute", c.gatewayURL, scriptID)

	reqBody := map[string]interface{}{
		"testMode": testMode,
	}

	if len(assetIDs) > 0 {
		reqBody["assetIds"] = assetIDs
	}
	if len(assetTagIDs) > 0 {
		reqBody["assetTagIds"] = assetTagIDs
	}

	body, _ := json.Marshal(reqBody)
	data, err := c.http.Post(ctx, endpoint, nil, "application/json")
	if err != nil {
		return nil, err
	}
	_ = body

	var resp ExecuteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &resp, nil
}

func (c *Client) ListJobs(ctx context.Context, status string, limit int) ([]ScriptJob, error) {
	endpoint := fmt.Sprintf("%s/sm/v1/jobs/search", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	} else {
		params.Set("pageSize", "100")
	}

	filters := make(map[string]interface{})
	if status != "" {
		filters["status"] = status
	}

	var data []byte
	var err error

	data, err = c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []ScriptJob{}, nil
	}

	var resp JobsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var jobs []ScriptJob
		if err2 := json.Unmarshal(data, &jobs); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return jobs, nil
	}

	if len(resp.Content) > 0 {
		return resp.Content, nil
	}
	return resp.Jobs, nil
}

func (c *Client) GetJobResults(ctx context.Context, jobID string, limit int) ([]JobResult, error) {
	endpoint := fmt.Sprintf("%s/sm/v1/jobs/%s/results", c.gatewayURL, jobID)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []JobResult{}, nil
	}

	var resp JobResultsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var results []JobResult
		if err2 := json.Unmarshal(data, &results); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return results, nil
	}

	if len(resp.Content) > 0 {
		return resp.Content, nil
	}
	return resp.Results, nil
}

func (c *Client) ListRemediationScripts(ctx context.Context, limit int) ([]Script, error) {
	return c.ListScripts(ctx, "", "REMEDIATION", limit)
}

func (c *Client) ListDetectionScripts(ctx context.Context, limit int) ([]Script, error) {
	return c.ListScripts(ctx, "", "DETECTION", limit)
}
