package patch

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

type Patch struct {
	ID          interface{} `json:"id,omitempty"`
	QID         int         `json:"qid,omitempty"`
	Name        string      `json:"name,omitempty"`
	Vendor      string      `json:"vendor,omitempty"`
	Category    string      `json:"category,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	CVEs        interface{} `json:"cves,omitempty"`
	ReleaseDate string      `json:"releaseDate,omitempty"`
	IsSupported bool        `json:"isSupported,omitempty"`
}

type Asset struct {
	ID            interface{} `json:"id,omitempty"`
	Name          string      `json:"name,omitempty"`
	IP            string      `json:"address,omitempty"`
	OS            string      `json:"operatingSystem,omitempty"`
	PatchCount    int         `json:"missingPatchCount,omitempty"`
	LastScanned   string      `json:"lastScanned,omitempty"`
	AgentID       string      `json:"agentId,omitempty"`
}

type Job struct {
	ID          interface{} `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Status      string      `json:"status,omitempty"`
	Type        string      `json:"type,omitempty"`
	Priority    string      `json:"priority,omitempty"`
	Created     string      `json:"created,omitempty"`
	Started     string      `json:"started,omitempty"`
	Completed   string      `json:"completed,omitempty"`
	TargetCount int         `json:"targetCount,omitempty"`
	SuccessCount int        `json:"successCount,omitempty"`
	FailedCount int         `json:"failedCount,omitempty"`
}

type PatchesResponse struct {
	Data  []Patch `json:"data"`
	Count int     `json:"count,omitempty"`
}

type AssetsResponse struct {
	Data  []Asset `json:"data"`
	Count int     `json:"count,omitempty"`
}

type JobsResponse struct {
	Data  []Job `json:"data"`
	Count int   `json:"count,omitempty"`
}

func (c *Client) ListPatches(ctx context.Context, filter string, limit int) ([]Patch, error) {
	endpoint := fmt.Sprintf("%s/pm/v1/patches", c.gatewayURL)

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
		return []Patch{}, nil
	}

	var resp PatchesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var patches []Patch
		if err2 := json.Unmarshal(data, &patches); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return patches, nil
	}

	return resp.Data, nil
}

func (c *Client) ListAssets(ctx context.Context, filter string, limit int) ([]Asset, error) {
	endpoint := fmt.Sprintf("%s/pm/v1/assets", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	body := "{}"
	if filter != "" {
		body = fmt.Sprintf(`{"filter":"%s"}`, filter)
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Asset{}, nil
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(data, &rawResp); err == nil {
		if assetList, ok := rawResp["data"].([]interface{}); ok {
			assets := make([]Asset, 0, len(assetList))
			for _, item := range assetList {
				assetData, _ := json.Marshal(item)
				var a Asset
				json.Unmarshal(assetData, &a)
				assets = append(assets, a)
			}
			return assets, nil
		}
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

func (c *Client) ListJobs(ctx context.Context, status string, limit int) ([]Job, error) {
	endpoint := fmt.Sprintf("%s/pm/v1/deploymentjobs", c.gatewayURL)

	params := url.Values{}
	if status != "" {
		params.Set("filter", fmt.Sprintf("status:%s", status))
	}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Job{}, nil
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(data, &rawResp); err == nil {
		if jobList, ok := rawResp["data"].([]interface{}); ok {
			jobs := make([]Job, 0, len(jobList))
			for _, item := range jobList {
				jobData, _ := json.Marshal(item)
				var j Job
				json.Unmarshal(jobData, &j)
				jobs = append(jobs, j)
			}
			return jobs, nil
		}
	}

	var resp JobsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var jobs []Job
		if err2 := json.Unmarshal(data, &jobs); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return jobs, nil
	}

	return resp.Data, nil
}

func (c *Client) GetJobDetails(ctx context.Context, jobID string) (*Job, error) {
	endpoint := fmt.Sprintf("%s/pm/v1/deploymentjob/%s", c.gatewayURL, jobID)

	data, err := c.http.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &job, nil
}

func (c *Client) GetAssetPatches(ctx context.Context, assetID string, limit int) ([]Patch, error) {
	endpoint := fmt.Sprintf("%s/pm/v1/assets/%s/patches", c.gatewayURL, assetID)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Patch{}, nil
	}

	var resp PatchesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var patches []Patch
		if err2 := json.Unmarshal(data, &patches); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return patches, nil
	}

	return resp.Data, nil
}
