package edr

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

type Event struct {
	ID          interface{} `json:"id,omitempty"`
	Type        string      `json:"type,omitempty"`
	Name        string      `json:"name,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Score       float64     `json:"score,omitempty"`
	Timestamp   string      `json:"dateTime,omitempty"`
	AssetID     string      `json:"assetId,omitempty"`
	AssetName   string      `json:"assetName,omitempty"`
	FilePath    string      `json:"filePath,omitempty"`
	ProcessName string      `json:"processName,omitempty"`
	SHA256      string      `json:"sha256,omitempty"`
	Action      string      `json:"action,omitempty"`
}

type Indicator struct {
	ID          interface{} `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Type        string      `json:"type,omitempty"`
	Score       float64     `json:"score,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Category    string      `json:"category,omitempty"`
	ThreatName  string      `json:"threatName,omitempty"`
	Description string      `json:"description,omitempty"`
	FirstSeen   string      `json:"firstSeen,omitempty"`
	LastSeen    string      `json:"lastSeen,omitempty"`
}

type Asset struct {
	ID            interface{} `json:"id,omitempty"`
	Name          string      `json:"name,omitempty"`
	IP            string      `json:"address,omitempty"`
	OS            string      `json:"operatingSystem,omitempty"`
	AgentVersion  string      `json:"agentVersion,omitempty"`
	AgentStatus   string      `json:"agentStatus,omitempty"`
	LastCheckin   string      `json:"lastCheckin,omitempty"`
	EventCount    int         `json:"eventCount,omitempty"`
	IndicatorCount int        `json:"indicatorCount,omitempty"`
}

type EventsResponse struct {
	Data  []Event `json:"data"`
	Count int     `json:"count,omitempty"`
}

type IndicatorsResponse struct {
	Data  []Indicator `json:"data"`
	Count int         `json:"count,omitempty"`
}

type AssetsResponse struct {
	Data  []Asset `json:"data"`
	Count int     `json:"count,omitempty"`
}

func (c *Client) ListEvents(ctx context.Context, eventType string, limit int) ([]Event, error) {
	endpoint := fmt.Sprintf("%s/ioc/incidents/events/searchAfter", c.gatewayURL)

	params := url.Values{}
	if eventType != "" {
		params.Set("filter", fmt.Sprintf("type:%s", eventType))
	}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Event{}, nil
	}

	var rawEvents []map[string]interface{}
	if err := json.Unmarshal(data, &rawEvents); err == nil {
		events := make([]Event, 0, len(rawEvents))
		for _, item := range rawEvents {
			eventData, _ := json.Marshal(item)
			var evt Event
			json.Unmarshal(eventData, &evt)
			events = append(events, evt)
		}
		return events, nil
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(data, &rawResp); err == nil {
		if eventList, ok := rawResp["data"].([]interface{}); ok {
			events := make([]Event, 0, len(eventList))
			for _, item := range eventList {
				eventData, _ := json.Marshal(item)
				var evt Event
				json.Unmarshal(eventData, &evt)
				events = append(events, evt)
			}
			return events, nil
		}
	}

	return nil, fmt.Errorf("parse response: unexpected format (first 200 chars: %s)", string(data[:min(len(data), 200)]))
}

func (c *Client) ListIndicators(ctx context.Context, severity string, limit int) ([]Indicator, error) {
	endpoint := fmt.Sprintf("%s/ioc/indicators", c.gatewayURL)

	params := url.Values{}
	if severity != "" {
		params.Set("severity", severity)
	}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Indicator{}, nil
	}

	var resp IndicatorsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var indicators []Indicator
		if err2 := json.Unmarshal(data, &indicators); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return indicators, nil
	}

	return resp.Data, nil
}

func (c *Client) ListAssets(ctx context.Context, filter string, limit int) ([]Asset, error) {
	endpoint := fmt.Sprintf("%s/ioc/assets", c.gatewayURL)

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

func (c *Client) GetAssetEvents(ctx context.Context, assetID string, limit int) ([]Event, error) {
	endpoint := fmt.Sprintf("%s/ioc/assets/%s/events", c.gatewayURL, assetID)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Event{}, nil
	}

	var resp EventsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var events []Event
		if err2 := json.Unmarshal(data, &events); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return events, nil
	}

	return resp.Data, nil
}

func (c *Client) SearchEvents(ctx context.Context, query string, limit int) ([]Event, error) {
	endpoint := fmt.Sprintf("%s/ioc/incidents/events/searchAfter", c.gatewayURL)

	params := url.Values{}
	if query != "" {
		params.Set("filter", query)
	}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Event{}, nil
	}

	var events []Event
	if err := json.Unmarshal(data, &events); err == nil {
		return events, nil
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(data, &rawResp); err == nil {
		if eventList, ok := rawResp["data"].([]interface{}); ok {
			events = make([]Event, 0, len(eventList))
			for _, item := range eventList {
				eventData, _ := json.Marshal(item)
				var evt Event
				json.Unmarshal(eventData, &evt)
				events = append(events, evt)
			}
			return events, nil
		}
	}

	var resp EventsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Data, nil
}
