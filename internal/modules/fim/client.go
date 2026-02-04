package fim

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

type Event struct {
	ID          interface{} `json:"id,omitempty"`
	Type        string      `json:"type,omitempty"`
	Action      string      `json:"action,omitempty"`
	FilePath    string      `json:"filePath,omitempty"`
	FileName    string      `json:"fileName,omitempty"`
	OldHash     string      `json:"oldHash,omitempty"`
	NewHash     string      `json:"newHash,omitempty"`
	Timestamp   string      `json:"dateTime,omitempty"`
	AssetID     string      `json:"assetId,omitempty"`
	AssetName   string      `json:"hostName,omitempty"`
	UserName    string      `json:"userName,omitempty"`
	ProcessName string      `json:"processName,omitempty"`
	Severity    string      `json:"severity,omitempty"`
}

type Profile struct {
	ID          interface{} `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Status      string      `json:"status,omitempty"`
	RulesCount  int         `json:"rulesCount,omitempty"`
	AssetsCount int         `json:"assetsCount,omitempty"`
	Created     string      `json:"created,omitempty"`
	Modified    string      `json:"modified,omitempty"`
}

type Asset struct {
	ID          interface{} `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	IP          string      `json:"address,omitempty"`
	OS          string      `json:"operatingSystem,omitempty"`
	AgentID     string      `json:"agentId,omitempty"`
	AgentStatus string      `json:"agentStatus,omitempty"`
	EventCount  int         `json:"eventCount,omitempty"`
	LastEvent   string      `json:"lastEventTime,omitempty"`
}

type Incident struct {
	ID          interface{} `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Status      string      `json:"status,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	EventCount  int         `json:"eventCount,omitempty"`
	AssetCount  int         `json:"assetCount,omitempty"`
	Created     string      `json:"created,omitempty"`
	Updated     string      `json:"updated,omitempty"`
}

type EventsResponse struct {
	Data  []Event `json:"data"`
	Count int     `json:"count,omitempty"`
}

type ProfilesResponse struct {
	Data  []Profile `json:"data"`
	Count int       `json:"count,omitempty"`
}

type AssetsResponse struct {
	Data  []Asset `json:"data"`
	Count int     `json:"count,omitempty"`
}

type IncidentsResponse struct {
	Data  []Incident `json:"data"`
	Count int        `json:"count,omitempty"`
}

func (c *Client) ListEvents(ctx context.Context, action string, limit int) ([]Event, error) {
	endpoint := fmt.Sprintf("%s/fim/v2/events/search", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	filter := ""
	if action != "" {
		filter = fmt.Sprintf(`{"filter":"action:%s"}`, action)
	} else {
		filter = `{}`
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(filter), "application/json")
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Event{}, nil
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

func (c *Client) ListProfiles(ctx context.Context, limit int) ([]Profile, error) {
	endpoint := fmt.Sprintf("%s/fim/v3/profiles", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Profile{}, nil
	}

	var resp ProfilesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var profiles []Profile
		if err2 := json.Unmarshal(data, &profiles); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return profiles, nil
	}

	return resp.Data, nil
}

func (c *Client) ListAssets(ctx context.Context, filter string, limit int) ([]Asset, error) {
	endpoint := fmt.Sprintf("%s/fim/v3/assets", c.gatewayURL)

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

func (c *Client) ListIncidents(ctx context.Context, status string, limit int) ([]Incident, error) {
	endpoint := fmt.Sprintf("%s/fim/v3/incidents/search", c.gatewayURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	filter := ""
	if status != "" {
		filter = fmt.Sprintf(`{"filter":"status:%s"}`, status)
	} else {
		filter = `{}`
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(filter), "application/json")
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Incident{}, nil
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(data, &rawResp); err == nil {
		if incidentList, ok := rawResp["data"].([]interface{}); ok {
			incidents := make([]Incident, 0, len(incidentList))
			for _, item := range incidentList {
				incData, _ := json.Marshal(item)
				var inc Incident
				json.Unmarshal(incData, &inc)
				incidents = append(incidents, inc)
			}
			return incidents, nil
		}
	}

	var resp IncidentsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		var incidents []Incident
		if err2 := json.Unmarshal(data, &incidents); err2 != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return incidents, nil
	}

	return resp.Data, nil
}

func (c *Client) GetAssetEvents(ctx context.Context, assetID string, limit int) ([]Event, error) {
	endpoint := fmt.Sprintf("%s/fim/v3/assets/%s/events", c.gatewayURL, assetID)

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
