package gav

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/common"
)

type Client struct {
	http        *common.HTTPClient
	gatewayURL  string
	classicHTTP *common.HTTPClient
	classicURL  string
}

func NewClient(http *common.HTTPClient, gatewayURL string, classicHTTP *common.HTTPClient, classicURL string) *Client {
	return &Client{
		http:        http,
		gatewayURL:  gatewayURL,
		classicHTTP: classicHTTP,
		classicURL:  classicURL,
	}
}

type Asset struct {
	AssetID       interface{} `json:"assetId"`
	IP            interface{} `json:"address,omitempty"`
	Hostname      interface{} `json:"dnsHostName,omitempty"`
	NetbiosName   interface{} `json:"netbiosName,omitempty"`
	OS            interface{} `json:"operatingSystem,omitempty"`
	LastSeen      interface{} `json:"lastModifiedDate,omitempty"`
	Tags          interface{} `json:"tags,omitempty"`
	AgentID       interface{} `json:"agentId,omitempty"`
	CloudProvider interface{} `json:"cloudProvider,omitempty"`
	AssetType     interface{} `json:"assetType,omitempty"`
	AssetName     interface{} `json:"assetName,omitempty"`
	TruRiskScore  interface{} `json:"truriskScore,omitempty"`
	Criticality   interface{} `json:"criticality,omitempty"`
	ACS           interface{} `json:"assetCriticalityScore,omitempty"`
}

type Tag struct {
	ID   interface{} `json:"id"`
	Name string      `json:"name"`
}

type AssetDetails struct {
	Asset
	Interfaces interface{} `json:"networkInterfaces,omitempty"`
	Software   interface{} `json:"software,omitempty"`
	OpenPorts  interface{} `json:"openPorts,omitempty"`
	VulnCount  interface{} `json:"vulnCount"`
}

type Interface struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MAC     string `json:"macAddress,omitempty"`
}

type Software struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
}

type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"serviceName,omitempty"`
}

type ListAssetsResponse struct {
	Data          []Asset     `json:"assetListData"`
	HasMore       interface{} `json:"hasMore"`
	LastSeenAsset interface{} `json:"lastSeenAssetId,omitempty"`
}

type HostListResponse struct {
	AssetListData struct {
		Asset []Asset `json:"asset"`
	} `json:"assetListData"`
	HasMore       interface{} `json:"hasMore"`
	LastSeenAsset interface{} `json:"lastSeenAssetId,omitempty"`
}

type ListTagsResponse struct {
	Data []Tag `json:"data"`
}

type TagListResponse struct {
	Count int   `json:"count"`
	Data  []Tag `json:"data"`
}

func (c *Client) ListAssets(ctx context.Context, filter string, limit int) ([]Asset, error) {
	endpoint := fmt.Sprintf("%s/am/v1/assets/host/list", c.gatewayURL)

	var result []Asset
	var lastSeenID interface{}
	pageSize := 300
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}
	maxAssets := 10000
	if limit > 0 && limit < maxAssets {
		maxAssets = limit
	}

	for {
		params := url.Values{}
		params.Set("pageSize", fmt.Sprintf("%d", pageSize))
		if filter != "" {
			params.Set("filter", filter)
		}
		if lastSeenID != nil {
			params.Set("lastSeenAssetId", fmt.Sprintf("%v", lastSeenID))
		}

		data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
		if err != nil {
			return nil, err
		}

		var resp HostListResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		result = append(result, resp.AssetListData.Asset...)

		hasMore := false
		if hm, ok := resp.HasMore.(bool); ok {
			hasMore = hm
		}

		if !hasMore || resp.LastSeenAsset == nil {
			break
		}
		if len(result) >= maxAssets {
			break
		}
		lastSeenID = resp.LastSeenAsset
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

func (c *Client) CountAssets(ctx context.Context, filter string) (int, error) {
	assets, err := c.ListAssets(ctx, filter, 0)
	if err != nil {
		return 0, err
	}
	return len(assets), nil
}

func (c *Client) SearchAssets(ctx context.Context, query string, limit int) ([]Asset, error) {
	return c.ListAssets(ctx, query, limit)
}

func (c *Client) GetAssetDetails(ctx context.Context, assetID string) (*AssetDetails, error) {
	endpoint := fmt.Sprintf("%s/am/v1/assets/host/list", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", "1")
	params.Set("filter", fmt.Sprintf("assetId:%s", assetID))

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
	if err != nil {
		return nil, err
	}

	var resp HostListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(resp.AssetListData.Asset) == 0 {
		return nil, fmt.Errorf("asset not found: %s", assetID)
	}

	asset := resp.AssetListData.Asset[0]
	return &AssetDetails{Asset: asset}, nil
}

type TagSearchXMLResponse struct {
	XMLName      xml.Name `xml:"ServiceResponse"`
	ResponseCode string   `xml:"responseCode"`
	Count        int      `xml:"count"`
	Data         struct {
		Tags []TagXML `xml:"Tag"`
	} `xml:"data"`
}

type TagXML struct {
	ID       int    `xml:"id"`
	Name     string `xml:"name"`
	TagUUID  string `xml:"tagUuid"`
	Created  string `xml:"created"`
	Modified string `xml:"modified"`
}

func (c *Client) ListTags(ctx context.Context) ([]Tag, error) {
	if c.classicHTTP == nil {
		return nil, fmt.Errorf("classic API client not configured for tags")
	}

	endpoint := fmt.Sprintf("%s/qps/rest/2.0/search/am/tag", c.classicURL)

	xmlBody := `<ServiceRequest><preferences><limitResults>100</limitResults></preferences></ServiceRequest>`
	data, err := c.classicHTTP.Post(ctx, endpoint, strings.NewReader(xmlBody), "text/xml")
	if err != nil {
		return nil, err
	}

	var resp TagSearchXMLResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.ResponseCode != "SUCCESS" {
		return nil, fmt.Errorf("API error: %s", resp.ResponseCode)
	}

	tags := make([]Tag, 0, len(resp.Data.Tags))
	for _, t := range resp.Data.Tags {
		tags = append(tags, Tag{
			ID:   fmt.Sprintf("%d", t.ID),
			Name: t.Name,
		})
	}

	return tags, nil
}

func (c *Client) GetAssetsByTag(ctx context.Context, tagID string, limit int) ([]Asset, error) {
	filter := fmt.Sprintf("tags.id:%s", tagID)
	return c.SearchAssets(ctx, filter, limit)
}

func (c *Client) GetHighRiskAssets(ctx context.Context, minTruRisk int, minCriticality int, limit int) ([]Asset, error) {
	var filters []string

	if minTruRisk > 0 {
		filters = append(filters, fmt.Sprintf("truriskScore:[%d-1000]", minTruRisk))
	}
	if minCriticality > 0 {
		filters = append(filters, fmt.Sprintf("criticality:%d", minCriticality))
	}

	filter := ""
	if len(filters) > 0 {
		filter = filters[0]
		for i := 1; i < len(filters); i++ {
			filter = fmt.Sprintf("%s and %s", filter, filters[i])
		}
	}

	return c.SearchAssets(ctx, filter, limit)
}

type EOLAsset struct {
	AssetID     interface{} `json:"assetId"`
	IP          interface{} `json:"address,omitempty"`
	Hostname    interface{} `json:"dnsHostName,omitempty"`
	OS          interface{} `json:"operatingSystem,omitempty"`
	Criticality interface{} `json:"criticality,omitempty"`
	OSLifecycle *OSLifecycle `json:"osLifecycle,omitempty"`
	HWLifecycle *HWLifecycle `json:"hwLifecycle,omitempty"`
}

type OSLifecycle struct {
	Stage   string `json:"stage,omitempty"`
	EOLDate string `json:"eolDate,omitempty"`
	EOSDate string `json:"eosDate,omitempty"`
}

type HWLifecycle struct {
	Stage   string `json:"stage,omitempty"`
	EOSDate string `json:"eosDate,omitempty"`
	OBSDate string `json:"obsDate,omitempty"`
}

type LifecycleFilterRequest struct {
	Filters   []LifecycleFilter `json:"filters"`
	Operation string            `json:"operation,omitempty"`
}

type LifecycleFilter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type V2AssetResponse struct {
	AssetListData struct {
		Asset []struct {
			AssetID     interface{} `json:"assetId"`
			Address     interface{} `json:"address,omitempty"`
			DnsHostName interface{} `json:"dnsHostName,omitempty"`
			Criticality interface{} `json:"criticality,omitempty"`
			OperatingSystem struct {
				Name      string `json:"osName,omitempty"`
				FullName  string `json:"fullName,omitempty"`
				Version   string `json:"version,omitempty"`
				Lifecycle struct {
					Stage   string `json:"stage,omitempty"`
					EolDate string `json:"eolDate,omitempty"`
					EosDate string `json:"eosDate,omitempty"`
				} `json:"lifecycle,omitempty"`
			} `json:"operatingSystem,omitempty"`
			Hardware struct {
				Name      string `json:"name,omitempty"`
				Model     string `json:"model,omitempty"`
				Lifecycle struct {
					Stage   string `json:"stage,omitempty"`
					EosDate string `json:"eosDate,omitempty"`
					ObsDate string `json:"obsDate,omitempty"`
				} `json:"lifecycle,omitempty"`
			} `json:"hardware,omitempty"`
		} `json:"asset"`
	} `json:"assetListData"`
	HasMore          interface{} `json:"hasMore"`
	LastSeenAssetId  interface{} `json:"lastSeenAssetId,omitempty"`
}

func (c *Client) GetEOLAssets(ctx context.Context, limit int) ([]EOLAsset, error) {
	endpoint := fmt.Sprintf("%s/rest/2.0/search/am/asset", c.gatewayURL)

	filterReq := LifecycleFilterRequest{
		Filters: []LifecycleFilter{
			{Field: "operatingSystem.lifecycle.stage", Operator: "IN", Value: "EOL,EOL/EOS"},
		},
	}

	filterJSON, _ := json.Marshal(filterReq)

	var result []EOLAsset
	var lastSeenID interface{}
	pageSize := 300
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}

	for {
		params := url.Values{}
		params.Set("pageSize", fmt.Sprintf("%d", pageSize))
		if lastSeenID != nil {
			params.Set("lastSeenAssetId", fmt.Sprintf("%v", lastSeenID))
		}

		data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(string(filterJSON)), "application/json")
		if err != nil {
			return nil, err
		}

		var resp V2AssetResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		for _, a := range resp.AssetListData.Asset {
			osName := ""
			if a.OperatingSystem.Name != "" {
				osName = a.OperatingSystem.Name
				if a.OperatingSystem.Version != "" {
					osName = osName + " " + a.OperatingSystem.Version
				}
			}

			asset := EOLAsset{
				AssetID:     a.AssetID,
				IP:          a.Address,
				Hostname:    a.DnsHostName,
				OS:          osName,
				Criticality: a.Criticality,
			}
			if a.OperatingSystem.Lifecycle.Stage != "" {
				asset.OSLifecycle = &OSLifecycle{
					Stage:   a.OperatingSystem.Lifecycle.Stage,
					EOLDate: a.OperatingSystem.Lifecycle.EolDate,
					EOSDate: a.OperatingSystem.Lifecycle.EosDate,
				}
			}
			result = append(result, asset)
		}

		hasMore := false
		if hm, ok := resp.HasMore.(float64); ok && hm > 0 {
			hasMore = true
		}
		if !hasMore || resp.LastSeenAssetId == nil {
			break
		}
		if limit > 0 && len(result) >= limit {
			break
		}
		lastSeenID = resp.LastSeenAssetId
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

func (c *Client) GetEOSAssets(ctx context.Context, limit int) ([]EOLAsset, error) {
	endpoint := fmt.Sprintf("%s/rest/2.0/search/am/asset", c.gatewayURL)

	filterReq := LifecycleFilterRequest{
		Filters: []LifecycleFilter{
			{Field: "operatingSystem.lifecycle.stage", Operator: "EQUALS", Value: "EOL/EOS"},
		},
	}

	filterJSON, _ := json.Marshal(filterReq)

	var result []EOLAsset
	var lastSeenID interface{}
	pageSize := 300
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}

	for {
		params := url.Values{}
		params.Set("pageSize", fmt.Sprintf("%d", pageSize))
		if lastSeenID != nil {
			params.Set("lastSeenAssetId", fmt.Sprintf("%v", lastSeenID))
		}

		data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(string(filterJSON)), "application/json")
		if err != nil {
			return nil, err
		}

		var resp V2AssetResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		for _, a := range resp.AssetListData.Asset {
			osName := ""
			if a.OperatingSystem.Name != "" {
				osName = a.OperatingSystem.Name
				if a.OperatingSystem.Version != "" {
					osName = osName + " " + a.OperatingSystem.Version
				}
			}

			asset := EOLAsset{
				AssetID:     a.AssetID,
				IP:          a.Address,
				Hostname:    a.DnsHostName,
				OS:          osName,
				Criticality: a.Criticality,
			}
			if a.OperatingSystem.Lifecycle.Stage != "" {
				asset.OSLifecycle = &OSLifecycle{
					Stage:   a.OperatingSystem.Lifecycle.Stage,
					EOLDate: a.OperatingSystem.Lifecycle.EolDate,
					EOSDate: a.OperatingSystem.Lifecycle.EosDate,
				}
			}
			result = append(result, asset)
		}

		hasMore := false
		if hm, ok := resp.HasMore.(float64); ok && hm > 0 {
			hasMore = true
		}
		if !hasMore || resp.LastSeenAssetId == nil {
			break
		}
		if limit > 0 && len(result) >= limit {
			break
		}
		lastSeenID = resp.LastSeenAssetId
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

func (c *Client) GetEOLHardware(ctx context.Context, limit int) ([]EOLAsset, error) {
	endpoint := fmt.Sprintf("%s/rest/2.0/search/am/asset", c.gatewayURL)

	filterReq := LifecycleFilterRequest{
		Filters: []LifecycleFilter{
			{Field: "hardware.lifecycle.stage", Operator: "IN", Value: "EOS,OBS"},
		},
	}

	filterJSON, _ := json.Marshal(filterReq)

	var result []EOLAsset
	var lastSeenID interface{}
	pageSize := 300
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}

	for {
		params := url.Values{}
		params.Set("pageSize", fmt.Sprintf("%d", pageSize))
		if lastSeenID != nil {
			params.Set("lastSeenAssetId", fmt.Sprintf("%v", lastSeenID))
		}

		data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), strings.NewReader(string(filterJSON)), "application/json")
		if err != nil {
			return nil, err
		}

		var resp V2AssetResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		for _, a := range resp.AssetListData.Asset {
			asset := EOLAsset{
				AssetID:     a.AssetID,
				IP:          a.Address,
				Hostname:    a.DnsHostName,
				OS:          a.OperatingSystem.Name,
				Criticality: a.Criticality,
			}
			if a.Hardware.Lifecycle.Stage != "" {
				asset.HWLifecycle = &HWLifecycle{
					Stage:   a.Hardware.Lifecycle.Stage,
					EOSDate: a.Hardware.Lifecycle.EosDate,
					OBSDate: a.Hardware.Lifecycle.ObsDate,
				}
			}
			result = append(result, asset)
		}

		hasMore := false
		if hm, ok := resp.HasMore.(float64); ok && hm > 0 {
			hasMore = true
		}
		if !hasMore || resp.LastSeenAssetId == nil {
			break
		}
		if limit > 0 && len(result) >= limit {
			break
		}
		lastSeenID = resp.LastSeenAssetId
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}
