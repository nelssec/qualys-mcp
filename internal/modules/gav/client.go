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

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	if filter != "" {
		params.Set("filter", filter)
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
	if err != nil {
		return nil, err
	}

	var resp HostListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.AssetListData.Asset, nil
}

func (c *Client) SearchAssets(ctx context.Context, query string, limit int) ([]Asset, error) {
	endpoint := fmt.Sprintf("%s/am/v1/assets/host/list", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	if query != "" {
		params.Set("filter", query)
	}

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
	if err != nil {
		return nil, err
	}

	var resp HostListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.AssetListData.Asset, nil
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

type EOLSoftware struct {
	Name        string      `json:"name"`
	Version     string      `json:"version,omitempty"`
	Vendor      string      `json:"vendor,omitempty"`
	EOLDate     string      `json:"eolDate,omitempty"`
	EOSDate     string      `json:"eosDate,omitempty"`
	IsSupported bool        `json:"isSupported"`
	AssetCount  int         `json:"assetCount"`
	Category    string      `json:"category,omitempty"`
}

type EOLAsset struct {
	AssetID      interface{} `json:"assetId"`
	IP           interface{} `json:"address,omitempty"`
	Hostname     interface{} `json:"dnsHostName,omitempty"`
	OS           interface{} `json:"operatingSystem,omitempty"`
	Criticality  interface{} `json:"criticality,omitempty"`
	EOLSoftware  []string    `json:"eolSoftware,omitempty"`
	EOSSoftware  []string    `json:"eosSoftware,omitempty"`
}

type SoftwareLifecycleResponse struct {
	AssetListData struct {
		Asset []struct {
			AssetID     interface{} `json:"assetId"`
			IP          interface{} `json:"address,omitempty"`
			Hostname    interface{} `json:"dnsHostName,omitempty"`
			OS          interface{} `json:"operatingSystem,omitempty"`
			Criticality interface{} `json:"criticality,omitempty"`
			Software    []struct {
				Name      string `json:"name"`
				Version   string `json:"version,omitempty"`
				Vendor    string `json:"vendor,omitempty"`
				Category  string `json:"category,omitempty"`
				Lifecycle struct {
					EOLDate     string `json:"eolDate,omitempty"`
					EOSDate     string `json:"eosDate,omitempty"`
					IsSupported bool   `json:"isSupported"`
				} `json:"lifecycle,omitempty"`
			} `json:"software,omitempty"`
		} `json:"asset"`
	} `json:"assetListData"`
}

func (c *Client) GetEOLSoftware(ctx context.Context, limit int) ([]EOLAsset, error) {
	endpoint := fmt.Sprintf("%s/am/v1/assets/host/list", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	params.Set("filter", "software.lifecycle.eolDate:[* TO now]")
	params.Set("fields", "assetId,address,dnsHostName,operatingSystem,criticality,software")

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
	if err != nil {
		return nil, err
	}

	var resp SoftwareLifecycleResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	var result []EOLAsset
	for _, a := range resp.AssetListData.Asset {
		asset := EOLAsset{
			AssetID:     a.AssetID,
			IP:          a.IP,
			Hostname:    a.Hostname,
			OS:          a.OS,
			Criticality: a.Criticality,
		}
		for _, sw := range a.Software {
			if sw.Lifecycle.EOLDate != "" {
				asset.EOLSoftware = append(asset.EOLSoftware, fmt.Sprintf("%s %s", sw.Name, sw.Version))
			}
		}
		if len(asset.EOLSoftware) > 0 {
			result = append(result, asset)
		}
	}

	return result, nil
}

func (c *Client) GetEOSSoftware(ctx context.Context, limit int) ([]EOLAsset, error) {
	endpoint := fmt.Sprintf("%s/am/v1/assets/host/list", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	params.Set("filter", "software.lifecycle.eosDate:[* TO now]")
	params.Set("fields", "assetId,address,dnsHostName,operatingSystem,criticality,software")

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
	if err != nil {
		return nil, err
	}

	var resp SoftwareLifecycleResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	var result []EOLAsset
	for _, a := range resp.AssetListData.Asset {
		asset := EOLAsset{
			AssetID:     a.AssetID,
			IP:          a.IP,
			Hostname:    a.Hostname,
			OS:          a.OS,
			Criticality: a.Criticality,
		}
		for _, sw := range a.Software {
			if sw.Lifecycle.EOSDate != "" {
				asset.EOSSoftware = append(asset.EOSSoftware, fmt.Sprintf("%s %s", sw.Name, sw.Version))
			}
		}
		if len(asset.EOSSoftware) > 0 {
			result = append(result, asset)
		}
	}

	return result, nil
}

func (c *Client) GetUnsupportedSoftwareAssets(ctx context.Context, limit int) ([]EOLAsset, error) {
	endpoint := fmt.Sprintf("%s/am/v1/assets/host/list", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	params.Set("filter", "software.isSupported:false")
	params.Set("fields", "assetId,address,dnsHostName,operatingSystem,criticality,software")

	data, err := c.http.Post(ctx, endpoint+"?"+params.Encode(), nil, "")
	if err != nil {
		return nil, err
	}

	var resp SoftwareLifecycleResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	var result []EOLAsset
	for _, a := range resp.AssetListData.Asset {
		asset := EOLAsset{
			AssetID:     a.AssetID,
			IP:          a.IP,
			Hostname:    a.Hostname,
			OS:          a.OS,
			Criticality: a.Criticality,
		}
		for _, sw := range a.Software {
			if !sw.Lifecycle.IsSupported {
				asset.EOLSoftware = append(asset.EOLSoftware, fmt.Sprintf("%s %s", sw.Name, sw.Version))
			}
		}
		if len(asset.EOLSoftware) > 0 {
			result = append(result, asset)
		}
	}

	return result, nil
}
