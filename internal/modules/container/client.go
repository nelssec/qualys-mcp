package container

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

type Image struct {
	ImageID     string      `json:"imageId"`
	SHA         string      `json:"sha,omitempty"`
	Registry    interface{} `json:"registry,omitempty"`
	Repository  interface{} `json:"repo,omitempty"`
	Tag         interface{} `json:"tag,omitempty"`
	Created     string      `json:"created,omitempty"`
	Size        int64       `json:"size,omitempty"`
	VulnCount   int         `json:"vulnCount"`
	Layers      interface{} `json:"layers,omitempty"`
}

type Container struct {
	ContainerID string      `json:"containerId"`
	Name        string      `json:"name,omitempty"`
	ImageID     string      `json:"imageId"`
	State       string      `json:"state"`
	Created     string      `json:"created,omitempty"`
	Host        interface{} `json:"host,omitempty"`
}

type ImageVulnerability struct {
	QID         int      `json:"qid"`
	Title       string   `json:"title"`
	Severity    int      `json:"severity"`
	CVEs        []string `json:"cveids,omitempty"`
	Package     string   `json:"packageName,omitempty"`
	Version     string   `json:"currentVersion,omitempty"`
	FixVersion  string   `json:"fixedVersion,omitempty"`
}

type ListImagesResponse struct {
	Data []Image `json:"data"`
}

type ListContainersResponse struct {
	Data []Container `json:"data"`
}

type ImageVulnsResponse struct {
	Data []ImageVulnerability `json:"data"`
}

func (c *Client) ListImages(ctx context.Context, filter string, limit int) ([]Image, error) {
	endpoint := fmt.Sprintf("%s/csapi/v1.3/images", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	if filter != "" {
		params.Set("filter", filter)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp ListImagesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Data, nil
}

func (c *Client) GetImageVulnerabilities(ctx context.Context, imageID string) ([]ImageVulnerability, error) {
	endpoint := fmt.Sprintf("%s/csapi/v1.3/images/%s/vuln", c.gatewayURL, imageID)

	data, err := c.http.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var resp ImageVulnsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Data, nil
}

func (c *Client) ListContainers(ctx context.Context, filter string, limit int) ([]Container, error) {
	endpoint := fmt.Sprintf("%s/csapi/v1.3/containers", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	if filter != "" {
		params.Set("filter", filter)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp ListContainersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Data, nil
}

func (c *Client) SearchImages(ctx context.Context, qql string, limit int) ([]Image, error) {
	endpoint := fmt.Sprintf("%s/csapi/v1.3/images", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	if qql != "" {
		params.Set("filter", qql)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []Image{}, nil
	}

	var resp ListImagesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Data, nil
}

func (c *Client) GetImageDetails(ctx context.Context, imageID string) (*Image, error) {
	endpoint := fmt.Sprintf("%s/csapi/v1.3/images/%s", c.gatewayURL, imageID)

	data, err := c.http.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var image Image
	if err := json.Unmarshal(data, &image); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &image, nil
}

type ImageVulnStats struct {
	TotalVulns   int            `json:"totalVulnerabilities"`
	BySeverity   map[int]int    `json:"bySeverity"`
	UniqueQIDs   int            `json:"uniqueQids"`
	TopVulns     []VulnSummary  `json:"topVulnerabilities"`
	AffectedPkgs int            `json:"affectedPackages"`
}

type VulnSummary struct {
	QID        int      `json:"qid"`
	Title      string   `json:"title"`
	Severity   int      `json:"severity"`
	CVEs       []string `json:"cves,omitempty"`
	Package    string   `json:"package,omitempty"`
	FixVersion string   `json:"fixVersion,omitempty"`
}

func GetImageVulnStats(vulns []ImageVulnerability, topN int) *ImageVulnStats {
	stats := &ImageVulnStats{
		TotalVulns: len(vulns),
		BySeverity: make(map[int]int),
	}

	qids := make(map[int]bool)
	pkgs := make(map[string]bool)

	for _, v := range vulns {
		stats.BySeverity[v.Severity]++
		qids[v.QID] = true
		if v.Package != "" {
			pkgs[v.Package] = true
		}
	}

	stats.UniqueQIDs = len(qids)
	stats.AffectedPkgs = len(pkgs)

	for i := 0; i < len(vulns) && i < topN; i++ {
		v := vulns[i]
		stats.TopVulns = append(stats.TopVulns, VulnSummary{
			QID:        v.QID,
			Title:      v.Title,
			Severity:   v.Severity,
			CVEs:       v.CVEs,
			Package:    v.Package,
			FixVersion: v.FixVersion,
		})
	}

	return stats
}

type VulnerableContainer struct {
	ContainerID   string      `json:"containerId"`
	ContainerName string      `json:"containerName"`
	ImageID       string      `json:"imageId"`
	ImageRepo     interface{} `json:"imageRepo"`
	State         string      `json:"state"`
	Host          interface{} `json:"host,omitempty"`
	VulnCount     int         `json:"vulnCount"`
	MaxQdsScore   int         `json:"maxQdsScore,omitempty"`
	QdsSeverity   string      `json:"qdsSeverity,omitempty"`
	RiskScore     int         `json:"riskScore,omitempty"`
}

type VulnContainerFilter struct {
	Severity    int
	QDS         int
	QDSSeverity string
	TruRisk     int
	CVE         string
	CustomQQL   string
}

func (f *VulnContainerFilter) ToQQL() string {
	var parts []string

	if f.Severity > 0 {
		parts = append(parts, fmt.Sprintf("vulnerabilities.severity:%d", f.Severity))
	}
	if f.QDS > 0 {
		parts = append(parts, fmt.Sprintf("maxQdsScore:[%d-100]", f.QDS))
	}
	if f.QDSSeverity != "" {
		parts = append(parts, fmt.Sprintf("qdsSeverity:%s", f.QDSSeverity))
	}
	if f.TruRisk > 0 {
		parts = append(parts, fmt.Sprintf("riskScore:[%d-1000]", f.TruRisk))
	}
	if f.CVE != "" {
		parts = append(parts, fmt.Sprintf("vulnerabilities.cveids:%s", f.CVE))
	}
	if f.CustomQQL != "" {
		parts = append(parts, f.CustomQQL)
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result = fmt.Sprintf("%s and %s", result, parts[i])
	}
	return result
}

type EOLImage struct {
	ImageID    string      `json:"imageId"`
	Repository interface{} `json:"repo,omitempty"`
	Tag        interface{} `json:"tag,omitempty"`
	Created    string      `json:"created,omitempty"`
	BaseOS     string      `json:"osName,omitempty"`
	EOLDate    string      `json:"eolDate,omitempty"`
	IsEOL      bool        `json:"isEol"`
}

type EOLImagesResponse struct {
	Data []struct {
		ImageID    string      `json:"imageId"`
		SHA        string      `json:"sha,omitempty"`
		Registry   interface{} `json:"registry,omitempty"`
		Repository interface{} `json:"repo,omitempty"`
		Tag        interface{} `json:"tag,omitempty"`
		Created    string      `json:"created,omitempty"`
		OSName     string      `json:"osName,omitempty"`
		IsEOL      bool        `json:"isEol"`
		EOLDate    string      `json:"eolDate,omitempty"`
	} `json:"data"`
}

func (c *Client) GetEOLImages(ctx context.Context, limit int) ([]EOLImage, error) {
	endpoint := fmt.Sprintf("%s/csapi/v1.3/images", c.gatewayURL)

	params := url.Values{}
	params.Set("pageSize", fmt.Sprintf("%d", limit))
	params.Set("filter", "isEol:true")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp EOLImagesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	var result []EOLImage
	for _, img := range resp.Data {
		result = append(result, EOLImage{
			ImageID:    img.ImageID,
			Repository: img.Repository,
			Tag:        img.Tag,
			Created:    img.Created,
			BaseOS:     img.OSName,
			EOLDate:    img.EOLDate,
			IsEOL:      img.IsEOL,
		})
	}

	return result, nil
}

func (c *Client) ListVulnerableContainers(ctx context.Context, filter VulnContainerFilter, limit int) ([]VulnerableContainer, error) {
	containers, err := c.ListContainers(ctx, "state:RUNNING", 500)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	vulnFilter := filter.ToQQL()
	if vulnFilter == "" {
		return nil, fmt.Errorf("at least one filter (severity, qds, cve, or filter) is required")
	}

	vulnImages, err := c.SearchImages(ctx, vulnFilter, 500)
	if err != nil {
		return nil, fmt.Errorf("search vulnerable images: %w", err)
	}

	vulnImageMap := make(map[string]Image)
	for _, img := range vulnImages {
		vulnImageMap[img.ImageID] = img
	}

	var result []VulnerableContainer
	for _, container := range containers {
		if img, found := vulnImageMap[container.ImageID]; found {
			result = append(result, VulnerableContainer{
				ContainerID:   container.ContainerID,
				ContainerName: container.Name,
				ImageID:       container.ImageID,
				ImageRepo:     img.Repository,
				State:         container.State,
				Host:          container.Host,
				VulnCount:     img.VulnCount,
			})
		}
	}

	if len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}
