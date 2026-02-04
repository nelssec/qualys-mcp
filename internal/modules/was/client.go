package was

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

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

type WebApp struct {
	ID          int    `xml:"id" json:"id,omitempty"`
	Name        string `xml:"name" json:"name,omitempty"`
	URL         string `xml:"url" json:"url,omitempty"`
	Owner       string `xml:"owner>username" json:"owner,omitempty"`
	Scope       string `xml:"scope" json:"scope,omitempty"`
	SubDomain   string `xml:"subDomain" json:"subDomain,omitempty"`
	CreatedDate string `xml:"createdDate" json:"createdDate,omitempty"`
	UpdatedDate string `xml:"updatedDate" json:"updatedDate,omitempty"`
}

type Scan struct {
	ID          int    `xml:"id" json:"id,omitempty"`
	Name        string `xml:"name" json:"name,omitempty"`
	Reference   string `xml:"reference" json:"reference,omitempty"`
	Type        string `xml:"type" json:"type,omitempty"`
	Mode        string `xml:"mode" json:"mode,omitempty"`
	Status      string `xml:"status" json:"status,omitempty"`
	LaunchedDate string `xml:"launchedDate" json:"launchedDate,omitempty"`
	EndScanDate string `xml:"endScanDate" json:"endScanDate,omitempty"`
	WebAppID    int    `xml:"webApp>id" json:"webAppId,omitempty"`
	WebAppName  string `xml:"webApp>name" json:"webAppName,omitempty"`
}

type Finding struct {
	ID          int    `xml:"id" json:"id,omitempty"`
	UniqueID    string `xml:"uniqueId" json:"uniqueId,omitempty"`
	QID         int    `xml:"qid" json:"qid,omitempty"`
	Name        string `xml:"name" json:"name,omitempty"`
	Type        string `xml:"type" json:"type,omitempty"`
	Severity    int    `xml:"severity" json:"severity,omitempty"`
	URL         string `xml:"url" json:"url,omitempty"`
	Status      string `xml:"status" json:"status,omitempty"`
	FirstDetectedDate string `xml:"firstDetectedDate" json:"firstDetectedDate,omitempty"`
	LastDetectedDate  string `xml:"lastDetectedDate" json:"lastDetectedDate,omitempty"`
	WebAppID    int    `xml:"webApp>id" json:"webAppId,omitempty"`
}

type Report struct {
	ID          int    `xml:"id" json:"id,omitempty"`
	Name        string `xml:"name" json:"name,omitempty"`
	Type        string `xml:"type" json:"type,omitempty"`
	Format      string `xml:"format" json:"format,omitempty"`
	Status      string `xml:"status" json:"status,omitempty"`
	CreatedDate string `xml:"createdDate" json:"createdDate,omitempty"`
	Size        int64  `xml:"size" json:"size,omitempty"`
}

type FindingStats struct {
	TotalFindings int            `json:"totalFindings"`
	BySeverity    map[int]int    `json:"bySeverity"`
	ByType        map[string]int `json:"byType"`
	UniqueQIDs    int            `json:"uniqueQids"`
	UniqueWebApps int            `json:"uniqueWebApps"`
	TopQIDs       []QIDSummary   `json:"topQids"`
}

type QIDSummary struct {
	QID      int    `json:"qid"`
	Name     string `json:"name"`
	Severity int    `json:"severity"`
	Count    int    `json:"count"`
}

type FindingBrief struct {
	ID       int    `json:"id"`
	QID      int    `json:"qid"`
	Severity int    `json:"severity"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	WebAppID int    `json:"webAppId"`
}

type FindingSummary struct {
	Stats       FindingStats   `json:"stats"`
	TopFindings []FindingBrief `json:"topFindings"`
}

func (c *Client) GetFindingStats(ctx context.Context, findings []Finding) *FindingStats {
	stats := &FindingStats{
		TotalFindings: len(findings),
		BySeverity:    make(map[int]int),
		ByType:        make(map[string]int),
	}

	qidCounts := make(map[int]int)
	qidInfo := make(map[int]Finding)
	webApps := make(map[int]bool)

	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByType[f.Type]++
		qidCounts[f.QID]++
		qidInfo[f.QID] = f
		webApps[f.WebAppID] = true
	}

	stats.UniqueQIDs = len(qidCounts)
	stats.UniqueWebApps = len(webApps)

	type qidCount struct {
		qid   int
		count int
	}
	var sorted []qidCount
	for qid, count := range qidCounts {
		sorted = append(sorted, qidCount{qid, count})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	for i := 0; i < len(sorted) && i < 10; i++ {
		f := qidInfo[sorted[i].qid]
		stats.TopQIDs = append(stats.TopQIDs, QIDSummary{
			QID:      sorted[i].qid,
			Name:     f.Name,
			Severity: f.Severity,
			Count:    sorted[i].count,
		})
	}

	return stats
}

func (c *Client) GetFindingSummary(ctx context.Context, findings []Finding, topN int) *FindingSummary {
	stats := c.GetFindingStats(ctx, findings)

	var topFindings []FindingBrief
	for i := 0; i < len(findings) && i < topN; i++ {
		f := findings[i]
		topFindings = append(topFindings, FindingBrief{
			ID:       f.ID,
			QID:      f.QID,
			Severity: f.Severity,
			Type:     f.Type,
			URL:      f.URL,
			WebAppID: f.WebAppID,
		})
	}

	return &FindingSummary{
		Stats:       *stats,
		TopFindings: topFindings,
	}
}

type ServiceResponse struct {
	XMLName      xml.Name `xml:"ServiceResponse"`
	ResponseCode string   `xml:"responseCode"`
	Count        int      `xml:"count"`
}

type WebAppsResponse struct {
	ServiceResponse
	Data struct {
		WebApps []WebApp `xml:"WebApp"`
	} `xml:"data"`
}

type ScansResponse struct {
	ServiceResponse
	Data struct {
		Scans []Scan `xml:"WasScan"`
	} `xml:"data"`
}

type FindingsResponse struct {
	ServiceResponse
	Data struct {
		Findings []Finding `xml:"Finding"`
	} `xml:"data"`
}

type ReportsResponse struct {
	ServiceResponse
	Data struct {
		Reports []Report `xml:"WasReport"`
	} `xml:"data"`
}

func (c *Client) ListWebApps(ctx context.Context, filter string, limit int) ([]WebApp, error) {
	endpoint := fmt.Sprintf("%s/qps/rest/3.0/search/was/webapp", c.baseURL)

	xmlBody := fmt.Sprintf(`<ServiceRequest><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, limit)
	if filter != "" {
		xmlBody = fmt.Sprintf(`<ServiceRequest><filters><Criteria field="name" operator="CONTAINS">%s</Criteria></filters><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, filter, limit)
	}

	data, err := c.http.Post(ctx, endpoint, strings.NewReader(xmlBody), "text/xml")
	if err != nil {
		return nil, err
	}

	var resp WebAppsResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.ResponseCode != "SUCCESS" {
		return nil, fmt.Errorf("API error: %s", resp.ResponseCode)
	}

	return resp.Data.WebApps, nil
}

func (c *Client) ListScans(ctx context.Context, status string, limit int) ([]Scan, error) {
	endpoint := fmt.Sprintf("%s/qps/rest/3.0/search/was/wasscan", c.baseURL)

	xmlBody := fmt.Sprintf(`<ServiceRequest><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, limit)
	if status != "" {
		xmlBody = fmt.Sprintf(`<ServiceRequest><filters><Criteria field="status" operator="EQUALS">%s</Criteria></filters><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, status, limit)
	}

	data, err := c.http.Post(ctx, endpoint, strings.NewReader(xmlBody), "text/xml")
	if err != nil {
		return nil, err
	}

	var resp ScansResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.ResponseCode != "SUCCESS" {
		return nil, fmt.Errorf("API error: %s", resp.ResponseCode)
	}

	return resp.Data.Scans, nil
}

func (c *Client) ListFindings(ctx context.Context, severity int, limit int) ([]Finding, error) {
	endpoint := fmt.Sprintf("%s/qps/rest/3.0/search/was/finding", c.baseURL)

	xmlBody := fmt.Sprintf(`<ServiceRequest><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, limit)
	if severity > 0 {
		xmlBody = fmt.Sprintf(`<ServiceRequest><filters><Criteria field="severity" operator="GREATER">%d</Criteria></filters><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, severity-1, limit)
	}

	data, err := c.http.Post(ctx, endpoint, strings.NewReader(xmlBody), "text/xml")
	if err != nil {
		return nil, err
	}

	var resp FindingsResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.ResponseCode != "SUCCESS" {
		return nil, fmt.Errorf("API error: %s", resp.ResponseCode)
	}

	return resp.Data.Findings, nil
}

func (c *Client) GetWebAppFindings(ctx context.Context, webAppID string, limit int) ([]Finding, error) {
	endpoint := fmt.Sprintf("%s/qps/rest/3.0/search/was/finding", c.baseURL)

	xmlBody := fmt.Sprintf(`<ServiceRequest><filters><Criteria field="webApp.id" operator="EQUALS">%s</Criteria></filters><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, webAppID, limit)

	data, err := c.http.Post(ctx, endpoint, strings.NewReader(xmlBody), "text/xml")
	if err != nil {
		return nil, err
	}

	var resp FindingsResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.ResponseCode != "SUCCESS" {
		return nil, fmt.Errorf("API error: %s", resp.ResponseCode)
	}

	return resp.Data.Findings, nil
}

func (c *Client) ListReports(ctx context.Context, limit int) ([]Report, error) {
	endpoint := fmt.Sprintf("%s/qps/rest/3.0/search/was/report", c.baseURL)

	params := url.Values{}
	if limit > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", limit))
	}

	xmlBody := fmt.Sprintf(`<ServiceRequest><preferences><limitResults>%d</limitResults></preferences></ServiceRequest>`, limit)

	data, err := c.http.Post(ctx, endpoint, strings.NewReader(xmlBody), "text/xml")
	if err != nil {
		return nil, err
	}

	var resp ReportsResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.ResponseCode != "SUCCESS" {
		return nil, fmt.Errorf("API error: %s", resp.ResponseCode)
	}

	return resp.Data.Reports, nil
}
