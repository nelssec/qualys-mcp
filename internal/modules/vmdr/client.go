package vmdr

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

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

type Host struct {
	ID            string `xml:"ID" json:"id"`
	IP            string `xml:"IP" json:"ip"`
	Hostname      string `xml:"DNS" json:"hostname,omitempty"`
	NetbiosName   string `xml:"NETBIOS" json:"netbios,omitempty"`
	OS            string `xml:"OS" json:"os,omitempty"`
	LastScan      string `xml:"LAST_VULN_SCAN_DATETIME" json:"lastScan,omitempty"`
	TrackingMethod string `xml:"TRACKING_METHOD" json:"trackingMethod,omitempty"`
}

type Detection struct {
	QID        int    `xml:"QID" json:"qid"`
	Type       string `xml:"TYPE" json:"type,omitempty"`
	Severity   int    `xml:"SEVERITY" json:"severity"`
	Port       int    `xml:"PORT" json:"port,omitempty"`
	Protocol   string `xml:"PROTOCOL" json:"protocol,omitempty"`
	SSL        int    `xml:"SSL" json:"ssl,omitempty"`
	Status     string `xml:"STATUS" json:"status"`
	FirstFound string `xml:"FIRST_FOUND_DATETIME" json:"firstFound,omitempty"`
	LastFound  string `xml:"LAST_FOUND_DATETIME" json:"lastFound,omitempty"`
	Results    string `xml:"RESULTS" json:"results,omitempty"`
	QDS        int    `xml:"QDS>SEVERITY" json:"qds,omitempty"`
	QDSFactors string `xml:"QDS_FACTORS" json:"qdsFactors,omitempty"`
}

type HostDetection struct {
	Host       Host        `xml:"HOST" json:"host"`
	Detections []Detection `xml:"DETECTION_LIST>DETECTION" json:"detections"`
}

type Scan struct {
	Ref        string `xml:"REF" json:"ref"`
	Title      string `xml:"TITLE" json:"title"`
	Type       string `xml:"TYPE" json:"type"`
	Status     string `xml:"STATUS>STATE" json:"status"`
	LaunchDate string `xml:"LAUNCH_DATETIME" json:"launchDate"`
	Duration   string `xml:"DURATION" json:"duration,omitempty"`
	Target     string `xml:"TARGET" json:"target,omitempty"`
}

type AssetGroup struct {
	ID    string `xml:"ID" json:"id"`
	Title string `xml:"TITLE" json:"title"`
}

type DetectionStats struct {
	TotalDetections int         `json:"totalDetections"`
	UniqueHosts     int         `json:"uniqueHosts"`
	UniqueQIDs      int         `json:"uniqueQids"`
	BySeverity      map[int]int `json:"bySeverity"`
	TopQIDs         []QIDCount  `json:"topQids"`
	AvgQDS          int         `json:"avgQdsScore"`
	MaxQDS          int         `json:"maxQdsScore"`
}

type QIDCount struct {
	QID      int `json:"qid"`
	Count    int `json:"count"`
	Severity int `json:"severity"`
}

type DetectionSummary struct {
	Stats        DetectionStats   `json:"stats"`
	TopRiskHosts []HostSummary    `json:"topRiskHosts"`
	TopFindings  []DetectionBrief `json:"topFindings"`
}

type HostSummary struct {
	HostID         string `json:"hostId"`
	IP             string `json:"ip"`
	DetectionCount int    `json:"detectionCount"`
	MaxSeverity    int    `json:"maxSeverity"`
}

type DetectionBrief struct {
	QID       int    `json:"qid"`
	Severity  int    `json:"severity"`
	Status    string `json:"status"`
	HostCount int    `json:"hostCount"`
}

type HostListResponse struct {
	XMLName  xml.Name `xml:"HOST_LIST_OUTPUT"`
	Response struct {
		HostList []Host `xml:"HOST_LIST>HOST"`
	} `xml:"RESPONSE"`
}

type HostDetectionResponse struct {
	XMLName  xml.Name `xml:"HOST_LIST_VM_DETECTION_OUTPUT"`
	Response struct {
		HostList []HostDetection `xml:"HOST_LIST>HOST"`
	} `xml:"RESPONSE"`
}

type ScanListResponse struct {
	XMLName  xml.Name `xml:"SCAN_LIST_OUTPUT"`
	Response struct {
		ScanList []Scan `xml:"SCAN_LIST>SCAN"`
	} `xml:"RESPONSE"`
}

type AssetGroupListResponse struct {
	XMLName  xml.Name `xml:"ASSET_GROUP_LIST_OUTPUT"`
	Response struct {
		AssetGroupList []AssetGroup `xml:"ASSET_GROUP_LIST>ASSET_GROUP"`
	} `xml:"RESPONSE"`
}

// ScanSchedule represents a scheduled scan entry.
type ScanSchedule struct {
	ID             string `xml:"ID" json:"id"`
	Active         string `xml:"ACTIVE" json:"active"`
	Title          string `xml:"TITLE" json:"title"`
	ScannerName    string `xml:"ISCANNER_NAME" json:"scannerName,omitempty"`
	OptionTitle    string `xml:"OPTION_TITLE" json:"optionTitle,omitempty"`
	StartDateUTC   string `xml:"START_DATE_UTC" json:"startDateUTC,omitempty"`
	StartHour      int    `xml:"START_HOUR" json:"startHour,omitempty"`
	StartMinute    int    `xml:"START_MINUTE" json:"startMinute,omitempty"`
	TimeZone       string `xml:"TIME_ZONE_CODE" json:"timeZone,omitempty"`
	NextLaunchUTC  string `xml:"NEXT_LAUNCH_UTC" json:"nextLaunchUTC,omitempty"`
	LastLaunchUTC  string `xml:"LAST_LAUNCH_UTC" json:"lastLaunchUTC,omitempty"`
	DaysUntilNext  *int   `json:"daysUntilNext,omitempty"`
}

type ScanScheduleListResponse struct {
	XMLName  xml.Name `xml:"SCHEDULE_SCAN_LIST_OUTPUT"`
	Response struct {
		ScheduleList []ScanSchedule `xml:"SCHEDULE_SCAN_LIST>SCHEDULE_SCAN"`
	} `xml:"RESPONSE"`
}

// OptionProfile represents a VM scan option profile.
type OptionProfile struct {
	ID                  string `xml:"BASIC_INFO>ID" json:"id"`
	Title               string `xml:"BASIC_INFO>GROUP_NAME" json:"title"`
	UserLogin           string `xml:"BASIC_INFO>USER_LOGIN" json:"userLogin,omitempty"`
	IsDefault           string `xml:"BASIC_INFO>IS_DEFAULT" json:"isDefault,omitempty"`
	SubscriptionDefault string `xml:"BASIC_INFO>SUBSCRIPTION_DEFAULT" json:"subscriptionDefault,omitempty"`
}

type OptionProfileListResponse struct {
	XMLName  xml.Name        `xml:"OPTION_PROFILES"`
	Profiles []OptionProfile `xml:"OPTION_PROFILE"`
}

// IPAsset represents a tracked IP or IP range.
type IPAsset struct {
	IP      string `xml:"IP" json:"ip,omitempty"`
	IPRange string `xml:"IP_RANGE" json:"ipRange,omitempty"`
}

type IPSetResponse struct {
	XMLName  xml.Name `xml:"IP_LIST_OUTPUT"`
	Response struct {
		IPs      []string `xml:"IP_SET>IP"`
		IPRanges []string `xml:"IP_SET>IP_RANGE"`
	} `xml:"RESPONSE"`
}

type TrackedIPList struct {
	IPs      []string `json:"ips"`
	IPRanges []string `json:"ipRanges"`
	Total    int      `json:"total"`
}

// LaunchScanResult is the result of launching a scan.
type LaunchScanResult struct {
	ID        string `json:"id"`
	Reference string `json:"reference"`
}

type SimpleReturn struct {
	XMLName  xml.Name `xml:"SIMPLE_RETURN"`
	Response struct {
		Items []struct {
			Key   string `xml:"KEY"`
			Value string `xml:"VALUE"`
		} `xml:"ITEM_LIST>ITEM"`
	} `xml:"RESPONSE"`
}

// CoverageGap represents an asset with stale or missing scan coverage.
type CoverageGap struct {
	HostID    string `json:"hostId"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	LastScan  string `json:"lastScan,omitempty"`
	DaysSince int    `json:"daysSince"`
}

// ScanCoverageReport summarises scan coverage across the asset estate.
type ScanCoverageReport struct {
	TotalAssets     int           `json:"totalAssets"`
	NeverScanned    int           `json:"neverScanned"`
	StaleAssets     int           `json:"staleAssets"`
	RecentlyScanned int           `json:"recentlyScanned"`
	ThresholdDays   int           `json:"thresholdDays"`
	CoverageGaps    []CoverageGap `json:"coverageGaps"`
}

func (c *Client) ListHosts(ctx context.Context, filter string, limit int) ([]Host, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/asset/host/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("details", "All")
	if filter != "" {
		params.Set("ids", filter)
	}
	if limit > 0 {
		params.Set("truncation_limit", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp HostListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Response.HostList, nil
}

func (c *Client) GetHostDetections(ctx context.Context, hostID string, severityFilter int, qdsMin int) ([]Detection, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/asset/host/vm/detection/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("ids", hostID)
	params.Set("show_igs", "1")
	params.Set("show_qds", "1")
	params.Set("filter_superseded_qids", "1")
	if severityFilter > 0 {
		params.Set("severities", fmt.Sprintf("%d", severityFilter))
	}
	if qdsMin > 0 {
		params.Set("qds_min", fmt.Sprintf("%d", qdsMin))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp HostDetectionResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(resp.Response.HostList) == 0 {
		return nil, nil
	}

	return resp.Response.HostList[0].Detections, nil
}

func (c *Client) SearchDetections(ctx context.Context, qids string, severity int, qdsMin int, limit int) ([]HostDetection, error) {
	return c.SearchDetectionsWithStatus(ctx, qids, severity, qdsMin, limit, "")
}

func (c *Client) SearchDetectionsWithStatus(ctx context.Context, qids string, severity int, qdsMin int, limit int, status string) ([]HostDetection, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/asset/host/vm/detection/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("show_qds", "1")
	params.Set("filter_superseded_qids", "1")
	if qids != "" {
		params.Set("qids", qids)
	}
	if severity > 0 {
		params.Set("severities", fmt.Sprintf("%d", severity))
	}
	if qdsMin > 0 {
		params.Set("qds_min", fmt.Sprintf("%d", qdsMin))
	}
	if limit > 0 {
		params.Set("truncation_limit", fmt.Sprintf("%d", limit))
	}
	if status != "" {
		params.Set("status", status)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp HostDetectionResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Response.HostList, nil
}

func (c *Client) ListScans(ctx context.Context, status string, limit int) ([]Scan, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/scan/", c.baseURL)

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

type ScanResultJSON struct {
	ScanReportTemplateTitle string `json:"scan_report_template_title,omitempty"`
	ResultDate              string `json:"result_date,omitempty"`
	Company                 string `json:"company,omitempty"`
	Username                string `json:"username,omitempty"`
	LaunchDate              string `json:"launch_date,omitempty"`
	ActiveHosts             string `json:"active_hosts,omitempty"`
	TotalHosts              string `json:"total_hosts,omitempty"`
	Type                    string `json:"type,omitempty"`
	ScanType                string `json:"scan_type,omitempty"`
	Status                  string `json:"status,omitempty"`
	Reference               string `json:"reference,omitempty"`
	Duration                string `json:"duration,omitempty"`
	ScanTitle               string `json:"scan_title,omitempty"`
	OptionProfile           string `json:"option_profile,omitempty"`
	FQDN                    string `json:"fqdn,omitempty"`
	IP                      string `json:"ip,omitempty"`
	DNS                     string `json:"dns,omitempty"`
	QID                     string `json:"qid,omitempty"`
	Title                   string `json:"title,omitempty"`
	Severity                string `json:"severity,omitempty"`
	Port                    string `json:"port,omitempty"`
	Protocol                string `json:"protocol,omitempty"`
	Results                 string `json:"results,omitempty"`
}

func (c *Client) GetScanResults(ctx context.Context, scanRef string) ([]ScanResultJSON, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/scan/", c.baseURL)

	params := url.Values{}
	params.Set("action", "fetch")
	params.Set("scan_ref", scanRef)
	params.Set("output_format", "json_extended")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []ScanResultJSON{}, nil
	}

	var results []ScanResultJSON
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return results, nil
}

func (c *Client) ListAssetGroups(ctx context.Context) ([]AssetGroup, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/asset/group/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp AssetGroupListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Response.AssetGroupList, nil
}

func (c *Client) GetDetectionStats(ctx context.Context, qids string, severity int, qdsMin int, status string, limit int) (*DetectionStats, error) {
	if limit <= 0 {
		limit = 200
	}
	detections, err := c.SearchDetectionsWithStatus(ctx, qids, severity, qdsMin, limit, status)
	if err != nil {
		return nil, err
	}

	stats := &DetectionStats{
		BySeverity: make(map[int]int),
		TopQIDs:    []QIDCount{},
	}

	hostSet := make(map[string]bool)
	qidCounts := make(map[int]*QIDCount)
	var totalQDS, qdsCount int

	for _, host := range detections {
		hostID := host.Host.ID
		if hostID == "" {
			hostID = host.Host.IP
		}
		if hostID != "" {
			hostSet[hostID] = true
		}

		for _, det := range host.Detections {
			stats.TotalDetections++
			stats.BySeverity[det.Severity]++

			if _, exists := qidCounts[det.QID]; !exists {
				qidCounts[det.QID] = &QIDCount{
					QID:      det.QID,
					Count:    0,
					Severity: det.Severity,
				}
			}
			qidCounts[det.QID].Count++

			if det.QDS > 0 {
				totalQDS += det.QDS
				qdsCount++
				if det.QDS > stats.MaxQDS {
					stats.MaxQDS = det.QDS
				}
			}
		}
	}

	stats.UniqueHosts = len(hostSet)
	stats.UniqueQIDs = len(qidCounts)

	if qdsCount > 0 {
		stats.AvgQDS = totalQDS / qdsCount
	}

	var sortable []QIDCount
	for _, qc := range qidCounts {
		sortable = append(sortable, QIDCount{qc.QID, qc.Count, qc.Severity})
	}
	sort.Slice(sortable, func(i, j int) bool {
		return sortable[i].Count > sortable[j].Count
	})
	for i := 0; i < len(sortable) && i < 10; i++ {
		stats.TopQIDs = append(stats.TopQIDs, sortable[i])
	}

	return stats, nil
}

func (c *Client) GetDetectionSummary(ctx context.Context, qids string, severity int, qdsMin int, status string, limit int) (*DetectionSummary, error) {
	if limit <= 0 {
		limit = 200
	}
	detections, err := c.SearchDetectionsWithStatus(ctx, qids, severity, qdsMin, limit, status)
	if err != nil {
		return nil, err
	}

	summary := &DetectionSummary{
		Stats: DetectionStats{
			BySeverity: make(map[int]int),
			TopQIDs:    []QIDCount{},
		},
		TopRiskHosts: []HostSummary{},
		TopFindings:  []DetectionBrief{},
	}

	hostMap := make(map[string]*HostSummary)
	qidCounts := make(map[int]*QIDCount)
	qidHostCounts := make(map[int]int)
	var totalQDS, qdsCount int

	for _, host := range detections {
		hostID := host.Host.ID
		if hostID == "" {
			hostID = host.Host.IP
		}

		if _, exists := hostMap[hostID]; !exists {
			hostMap[hostID] = &HostSummary{
				HostID:      hostID,
				IP:          host.Host.IP,
				MaxSeverity: 0,
			}
		}

		for _, det := range host.Detections {
			summary.Stats.TotalDetections++
			summary.Stats.BySeverity[det.Severity]++
			hostMap[hostID].DetectionCount++

			if det.Severity > hostMap[hostID].MaxSeverity {
				hostMap[hostID].MaxSeverity = det.Severity
			}

			if _, exists := qidCounts[det.QID]; !exists {
				qidCounts[det.QID] = &QIDCount{
					QID:      det.QID,
					Count:    0,
					Severity: det.Severity,
				}
			}
			qidCounts[det.QID].Count++
			qidHostCounts[det.QID]++

			if det.QDS > 0 {
				totalQDS += det.QDS
				qdsCount++
				if det.QDS > summary.Stats.MaxQDS {
					summary.Stats.MaxQDS = det.QDS
				}
			}
		}
	}

	summary.Stats.UniqueHosts = len(hostMap)
	summary.Stats.UniqueQIDs = len(qidCounts)
	if qdsCount > 0 {
		summary.Stats.AvgQDS = totalQDS / qdsCount
	}

	var sortableHosts []*HostSummary
	for _, h := range hostMap {
		sortableHosts = append(sortableHosts, h)
	}
	sort.Slice(sortableHosts, func(i, j int) bool {
		if sortableHosts[i].MaxSeverity != sortableHosts[j].MaxSeverity {
			return sortableHosts[i].MaxSeverity > sortableHosts[j].MaxSeverity
		}
		return sortableHosts[i].DetectionCount > sortableHosts[j].DetectionCount
	})
	for i := 0; i < len(sortableHosts) && i < 10; i++ {
		summary.TopRiskHosts = append(summary.TopRiskHosts, *sortableHosts[i])
	}

	type qidSort struct {
		qid       int
		count     int
		sev       int
		hostCount int
	}
	var sortableQIDs []qidSort
	for qid, qc := range qidCounts {
		sortableQIDs = append(sortableQIDs, qidSort{qid, qc.Count, qc.Severity, qidHostCounts[qid]})
	}
	sort.Slice(sortableQIDs, func(i, j int) bool {
		if sortableQIDs[i].sev != sortableQIDs[j].sev {
			return sortableQIDs[i].sev > sortableQIDs[j].sev
		}
		return sortableQIDs[i].hostCount > sortableQIDs[j].hostCount
	})
	for i := 0; i < len(sortableQIDs) && i < 10; i++ {
		summary.Stats.TopQIDs = append(summary.Stats.TopQIDs, QIDCount{
			QID: sortableQIDs[i].qid, Count: sortableQIDs[i].count, Severity: sortableQIDs[i].sev,
		})
	}
	for i := 0; i < len(sortableQIDs) && i < 20; i++ {
		summary.TopFindings = append(summary.TopFindings, DetectionBrief{
			QID: sortableQIDs[i].qid, Severity: sortableQIDs[i].sev, HostCount: sortableQIDs[i].hostCount,
		})
	}

	return summary, nil
}

func (c *Client) ListScanSchedules(ctx context.Context) ([]ScanSchedule, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/schedule/scan/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp ScanScheduleListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	now := time.Now().UTC()
	for i, s := range resp.Response.ScheduleList {
		if s.NextLaunchUTC != "" {
			t, err := time.Parse("2006-01-02T15:04:05Z", s.NextLaunchUTC)
			if err == nil {
				days := int(t.Sub(now).Hours() / 24)
				resp.Response.ScheduleList[i].DaysUntilNext = &days
			}
		}
	}

	return resp.Response.ScheduleList, nil
}

func (c *Client) ListOptionProfiles(ctx context.Context) ([]OptionProfile, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/subscription/option_profile/vm/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp OptionProfileListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Profiles, nil
}

func (c *Client) ListTrackedIPs(ctx context.Context, network string) (*TrackedIPList, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/asset/ip/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	if network != "" {
		params.Set("ips", network)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp IPSetResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	result := &TrackedIPList{
		IPs:      resp.Response.IPs,
		IPRanges: resp.Response.IPRanges,
	}
	if result.IPs == nil {
		result.IPs = []string{}
	}
	if result.IPRanges == nil {
		result.IPRanges = []string{}
	}
	result.Total = len(result.IPs) + len(result.IPRanges)
	return result, nil
}

func (c *Client) LaunchScan(ctx context.Context, title, optionTitle, targets, assetGroups string) (*LaunchScanResult, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/scan/", c.baseURL)

	params := url.Values{}
	params.Set("action", "launch")
	params.Set("scan_title", title)
	if optionTitle != "" {
		params.Set("option_title", optionTitle)
	}
	if targets != "" {
		params.Set("ip", targets)
	}
	if assetGroups != "" {
		params.Set("asset_group_ids", assetGroups)
	}

	body := strings.NewReader(params.Encode())
	data, err := c.http.Post(ctx, endpoint, body, "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	var sr SimpleReturn
	if err := xml.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	result := &LaunchScanResult{}
	for _, item := range sr.Response.Items {
		switch item.Key {
		case "ID":
			result.ID = item.Value
		case "REFERENCE":
			result.Reference = item.Value
		}
	}
	return result, nil
}

func (c *Client) GetScanCoverageGaps(ctx context.Context, thresholdDays int) (*ScanCoverageReport, error) {
	if thresholdDays <= 0 {
		thresholdDays = 7
	}

	hosts, err := c.ListHosts(ctx, "", 500)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	threshold := now.Add(-time.Duration(thresholdDays) * 24 * time.Hour)

	report := &ScanCoverageReport{
		TotalAssets:   len(hosts),
		ThresholdDays: thresholdDays,
		CoverageGaps:  []CoverageGap{},
	}

	for _, h := range hosts {
		if h.LastScan == "" {
			report.NeverScanned++
			report.CoverageGaps = append(report.CoverageGaps, CoverageGap{
				HostID:    h.ID,
				IP:        h.IP,
				Hostname:  h.Hostname,
				LastScan:  "",
				DaysSince: -1,
			})
			continue
		}

		// Qualys uses format: 2024-01-15T10:00:00Z
		t, err := time.Parse("2006-01-02T15:04:05Z", h.LastScan)
		if err != nil {
			// Try alternative format
			t, err = time.Parse("2006-01-02T15:04:05+0000", h.LastScan)
		}
		if err != nil {
			// Can't parse date — treat as stale
			report.StaleAssets++
			report.CoverageGaps = append(report.CoverageGaps, CoverageGap{
				HostID:    h.ID,
				IP:        h.IP,
				Hostname:  h.Hostname,
				LastScan:  h.LastScan,
				DaysSince: -1,
			})
			continue
		}

		if t.Before(threshold) {
			days := int(now.Sub(t).Hours() / 24)
			report.StaleAssets++
			report.CoverageGaps = append(report.CoverageGaps, CoverageGap{
				HostID:    h.ID,
				IP:        h.IP,
				Hostname:  h.Hostname,
				LastScan:  h.LastScan,
				DaysSince: days,
			})
		} else {
			report.RecentlyScanned++
		}
	}

	// Sort gaps: never scanned first, then by days since (desc)
	sort.Slice(report.CoverageGaps, func(i, j int) bool {
		if report.CoverageGaps[i].DaysSince == -1 && report.CoverageGaps[j].DaysSince != -1 {
			return true
		}
		if report.CoverageGaps[i].DaysSince != -1 && report.CoverageGaps[j].DaysSince == -1 {
			return false
		}
		return report.CoverageGaps[i].DaysSince > report.CoverageGaps[j].DaysSince
	})

	return report, nil
}
