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

type ScanSchedule struct {
	ID             string `xml:"ID" json:"id"`
	Title          string `xml:"TITLE" json:"title"`
	Active         string `xml:"ACTIVE" json:"active"`
	OptionProfile  string `xml:"OPTION_PROFILE>TITLE" json:"optionProfile,omitempty"`
	Target         string `xml:"TARGET" json:"target,omitempty"`
	NextLaunchDate string `xml:"NEXTLAUNCH_DATE" json:"nextLaunchDate,omitempty"`
	Schedule       string `xml:"SCHEDULE" json:"schedule,omitempty"`
}

type OptionProfile struct {
	ID          string `xml:"ID" json:"id"`
	Title       string `xml:"TITLE" json:"title"`
	IsDefault   string `xml:"IS_DEFAULT" json:"isDefault,omitempty"`
	IsGlobal    string `xml:"IS_GLOBAL" json:"isGlobal,omitempty"`
	OwnerName   string `xml:"OWNER>NAME" json:"ownerName,omitempty"`
	UpdateDate  string `xml:"UPDATE_DATE" json:"updateDate,omitempty"`
}

type IPEntry struct {
	IP    string `xml:"IP" json:"ip,omitempty"`
	Range string `xml:"RANGE" json:"range,omitempty"`
}

type ScanLaunchResponse struct {
	XMLName  xml.Name `xml:"SIMPLE_RETURN"`
	Response struct {
		ItemList []struct {
			Key   string `xml:"KEY"`
			Value string `xml:"VALUE"`
		} `xml:"ITEM_LIST>ITEM"`
		Text string `xml:"TEXT"`
		Code string `xml:"CODE"`
	} `xml:"RESPONSE"`
}

type ScanStatus struct {
	Ref            string `json:"ref"`
	Title          string `json:"title"`
	Status         string `json:"status"`
	Target         string `json:"target,omitempty"`
	LaunchDate     string `json:"launchDate,omitempty"`
	Duration       string `json:"duration,omitempty"`
	Type           string `json:"type,omitempty"`
	OptionProfile  string `json:"optionProfile,omitempty"`
	Processed      int    `json:"processed,omitempty"`
	TotalHosts     int    `json:"totalHosts,omitempty"`
	ProgressPct    int    `json:"progressPercent,omitempty"`
	EstCompletionTime string `json:"estimatedCompletion,omitempty"`
}

type CoverageGap struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	LastScan string `json:"lastScan"`
	DaysAgo  int    `json:"daysSinceLastScan"`
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

type ScanScheduleListResponse struct {
	XMLName  xml.Name `xml:"SCHEDULE_SCAN_LIST_OUTPUT"`
	Response struct {
		ScanList []ScanSchedule `xml:"SCAN_LIST>SCAN"`
	} `xml:"RESPONSE"`
}

type OptionProfileListResponse struct {
	XMLName  xml.Name `xml:"OPTION_PROFILES"`
	Response struct {
		ProfileList []OptionProfile `xml:"OPTION_PROFILE"`
	} `xml:""`
}

type IPListResponse struct {
	XMLName  xml.Name `xml:"IP_LIST_OUTPUT"`
	Response struct {
		IPSet []IPEntry `xml:"RESPONSE>IP_SET>IP,omitempty"`
		IPRangeSet []IPEntry `xml:"RESPONSE>IP_SET>IP_RANGE,omitempty"`
	} `xml:""`
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

func (c *Client) GetScanSchedules(ctx context.Context) ([]ScanSchedule, error) {
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

	return resp.Response.ScanList, nil
}

func (c *Client) GetOptionProfiles(ctx context.Context) ([]OptionProfile, error) {
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

	return resp.Response.ProfileList, nil
}

func (c *Client) GetIPList(ctx context.Context) ([]IPEntry, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/asset/ip/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp IPListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	var result []IPEntry
	for _, ip := range resp.Response.IPSet {
		result = append(result, IPEntry{IP: ip.IP})
	}
	for _, r := range resp.Response.IPRangeSet {
		result = append(result, IPEntry{Range: r.Range})
	}

	return result, nil
}

func (c *Client) LaunchScan(ctx context.Context, title string, optionProfile string, targets string) (map[string]string, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/scan/", c.baseURL)

	params := url.Values{}
	params.Set("action", "launch")
	params.Set("scan_title", title)
	params.Set("option_title", optionProfile)
	params.Set("ip", targets)

	body := strings.NewReader(params.Encode())
	data, err := c.http.Post(ctx, endpoint, body, "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	var resp ScanLaunchResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	result := map[string]string{
		"text": resp.Response.Text,
		"code": resp.Response.Code,
	}
	for _, item := range resp.Response.ItemList {
		result[item.Key] = item.Value
	}

	return result, nil
}

func (c *Client) GetScanStatus(ctx context.Context, scanRef string) (*ScanStatus, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/scan/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("scan_ref", scanRef)
	params.Set("show_status", "1")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp ScanListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(resp.Response.ScanList) == 0 {
		return nil, fmt.Errorf("scan not found: %s", scanRef)
	}

	scan := resp.Response.ScanList[0]
	status := &ScanStatus{
		Ref:        scan.Ref,
		Title:      scan.Title,
		Status:     scan.Status,
		Target:     scan.Target,
		LaunchDate: scan.LaunchDate,
		Duration:   scan.Duration,
		Type:       scan.Type,
	}

	// Fetch detailed results for progress info if scan is running
	if scan.Status == "Running" {
		results, err := c.GetScanResults(ctx, scanRef)
		if err == nil && len(results) > 0 {
			total := 0
			processed := 0
			for _, r := range results {
				if r.TotalHosts != "" {
					fmt.Sscanf(r.TotalHosts, "%d", &total)
				}
				if r.ActiveHosts != "" {
					fmt.Sscanf(r.ActiveHosts, "%d", &processed)
				}
			}
			if total > 0 {
				status.TotalHosts = total
				status.Processed = processed
				status.ProgressPct = (processed * 100) / total
			}
		}
	}

	return status, nil
}

func (c *Client) GetCoverageGaps(ctx context.Context, daysThreshold int, limit int) ([]CoverageGap, error) {
	if daysThreshold <= 0 {
		daysThreshold = 7
	}
	if limit <= 0 {
		limit = 100
	}

	hosts, err := c.ListHosts(ctx, "", limit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	threshold := now.AddDate(0, 0, -daysThreshold)

	var gaps []CoverageGap
	for _, host := range hosts {
		if host.LastScan == "" {
			gaps = append(gaps, CoverageGap{
				ID:       host.ID,
				IP:       host.IP,
				Hostname: host.Hostname,
				OS:       host.OS,
				LastScan: "never",
				DaysAgo:  -1,
			})
			continue
		}

		lastScan, err := time.Parse("2006-01-02T15:04:05Z", host.LastScan)
		if err != nil {
			continue
		}

		if lastScan.Before(threshold) {
			daysAgo := int(now.Sub(lastScan).Hours() / 24)
			gaps = append(gaps, CoverageGap{
				ID:       host.ID,
				IP:       host.IP,
				Hostname: host.Hostname,
				OS:       host.OS,
				LastScan: host.LastScan,
				DaysAgo:  daysAgo,
			})
		}
	}

	sort.Slice(gaps, func(i, j int) bool {
		return gaps[i].DaysAgo > gaps[j].DaysAgo
	})

	return gaps, nil
}
