package activitylog

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
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

// ActivityLogEntry represents a single activity log event from Qualys.
type ActivityLogEntry struct {
	Date      string `xml:"DATE" json:"date"`
	UserLogin string `xml:"USER_LOGIN" json:"userLogin"`
	UserName  string `xml:"USER_NAME" json:"userName,omitempty"`
	UserRole  string `xml:"USER_ROLE" json:"userRole,omitempty"`
	UserIP    string `xml:"USER_IP" json:"userIp,omitempty"`
	Action    string `xml:"ACTION" json:"action"`
	Module    string `xml:"MODULE" json:"module,omitempty"`
	Details   string `xml:"DETAILS" json:"details,omitempty"`
}

type activityLogResponse struct {
	XMLName  xml.Name `xml:"ACTIVITY_LOG_OUTPUT"`
	Response struct {
		ActivityLogList []ActivityLogEntry `xml:"ACTIVITY_LOG_LIST>ACTIVITY_LOG_ENTRY"`
	} `xml:"RESPONSE"`
}

// ActivityLogResult is the structured output returned by the tool.
type ActivityLogResult struct {
	TotalEntries int                `json:"totalEntries"`
	DateRange    DateRange          `json:"dateRange"`
	Entries      []ActivityLogEntry `json:"entries"`
	Summary      ActivitySummary    `json:"summary"`
}

type DateRange struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

type ActivitySummary struct {
	ByUser   map[string]int `json:"byUser"`
	ByAction map[string]int `json:"byAction"`
	ByModule map[string]int `json:"byModule"`
}

// NotableChanges represents config drift and notable activity for the morning report.
type NotableChanges struct {
	DateRange        DateRange          `json:"dateRange"`
	TotalEvents      int                `json:"totalEvents"`
	ConfigDrift      []ActivityLogEntry `json:"configDrift,omitempty"`
	PolicyChanges    []ActivityLogEntry `json:"policyChanges,omitempty"`
	ScanActivity     []ActivityLogEntry `json:"scanActivity,omitempty"`
	UserChanges      []ActivityLogEntry `json:"userChanges,omitempty"`
	ExceptionChanges []ActivityLogEntry `json:"exceptionChanges,omitempty"`
	Summary          string             `json:"summary"`
}

func (c *Client) GetActivityLog(ctx context.Context, days int, user string, action string) (*ActivityLogResult, error) {
	if days <= 0 {
		days = 7
	}

	endpoint := fmt.Sprintf("%s/api/2.0/fo/activity_log/", c.baseURL)

	now := time.Now().UTC()
	since := now.Add(-time.Duration(days) * 24 * time.Hour)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("since_datetime", since.Format("2006-01-02T15:04:05Z"))
	params.Set("until_datetime", now.Format("2006-01-02T15:04:05Z"))
	params.Set("truncation_limit", "1000")
	if user != "" {
		params.Set("user_login", user)
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp activityLogResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	entries := resp.Response.ActivityLogList

	// Apply action filter client-side (API may not support exact action filtering).
	if action != "" {
		actionLower := strings.ToLower(action)
		var filtered []ActivityLogEntry
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Action), actionLower) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	summary := ActivitySummary{
		ByUser:   make(map[string]int),
		ByAction: make(map[string]int),
		ByModule: make(map[string]int),
	}
	for _, e := range entries {
		summary.ByUser[e.UserLogin]++
		summary.ByAction[e.Action]++
		if e.Module != "" {
			summary.ByModule[e.Module]++
		}
	}

	return &ActivityLogResult{
		TotalEntries: len(entries),
		DateRange: DateRange{
			Since: since.Format("2006-01-02T15:04:05Z"),
			Until: now.Format("2006-01-02T15:04:05Z"),
		},
		Entries: entries,
		Summary: summary,
	}, nil
}

// GetNotableChanges returns activity categorized for morning report integration.
// Looks at the last 24 hours by default and categorizes events into config drift,
// policy changes, scan activity, user changes, and exception acknowledgements.
func (c *Client) GetNotableChanges(ctx context.Context, hours int) (*NotableChanges, error) {
	if hours <= 0 {
		hours = 24
	}

	endpoint := fmt.Sprintf("%s/api/2.0/fo/activity_log/", c.baseURL)

	now := time.Now().UTC()
	since := now.Add(-time.Duration(hours) * time.Hour)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("since_datetime", since.Format("2006-01-02T15:04:05Z"))
	params.Set("until_datetime", now.Format("2006-01-02T15:04:05Z"))
	params.Set("truncation_limit", "1000")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp activityLogResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	entries := resp.Response.ActivityLogList
	result := &NotableChanges{
		DateRange: DateRange{
			Since: since.Format("2006-01-02T15:04:05Z"),
			Until: now.Format("2006-01-02T15:04:05Z"),
		},
		TotalEvents: len(entries),
	}

	for _, e := range entries {
		actionLower := strings.ToLower(e.Action)
		detailsLower := strings.ToLower(e.Details)
		combined := actionLower + " " + detailsLower

		switch {
		case isConfigDrift(combined):
			result.ConfigDrift = append(result.ConfigDrift, e)
		case isPolicyChange(combined):
			result.PolicyChanges = append(result.PolicyChanges, e)
		case isScanActivity(combined):
			result.ScanActivity = append(result.ScanActivity, e)
		case isUserChange(combined):
			result.UserChanges = append(result.UserChanges, e)
		case isExceptionChange(combined):
			result.ExceptionChanges = append(result.ExceptionChanges, e)
		}
	}

	// Build summary text.
	var parts []string
	if len(result.ConfigDrift) > 0 {
		parts = append(parts, fmt.Sprintf("%d config change(s)", len(result.ConfigDrift)))
	}
	if len(result.PolicyChanges) > 0 {
		parts = append(parts, fmt.Sprintf("%d policy change(s)", len(result.PolicyChanges)))
	}
	if len(result.ScanActivity) > 0 {
		parts = append(parts, fmt.Sprintf("%d scan event(s)", len(result.ScanActivity)))
	}
	if len(result.UserChanges) > 0 {
		parts = append(parts, fmt.Sprintf("%d user change(s)", len(result.UserChanges)))
	}
	if len(result.ExceptionChanges) > 0 {
		parts = append(parts, fmt.Sprintf("%d exception change(s)", len(result.ExceptionChanges)))
	}
	if len(parts) == 0 {
		result.Summary = "No notable changes in the last " + fmt.Sprintf("%d", hours) + " hours."
	} else {
		result.Summary = fmt.Sprintf("Notable changes (%d total events): %s", result.TotalEvents, strings.Join(parts, ", "))
	}

	return result, nil
}

func isConfigDrift(s string) bool {
	keywords := []string{"scanner", "option profile", "appliance", "connector", "virtual scanner", "network", "map"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isPolicyChange(s string) bool {
	keywords := []string{"policy", "compliance", "control", "benchmark"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isScanActivity(s string) bool {
	keywords := []string{"scan", "launch", "schedule", "cancel"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isUserChange(s string) bool {
	keywords := []string{"user", "role", "permission", "login", "password", "account"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isExceptionChange(s string) bool {
	keywords := []string{"exception", "acknowledge", "whitelist", "ignore", "approve", "waive"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
