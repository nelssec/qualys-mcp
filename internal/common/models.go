package common

import "github.com/mark3labs/mcp-go/mcp"

func NewToolResultError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: msg,
			},
		},
		IsError: true,
	}
}

type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "Info"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

type Vulnerability struct {
	QID         int      `json:"qid"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	CVEs        []string `json:"cves,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	CVSSv3      float64  `json:"cvssv3,omitempty"`
	Exploitable bool     `json:"exploitable,omitempty"`
}

type Asset struct {
	ID       string   `json:"id"`
	IP       string   `json:"ip,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	OS       string   `json:"os,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}
