package remediation

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

type Ticket struct {
	ID           string `xml:"ID" json:"id"`
	Title        string `xml:"TITLE" json:"title,omitempty"`
	Status       string `xml:"CURRENT_STATE" json:"status"`
	Assignee     string `xml:"ASSIGNEE" json:"assignee,omitempty"`
	QID          int    `xml:"VULNINFO>QID" json:"qid,omitempty"`
	Severity     int    `xml:"VULNINFO>SEVERITY" json:"severity,omitempty"`
	AssetID      string `xml:"ASSET_ID" json:"assetId,omitempty"`
	IP           string `xml:"IP" json:"ip,omitempty"`
	CreatedDate  string `xml:"CREATED_DATE" json:"createdDate,omitempty"`
	ModifiedDate string `xml:"MODIFIED_DATE" json:"modifiedDate,omitempty"`
	DueDate      string `xml:"DUE_DATE" json:"dueDate,omitempty"`
	ResolvedDate string `xml:"RESOLVED_DATE" json:"resolvedDate,omitempty"`
	Priority     string `xml:"PRIORITY" json:"priority,omitempty"`
}

type TicketListResponse struct {
	XMLName  xml.Name `xml:"REMEDIATION_TICKETS"`
	Response struct {
		TicketList []Ticket `xml:"TICKET_LIST>TICKET"`
	} `xml:"RESPONSE"`
}

type TicketCreateResponse struct {
	XMLName  xml.Name `xml:"SIMPLE_RETURN"`
	Response struct {
		Text string `xml:"TEXT"`
		Item struct {
			Key   string `xml:"KEY"`
			Value string `xml:"VALUE"`
		} `xml:"ITEM_LIST>ITEM"`
	} `xml:"RESPONSE"`
}

type SLAStatus struct {
	TotalTickets   int            `json:"totalTickets"`
	OpenTickets    int            `json:"openTickets"`
	ClosedTickets  int            `json:"closedTickets"`
	OverdueTickets int            `json:"overdueTickets"`
	ComplianceRate float64        `json:"complianceRate"`
	ByStatus       map[string]int `json:"byStatus"`
	BySeverity     map[int]int    `json:"bySeverity"`
	OverdueList    []Ticket       `json:"overdueList,omitempty"`
	MTTRDays       float64        `json:"mttrDays"`
	MTTRBySeverity map[int]float64 `json:"mttrBySeverity"`
}

func (c *Client) ListTickets(ctx context.Context, status string, assignee string, overdue bool, limit int) ([]Ticket, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/remediation/ticket/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	if status != "" {
		params.Set("status", status)
	}
	if assignee != "" {
		params.Set("assignee", assignee)
	}
	if limit > 0 {
		params.Set("truncation_limit", fmt.Sprintf("%d", limit))
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp TicketListResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	tickets := resp.Response.TicketList

	if overdue {
		now := time.Now()
		var overdueTickets []Ticket
		for _, t := range tickets {
			if t.DueDate != "" && t.ResolvedDate == "" {
				due, err := time.Parse("2006-01-02T15:04:05Z", t.DueDate)
				if err == nil && now.After(due) {
					overdueTickets = append(overdueTickets, t)
				}
			}
		}
		tickets = overdueTickets
	}

	return tickets, nil
}

func (c *Client) CreateTicket(ctx context.Context, qid string, assetID string, assignee string) (string, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/remediation/ticket/", c.baseURL)

	params := url.Values{}
	params.Set("action", "create")
	params.Set("qids", qid)
	if assetID != "" {
		params.Set("asset_ids", assetID)
	}
	if assignee != "" {
		params.Set("assignee", assignee)
	}

	data, err := c.http.Post(ctx, endpoint, strings.NewReader(params.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return "", err
	}

	var resp TicketCreateResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if resp.Response.Item.Value != "" {
		return resp.Response.Item.Value, nil
	}

	return resp.Response.Text, nil
}

func (c *Client) GetSLAStatus(ctx context.Context, limit int) (*SLAStatus, error) {
	if limit <= 0 {
		limit = 500
	}

	tickets, err := c.ListTickets(ctx, "", "", false, limit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	sla := &SLAStatus{
		TotalTickets:   len(tickets),
		ByStatus:       make(map[string]int),
		BySeverity:     make(map[int]int),
		MTTRBySeverity: make(map[int]float64),
	}

	var totalResolveDays float64
	var resolvedCount int
	severityResolveDays := make(map[int]float64)
	severityResolvedCount := make(map[int]int)

	for _, t := range tickets {
		sla.ByStatus[t.Status]++
		sla.BySeverity[t.Severity]++

		if t.ResolvedDate != "" || t.Status == "CLOSED" || t.Status == "RESOLVED" || t.Status == "FIXED" {
			sla.ClosedTickets++

			if t.CreatedDate != "" && t.ResolvedDate != "" {
				created, errC := time.Parse("2006-01-02T15:04:05Z", t.CreatedDate)
				resolved, errR := time.Parse("2006-01-02T15:04:05Z", t.ResolvedDate)
				if errC == nil && errR == nil {
					days := resolved.Sub(created).Hours() / 24
					totalResolveDays += days
					resolvedCount++
					severityResolveDays[t.Severity] += days
					severityResolvedCount[t.Severity]++
				}
			}
		} else {
			sla.OpenTickets++

			if t.DueDate != "" {
				due, err := time.Parse("2006-01-02T15:04:05Z", t.DueDate)
				if err == nil && now.After(due) {
					sla.OverdueTickets++
					sla.OverdueList = append(sla.OverdueList, t)
				}
			}
		}
	}

	if sla.TotalTickets > 0 {
		onTime := sla.TotalTickets - sla.OverdueTickets
		sla.ComplianceRate = float64(onTime) / float64(sla.TotalTickets) * 100
	}

	if resolvedCount > 0 {
		sla.MTTRDays = totalResolveDays / float64(resolvedCount)
	}

	for sev, days := range severityResolveDays {
		if severityResolvedCount[sev] > 0 {
			sla.MTTRBySeverity[sev] = days / float64(severityResolvedCount[sev])
		}
	}

	// Cap overdue list to 20 for readability
	if len(sla.OverdueList) > 20 {
		sla.OverdueList = sla.OverdueList[:20]
	}

	return sla, nil
}
