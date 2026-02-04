package knowledgebase

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

type QIDInfo struct {
	QID             int      `xml:"QID" json:"qid"`
	Title           string   `xml:"TITLE" json:"title"`
	Category        string   `xml:"CATEGORY" json:"category,omitempty"`
	Severity        int      `xml:"SEVERITY_LEVEL" json:"severity"`
	CVEs            []string `json:"cveList,omitempty"`
	Solution        string   `xml:"SOLUTION" json:"solution,omitempty"`
	Diagnosis       string   `xml:"DIAGNOSIS" json:"diagnosis,omitempty"`
	Consequence     string   `xml:"CONSEQUENCE" json:"consequence,omitempty"`
	VendorReference string   `xml:"VENDOR_REFERENCE_LIST>VENDOR_REFERENCE>URL" json:"vendorReference,omitempty"`
	Published       string   `xml:"PUBLISHED_DATETIME" json:"publishedDate,omitempty"`
	Modified        string   `xml:"LAST_SERVICE_MODIFICATION_DATETIME" json:"lastModifiedDate,omitempty"`
	PatchAvailable  bool     `json:"patchAvailable"`
	PCI             int      `xml:"PCI_FLAG" json:"pciFlag"`
}

type CVEMapping struct {
	CVE  string `json:"cve"`
	QIDs []int  `json:"qids"`
}

type KBXMLResponse struct {
	XMLName  xml.Name  `xml:"KNOWLEDGE_BASE_VULN_LIST_OUTPUT"`
	Response KBResponse `xml:"RESPONSE"`
}

type KBResponse struct {
	DateTime string    `xml:"DATETIME"`
	VulnList []QIDInfo `xml:"VULN_LIST>VULN"`
}

func (c *Client) GetQID(ctx context.Context, qid int) (*QIDInfo, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/knowledge_base/vuln/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("ids", fmt.Sprintf("%d", qid))
	params.Set("details", "All")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp KBXMLResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(resp.Response.VulnList) == 0 {
		return nil, fmt.Errorf("QID %d not found", qid)
	}

	return &resp.Response.VulnList[0], nil
}

func (c *Client) SearchVulns(ctx context.Context, keyword string, limit int) ([]QIDInfo, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/knowledge_base/vuln/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("details", "All")

	if strings.HasPrefix(strings.ToUpper(keyword), "CVE-") {
		params.Set("cve", keyword)
	} else {
		return nil, fmt.Errorf("keyword search not supported by Qualys API - use CVE ID (e.g., CVE-2021-44228) or use kb_get_qid with a specific QID")
	}

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp KBXMLResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	results := resp.Response.VulnList
	if limit > 0 && len(results) > limit {
		return results[:limit], nil
	}

	return results, nil
}

func (c *Client) GetCVEMapping(ctx context.Context, cve string) (*CVEMapping, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/knowledge_base/vuln/", c.baseURL)

	params := url.Values{}
	params.Set("action", "list")
	params.Set("cve", cve)
	params.Set("details", "Basic")

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp KBXMLResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	mapping := &CVEMapping{
		CVE:  cve,
		QIDs: make([]int, len(resp.Response.VulnList)),
	}

	for i, info := range resp.Response.VulnList {
		mapping.QIDs[i] = info.QID
	}

	return mapping, nil
}

func (c *Client) ListRecentVulns(ctx context.Context, days int, limit int) ([]QIDInfo, error) {
	endpoint := fmt.Sprintf("%s/api/2.0/fo/knowledge_base/vuln/", c.baseURL)

	afterDate := time.Now().AddDate(0, 0, -days).Format("2006-01-02")

	params := url.Values{}
	params.Set("action", "list")
	params.Set("details", "All")
	params.Set("last_modified_after", afterDate)

	data, err := c.http.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var resp KBXMLResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	results := resp.Response.VulnList
	if limit > 0 && len(results) > limit {
		return results[:limit], nil
	}

	return results, nil
}
