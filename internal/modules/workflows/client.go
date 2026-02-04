package workflows

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/modules/car"
	"github.com/nelssec/qualys-mcp/internal/modules/gav"
	"github.com/nelssec/qualys-mcp/internal/modules/knowledgebase"
	"github.com/nelssec/qualys-mcp/internal/modules/patch"
	"github.com/nelssec/qualys-mcp/internal/modules/vmdr"
	"github.com/nelssec/qualys-mcp/internal/modules/was"
)

type Client struct {
	gav  *gav.Client
	vmdr *vmdr.Client
	kb   *knowledgebase.Client
	pm   *patch.Client
	car  *car.Client
	was  *was.Client
}

func NewClient(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client) *Client {
	return &Client{
		gav:  gavClient,
		vmdr: vmdrClient,
		kb:   kbClient,
		pm:   pmClient,
		car:  carClient,
	}
}

func NewClientWithWAS(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client) *Client {
	return &Client{
		gav:  gavClient,
		vmdr: vmdrClient,
		kb:   kbClient,
		pm:   pmClient,
		car:  carClient,
		was:  wasClient,
	}
}

type AssetRiskSummary struct {
	Asset           *AssetInfo         `json:"asset"`
	RiskScore       int                `json:"riskScore"`
	Criticality     int                `json:"criticality"`
	TopVulns        []VulnInfo         `json:"topVulnerabilities"`
	AvailablePatches []PatchInfo       `json:"availablePatches,omitempty"`
	RemediationSteps []RemediationInfo `json:"remediationSteps,omitempty"`
}

type AssetInfo struct {
	AssetID   string `json:"assetId"`
	IP        string `json:"ip,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
}

type VulnInfo struct {
	QID       int      `json:"qid"`
	Title     string   `json:"title,omitempty"`
	Severity  int      `json:"severity"`
	CVEs      []string `json:"cves,omitempty"`
	FirstFound string  `json:"firstFound,omitempty"`
}

type PatchInfo struct {
	PatchID     string `json:"patchId,omitempty"`
	Title       string `json:"title,omitempty"`
	Severity    string `json:"severity,omitempty"`
	ReleaseDate string `json:"releaseDate,omitempty"`
}

type RemediationInfo struct {
	QID      int    `json:"qid"`
	Title    string `json:"title,omitempty"`
	Solution string `json:"solution,omitempty"`
}

type RemediationPlan struct {
	Vulnerability   *VulnDetails       `json:"vulnerability"`
	AffectedAssets  []AffectedAsset    `json:"affectedAssets"`
	Patches         []PatchInfo        `json:"availablePatches,omitempty"`
	Scripts         []ScriptInfo       `json:"remediationScripts,omitempty"`
	ManualSteps     string             `json:"manualRemediationSteps,omitempty"`
}

type VulnDetails struct {
	QID         int      `json:"qid"`
	Title       string   `json:"title"`
	Severity    int      `json:"severity"`
	CVEs        []string `json:"cves,omitempty"`
	Description string   `json:"description,omitempty"`
}

type AffectedAsset struct {
	AssetID    string `json:"assetId,omitempty"`
	IP         string `json:"ip,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	FirstFound string `json:"firstFound,omitempty"`
	Status     string `json:"status,omitempty"`
}

type ScriptInfo struct {
	ScriptID    string `json:"scriptId"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Platform    string `json:"platform,omitempty"`
}

func (c *Client) GetAssetRiskSummary(ctx context.Context, assetID string) (*AssetRiskSummary, error) {
	summary := &AssetRiskSummary{
		Asset: &AssetInfo{AssetID: assetID},
	}

	if c.gav != nil {
		asset, err := c.gav.GetAssetDetails(ctx, assetID)
		if err == nil && asset != nil {
			if ip, ok := asset.IP.(string); ok {
				summary.Asset.IP = ip
			}
			if hostname, ok := asset.Hostname.(string); ok {
				summary.Asset.Hostname = hostname
			}
			if os, ok := asset.OS.(string); ok {
				summary.Asset.OS = os
			}
			if trurisk, ok := asset.TruRiskScore.(float64); ok {
				summary.RiskScore = int(trurisk)
			}
			if crit, ok := asset.Criticality.(float64); ok {
				summary.Criticality = int(crit)
			}
		}
	}

	if c.vmdr != nil {
		detections, err := c.vmdr.GetHostDetections(ctx, assetID, 4, 0)
		if err == nil && len(detections) > 0 {
			seen := make(map[int]bool)
			for _, det := range detections {
				if seen[det.QID] || len(summary.TopVulns) >= 10 {
					continue
				}
				seen[det.QID] = true

				vuln := VulnInfo{
					QID:        det.QID,
					Severity:   det.Severity,
					FirstFound: det.FirstFound,
				}

				if c.kb != nil {
					kbEntry, err := c.kb.GetQID(ctx, det.QID)
					if err == nil && kbEntry != nil {
						vuln.Title = kbEntry.Title
						vuln.CVEs = kbEntry.CVEs

						summary.RemediationSteps = append(summary.RemediationSteps, RemediationInfo{
							QID:      det.QID,
							Title:    kbEntry.Title,
							Solution: truncate(kbEntry.Solution, 500),
						})
					}
				}

				summary.TopVulns = append(summary.TopVulns, vuln)
			}
		}
	}

	if c.pm != nil {
		patches, err := c.pm.GetAssetPatches(ctx, assetID, 20)
		if err == nil {
			for _, p := range patches {
				if len(summary.AvailablePatches) >= 10 {
					break
				}
				patchID := ""
				if id, ok := p.ID.(string); ok {
					patchID = id
				} else if id, ok := p.ID.(float64); ok {
					patchID = fmt.Sprintf("%.0f", id)
				}
				summary.AvailablePatches = append(summary.AvailablePatches, PatchInfo{
					PatchID:  patchID,
					Title:    p.Name,
					Severity: p.Severity,
				})
			}
		}
	}

	return summary, nil
}

func (c *Client) GetRemediationPlan(ctx context.Context, identifier string) (*RemediationPlan, error) {
	plan := &RemediationPlan{}

	var qid int
	var cve string

	if len(identifier) > 4 && (identifier[:4] == "CVE-" || identifier[:4] == "cve-") {
		cve = identifier
	} else {
		q, err := strconv.Atoi(identifier)
		if err != nil {
			return nil, fmt.Errorf("identifier must be a QID number or CVE ID (e.g., CVE-2024-1234)")
		}
		qid = q
	}

	if cve != "" && c.kb != nil {
		mapping, err := c.kb.GetCVEMapping(ctx, cve)
		if err == nil && mapping != nil && len(mapping.QIDs) > 0 {
			qid = mapping.QIDs[0]
		} else {
			return nil, fmt.Errorf("could not find QID for CVE %s", cve)
		}
	}

	if c.kb != nil && qid > 0 {
		kbEntry, err := c.kb.GetQID(ctx, qid)
		if err == nil && kbEntry != nil {
			plan.Vulnerability = &VulnDetails{
				QID:         qid,
				Title:       kbEntry.Title,
				Severity:    kbEntry.Severity,
				CVEs:        kbEntry.CVEs,
				Description: truncate(kbEntry.Diagnosis, 500),
			}
			plan.ManualSteps = truncate(kbEntry.Solution, 1000)
		}
	}

	if c.vmdr != nil && qid > 0 {
		detections, err := c.vmdr.SearchDetections(ctx, fmt.Sprintf("%d", qid), 0, 0, 100)
		if err == nil {
			for _, hostDet := range detections {
				ip := ""
				hostname := ""
				if hostDet.Host.IP != "" {
					ip = hostDet.Host.IP
				}

				for _, det := range hostDet.Detections {
					if det.QID == qid {
						plan.AffectedAssets = append(plan.AffectedAssets, AffectedAsset{
							AssetID:    hostDet.Host.ID,
							IP:         ip,
							Hostname:   hostname,
							FirstFound: det.FirstFound,
							Status:     det.Status,
						})
						break
					}
				}
			}
		}
	}

	if c.car != nil {
		scripts, err := c.car.ListRemediationScripts(ctx, 50)
		if err == nil {
			for _, s := range scripts {
				scriptID := ""
				if id, ok := s.ID.(string); ok {
					scriptID = id
				} else if id, ok := s.ID.(float64); ok {
					scriptID = fmt.Sprintf("%.0f", id)
				}
				plan.Scripts = append(plan.Scripts, ScriptInfo{
					ScriptID:    scriptID,
					Title:       s.Title,
					Description: s.Description,
					Platform:    s.Platform,
				})
				if len(plan.Scripts) >= 5 {
					break
				}
			}
		}
	}

	return plan, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

type ExternalRiskPriority struct {
	Stats             ExternalRiskStats      `json:"stats"`
	CriticalWebAppVulns []WebAppVulnPriority `json:"criticalWebAppVulns,omitempty"`
	CriticalInfraVulns  []InfraVulnPriority  `json:"criticalInfraVulns,omitempty"`
	HighInfraVulns      []InfraVulnPriority  `json:"highInfraVulns,omitempty"`
	TopRiskAssets       []ExternalAssetRisk  `json:"topRiskAssets,omitempty"`
}

type ExternalRiskStats struct {
	ExternalAssetCount int `json:"externalAssetCount"`
	CriticalVulns      int `json:"criticalVulns"`
	HighVulns          int `json:"highVulns"`
	WebAppFindings     int `json:"webAppFindings"`
	TagUsed            string `json:"tagUsed,omitempty"`
}

type WebAppVulnPriority struct {
	QID          int      `json:"qid"`
	Title        string   `json:"title"`
	Severity     int      `json:"severity"`
	Type         string   `json:"type"`
	AffectedURLs []string `json:"affectedUrls"`
	Remediation  string   `json:"remediation,omitempty"`
}

type InfraVulnPriority struct {
	QID            int      `json:"qid"`
	Title          string   `json:"title"`
	Severity       int      `json:"severity"`
	CVEs           []string `json:"cves,omitempty"`
	AffectedHosts  int      `json:"affectedHosts"`
	ExternalHosts  int      `json:"externalHosts,omitempty"`
	Fix            string   `json:"fix,omitempty"`
	PatchAvailable bool     `json:"patchAvailable"`
}

type ExternalAssetRisk struct {
	AssetID     string `json:"assetId"`
	IP          string `json:"ip"`
	Name        string `json:"hostname,omitempty"`
	Criticality int    `json:"criticality"`
	VulnCount   int    `json:"vulnCount,omitempty"`
	TopQID      int    `json:"topQid,omitempty"`
	TopQIDTitle string `json:"topQidTitle,omitempty"`
}

func (c *Client) PrioritizeExternalRisk(ctx context.Context, tagName string, minSeverity int, limit int, includeWebApps bool) (*ExternalRiskPriority, error) {
	if tagName == "" {
		tagName = "Internet Facing Assets"
	}
	if minSeverity <= 0 {
		minSeverity = 4
	}
	if limit <= 0 {
		limit = 20
	}

	result := &ExternalRiskPriority{
		Stats: ExternalRiskStats{
			TagUsed: tagName,
		},
	}

	var tagID string
	if c.gav != nil {
		tags, err := c.gav.ListTags(ctx)
		if err == nil {
			for _, t := range tags {
				if strings.EqualFold(t.Name, tagName) {
					if id, ok := t.ID.(string); ok {
						tagID = id
					} else if id, ok := t.ID.(int); ok {
						tagID = fmt.Sprintf("%d", id)
					}
					break
				}
			}
		}
	}

	var externalAssetIDs []string
	externalIPMap := make(map[string]bool)

	if tagID != "" && c.gav != nil {
		assets, err := c.gav.GetAssetsByTag(ctx, tagID, 200)
		if err == nil {
			result.Stats.ExternalAssetCount = len(assets)

			assetMap := make(map[string]*ExternalAssetRisk)
			for _, a := range assets {
				assetID := ""
				if id, ok := a.AssetID.(float64); ok {
					assetID = fmt.Sprintf("%.0f", id)
				} else if id, ok := a.AssetID.(string); ok {
					assetID = id
				}

				ip := ""
				if addr, ok := a.IP.(string); ok {
					ip = addr
					externalIPMap[ip] = true
				}

				name := ""
				if n, ok := a.AssetName.(string); ok {
					name = n
				}

				crit := 2
				if c, ok := a.Criticality.(map[string]interface{}); ok {
					if score, ok := c["score"].(float64); ok {
						crit = int(score)
					}
				} else if c, ok := a.Criticality.(float64); ok {
					crit = int(c)
				}

				if assetID != "" {
					externalAssetIDs = append(externalAssetIDs, assetID)
					assetMap[assetID] = &ExternalAssetRisk{
						AssetID:     assetID,
						IP:          ip,
						Name:        name,
						Criticality: crit,
					}
				}
			}

			type assetSort struct {
				asset *ExternalAssetRisk
			}
			var sortable []assetSort
			for _, a := range assetMap {
				sortable = append(sortable, assetSort{a})
			}
			for i := 0; i < len(sortable)-1; i++ {
				for j := i + 1; j < len(sortable); j++ {
					if sortable[j].asset.Criticality > sortable[i].asset.Criticality {
						sortable[i], sortable[j] = sortable[j], sortable[i]
					}
				}
			}
			for i := 0; i < len(sortable) && i < 10; i++ {
				result.TopRiskAssets = append(result.TopRiskAssets, *sortable[i].asset)
			}
		}
	}

	if includeWebApps && c.was != nil {
		findings, err := c.was.ListFindings(ctx, minSeverity, 100)
		if err == nil {
			result.Stats.WebAppFindings = len(findings)

			qidFindings := make(map[int]*WebAppVulnPriority)
			for _, f := range findings {
				if f.Status == "FIXED" {
					continue
				}
				if _, exists := qidFindings[f.QID]; !exists {
					title := f.Name
					remediation := ""

					if c.kb != nil {
						kbEntry, err := c.kb.GetQID(ctx, f.QID)
						if err == nil && kbEntry != nil {
							title = kbEntry.Title
							remediation = truncate(kbEntry.Solution, 200)
						}
					}

					qidFindings[f.QID] = &WebAppVulnPriority{
						QID:          f.QID,
						Title:        title,
						Severity:     f.Severity,
						Type:         f.Type,
						AffectedURLs: []string{},
						Remediation:  remediation,
					}
				}
				if len(qidFindings[f.QID].AffectedURLs) < 3 {
					qidFindings[f.QID].AffectedURLs = append(qidFindings[f.QID].AffectedURLs, f.URL)
				}
			}

			type webSort struct {
				vuln *WebAppVulnPriority
			}
			var sortableWeb []webSort
			for _, v := range qidFindings {
				sortableWeb = append(sortableWeb, webSort{v})
			}
			for i := 0; i < len(sortableWeb)-1; i++ {
				for j := i + 1; j < len(sortableWeb); j++ {
					if sortableWeb[j].vuln.Severity > sortableWeb[i].vuln.Severity ||
						(sortableWeb[j].vuln.Severity == sortableWeb[i].vuln.Severity &&
							len(sortableWeb[j].vuln.AffectedURLs) > len(sortableWeb[i].vuln.AffectedURLs)) {
						sortableWeb[i], sortableWeb[j] = sortableWeb[j], sortableWeb[i]
					}
				}
			}
			for i := 0; i < len(sortableWeb) && i < limit; i++ {
				result.CriticalWebAppVulns = append(result.CriticalWebAppVulns, *sortableWeb[i].vuln)
			}
		}
	}

	if c.vmdr != nil {
		critDets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 5, 0, 500, "Active")
		if err == nil {
			qidCounts := make(map[int]int)
			for _, host := range critDets {
				for _, det := range host.Detections {
					result.Stats.CriticalVulns++
					qidCounts[det.QID]++
				}
			}

			type qidSort struct {
				qid   int
				count int
			}
			var sortable []qidSort
			for qid, count := range qidCounts {
				sortable = append(sortable, qidSort{qid, count})
			}
			for i := 0; i < len(sortable)-1; i++ {
				for j := i + 1; j < len(sortable); j++ {
					if sortable[j].count > sortable[i].count {
						sortable[i], sortable[j] = sortable[j], sortable[i]
					}
				}
			}
			for i := 0; i < len(sortable) && i < limit/2; i++ {
				vuln := InfraVulnPriority{
					QID:           sortable[i].qid,
					Severity:      5,
					AffectedHosts: sortable[i].count,
				}
				if c.kb != nil {
					kbEntry, err := c.kb.GetQID(ctx, sortable[i].qid)
					if err == nil && kbEntry != nil {
						vuln.Title = kbEntry.Title
						vuln.CVEs = kbEntry.CVEs
						vuln.Fix = truncate(kbEntry.Solution, 150)
						vuln.PatchAvailable = kbEntry.PatchAvailable
					}
				}
				result.CriticalInfraVulns = append(result.CriticalInfraVulns, vuln)
			}
		}

		highDets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 4, 0, 500, "Active")
		if err == nil {
			qidCounts := make(map[int]int)
			for _, host := range highDets {
				for _, det := range host.Detections {
					result.Stats.HighVulns++
					qidCounts[det.QID]++
				}
			}

			type qidSort struct {
				qid   int
				count int
			}
			var sortable []qidSort
			for qid, count := range qidCounts {
				sortable = append(sortable, qidSort{qid, count})
			}
			for i := 0; i < len(sortable)-1; i++ {
				for j := i + 1; j < len(sortable); j++ {
					if sortable[j].count > sortable[i].count {
						sortable[i], sortable[j] = sortable[j], sortable[i]
					}
				}
			}
			for i := 0; i < len(sortable) && i < limit/2; i++ {
				vuln := InfraVulnPriority{
					QID:           sortable[i].qid,
					Severity:      4,
					AffectedHosts: sortable[i].count,
				}
				if c.kb != nil {
					kbEntry, err := c.kb.GetQID(ctx, sortable[i].qid)
					if err == nil && kbEntry != nil {
						vuln.Title = kbEntry.Title
						vuln.CVEs = kbEntry.CVEs
						vuln.Fix = truncate(kbEntry.Solution, 150)
						vuln.PatchAvailable = kbEntry.PatchAvailable
					}
				}
				result.HighInfraVulns = append(result.HighInfraVulns, vuln)
			}
		}
	}

	return result, nil
}
