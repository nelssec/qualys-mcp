package workflows

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/modules/car"
	"github.com/nelssec/qualys-mcp/internal/modules/container"
	"github.com/nelssec/qualys-mcp/internal/modules/gav"
	"github.com/nelssec/qualys-mcp/internal/modules/knowledgebase"
	"github.com/nelssec/qualys-mcp/internal/modules/patch"
	"github.com/nelssec/qualys-mcp/internal/modules/vmdr"
	"github.com/nelssec/qualys-mcp/internal/modules/was"
)

type Client struct {
	gav       *gav.Client
	vmdr      *vmdr.Client
	kb        *knowledgebase.Client
	pm        *patch.Client
	car       *car.Client
	was       *was.Client
	container *container.Client
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

func NewClientFull(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client, containerClient *container.Client) *Client {
	return &Client{
		gav:       gavClient,
		vmdr:      vmdrClient,
		kb:        kbClient,
		pm:        pmClient,
		car:       carClient,
		was:       wasClient,
		container: containerClient,
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

type TechDebtSummary struct {
	Stats               TechDebtStats           `json:"stats"`
	ByLifecycleStage    LifecycleBreakdown      `json:"byLifecycleStage"`
	ByCriticality       CriticalityBreakdown    `json:"byCriticality"`
	EOLOperatingSystems []OSDebtItem            `json:"eolOperatingSystems"`
	EOLHardware         []HardwareDebtItem      `json:"eolHardware,omitempty"`
	EOLContainerImages  []ContainerDebtItem     `json:"eolContainerImages,omitempty"`
	TopAffectedAssets   []TechDebtAsset         `json:"topAffectedAssets"`
	CriticalAssets      []TechDebtAsset         `json:"criticalAssets,omitempty"`
	ReductionPlan       TechDebtReductionPlan   `json:"reductionPlan"`
}

type TechDebtStats struct {
	TotalAssets           int     `json:"totalAssets"`
	AssetsWithEOLOS       int     `json:"assetsWithEolOs"`
	AssetsWithEOSOS       int     `json:"assetsWithEosOs"`
	AssetsWithEOLHardware int     `json:"assetsWithEolHardware"`
	EOLContainerImages    int     `json:"eolContainerImages"`
	TechDebtPercentage    float64 `json:"techDebtPercentage"`
	UniqueOSVersions      int     `json:"uniqueEolOsVersions"`
}

type LifecycleBreakdown struct {
	EOL    int `json:"eol"`
	EOLEOS int `json:"eolEos"`
	EOS    int `json:"hardwareEos"`
	OBS    int `json:"hardwareObsolete"`
}

type CriticalityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type OSDebtItem struct {
	Name         string `json:"name"`
	Stage        string `json:"stage"`
	AssetCount   int    `json:"assetCount"`
	EOLDate      string `json:"eolDate,omitempty"`
	EOSDate      string `json:"eosDate,omitempty"`
}

type HardwareDebtItem struct {
	Name         string `json:"name"`
	Stage        string `json:"stage"`
	AssetCount   int    `json:"assetCount"`
	EOSDate      string `json:"eosDate,omitempty"`
	OBSDate      string `json:"obsDate,omitempty"`
}

type ContainerDebtItem struct {
	ImageID    string `json:"imageId"`
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	BaseOS     string `json:"baseOs,omitempty"`
	EOLDate    string `json:"eolDate,omitempty"`
}

type TechDebtAsset struct {
	AssetID       string `json:"assetId"`
	IP            string `json:"ip,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	OSStage       string `json:"osLifecycleStage,omitempty"`
	Criticality   int    `json:"criticality"`
}

type TechDebtReductionPlan struct {
	TargetPercentage    float64              `json:"targetReductionPercentage"`
	CurrentDebtAssets   int                  `json:"currentDebtAssets"`
	TargetDebtAssets    int                  `json:"targetDebtAssets"`
	AssetsToFix         int                  `json:"assetsToFix"`
	PrioritizedActions  []TechDebtAction     `json:"prioritizedActions"`
}

type TechDebtAction struct {
	Priority     int    `json:"priority"`
	OS           string `json:"operatingSystem"`
	AssetCount   int    `json:"assetCount"`
	Action       string `json:"action"`
	Impact       string `json:"impact"`
}

func (c *Client) GetTechDebtSummary(ctx context.Context, reductionTarget float64, limit int) (*TechDebtSummary, error) {
	if reductionTarget <= 0 {
		reductionTarget = 30.0
	}
	if limit <= 0 {
		limit = 0
	}

	summary := &TechDebtSummary{
		ReductionPlan: TechDebtReductionPlan{
			TargetPercentage: reductionTarget,
		},
	}

	osCounts := make(map[string]*OSDebtItem)
	hwCounts := make(map[string]*HardwareDebtItem)
	var criticalAssets []TechDebtAsset

	if c.gav != nil {
		allAssets, err := c.gav.ListAssets(ctx, "", 300)
		if err == nil {
			summary.Stats.TotalAssets = len(allAssets)
		}

		eolAssets, err := c.gav.GetEOLAssets(ctx, limit)
		if err == nil {
			summary.Stats.AssetsWithEOLOS = len(eolAssets)
			for _, asset := range eolAssets {
				osName := ""
				if os, ok := asset.OS.(string); ok {
					osName = os
				}

				stage := ""
				if asset.OSLifecycle != nil {
					stage = asset.OSLifecycle.Stage
					if strings.Contains(stage, "EOS") {
						summary.ByLifecycleStage.EOLEOS++
					} else if stage == "EOL" {
						summary.ByLifecycleStage.EOL++
					}
				}

				if osName != "" {
					if _, exists := osCounts[osName]; !exists {
						osCounts[osName] = &OSDebtItem{
							Name:       osName,
							AssetCount: 0,
						}
						if asset.OSLifecycle != nil {
							osCounts[osName].Stage = asset.OSLifecycle.Stage
							osCounts[osName].EOLDate = asset.OSLifecycle.EOLDate
							osCounts[osName].EOSDate = asset.OSLifecycle.EOSDate
						}
					}
					osCounts[osName].AssetCount++
				}

				assetID := ""
				if id, ok := asset.AssetID.(float64); ok {
					assetID = fmt.Sprintf("%.0f", id)
				} else if id, ok := asset.AssetID.(string); ok {
					assetID = id
				}

				ip := ""
				if addr, ok := asset.IP.(string); ok {
					ip = addr
				}

				hostname := ""
				if h, ok := asset.Hostname.(string); ok {
					hostname = h
				}

				crit := 2
				if cr, ok := asset.Criticality.(float64); ok {
					crit = int(cr)
				}

				switch crit {
				case 5:
					summary.ByCriticality.Critical++
				case 4:
					summary.ByCriticality.High++
				case 3:
					summary.ByCriticality.Medium++
				default:
					summary.ByCriticality.Low++
				}

				debtAsset := TechDebtAsset{
					AssetID:     assetID,
					IP:          ip,
					Hostname:    hostname,
					OS:          osName,
					OSStage:     stage,
					Criticality: crit,
				}

				if crit >= 4 {
					criticalAssets = append(criticalAssets, debtAsset)
				}

				if len(summary.TopAffectedAssets) < 20 {
					summary.TopAffectedAssets = append(summary.TopAffectedAssets, debtAsset)
				}
			}
		}

		eosAssets, err := c.gav.GetEOSAssets(ctx, limit)
		if err == nil {
			summary.Stats.AssetsWithEOSOS = len(eosAssets)
		}

		eolHW, err := c.gav.GetEOLHardware(ctx, limit)
		if err == nil {
			summary.Stats.AssetsWithEOLHardware = len(eolHW)
			for _, asset := range eolHW {
				if asset.HWLifecycle != nil {
					hwName := "Unknown Hardware"
					if os, ok := asset.OS.(string); ok && os != "" {
						hwName = os
					}

					if asset.HWLifecycle.Stage == "EOS" {
						summary.ByLifecycleStage.EOS++
					} else if asset.HWLifecycle.Stage == "OBS" {
						summary.ByLifecycleStage.OBS++
					}

					if _, exists := hwCounts[hwName]; !exists {
						hwCounts[hwName] = &HardwareDebtItem{
							Name:       hwName,
							Stage:      asset.HWLifecycle.Stage,
							AssetCount: 0,
							EOSDate:    asset.HWLifecycle.EOSDate,
							OBSDate:    asset.HWLifecycle.OBSDate,
						}
					}
					hwCounts[hwName].AssetCount++
				}
			}
		}
	}

	if c.container != nil {
		eolImages, err := c.container.GetEOLImages(ctx, limit)
		if err == nil {
			summary.Stats.EOLContainerImages = len(eolImages)
			for _, img := range eolImages {
				repo := ""
				if r, ok := img.Repository.(string); ok {
					repo = r
				}
				tag := ""
				if t, ok := img.Tag.(string); ok {
					tag = t
				}
				summary.EOLContainerImages = append(summary.EOLContainerImages, ContainerDebtItem{
					ImageID:    img.ImageID,
					Repository: repo,
					Tag:        tag,
					BaseOS:     img.BaseOS,
					EOLDate:    img.EOLDate,
				})
				if len(summary.EOLContainerImages) >= 15 {
					break
				}
			}
		}
	}

	type osSort struct {
		item *OSDebtItem
	}
	var sortableOS []osSort
	for _, item := range osCounts {
		sortableOS = append(sortableOS, osSort{item})
	}
	for i := 0; i < len(sortableOS)-1; i++ {
		for j := i + 1; j < len(sortableOS); j++ {
			if sortableOS[j].item.AssetCount > sortableOS[i].item.AssetCount {
				sortableOS[i], sortableOS[j] = sortableOS[j], sortableOS[i]
			}
		}
	}
	for i := 0; i < len(sortableOS) && i < 20; i++ {
		summary.EOLOperatingSystems = append(summary.EOLOperatingSystems, *sortableOS[i].item)
	}
	summary.Stats.UniqueOSVersions = len(osCounts)

	type hwSort struct {
		item *HardwareDebtItem
	}
	var sortableHW []hwSort
	for _, item := range hwCounts {
		sortableHW = append(sortableHW, hwSort{item})
	}
	for i := 0; i < len(sortableHW)-1; i++ {
		for j := i + 1; j < len(sortableHW); j++ {
			if sortableHW[j].item.AssetCount > sortableHW[i].item.AssetCount {
				sortableHW[i], sortableHW[j] = sortableHW[j], sortableHW[i]
			}
		}
	}
	for i := 0; i < len(sortableHW) && i < 15; i++ {
		summary.EOLHardware = append(summary.EOLHardware, *sortableHW[i].item)
	}

	for i := 0; i < len(criticalAssets)-1; i++ {
		for j := i + 1; j < len(criticalAssets); j++ {
			if criticalAssets[j].Criticality > criticalAssets[i].Criticality {
				criticalAssets[i], criticalAssets[j] = criticalAssets[j], criticalAssets[i]
			}
		}
	}
	for i := 0; i < len(criticalAssets) && i < 15; i++ {
		summary.CriticalAssets = append(summary.CriticalAssets, criticalAssets[i])
	}

	if summary.Stats.TotalAssets > 0 {
		affectedAssets := summary.Stats.AssetsWithEOLOS + summary.Stats.AssetsWithEOLHardware
		summary.Stats.TechDebtPercentage = float64(affectedAssets) / float64(summary.Stats.TotalAssets) * 100
	}

	totalDebtAssets := summary.Stats.AssetsWithEOLOS
	summary.ReductionPlan.CurrentDebtAssets = totalDebtAssets
	summary.ReductionPlan.AssetsToFix = int(float64(totalDebtAssets) * (reductionTarget / 100))
	summary.ReductionPlan.TargetDebtAssets = totalDebtAssets - summary.ReductionPlan.AssetsToFix

	priority := 1
	fixedSoFar := 0
	for _, os := range sortableOS {
		if fixedSoFar >= summary.ReductionPlan.AssetsToFix {
			break
		}
		impact := float64(os.item.AssetCount) / float64(summary.ReductionPlan.AssetsToFix) * 100
		if impact > 100 {
			impact = 100
		}
		action := TechDebtAction{
			Priority:   priority,
			OS:         os.item.Name,
			AssetCount: os.item.AssetCount,
			Action:     "Upgrade to supported OS version",
			Impact:     fmt.Sprintf("Fixes %d assets (%.1f%% of target)", os.item.AssetCount, impact),
		}
		summary.ReductionPlan.PrioritizedActions = append(summary.ReductionPlan.PrioritizedActions, action)
		fixedSoFar += os.item.AssetCount
		priority++
		if priority > 10 {
			break
		}
	}

	return summary, nil
}
