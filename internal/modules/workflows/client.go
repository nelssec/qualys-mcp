package workflows

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/modules/car"
	"github.com/nelssec/qualys-mcp/internal/modules/compliance"
	"github.com/nelssec/qualys-mcp/internal/modules/container"
	"github.com/nelssec/qualys-mcp/internal/modules/gav"
	"github.com/nelssec/qualys-mcp/internal/modules/knowledgebase"
	"github.com/nelssec/qualys-mcp/internal/modules/patch"
	"github.com/nelssec/qualys-mcp/internal/modules/totalcloud"
	"github.com/nelssec/qualys-mcp/internal/modules/vmdr"
	"github.com/nelssec/qualys-mcp/internal/modules/was"
)

type Client struct {
	gav        *gav.Client
	vmdr       *vmdr.Client
	kb         *knowledgebase.Client
	pm         *patch.Client
	car        *car.Client
	was        *was.Client
	container  *container.Client
	totalcloud *totalcloud.Client
	compliance *compliance.Client
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

func NewClientComplete(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client, containerClient *container.Client, tcClient *totalcloud.Client, pcClient *compliance.Client) *Client {
	return &Client{
		gav:        gavClient,
		vmdr:       vmdrClient,
		kb:         kbClient,
		pm:         pmClient,
		car:        carClient,
		was:        wasClient,
		container:  containerClient,
		totalcloud: tcClient,
		compliance: pcClient,
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
		totalCount, err := c.gav.CountAssets(ctx, "")
		if err == nil {
			summary.Stats.TotalAssets = totalCount
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

type WeeklyPriorities struct {
	Summary       WeeklyPrioritiesSummary `json:"summary"`
	TopPriorities []PriorityItem          `json:"topPriorities"`
	ByEffort      EffortBreakdown         `json:"byEffort"`
	BySource      SourceBreakdown         `json:"bySource"`
	Warnings      []string                `json:"warnings,omitempty"`
}

type WeeklyPrioritiesSummary struct {
	TotalCriticalItems int `json:"totalCriticalItems"`
	AssetsAffected     int `json:"assetsAffected"`
	ContainersAtRisk   int `json:"containersAtRisk"`
	PatchableItems     int `json:"patchableItems"`
}

type PriorityItem struct {
	Priority           int      `json:"priority"`
	Category           string   `json:"category"`
	Title              string   `json:"title"`
	QIDs               []int    `json:"qids,omitempty"`
	CVEs               []string `json:"cves,omitempty"`
	AffectedHosts      int      `json:"affectedHosts"`
	AffectedContainers int      `json:"affectedContainers,omitempty"`
	Severity           int      `json:"severity"`
	Effort             string   `json:"effort"`
	Action             string   `json:"action"`
	Impact             string   `json:"impact"`
}

type EffortBreakdown struct {
	PatchAvailable  int `json:"patchAvailable"`
	ConfigChange    int `json:"configChange"`
	UpgradeRequired int `json:"upgradeRequired"`
}

type SourceBreakdown struct {
	Infrastructure int `json:"infrastructure"`
	Containers     int `json:"containers"`
}

func (c *Client) GetWeeklyPriorities(ctx context.Context, limit int) (*WeeklyPriorities, error) {
	if limit <= 0 {
		limit = 10
	}

	result := &WeeklyPriorities{
		TopPriorities: []PriorityItem{},
	}

	qidCounts := make(map[int]int)
	qidSeverity := make(map[int]int)
	qidHosts := make(map[int]map[string]bool)

	if c.vmdr != nil {
		critDets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 5, 0, 500, "Active")
		if err == nil {
			for _, host := range critDets {
				for _, det := range host.Detections {
					qidCounts[det.QID]++
					qidSeverity[det.QID] = det.Severity
					if qidHosts[det.QID] == nil {
						qidHosts[det.QID] = make(map[string]bool)
					}
					qidHosts[det.QID][host.Host.ID] = true
				}
			}
		} else {
			result.Warnings = append(result.Warnings, "VMDR data unavailable")
		}
	}

	type qidInfo struct {
		qid        int
		count      int
		severity   int
		hostCount  int
		title      string
		cves       []string
		patchAvail bool
		solution   string
	}

	var sortedQIDs []qidInfo
	for qid, count := range qidCounts {
		hostCount := len(qidHosts[qid])
		sortedQIDs = append(sortedQIDs, qidInfo{
			qid:       qid,
			count:     count,
			severity:  qidSeverity[qid],
			hostCount: hostCount,
		})
	}

	for i := 0; i < len(sortedQIDs)-1; i++ {
		for j := i + 1; j < len(sortedQIDs); j++ {
			scoreI := sortedQIDs[i].severity*1000 + sortedQIDs[i].hostCount*10
			scoreJ := sortedQIDs[j].severity*1000 + sortedQIDs[j].hostCount*10
			if scoreJ > scoreI {
				sortedQIDs[i], sortedQIDs[j] = sortedQIDs[j], sortedQIDs[i]
			}
		}
	}

	if c.kb != nil && len(sortedQIDs) > 0 {
		maxEnrich := limit * 2
		if maxEnrich > len(sortedQIDs) {
			maxEnrich = len(sortedQIDs)
		}
		for i := 0; i < maxEnrich; i++ {
			kbEntry, err := c.kb.GetQID(ctx, sortedQIDs[i].qid)
			if err == nil && kbEntry != nil {
				sortedQIDs[i].title = kbEntry.Title
				sortedQIDs[i].cves = kbEntry.CVEs
				sortedQIDs[i].patchAvail = kbEntry.PatchAvailable
				sortedQIDs[i].solution = truncate(kbEntry.Solution, 100)
			}
		}
	}

	affectedHostsMap := make(map[string]bool)
	priority := 1
	for i := 0; i < len(sortedQIDs) && priority <= limit; i++ {
		q := sortedQIDs[i]
		if q.title == "" {
			q.title = fmt.Sprintf("QID %d", q.qid)
		}

		effort := "configChange"
		if q.patchAvail {
			effort = "patchAvailable"
			result.ByEffort.PatchAvailable++
		} else {
			result.ByEffort.ConfigChange++
		}

		item := PriorityItem{
			Priority:      priority,
			Category:      "infrastructure",
			Title:         q.title,
			QIDs:          []int{q.qid},
			CVEs:          q.cves,
			AffectedHosts: q.hostCount,
			Severity:      q.severity,
			Effort:        effort,
			Action:        q.solution,
			Impact:        fmt.Sprintf("Fixes %d detections across %d hosts", q.count, q.hostCount),
		}
		result.TopPriorities = append(result.TopPriorities, item)
		result.BySource.Infrastructure++

		for host := range qidHosts[q.qid] {
			affectedHostsMap[host] = true
		}
		priority++
	}

	result.Summary.TotalCriticalItems = len(qidCounts)
	result.Summary.AssetsAffected = len(affectedHostsMap)
	result.Summary.PatchableItems = result.ByEffort.PatchAvailable

	if c.container != nil {
		filter := container.VulnContainerFilter{Severity: 5}
		vulnContainers, err := c.container.ListVulnerableContainers(ctx, filter, 50)
		if err == nil && len(vulnContainers) > 0 {
			imageGroups := make(map[string][]container.VulnerableContainer)
			for _, vc := range vulnContainers {
				repo := ""
				if r, ok := vc.ImageRepo.(string); ok {
					repo = r
				}
				imageGroups[repo] = append(imageGroups[repo], vc)
			}

			for repo, containers := range imageGroups {
				if priority > limit+5 {
					break
				}
				title := "Rebuild vulnerable container images"
				if repo != "" {
					title = fmt.Sprintf("Rebuild %s container images", repo)
				}
				item := PriorityItem{
					Priority:           priority,
					Category:           "container",
					Title:              title,
					AffectedContainers: len(containers),
					Severity:           5,
					Effort:             "upgradeRequired",
					Action:             "Update base images and rebuild affected containers",
					Impact:             fmt.Sprintf("Secures %d running containers", len(containers)),
				}
				result.TopPriorities = append(result.TopPriorities, item)
				result.BySource.Containers++
				result.ByEffort.UpgradeRequired++
				result.Summary.ContainersAtRisk += len(containers)
				priority++
			}
		}
	}

	return result, nil
}

type CVEInvestigation struct {
	CVE            string                  `json:"cve"`
	Details        *CVEDetails             `json:"details,omitempty"`
	QIDs           []int                   `json:"qids"`
	AffectedHosts  []CVEAffectedHost       `json:"affectedHosts"`
	AffectedImages []CVEAffectedImage      `json:"affectedImages,omitempty"`
	Patches        []PatchInfo             `json:"availablePatches,omitempty"`
	Scripts        []ScriptInfo            `json:"remediationScripts,omitempty"`
	ManualFix      string                  `json:"manualRemediationSteps,omitempty"`
	Summary        CVEInvestigationSummary `json:"summary"`
	Warnings       []string                `json:"warnings,omitempty"`
}

type CVEDetails struct {
	CVE         string  `json:"cve"`
	Description string  `json:"description,omitempty"`
	Severity    int     `json:"severity"`
	CVSSv3      float64 `json:"cvssV3,omitempty"`
	Published   string  `json:"publishedDate,omitempty"`
}

type CVEAffectedHost struct {
	AssetID     string `json:"assetId"`
	IP          string `json:"ip,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Criticality int    `json:"criticality,omitempty"`
	FirstFound  string `json:"firstFound,omitempty"`
	Status      string `json:"status,omitempty"`
}

type CVEAffectedImage struct {
	ImageID    string `json:"imageId"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	VulnCount  int    `json:"vulnCount"`
}

type CVEInvestigationSummary struct {
	TotalHostsAffected  int  `json:"totalHostsAffected"`
	TotalImagesAffected int  `json:"totalImagesAffected"`
	PatchAvailable      bool `json:"patchAvailable"`
	ScriptAvailable     bool `json:"scriptAvailable"`
}

func (c *Client) InvestigateCVE(ctx context.Context, cve string) (*CVEInvestigation, error) {
	result := &CVEInvestigation{
		CVE:            cve,
		QIDs:           []int{},
		AffectedHosts:  []CVEAffectedHost{},
		AffectedImages: []CVEAffectedImage{},
	}

	var qids []int
	if c.kb != nil {
		mapping, err := c.kb.GetCVEMapping(ctx, cve)
		if err == nil && mapping != nil {
			qids = mapping.QIDs
			result.QIDs = qids
		}

		if len(qids) > 0 {
			kbEntry, err := c.kb.GetQID(ctx, qids[0])
			if err == nil && kbEntry != nil {
				result.Details = &CVEDetails{
					CVE:         cve,
					Description: truncate(kbEntry.Diagnosis, 500),
					Severity:    kbEntry.Severity,
				}
				result.ManualFix = truncate(kbEntry.Solution, 1000)
				result.Summary.PatchAvailable = kbEntry.PatchAvailable
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "KnowledgeBase unavailable")
	}

	if c.vmdr != nil && len(qids) > 0 {
		qidStr := fmt.Sprintf("%d", qids[0])
		detections, err := c.vmdr.SearchDetections(ctx, qidStr, 0, 0, 200)
		if err == nil {
			for _, hostDet := range detections {
				for _, det := range hostDet.Detections {
					for _, qid := range qids {
						if det.QID == qid {
							host := CVEAffectedHost{
								AssetID:    hostDet.Host.ID,
								IP:         hostDet.Host.IP,
								FirstFound: det.FirstFound,
								Status:     det.Status,
							}
							result.AffectedHosts = append(result.AffectedHosts, host)
							break
						}
					}
				}
			}
		}
	}
	result.Summary.TotalHostsAffected = len(result.AffectedHosts)

	if c.container != nil {
		filter := fmt.Sprintf("vulnerabilities.cveids:%s", cve)
		images, err := c.container.SearchImages(ctx, filter, 100)
		if err == nil {
			for _, img := range images {
				repo := ""
				if r, ok := img.Repository.(string); ok {
					repo = r
				}
				tag := ""
				if t, ok := img.Tag.(string); ok {
					tag = t
				}
				result.AffectedImages = append(result.AffectedImages, CVEAffectedImage{
					ImageID:    img.ImageID,
					Repository: repo,
					Tag:        tag,
					VulnCount:  img.VulnCount,
				})
			}
		}
	}
	result.Summary.TotalImagesAffected = len(result.AffectedImages)

	if c.car != nil {
		scripts, err := c.car.ListRemediationScripts(ctx, 20)
		if err == nil && len(scripts) > 0 {
			for _, s := range scripts {
				scriptID := ""
				if id, ok := s.ID.(string); ok {
					scriptID = id
				} else if id, ok := s.ID.(float64); ok {
					scriptID = fmt.Sprintf("%.0f", id)
				}
				result.Scripts = append(result.Scripts, ScriptInfo{
					ScriptID:    scriptID,
					Title:       s.Title,
					Description: s.Description,
					Platform:    s.Platform,
				})
				if len(result.Scripts) >= 5 {
					break
				}
			}
			result.Summary.ScriptAvailable = len(result.Scripts) > 0
		}
	}

	return result, nil
}

type SecurityPosture struct {
	HealthScore     int                    `json:"healthScore"`
	AssetStats      AssetPostureStats      `json:"assetStats"`
	VulnStats       VulnPostureStats       `json:"vulnerabilityStats"`
	ContainerStats  ContainerPostureStats  `json:"containerStats,omitempty"`
	CloudStats      CloudPostureStats      `json:"cloudStats,omitempty"`
	ComplianceStats CompliancePostureStats `json:"complianceStats,omitempty"`
	Warnings        []string               `json:"warnings,omitempty"`
}

type AssetPostureStats struct {
	TotalAssets    int            `json:"totalAssets"`
	ByOS           map[string]int `json:"byOperatingSystem,omitempty"`
	ByCriticality  map[int]int    `json:"byCriticality,omitempty"`
	HighRiskAssets int            `json:"highRiskAssets"`
}

type VulnPostureStats struct {
	TotalDetections int `json:"totalDetections"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	ActiveCount     int `json:"activeCount"`
}

type ContainerPostureStats struct {
	TotalImages       int `json:"totalImages"`
	VulnerableImages  int `json:"vulnerableImages"`
	RunningContainers int `json:"runningContainers"`
	ContainersAtRisk  int `json:"containersAtRisk"`
}

type CloudPostureStats struct {
	TotalAccounts  int            `json:"totalAccounts"`
	FailedControls int            `json:"failedControls"`
	PassedControls int            `json:"passedControls"`
	ByProvider     map[string]int `json:"byProvider,omitempty"`
	RecentFindings int            `json:"recentCdrFindings"`
}

type CompliancePostureStats struct {
	TotalPolicies int     `json:"totalPolicies"`
	ActiveScans   int     `json:"activeScans"`
	PassRate      float64 `json:"passRatePercent,omitempty"`
}

func (c *Client) GetSecurityPosture(ctx context.Context) (*SecurityPosture, error) {
	result := &SecurityPosture{
		AssetStats: AssetPostureStats{
			ByOS:          make(map[string]int),
			ByCriticality: make(map[int]int),
		},
		CloudStats: CloudPostureStats{
			ByProvider: make(map[string]int),
		},
	}

	healthPoints := 100

	if c.gav != nil {
		totalCount, err := c.gav.CountAssets(ctx, "")
		if err == nil {
			result.AssetStats.TotalAssets = totalCount
		}

		highRisk, err := c.gav.GetHighRiskAssets(ctx, 700, 0, 100)
		if err == nil {
			result.AssetStats.HighRiskAssets = len(highRisk)
			if result.AssetStats.TotalAssets > 0 {
				riskPercent := float64(len(highRisk)) / float64(result.AssetStats.TotalAssets) * 100
				healthPoints -= int(riskPercent)
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "Global AssetView unavailable")
	}

	if c.vmdr != nil {
		stats, err := c.vmdr.GetDetectionStats(ctx, "", 0, 0, "", 500)
		if err == nil {
			result.VulnStats.TotalDetections = stats.TotalDetections
			result.VulnStats.Critical = stats.BySeverity[5]
			result.VulnStats.High = stats.BySeverity[4]
			result.VulnStats.Medium = stats.BySeverity[3]
			result.VulnStats.Low = stats.BySeverity[1] + stats.BySeverity[2]
			result.VulnStats.ActiveCount = stats.TotalDetections

			if result.VulnStats.Critical > 50 {
				healthPoints -= 20
			} else if result.VulnStats.Critical > 20 {
				healthPoints -= 10
			} else if result.VulnStats.Critical > 0 {
				healthPoints -= 5
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "VMDR unavailable")
	}

	if c.container != nil {
		images, err := c.container.ListImages(ctx, "", 500)
		if err == nil {
			result.ContainerStats.TotalImages = len(images)
			for _, img := range images {
				if img.VulnCount > 0 {
					result.ContainerStats.VulnerableImages++
				}
			}
		}

		containers, err := c.container.ListContainers(ctx, "state:RUNNING", 500)
		if err == nil {
			result.ContainerStats.RunningContainers = len(containers)
		}

		filter := container.VulnContainerFilter{Severity: 5}
		vulnContainers, err := c.container.ListVulnerableContainers(ctx, filter, 100)
		if err == nil {
			result.ContainerStats.ContainersAtRisk = len(vulnContainers)
			if result.ContainerStats.RunningContainers > 0 {
				riskPercent := float64(len(vulnContainers)) / float64(result.ContainerStats.RunningContainers) * 100
				healthPoints -= int(riskPercent / 5)
			}
		}
	}

	if c.totalcloud != nil {
		for _, provider := range []string{"aws", "azure", "gcp"} {
			connectors, err := c.totalcloud.ListConnectors(ctx, provider, 100)
			if err == nil && len(connectors) > 0 {
				result.CloudStats.ByProvider[strings.ToUpper(provider)] = len(connectors)
				result.CloudStats.TotalAccounts += len(connectors)
			}
		}

		if result.CloudStats.TotalAccounts > 0 {
			connectors, _ := c.totalcloud.ListConnectors(ctx, "aws", 1)
			if len(connectors) > 0 {
				accountID := connectors[0].AwsAccountID
				if accountID != "" {
					evals, err := c.totalcloud.ListEvaluations(ctx, accountID, "aws", 500)
					if err == nil {
						stats := totalcloud.GetEvaluationStats(evals, 0)
						result.CloudStats.FailedControls = stats.FailedControls
						result.CloudStats.PassedControls = stats.PassedControls
					}
				}
			}
		}

		findings, err := c.totalcloud.ListCDRFindings(ctx, "", "", 7, 100)
		if err == nil {
			result.CloudStats.RecentFindings = len(findings)
			if len(findings) > 20 {
				healthPoints -= 10
			}
		}
	}

	if c.compliance != nil {
		policies, err := c.compliance.ListPolicies(ctx, 100)
		if err == nil {
			result.ComplianceStats.TotalPolicies = len(policies)
		}

		scans, err := c.compliance.ListScans(ctx, "Running", 100)
		if err == nil {
			result.ComplianceStats.ActiveScans = len(scans)
		}
	}

	if healthPoints < 0 {
		healthPoints = 0
	}
	result.HealthScore = healthPoints

	return result, nil
}

type PatchStatus struct {
	Summary         PatchStatusSummary `json:"summary"`
	CriticalPatches []MissingPatchItem `json:"criticalMissingPatches"`
	AssetsByPatch   []AssetPatchInfo   `json:"assetsMissingPatches"`
	RecentJobs      []PatchJobInfo     `json:"recentPatchJobs,omitempty"`
	Breakdown       PatchBreakdown     `json:"breakdown"`
	Warnings        []string           `json:"warnings,omitempty"`
}

type PatchStatusSummary struct {
	TotalAssets          int     `json:"totalAssets"`
	AssetsNeedingPatches int     `json:"assetsNeedingPatches"`
	CoveragePercent      float64 `json:"patchCoveragePercent"`
	TotalMissingPatches  int     `json:"totalMissingPatches"`
	CriticalMissing      int     `json:"criticalPatchesMissing"`
}

type MissingPatchItem struct {
	PatchID       string   `json:"patchId"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	CVEs          []string `json:"cves,omitempty"`
	AffectedHosts int      `json:"affectedHosts"`
	ReleaseDate   string   `json:"releaseDate,omitempty"`
}

type AssetPatchInfo struct {
	AssetID       string `json:"assetId"`
	IP            string `json:"ip,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	Criticality   int    `json:"criticality"`
	MissingCount  int    `json:"missingPatchCount"`
	CriticalCount int    `json:"criticalPatchCount"`
}

type PatchJobInfo struct {
	JobID       string `json:"jobId"`
	Status      string `json:"status"`
	SuccessRate int    `json:"successRatePercent,omitempty"`
	AssetCount  int    `json:"assetCount,omitempty"`
}

type PatchBreakdown struct {
	Patchable    int `json:"patchableVulns"`
	NotPatchable int `json:"notPatchableVulns"`
}

func (c *Client) GetPatchStatus(ctx context.Context, limit int) (*PatchStatus, error) {
	if limit <= 0 {
		limit = 20
	}

	result := &PatchStatus{
		CriticalPatches: []MissingPatchItem{},
		AssetsByPatch:   []AssetPatchInfo{},
		RecentJobs:      []PatchJobInfo{},
	}

	if c.gav != nil {
		totalCount, err := c.gav.CountAssets(ctx, "")
		if err == nil {
			result.Summary.TotalAssets = totalCount
		}
	}

	assetPatchCounts := make(map[string]int)
	assetCritCounts := make(map[string]int)
	patchCounts := make(map[string]int)
	patchDetails := make(map[string]*MissingPatchItem)

	if c.pm != nil {
		assets, err := c.pm.ListAssets(ctx, "", 200)
		if err == nil {
			for _, asset := range assets {
				assetID := ""
				if id, ok := asset.ID.(float64); ok {
					assetID = fmt.Sprintf("%.0f", id)
				} else if id, ok := asset.ID.(string); ok {
					assetID = id
				}
				if assetID == "" {
					continue
				}

				patches, err := c.pm.GetAssetPatches(ctx, assetID, 50)
				if err == nil && len(patches) > 0 {
					result.Summary.AssetsNeedingPatches++
					assetPatchCounts[assetID] = len(patches)

					for _, p := range patches {
						patchID := ""
						if id, ok := p.ID.(string); ok {
							patchID = id
						} else if id, ok := p.ID.(float64); ok {
							patchID = fmt.Sprintf("%.0f", id)
						}
						if patchID == "" {
							continue
						}

						patchCounts[patchID]++
						result.Summary.TotalMissingPatches++

						if p.Severity == "Critical" || p.Severity == "CRITICAL" {
							assetCritCounts[assetID]++
							result.Summary.CriticalMissing++
						}

						if patchDetails[patchID] == nil {
							patchDetails[patchID] = &MissingPatchItem{
								PatchID:  patchID,
								Title:    p.Name,
								Severity: p.Severity,
							}
						}
						patchDetails[patchID].AffectedHosts++
					}
				}
			}
		} else {
			result.Warnings = append(result.Warnings, "Patch Management asset data unavailable")
		}

		jobs, err := c.pm.ListJobs(ctx, "", 10)
		if err == nil {
			for _, j := range jobs {
				jobID := ""
				if id, ok := j.ID.(float64); ok {
					jobID = fmt.Sprintf("%.0f", id)
				} else if id, ok := j.ID.(string); ok {
					jobID = id
				}
				result.RecentJobs = append(result.RecentJobs, PatchJobInfo{
					JobID:  jobID,
					Status: j.Status,
				})
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "Patch Management unavailable")
	}

	type patchSort struct {
		id    string
		count int
	}
	var sortedPatches []patchSort
	for id, count := range patchCounts {
		sortedPatches = append(sortedPatches, patchSort{id, count})
	}
	for i := 0; i < len(sortedPatches)-1; i++ {
		for j := i + 1; j < len(sortedPatches); j++ {
			if sortedPatches[j].count > sortedPatches[i].count {
				sortedPatches[i], sortedPatches[j] = sortedPatches[j], sortedPatches[i]
			}
		}
	}
	for i := 0; i < len(sortedPatches) && i < limit; i++ {
		if detail := patchDetails[sortedPatches[i].id]; detail != nil {
			result.CriticalPatches = append(result.CriticalPatches, *detail)
		}
	}

	type assetSort struct {
		id    string
		count int
		crit  int
	}
	var sortedAssets []assetSort
	for id, count := range assetPatchCounts {
		sortedAssets = append(sortedAssets, assetSort{id, count, assetCritCounts[id]})
	}
	for i := 0; i < len(sortedAssets)-1; i++ {
		for j := i + 1; j < len(sortedAssets); j++ {
			if sortedAssets[j].crit > sortedAssets[i].crit ||
				(sortedAssets[j].crit == sortedAssets[i].crit && sortedAssets[j].count > sortedAssets[i].count) {
				sortedAssets[i], sortedAssets[j] = sortedAssets[j], sortedAssets[i]
			}
		}
	}
	for i := 0; i < len(sortedAssets) && i < limit; i++ {
		result.AssetsByPatch = append(result.AssetsByPatch, AssetPatchInfo{
			AssetID:       sortedAssets[i].id,
			MissingCount:  sortedAssets[i].count,
			CriticalCount: sortedAssets[i].crit,
		})
	}

	if c.vmdr != nil && c.kb != nil {
		stats, err := c.vmdr.GetDetectionStats(ctx, "", 5, 0, "", 500)
		if err == nil {
			for _, top := range stats.TopQIDs {
				kbEntry, err := c.kb.GetQID(ctx, top.QID)
				if err == nil && kbEntry != nil && kbEntry.PatchAvailable {
					result.Breakdown.Patchable++
				} else {
					result.Breakdown.NotPatchable++
				}
			}
		}
	}

	if result.Summary.TotalAssets > 0 {
		patchedAssets := result.Summary.TotalAssets - result.Summary.AssetsNeedingPatches
		result.Summary.CoveragePercent = float64(patchedAssets) / float64(result.Summary.TotalAssets) * 100
	}

	return result, nil
}

type ComplianceGaps struct {
	Summary         ComplianceGapsSummary `json:"summary"`
	TopFailingCtrls []FailingControl      `json:"topFailingControls"`
	AssetsWithGaps  []ComplianceAssetGap  `json:"assetsWithMostGaps"`
	CriticalGaps    []CriticalGap         `json:"criticalGaps,omitempty"`
	Warnings        []string              `json:"warnings,omitempty"`
}

type ComplianceGapsSummary struct {
	TotalPolicies   int     `json:"totalPolicies"`
	TotalControls   int     `json:"totalControls"`
	PassingControls int     `json:"passingControls"`
	FailingControls int     `json:"failingControls"`
	PassRate        float64 `json:"passRatePercent"`
}

type FailingControl struct {
	ControlID   int    `json:"controlId"`
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
	Category    string `json:"category,omitempty"`
	FailCount   int    `json:"failingAssetCount"`
	Remediation string `json:"remediation,omitempty"`
}

type ComplianceAssetGap struct {
	AssetID     string `json:"assetId"`
	IP          string `json:"ip,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Criticality int    `json:"criticality"`
	FailCount   int    `json:"failingControlCount"`
}

type CriticalGap struct {
	PolicyID    int    `json:"policyId"`
	PolicyName  string `json:"policyName"`
	ControlID   int    `json:"controlId"`
	ControlName string `json:"controlName"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation,omitempty"`
}

func (c *Client) GetComplianceGaps(ctx context.Context, limit int) (*ComplianceGaps, error) {
	if limit <= 0 {
		limit = 20
	}

	result := &ComplianceGaps{
		TopFailingCtrls: []FailingControl{},
		AssetsWithGaps:  []ComplianceAssetGap{},
		CriticalGaps:    []CriticalGap{},
	}

	if c.compliance != nil {
		policies, err := c.compliance.ListPolicies(ctx, 100)
		if err == nil {
			result.Summary.TotalPolicies = len(policies)
			for _, p := range policies {
				result.Summary.TotalControls += p.ControlCount
			}
		} else {
			result.Warnings = append(result.Warnings, "Policy data unavailable")
		}
	} else {
		result.Warnings = append(result.Warnings, "Compliance module unavailable")
	}

	if c.totalcloud != nil {
		connectors, err := c.totalcloud.ListConnectors(ctx, "aws", 10)
		if err == nil && len(connectors) > 0 {
			accountID := connectors[0].AwsAccountID
			if accountID != "" {
				evals, err := c.totalcloud.ListEvaluations(ctx, accountID, "aws", 500)
				if err == nil {
					stats := totalcloud.GetEvaluationStats(evals, 20)
					result.Summary.FailingControls = stats.FailedControls
					result.Summary.PassingControls = stats.PassedControls

					if stats.FailedControls+stats.PassedControls > 0 {
						result.Summary.PassRate = float64(stats.PassedControls) / float64(stats.FailedControls+stats.PassedControls) * 100
					}

					controlFails := make(map[string]int)
					for _, e := range evals {
						if e.Status == "FAIL" || e.Status == "FAILED" {
							controlFails[e.ControlID]++
						}
					}

					type ctrlSort struct {
						id    string
						count int
					}
					var sorted []ctrlSort
					for id, count := range controlFails {
						sorted = append(sorted, ctrlSort{id, count})
					}
					for i := 0; i < len(sorted)-1; i++ {
						for j := i + 1; j < len(sorted); j++ {
							if sorted[j].count > sorted[i].count {
								sorted[i], sorted[j] = sorted[j], sorted[i]
							}
						}
					}

					controls, _ := c.totalcloud.ListControls(ctx, "aws", 500)
					controlMap := make(map[string]totalcloud.Control)
					for _, ctrl := range controls {
						controlMap[ctrl.ControlID] = ctrl
					}

					for i := 0; i < len(sorted) && i < limit; i++ {
						fc := FailingControl{
							FailCount: sorted[i].count,
						}
						if ctrl, ok := controlMap[sorted[i].id]; ok {
							fc.Name = ctrl.Name
							fc.Criticality = ctrl.Criticality
							fc.Category = ctrl.Category
						} else {
							fc.Name = sorted[i].id
						}
						result.TopFailingCtrls = append(result.TopFailingCtrls, fc)
					}
				}
			}
		}
	}

	return result, nil
}

type CloudRiskSummary struct {
	Summary           CloudRiskOverview      `json:"summary"`
	AccountsOverview  []CloudAccountInfo     `json:"accountsOverview"`
	FailedControls    []CloudFailedControl   `json:"topFailedControls"`
	Misconfigs        []CloudMisconfig       `json:"misconfigurationsByType,omitempty"`
	ContainerRisks    []CloudContainerRisk   `json:"containerRisks,omitempty"`
	CDRFindings       []CloudCDRFinding      `json:"recentThreats,omitempty"`
	TopRiskyResources []CloudRiskyResource   `json:"topRiskyResources,omitempty"`
	Warnings          []string               `json:"warnings,omitempty"`
}

type CloudRiskOverview struct {
	TotalAccounts      int `json:"totalCloudAccounts"`
	TotalResources     int `json:"totalResources"`
	FailedControlCount int `json:"failedControlCount"`
	CriticalFindings   int `json:"criticalFindings"`
	ContainersAtRisk   int `json:"containersAtRisk"`
}

type CloudAccountInfo struct {
	AccountID   string `json:"accountId"`
	Provider    string `json:"provider"`
	Name        string `json:"name,omitempty"`
	State       string `json:"state,omitempty"`
	TotalAssets int    `json:"totalAssets,omitempty"`
}

type CloudFailedControl struct {
	ControlID   string `json:"controlId"`
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
	Service     string `json:"service,omitempty"`
	FailCount   int    `json:"failingResourceCount"`
}

type CloudMisconfig struct {
	ResourceType string `json:"resourceType"`
	Count        int    `json:"count"`
	Critical     int    `json:"criticalCount"`
}

type CloudContainerRisk struct {
	ClusterName    string `json:"clusterName,omitempty"`
	Provider       string `json:"provider"`
	VulnImageCount int    `json:"vulnerableImageCount"`
	RunningCount   int    `json:"runningContainerCount"`
}

type CloudCDRFinding struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Message    string `json:"message"`
	ResourceID string `json:"resourceId"`
	Timestamp  string `json:"timestamp"`
	Provider   string `json:"provider,omitempty"`
}

type CloudRiskyResource struct {
	ResourceID  string `json:"resourceId"`
	Type        string `json:"resourceType"`
	Provider    string `json:"provider"`
	Region      string `json:"region,omitempty"`
	FailedCtrls int    `json:"failedControlCount"`
}

func (c *Client) GetCloudRiskSummary(ctx context.Context, limit int) (*CloudRiskSummary, error) {
	if limit <= 0 {
		limit = 20
	}

	result := &CloudRiskSummary{
		AccountsOverview:  []CloudAccountInfo{},
		FailedControls:    []CloudFailedControl{},
		Misconfigs:        []CloudMisconfig{},
		ContainerRisks:    []CloudContainerRisk{},
		CDRFindings:       []CloudCDRFinding{},
		TopRiskyResources: []CloudRiskyResource{},
	}

	if c.totalcloud != nil {
		for _, provider := range []string{"aws", "azure", "gcp"} {
			connectors, err := c.totalcloud.ListConnectors(ctx, provider, 50)
			if err == nil {
				for _, conn := range connectors {
					accountID := ""
					switch provider {
					case "aws":
						accountID = conn.AwsAccountID
					case "azure":
						accountID = conn.AzureSubID
					case "gcp":
						accountID = conn.GcpProjectID
					}
					result.AccountsOverview = append(result.AccountsOverview, CloudAccountInfo{
						AccountID:   accountID,
						Provider:    strings.ToUpper(provider),
						Name:        conn.Name,
						State:       conn.State,
						TotalAssets: conn.TotalAssets,
					})
					result.Summary.TotalAccounts++
					result.Summary.TotalResources += conn.TotalAssets
				}
			}
		}

		if len(result.AccountsOverview) > 0 {
			acc := result.AccountsOverview[0]
			provider := strings.ToLower(acc.Provider)
			evals, err := c.totalcloud.ListEvaluations(ctx, acc.AccountID, provider, 500)
			if err == nil {
				controlFails := make(map[string]int)
				resourceFails := make(map[string]int)
				resourceTypes := make(map[string]string)

				for _, e := range evals {
					if e.Status == "FAIL" || e.Status == "FAILED" {
						controlFails[e.ControlID]++
						resourceFails[e.ResourceID]++
						result.Summary.FailedControlCount++
					}
				}

				controls, _ := c.totalcloud.ListControls(ctx, provider, 500)
				controlMap := make(map[string]totalcloud.Control)
				for _, ctrl := range controls {
					controlMap[ctrl.ControlID] = ctrl
				}

				type ctrlSort struct {
					id    string
					count int
				}
				var sortedCtrls []ctrlSort
				for id, count := range controlFails {
					sortedCtrls = append(sortedCtrls, ctrlSort{id, count})
				}
				for i := 0; i < len(sortedCtrls)-1; i++ {
					for j := i + 1; j < len(sortedCtrls); j++ {
						if sortedCtrls[j].count > sortedCtrls[i].count {
							sortedCtrls[i], sortedCtrls[j] = sortedCtrls[j], sortedCtrls[i]
						}
					}
				}
				for i := 0; i < len(sortedCtrls) && i < limit; i++ {
					fc := CloudFailedControl{
						ControlID: sortedCtrls[i].id,
						FailCount: sortedCtrls[i].count,
					}
					if ctrl, ok := controlMap[sortedCtrls[i].id]; ok {
						fc.Name = ctrl.Name
						fc.Criticality = ctrl.Criticality
						fc.Service = ctrl.Service
					}
					result.FailedControls = append(result.FailedControls, fc)
				}

				type resSort struct {
					id    string
					count int
				}
				var sortedRes []resSort
				for id, count := range resourceFails {
					sortedRes = append(sortedRes, resSort{id, count})
				}
				for i := 0; i < len(sortedRes)-1; i++ {
					for j := i + 1; j < len(sortedRes); j++ {
						if sortedRes[j].count > sortedRes[i].count {
							sortedRes[i], sortedRes[j] = sortedRes[j], sortedRes[i]
						}
					}
				}
				for i := 0; i < len(sortedRes) && i < limit; i++ {
					rr := CloudRiskyResource{
						ResourceID:  sortedRes[i].id,
						Provider:    strings.ToUpper(provider),
						FailedCtrls: sortedRes[i].count,
						Type:        resourceTypes[sortedRes[i].id],
					}
					result.TopRiskyResources = append(result.TopRiskyResources, rr)
				}
			}
		}

		findings, err := c.totalcloud.ListCDRFindings(ctx, "", "", 7, limit)
		if err == nil {
			for _, f := range findings {
				sev := ""
				if s, ok := f.Severity.(string); ok {
					sev = s
				} else if s, ok := f.Severity.(float64); ok {
					sev = fmt.Sprintf("%.0f", s)
				}
				if sev == "CRITICAL" || sev == "5" {
					result.Summary.CriticalFindings++
				}
				result.CDRFindings = append(result.CDRFindings, CloudCDRFinding{
					Severity:   sev,
					Category:   f.Category,
					Message:    f.EventMessage,
					ResourceID: f.ResourceID,
					Timestamp:  f.Timestamp,
					Provider:   f.CloudType,
				})
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "TotalCloud unavailable")
	}

	if c.container != nil {
		filter := container.VulnContainerFilter{Severity: 5}
		vulnContainers, err := c.container.ListVulnerableContainers(ctx, filter, 100)
		if err == nil {
			result.Summary.ContainersAtRisk = len(vulnContainers)
		}
	}

	return result, nil
}
