package workflows

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/nelssec/qualys-mcp/internal/modules/activitylog"
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
	gav         *gav.Client
	vmdr        *vmdr.Client
	kb          *knowledgebase.Client
	pm          *patch.Client
	car         *car.Client
	was         *was.Client
	container   *container.Client
	totalcloud  *totalcloud.Client
	compliance  *compliance.Client
	activitylog *activitylog.Client
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

func NewClientComplete(gavClient *gav.Client, vmdrClient *vmdr.Client, kbClient *knowledgebase.Client, pmClient *patch.Client, carClient *car.Client, wasClient *was.Client, containerClient *container.Client, tcClient *totalcloud.Client, pcClient *compliance.Client, alClient *activitylog.Client) *Client {
	return &Client{
		gav:         gavClient,
		vmdr:        vmdrClient,
		kb:          kbClient,
		pm:          pmClient,
		car:         carClient,
		was:         wasClient,
		container:   containerClient,
		totalcloud:  tcClient,
		compliance:  pcClient,
		activitylog: alClient,
	}
}

// --- Shared Types ---

type AssetRiskSummary struct {
	Asset            *AssetInfo        `json:"asset"`
	RiskScore        int               `json:"riskScore"`
	Criticality      int               `json:"criticality"`
	TopVulns         []VulnInfo        `json:"topVulnerabilities"`
	AvailablePatches []PatchInfo       `json:"availablePatches,omitempty"`
	RemediationSteps []RemediationInfo `json:"remediationSteps,omitempty"`
}

type AssetInfo struct {
	AssetID  string `json:"assetId"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

type VulnInfo struct {
	QID        int      `json:"qid"`
	Title      string   `json:"title,omitempty"`
	Severity   int      `json:"severity"`
	CVEs       []string `json:"cves,omitempty"`
	FirstFound string   `json:"firstFound,omitempty"`
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
	Vulnerability  *VulnDetails    `json:"vulnerability"`
	AffectedAssets []AffectedAsset `json:"affectedAssets"`
	Patches        []PatchInfo     `json:"availablePatches,omitempty"`
	Scripts        []ScriptInfo    `json:"remediationScripts,omitempty"`
	ManualSteps    string          `json:"manualRemediationSteps,omitempty"`
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

// --- GetAssetRiskSummary ---
// Goroutines: GAV details, VMDR detections, PM patches all run concurrently.
// KB batch enrichment after detections arrive.

func (c *Client) GetAssetRiskSummary(ctx context.Context, assetID string) (*AssetRiskSummary, error) {
	summary := &AssetRiskSummary{
		Asset: &AssetInfo{AssetID: assetID},
	}

	var wg sync.WaitGroup
	var detections []vmdr.Detection
	var patches []patch.Patch

	// Goroutine 1: GAV asset details
	if c.gav != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			asset, err := c.gav.GetAssetDetails(ctx, assetID)
			if err != nil || asset == nil {
				return
			}
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
		}()
	}

	// Goroutine 2: VMDR detections for this host
	if c.vmdr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dets, err := c.vmdr.GetHostDetections(ctx, assetID, 4, 0)
			if err == nil {
				detections = dets
			}
		}()
	}

	// Goroutine 3: PM patches for this asset
	if c.pm != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := c.pm.GetAssetPatches(ctx, assetID, 20)
			if err == nil {
				patches = p
			}
		}()
	}

	wg.Wait()

	// Process detections + batch KB enrichment
	if len(detections) > 0 {
		seen := make(map[int]bool)
		var qidsToEnrich []int
		for _, det := range detections {
			if seen[det.QID] || len(qidsToEnrich) >= 10 {
				continue
			}
			seen[det.QID] = true
			qidsToEnrich = append(qidsToEnrich, det.QID)
			summary.TopVulns = append(summary.TopVulns, VulnInfo{
				QID:        det.QID,
				Severity:   det.Severity,
				FirstFound: det.FirstFound,
			})
		}

		if c.kb != nil && len(qidsToEnrich) > 0 {
			kbData, _ := c.kb.GetQIDBatch(ctx, qidsToEnrich)
			for i := range summary.TopVulns {
				if kb, ok := kbData[summary.TopVulns[i].QID]; ok {
					summary.TopVulns[i].Title = kb.Title
					summary.TopVulns[i].CVEs = kb.CVEs
					summary.RemediationSteps = append(summary.RemediationSteps, RemediationInfo{
						QID:      kb.QID,
						Title:    kb.Title,
						Solution: truncate(kb.Solution, 500),
					})
				}
			}
		}
	}

	// Process patches
	for _, p := range patches {
		if len(summary.AvailablePatches) >= 10 {
			break
		}
		patchID := interfaceToString(p.ID)
		summary.AvailablePatches = append(summary.AvailablePatches, PatchInfo{
			PatchID:  patchID,
			Title:    p.Name,
			Severity: p.Severity,
		})
	}

	return summary, nil
}

// --- GetRemediationPlan ---
// Goroutines: KB lookup, VMDR search, CAR scripts all run concurrently after QID resolution.

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

	// Resolve CVE -> QID first (must be sequential)
	if cve != "" && c.kb != nil {
		mapping, err := c.kb.GetCVEMapping(ctx, cve)
		if err == nil && mapping != nil && len(mapping.QIDs) > 0 {
			qid = mapping.QIDs[0]
		} else {
			return nil, fmt.Errorf("could not find QID for CVE %s", cve)
		}
	}

	// Now run KB details, VMDR search, and CAR scripts concurrently
	var wg sync.WaitGroup

	if c.kb != nil && qid > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kbEntry, err := c.kb.GetQID(ctx, qid)
			if err != nil || kbEntry == nil {
				return
			}
			plan.Vulnerability = &VulnDetails{
				QID:         qid,
				Title:       kbEntry.Title,
				Severity:    kbEntry.Severity,
				CVEs:        kbEntry.CVEs,
				Description: truncate(kbEntry.Diagnosis, 500),
			}
			plan.ManualSteps = truncate(kbEntry.Solution, 1000)
		}()
	}

	if c.vmdr != nil && qid > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			detections, err := c.vmdr.SearchDetections(ctx, fmt.Sprintf("%d", qid), 0, 0, 100)
			if err != nil {
				return
			}
			for _, hostDet := range detections {
				for _, det := range hostDet.Detections {
					if det.QID == qid {
						plan.AffectedAssets = append(plan.AffectedAssets, AffectedAsset{
							AssetID:    hostDet.Host.ID,
							IP:         hostDet.Host.IP,
							Hostname:   hostDet.Host.Hostname,
							FirstFound: det.FirstFound,
							Status:     det.Status,
						})
						break
					}
				}
			}
		}()
	}

	if c.car != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scripts, err := c.car.ListRemediationScripts(ctx, 50)
			if err != nil {
				return
			}
			for _, s := range scripts {
				plan.Scripts = append(plan.Scripts, ScriptInfo{
					ScriptID:    interfaceToString(s.ID),
					Title:       s.Title,
					Description: s.Description,
					Platform:    s.Platform,
				})
				if len(plan.Scripts) >= 5 {
					break
				}
			}
		}()
	}

	wg.Wait()
	return plan, nil
}

// --- PrioritizeExternalRisk ---

type ExternalRiskPriority struct {
	Stats               ExternalRiskStats    `json:"stats"`
	CriticalWebAppVulns []WebAppVulnPriority `json:"criticalWebAppVulns,omitempty"`
	CriticalInfraVulns  []InfraVulnPriority  `json:"criticalInfraVulns,omitempty"`
	HighInfraVulns      []InfraVulnPriority  `json:"highInfraVulns,omitempty"`
	TopRiskAssets       []ExternalAssetRisk  `json:"topRiskAssets,omitempty"`
}

type ExternalRiskStats struct {
	ExternalAssetCount int    `json:"externalAssetCount"`
	CriticalVulns      int    `json:"criticalVulns"`
	HighVulns          int    `json:"highVulns"`
	WebAppFindings     int    `json:"webAppFindings"`
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
		Stats: ExternalRiskStats{TagUsed: tagName},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Data collectors
	var tagAssets []gav.Asset
	var critDets, highDets []vmdr.HostDetection
	var wasFindings []was.Finding

	// Goroutine 1: Resolve tag -> fetch assets
	if c.gav != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tags, err := c.gav.ListTags(ctx)
			if err != nil {
				return
			}
			var tagID string
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
			if tagID != "" {
				assets, err := c.gav.GetAssetsByTag(ctx, tagID, 200)
				if err == nil {
					mu.Lock()
					tagAssets = assets
					mu.Unlock()
				}
			}
		}()
	}

	// Goroutine 2: Critical detections (sev 5)
	if c.vmdr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 5, 0, 500, "Active")
			if err == nil {
				mu.Lock()
				critDets = dets
				mu.Unlock()
			}
		}()

		// Goroutine 3: High detections (sev 4)
		wg.Add(1)
		go func() {
			defer wg.Done()
			dets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 4, 0, 500, "Active")
			if err == nil {
				mu.Lock()
				highDets = dets
				mu.Unlock()
			}
		}()
	}

	// Goroutine 4: WAS findings
	if includeWebApps && c.was != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, err := c.was.ListFindings(ctx, minSeverity, 100)
			if err == nil {
				mu.Lock()
				wasFindings = findings
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Process tag assets
	if len(tagAssets) > 0 {
		result.Stats.ExternalAssetCount = len(tagAssets)
		var riskAssets []ExternalAssetRisk
		for _, a := range tagAssets {
			assetID := interfaceToString(a.AssetID)
			ip := ""
			if addr, ok := a.IP.(string); ok {
				ip = addr
			}
			name := ""
			if n, ok := a.AssetName.(string); ok {
				name = n
			}
			crit := extractCriticality(a.Criticality)
			if assetID != "" {
				riskAssets = append(riskAssets, ExternalAssetRisk{
					AssetID:     assetID,
					IP:          ip,
					Name:        name,
					Criticality: crit,
				})
			}
		}
		sort.Slice(riskAssets, func(i, j int) bool {
			return riskAssets[i].Criticality > riskAssets[j].Criticality
		})
		if len(riskAssets) > 10 {
			riskAssets = riskAssets[:10]
		}
		result.TopRiskAssets = riskAssets
	}

	// Process critical infra vulns - collect QIDs for batch KB
	critQIDCounts := countDetectionQIDs(critDets)
	highQIDCounts := countDetectionQIDs(highDets)

	result.Stats.CriticalVulns = sumCounts(critQIDCounts)
	result.Stats.HighVulns = sumCounts(highQIDCounts)

	// Batch KB enrichment for all unique QIDs
	var allQIDs []int
	for qid := range critQIDCounts {
		allQIDs = append(allQIDs, qid)
	}
	for qid := range highQIDCounts {
		if _, exists := critQIDCounts[qid]; !exists {
			allQIDs = append(allQIDs, qid)
		}
	}

	var kbData map[int]*knowledgebase.QIDInfo
	if c.kb != nil && len(allQIDs) > 0 {
		kbData, _ = c.kb.GetQIDBatch(ctx, allQIDs)
	}

	result.CriticalInfraVulns = buildInfraVulns(critQIDCounts, kbData, 5, limit/2)
	result.HighInfraVulns = buildInfraVulns(highQIDCounts, kbData, 4, limit/2)

	// Process WAS findings
	if len(wasFindings) > 0 {
		result.Stats.WebAppFindings = len(wasFindings)
		qidFindings := make(map[int]*WebAppVulnPriority)
		var wasQIDs []int
		for _, f := range wasFindings {
			if f.Status == "FIXED" {
				continue
			}
			if _, exists := qidFindings[f.QID]; !exists {
				qidFindings[f.QID] = &WebAppVulnPriority{
					QID:          f.QID,
					Title:        f.Name,
					Severity:     f.Severity,
					Type:         f.Type,
					AffectedURLs: []string{},
				}
				wasQIDs = append(wasQIDs, f.QID)
			}
			if len(qidFindings[f.QID].AffectedURLs) < 3 {
				qidFindings[f.QID].AffectedURLs = append(qidFindings[f.QID].AffectedURLs, f.URL)
			}
		}

		// Batch KB for WAS QIDs
		if c.kb != nil && len(wasQIDs) > 0 {
			wasKB, _ := c.kb.GetQIDBatch(ctx, wasQIDs)
			for qid, finding := range qidFindings {
				if kb, ok := wasKB[qid]; ok {
					finding.Title = kb.Title
					finding.Remediation = truncate(kb.Solution, 200)
				}
			}
		}

		var sortableWeb []*WebAppVulnPriority
		for _, v := range qidFindings {
			sortableWeb = append(sortableWeb, v)
		}
		sort.Slice(sortableWeb, func(i, j int) bool {
			if sortableWeb[i].Severity != sortableWeb[j].Severity {
				return sortableWeb[i].Severity > sortableWeb[j].Severity
			}
			return len(sortableWeb[i].AffectedURLs) > len(sortableWeb[j].AffectedURLs)
		})
		for i := 0; i < len(sortableWeb) && i < limit; i++ {
			result.CriticalWebAppVulns = append(result.CriticalWebAppVulns, *sortableWeb[i])
		}
	}

	return result, nil
}

// --- GetTechDebtSummary ---
// Goroutines: EOL OS, EOS OS, EOL HW, EOL containers, and asset count all run concurrently.

type TechDebtSummary struct {
	Stats               TechDebtStats         `json:"stats"`
	ByLifecycleStage    LifecycleBreakdown    `json:"byLifecycleStage"`
	ByCriticality       CriticalityBreakdown  `json:"byCriticality"`
	EOLOperatingSystems []OSDebtItem          `json:"eolOperatingSystems"`
	EOLHardware         []HardwareDebtItem    `json:"eolHardware,omitempty"`
	EOLContainerImages  []ContainerDebtItem   `json:"eolContainerImages,omitempty"`
	TopAffectedAssets   []TechDebtAsset       `json:"topAffectedAssets"`
	CriticalAssets      []TechDebtAsset       `json:"criticalAssets,omitempty"`
	ReductionPlan       TechDebtReductionPlan `json:"reductionPlan"`
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
	Name       string `json:"name"`
	Stage      string `json:"stage"`
	AssetCount int    `json:"assetCount"`
	EOLDate    string `json:"eolDate,omitempty"`
	EOSDate    string `json:"eosDate,omitempty"`
}

type HardwareDebtItem struct {
	Name       string `json:"name"`
	Stage      string `json:"stage"`
	AssetCount int    `json:"assetCount"`
	EOSDate    string `json:"eosDate,omitempty"`
	OBSDate    string `json:"obsDate,omitempty"`
}

type ContainerDebtItem struct {
	ImageID    string `json:"imageId"`
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	BaseOS     string `json:"baseOs,omitempty"`
	EOLDate    string `json:"eolDate,omitempty"`
}

type TechDebtAsset struct {
	AssetID     string `json:"assetId"`
	IP          string `json:"ip,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	OS          string `json:"os,omitempty"`
	OSStage     string `json:"osLifecycleStage,omitempty"`
	Criticality int    `json:"criticality"`
}

type TechDebtReductionPlan struct {
	TargetPercentage   float64          `json:"targetReductionPercentage"`
	CurrentDebtAssets  int              `json:"currentDebtAssets"`
	TargetDebtAssets   int              `json:"targetDebtAssets"`
	AssetsToFix        int              `json:"assetsToFix"`
	PrioritizedActions []TechDebtAction `json:"prioritizedActions"`
}

type TechDebtAction struct {
	Priority   int    `json:"priority"`
	OS         string `json:"operatingSystem"`
	AssetCount int    `json:"assetCount"`
	Action     string `json:"action"`
	Impact     string `json:"impact"`
}

func (c *Client) GetTechDebtSummary(ctx context.Context, reductionTarget float64, limit int) (*TechDebtSummary, error) {
	if reductionTarget <= 0 {
		reductionTarget = 30.0
	}
	if limit <= 0 {
		limit = 0
	}

	summary := &TechDebtSummary{
		ReductionPlan: TechDebtReductionPlan{TargetPercentage: reductionTarget},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var totalCount int
	var eolAssets []gav.EOLAsset
	var eosAssets []gav.EOLAsset
	var eolHW []gav.EOLAsset
	var eolImages []container.EOLImage

	if c.gav != nil {
		// Goroutine 1: Total asset count (fast endpoint)
		wg.Add(1)
		go func() {
			defer wg.Done()
			count, err := c.gav.CountAssets(ctx, "")
			if err == nil {
				mu.Lock()
				totalCount = count
				mu.Unlock()
			}
		}()

		// Goroutine 2: EOL OS assets
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := c.gav.GetEOLAssets(ctx, limit)
			if err == nil {
				mu.Lock()
				eolAssets = assets
				mu.Unlock()
			}
		}()

		// Goroutine 3: EOS OS assets
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := c.gav.GetEOSAssets(ctx, limit)
			if err == nil {
				mu.Lock()
				eosAssets = assets
				mu.Unlock()
			}
		}()

		// Goroutine 4: EOL Hardware
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := c.gav.GetEOLHardware(ctx, limit)
			if err == nil {
				mu.Lock()
				eolHW = assets
				mu.Unlock()
			}
		}()
	}

	// Goroutine 5: EOL Container images
	if c.container != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			imgs, err := c.container.GetEOLImages(ctx, limit)
			if err == nil {
				mu.Lock()
				eolImages = imgs
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Process results
	summary.Stats.TotalAssets = totalCount
	summary.Stats.AssetsWithEOLOS = len(eolAssets)
	summary.Stats.AssetsWithEOSOS = len(eosAssets)
	summary.Stats.AssetsWithEOLHardware = len(eolHW)
	summary.Stats.EOLContainerImages = len(eolImages)

	// Process EOL OS
	osCounts := make(map[string]*OSDebtItem)
	var criticalAssets []TechDebtAsset
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
				osCounts[osName] = &OSDebtItem{Name: osName}
				if asset.OSLifecycle != nil {
					osCounts[osName].Stage = asset.OSLifecycle.Stage
					osCounts[osName].EOLDate = asset.OSLifecycle.EOLDate
					osCounts[osName].EOSDate = asset.OSLifecycle.EOSDate
				}
			}
			osCounts[osName].AssetCount++
		}

		assetID := interfaceToString(asset.AssetID)
		ip := ""
		if addr, ok := asset.IP.(string); ok {
			ip = addr
		}
		hostname := ""
		if h, ok := asset.Hostname.(string); ok {
			hostname = h
		}
		crit := extractCriticality(asset.Criticality)

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
			AssetID: assetID, IP: ip, Hostname: hostname,
			OS: osName, OSStage: stage, Criticality: crit,
		}
		if crit >= 4 {
			criticalAssets = append(criticalAssets, debtAsset)
		}
		if len(summary.TopAffectedAssets) < 20 {
			summary.TopAffectedAssets = append(summary.TopAffectedAssets, debtAsset)
		}
	}

	// Process EOL Hardware
	hwCounts := make(map[string]*HardwareDebtItem)
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
					Name: hwName, Stage: asset.HWLifecycle.Stage,
					EOSDate: asset.HWLifecycle.EOSDate, OBSDate: asset.HWLifecycle.OBSDate,
				}
			}
			hwCounts[hwName].AssetCount++
		}
	}

	// Process container images
	for _, img := range eolImages {
		if len(summary.EOLContainerImages) >= 15 {
			break
		}
		repo := ""
		if r, ok := img.Repository.(string); ok {
			repo = r
		}
		tag := ""
		if t, ok := img.Tag.(string); ok {
			tag = t
		}
		summary.EOLContainerImages = append(summary.EOLContainerImages, ContainerDebtItem{
			ImageID: img.ImageID, Repository: repo, Tag: tag,
			BaseOS: img.BaseOS, EOLDate: img.EOLDate,
		})
	}

	// Sort and limit OS items
	var sortedOS []*OSDebtItem
	for _, item := range osCounts {
		sortedOS = append(sortedOS, item)
	}
	sort.Slice(sortedOS, func(i, j int) bool {
		return sortedOS[i].AssetCount > sortedOS[j].AssetCount
	})
	for i := 0; i < len(sortedOS) && i < 20; i++ {
		summary.EOLOperatingSystems = append(summary.EOLOperatingSystems, *sortedOS[i])
	}
	summary.Stats.UniqueOSVersions = len(osCounts)

	// Sort and limit HW items
	var sortedHW []*HardwareDebtItem
	for _, item := range hwCounts {
		sortedHW = append(sortedHW, item)
	}
	sort.Slice(sortedHW, func(i, j int) bool {
		return sortedHW[i].AssetCount > sortedHW[j].AssetCount
	})
	for i := 0; i < len(sortedHW) && i < 15; i++ {
		summary.EOLHardware = append(summary.EOLHardware, *sortedHW[i])
	}

	// Sort critical assets
	sort.Slice(criticalAssets, func(i, j int) bool {
		return criticalAssets[i].Criticality > criticalAssets[j].Criticality
	})
	for i := 0; i < len(criticalAssets) && i < 15; i++ {
		summary.CriticalAssets = append(summary.CriticalAssets, criticalAssets[i])
	}

	// Compute debt percentage and reduction plan
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
	for _, os := range sortedOS {
		if fixedSoFar >= summary.ReductionPlan.AssetsToFix || priority > 10 {
			break
		}
		impact := float64(os.AssetCount) / float64(summary.ReductionPlan.AssetsToFix) * 100
		if impact > 100 {
			impact = 100
		}
		summary.ReductionPlan.PrioritizedActions = append(summary.ReductionPlan.PrioritizedActions, TechDebtAction{
			Priority: priority, OS: os.Name, AssetCount: os.AssetCount,
			Action: "Upgrade to supported OS version",
			Impact: fmt.Sprintf("Fixes %d assets (%.1f%% of target)", os.AssetCount, impact),
		})
		fixedSoFar += os.AssetCount
		priority++
	}

	return summary, nil
}

// --- GetWeeklyPriorities ---
// Goroutines: VMDR detections and container vuln search run concurrently.
// Batch KB enrichment after VMDR data arrives.

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

	var wg sync.WaitGroup
	var mu sync.Mutex
	var critDets []vmdr.HostDetection
	var vulnContainers []container.VulnerableContainer

	// Goroutine 1: VMDR critical detections
	if c.vmdr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 5, 0, 500, "Active")
			if err != nil {
				mu.Lock()
				result.Warnings = append(result.Warnings, "VMDR data unavailable")
				mu.Unlock()
				return
			}
			mu.Lock()
			critDets = dets
			mu.Unlock()
		}()
	}

	// Goroutine 2: Vulnerable containers
	if c.container != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			filter := container.VulnContainerFilter{Severity: 5}
			vc, err := c.container.ListVulnerableContainers(ctx, filter, 50)
			if err == nil {
				mu.Lock()
				vulnContainers = vc
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Process VMDR detections
	qidCounts := make(map[int]int)
	qidSeverity := make(map[int]int)
	qidHosts := make(map[int]map[string]bool)

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
		sortedQIDs = append(sortedQIDs, qidInfo{
			qid: qid, count: count,
			severity: qidSeverity[qid], hostCount: len(qidHosts[qid]),
		})
	}
	sort.Slice(sortedQIDs, func(i, j int) bool {
		scoreI := sortedQIDs[i].severity*1000 + sortedQIDs[i].hostCount*10
		scoreJ := sortedQIDs[j].severity*1000 + sortedQIDs[j].hostCount*10
		return scoreI > scoreJ
	})

	// Batch KB enrichment for top QIDs
	if c.kb != nil && len(sortedQIDs) > 0 {
		maxEnrich := limit * 2
		if maxEnrich > len(sortedQIDs) {
			maxEnrich = len(sortedQIDs)
		}
		qidsToEnrich := make([]int, maxEnrich)
		for i := 0; i < maxEnrich; i++ {
			qidsToEnrich[i] = sortedQIDs[i].qid
		}
		kbData, _ := c.kb.GetQIDBatch(ctx, qidsToEnrich)
		for i := 0; i < maxEnrich; i++ {
			if kb, ok := kbData[sortedQIDs[i].qid]; ok {
				sortedQIDs[i].title = kb.Title
				sortedQIDs[i].cves = kb.CVEs
				sortedQIDs[i].patchAvail = kb.PatchAvailable
				sortedQIDs[i].solution = truncate(kb.Solution, 100)
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

		result.TopPriorities = append(result.TopPriorities, PriorityItem{
			Priority: priority, Category: "infrastructure", Title: q.title,
			QIDs: []int{q.qid}, CVEs: q.cves, AffectedHosts: q.hostCount,
			Severity: q.severity, Effort: effort, Action: q.solution,
			Impact: fmt.Sprintf("Fixes %d detections across %d hosts", q.count, q.hostCount),
		})
		result.BySource.Infrastructure++
		for host := range qidHosts[q.qid] {
			affectedHostsMap[host] = true
		}
		priority++
	}

	result.Summary.TotalCriticalItems = len(qidCounts)
	result.Summary.AssetsAffected = len(affectedHostsMap)
	result.Summary.PatchableItems = result.ByEffort.PatchAvailable

	// Process container vulns
	if len(vulnContainers) > 0 {
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
			result.TopPriorities = append(result.TopPriorities, PriorityItem{
				Priority: priority, Category: "container", Title: title,
				AffectedContainers: len(containers), Severity: 5,
				Effort: "upgradeRequired",
				Action:  "Update base images and rebuild affected containers",
				Impact:  fmt.Sprintf("Secures %d running containers", len(containers)),
			})
			result.BySource.Containers++
			result.ByEffort.UpgradeRequired++
			result.Summary.ContainersAtRisk += len(containers)
			priority++
		}
	}

	return result, nil
}

// --- InvestigateCVE ---
// Goroutines: VMDR detection search, container image search, and CAR scripts all run concurrently
// after CVE -> QID resolution.

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

	// Step 1: CVE -> QIDs (must happen first)
	var qids []int
	if c.kb != nil {
		mapping, err := c.kb.GetCVEMapping(ctx, cve)
		if err == nil && mapping != nil {
			qids = mapping.QIDs
			result.QIDs = qids
		}

		// Get KB details for first QID (already cached from GetCVEMapping)
		if len(qids) > 0 {
			kbEntry, err := c.kb.GetQID(ctx, qids[0])
			if err == nil && kbEntry != nil {
				result.Details = &CVEDetails{
					CVE: cve, Description: truncate(kbEntry.Diagnosis, 500),
					Severity: kbEntry.Severity,
				}
				result.ManualFix = truncate(kbEntry.Solution, 1000)
				result.Summary.PatchAvailable = kbEntry.PatchAvailable
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "KnowledgeBase unavailable")
	}

	// Step 2: Run VMDR, container, and CAR searches concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	if c.vmdr != nil && len(qids) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			qidStr := fmt.Sprintf("%d", qids[0])
			detections, err := c.vmdr.SearchDetections(ctx, qidStr, 0, 0, 200)
			if err != nil {
				return
			}
			var hosts []CVEAffectedHost
			for _, hostDet := range detections {
				for _, det := range hostDet.Detections {
					for _, qid := range qids {
						if det.QID == qid {
							hosts = append(hosts, CVEAffectedHost{
								AssetID:    hostDet.Host.ID,
								IP:         hostDet.Host.IP,
								Hostname:   hostDet.Host.Hostname,
								FirstFound: det.FirstFound,
								Status:     det.Status,
							})
							break
						}
					}
				}
			}
			mu.Lock()
			result.AffectedHosts = hosts
			mu.Unlock()
		}()
	}

	if c.container != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			filter := fmt.Sprintf("vulnerabilities.cveids:%s", cve)
			images, err := c.container.SearchImages(ctx, filter, 100)
			if err != nil {
				return
			}
			var affected []CVEAffectedImage
			for _, img := range images {
				repo := ""
				if r, ok := img.Repository.(string); ok {
					repo = r
				}
				tag := ""
				if t, ok := img.Tag.(string); ok {
					tag = t
				}
				affected = append(affected, CVEAffectedImage{
					ImageID: img.ImageID, Repository: repo,
					Tag: tag, VulnCount: img.VulnCount,
				})
			}
			mu.Lock()
			result.AffectedImages = affected
			mu.Unlock()
		}()
	}

	if c.car != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scripts, err := c.car.ListRemediationScripts(ctx, 20)
			if err != nil || len(scripts) == 0 {
				return
			}
			var scriptInfos []ScriptInfo
			for _, s := range scripts {
				scriptInfos = append(scriptInfos, ScriptInfo{
					ScriptID:    interfaceToString(s.ID),
					Title:       s.Title,
					Description: s.Description,
					Platform:    s.Platform,
				})
				if len(scriptInfos) >= 5 {
					break
				}
			}
			mu.Lock()
			result.Scripts = scriptInfos
			result.Summary.ScriptAvailable = len(scriptInfos) > 0
			mu.Unlock()
		}()
	}

	wg.Wait()

	result.Summary.TotalHostsAffected = len(result.AffectedHosts)
	result.Summary.TotalImagesAffected = len(result.AffectedImages)

	return result, nil
}

// --- GetSecurityPosture ---
// Goroutines: ALL data sources run concurrently (GAV, VMDR, Container, Cloud, Compliance).

type SecurityPosture struct {
	HealthScore     int                    `json:"healthScore"`
	AssetStats      AssetPostureStats      `json:"assetStats"`
	VulnStats       VulnPostureStats       `json:"vulnerabilityStats"`
	ContainerStats  ContainerPostureStats  `json:"containerStats,omitempty"`
	CloudStats      CloudPostureStats      `json:"cloudStats,omitempty"`
	ComplianceStats CompliancePostureStats `json:"complianceStats,omitempty"`
	NotableChanges  *NotableChangesStats   `json:"notableChanges,omitempty"`
	Warnings        []string               `json:"warnings,omitempty"`
}

type NotableChangesStats struct {
	TotalEvents      int    `json:"totalEvents"`
	ConfigDrift      int    `json:"configDrift"`
	PolicyChanges    int    `json:"policyChanges"`
	ScanActivity     int    `json:"scanActivity"`
	UserChanges      int    `json:"userChanges"`
	ExceptionChanges int    `json:"exceptionChanges"`
	Summary          string `json:"summary"`
}

type AssetPostureStats struct {
	TotalAssets    int         `json:"totalAssets"`
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
			ByOS: make(map[string]int), ByCriticality: make(map[int]int),
		},
		CloudStats: CloudPostureStats{ByProvider: make(map[string]int)},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	healthPoints := 100

	// Goroutine 1: GAV asset count + high risk
	if c.gav != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			totalCount, err := c.gav.CountAssets(ctx, "")
			if err != nil {
				mu.Lock()
				result.Warnings = append(result.Warnings, "Global AssetView unavailable")
				mu.Unlock()
				return
			}
			highRisk, _ := c.gav.GetHighRiskAssets(ctx, 700, 0, 100)
			mu.Lock()
			result.AssetStats.TotalAssets = totalCount
			result.AssetStats.HighRiskAssets = len(highRisk)
			if totalCount > 0 {
				riskPercent := float64(len(highRisk)) / float64(totalCount) * 100
				healthPoints -= int(riskPercent)
			}
			mu.Unlock()
		}()
	}

	// Goroutine 2: VMDR stats
	if c.vmdr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats, err := c.vmdr.GetDetectionStats(ctx, "", 0, 0, "", 500)
			if err != nil {
				mu.Lock()
				result.Warnings = append(result.Warnings, "VMDR unavailable")
				mu.Unlock()
				return
			}
			mu.Lock()
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
			mu.Unlock()
		}()
	}

	// Goroutine 3: Container stats (images + running + vuln in parallel)
	if c.container != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var innerWg sync.WaitGroup

			var images []container.Image
			var containers []container.Container
			var vulnContainers []container.VulnerableContainer

			innerWg.Add(3)
			go func() {
				defer innerWg.Done()
				imgs, err := c.container.ListImages(ctx, "", 500)
				if err == nil {
					images = imgs
				}
			}()
			go func() {
				defer innerWg.Done()
				ctrs, err := c.container.ListContainers(ctx, "state:RUNNING", 500)
				if err == nil {
					containers = ctrs
				}
			}()
			go func() {
				defer innerWg.Done()
				filter := container.VulnContainerFilter{Severity: 5}
				vc, err := c.container.ListVulnerableContainers(ctx, filter, 100)
				if err == nil {
					vulnContainers = vc
				}
			}()
			innerWg.Wait()

			vulnImageCount := 0
			for _, img := range images {
				if img.VulnCount > 0 {
					vulnImageCount++
				}
			}

			mu.Lock()
			result.ContainerStats.TotalImages = len(images)
			result.ContainerStats.VulnerableImages = vulnImageCount
			result.ContainerStats.RunningContainers = len(containers)
			result.ContainerStats.ContainersAtRisk = len(vulnContainers)
			if len(containers) > 0 {
				riskPercent := float64(len(vulnContainers)) / float64(len(containers)) * 100
				healthPoints -= int(riskPercent / 5)
			}
			mu.Unlock()
		}()
	}

	// Goroutine 4: Cloud connectors + evaluations + CDR
	if c.totalcloud != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Fetch all provider connectors concurrently
			type providerResult struct {
				provider   string
				connectors []totalcloud.Connector
			}
			providers := []string{"aws", "azure", "gcp"}
			provResults := make([]providerResult, len(providers))
			var provWg sync.WaitGroup
			for idx, p := range providers {
				provWg.Add(1)
				go func(i int, prov string) {
					defer provWg.Done()
					conns, err := c.totalcloud.ListConnectors(ctx, prov, 100)
					if err == nil {
						provResults[i] = providerResult{provider: prov, connectors: conns}
					}
				}(idx, p)
			}

			// CDR findings concurrently
			var cdrFindings []totalcloud.CDRFinding
			provWg.Add(1)
			go func() {
				defer provWg.Done()
				findings, err := c.totalcloud.ListCDRFindings(ctx, "", "", 7, 100)
				if err == nil {
					cdrFindings = findings
				}
			}()
			provWg.Wait()

			// Process connector results
			var firstAccountID, firstProvider string
			mu.Lock()
			for _, pr := range provResults {
				if len(pr.connectors) > 0 {
					result.CloudStats.ByProvider[strings.ToUpper(pr.provider)] = len(pr.connectors)
					result.CloudStats.TotalAccounts += len(pr.connectors)
					if firstAccountID == "" {
						firstProvider = pr.provider
						switch pr.provider {
						case "aws":
							firstAccountID = pr.connectors[0].AwsAccountID
						case "azure":
							firstAccountID = pr.connectors[0].AzureSubID
						case "gcp":
							firstAccountID = pr.connectors[0].GcpProjectID
						}
					}
				}
			}
			mu.Unlock()

			// Fetch evaluations for first account
			if firstAccountID != "" {
				evals, err := c.totalcloud.ListEvaluations(ctx, firstAccountID, firstProvider, 500)
				if err == nil {
					stats := totalcloud.GetEvaluationStats(evals, 0)
					mu.Lock()
					result.CloudStats.FailedControls = stats.FailedControls
					result.CloudStats.PassedControls = stats.PassedControls
					mu.Unlock()
				}
			}

			mu.Lock()
			result.CloudStats.RecentFindings = len(cdrFindings)
			if len(cdrFindings) > 20 {
				healthPoints -= 10
			}
			mu.Unlock()
		}()
	}

	// Goroutine 5: Compliance
	if c.compliance != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var innerWg sync.WaitGroup
			var policies []compliance.Policy
			var scans []compliance.Scan

			innerWg.Add(2)
			go func() {
				defer innerWg.Done()
				p, err := c.compliance.ListPolicies(ctx, 100)
				if err == nil {
					policies = p
				}
			}()
			go func() {
				defer innerWg.Done()
				s, err := c.compliance.ListScans(ctx, "Running", 100)
				if err == nil {
					scans = s
				}
			}()
			innerWg.Wait()

			mu.Lock()
			result.ComplianceStats.TotalPolicies = len(policies)
			result.ComplianceStats.ActiveScans = len(scans)
			mu.Unlock()
		}()
	}

	// Goroutine 6: Activity log notable changes (last 24h)
	if c.activitylog != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			changes, err := c.activitylog.GetNotableChanges(ctx, 24)
			if err != nil {
				mu.Lock()
				result.Warnings = append(result.Warnings, "Activity log unavailable")
				mu.Unlock()
				return
			}
			mu.Lock()
			result.NotableChanges = &NotableChangesStats{
				TotalEvents:      changes.TotalEvents,
				ConfigDrift:      len(changes.ConfigDrift),
				PolicyChanges:    len(changes.PolicyChanges),
				ScanActivity:     len(changes.ScanActivity),
				UserChanges:      len(changes.UserChanges),
				ExceptionChanges: len(changes.ExceptionChanges),
				Summary:          changes.Summary,
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	if healthPoints < 0 {
		healthPoints = 0
	}
	result.HealthScore = healthPoints
	return result, nil
}

// --- GetPatchStatus ---
// Optimized: uses VMDR stats instead of N+1 PM asset calls.

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

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Goroutine 1: Asset count
	if c.gav != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			totalCount, err := c.gav.CountAssets(ctx, "")
			if err == nil {
				mu.Lock()
				result.Summary.TotalAssets = totalCount
				mu.Unlock()
			}
		}()
	}

	// Goroutine 2: VMDR detections for patchable analysis
	var critDets []vmdr.HostDetection
	if c.vmdr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dets, err := c.vmdr.SearchDetectionsWithStatus(ctx, "", 5, 0, 500, "Active")
			if err == nil {
				mu.Lock()
				critDets = dets
				mu.Unlock()
			}
		}()
	}

	// Goroutine 3: PM patches (list available, not per-asset)
	if c.pm != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			patches, err := c.pm.ListPatches(ctx, "Critical", limit*2)
			if err == nil {
				mu.Lock()
				for _, p := range patches {
					if len(result.CriticalPatches) >= limit {
						break
					}
					patchID := interfaceToString(p.ID)
					result.CriticalPatches = append(result.CriticalPatches, MissingPatchItem{
						PatchID:  patchID,
						Title:    p.Name,
						Severity: p.Severity,
					})
					result.Summary.TotalMissingPatches++
					if p.Severity == "Critical" || p.Severity == "CRITICAL" {
						result.Summary.CriticalMissing++
					}
				}
				mu.Unlock()
			}
		}()
	}

	// Goroutine 4: PM recent jobs
	if c.pm != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jobs, err := c.pm.ListJobs(ctx, "", 10)
			if err == nil {
				mu.Lock()
				for _, j := range jobs {
					result.RecentJobs = append(result.RecentJobs, PatchJobInfo{
						JobID:  interfaceToString(j.ID),
						Status: j.Status,
					})
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Batch KB enrichment for VMDR QIDs to determine patchable vs not
	if c.kb != nil && len(critDets) > 0 {
		qidCounts := countDetectionQIDs(critDets)
		var qids []int
		for qid := range qidCounts {
			qids = append(qids, qid)
		}
		kbData, _ := c.kb.GetQIDBatch(ctx, qids)

		hostsNeedingPatches := make(map[string]bool)
		for _, host := range critDets {
			for _, det := range host.Detections {
				if kb, ok := kbData[det.QID]; ok && kb.PatchAvailable {
					hostsNeedingPatches[host.Host.ID] = true
					result.Breakdown.Patchable++
				} else {
					result.Breakdown.NotPatchable++
				}
			}
		}
		result.Summary.AssetsNeedingPatches = len(hostsNeedingPatches)
	}

	if result.Summary.TotalAssets > 0 {
		patchedAssets := result.Summary.TotalAssets - result.Summary.AssetsNeedingPatches
		result.Summary.CoveragePercent = float64(patchedAssets) / float64(result.Summary.TotalAssets) * 100
	}

	return result, nil
}

// --- GetComplianceGaps ---

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

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Goroutine 1: Compliance policies
	if c.compliance != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			policies, err := c.compliance.ListPolicies(ctx, 100)
			if err == nil {
				mu.Lock()
				result.Summary.TotalPolicies = len(policies)
				for _, p := range policies {
					result.Summary.TotalControls += p.ControlCount
				}
				mu.Unlock()
			} else {
				mu.Lock()
				result.Warnings = append(result.Warnings, "Policy data unavailable")
				mu.Unlock()
			}
		}()
	}

	// Goroutine 2: Cloud evaluations for compliance
	if c.totalcloud != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			connectors, err := c.totalcloud.ListConnectors(ctx, "aws", 10)
			if err != nil || len(connectors) == 0 {
				return
			}
			accountID := connectors[0].AwsAccountID
			if accountID == "" {
				return
			}

			// Fetch evaluations and controls concurrently
			var evals []totalcloud.Evaluation
			var controls []totalcloud.Control
			var innerWg sync.WaitGroup
			innerWg.Add(2)
			go func() {
				defer innerWg.Done()
				e, err := c.totalcloud.ListEvaluations(ctx, accountID, "aws", 500)
				if err == nil {
					evals = e
				}
			}()
			go func() {
				defer innerWg.Done()
				ctrl, err := c.totalcloud.ListControls(ctx, "aws", 500)
				if err == nil {
					controls = ctrl
				}
			}()
			innerWg.Wait()

			if len(evals) == 0 {
				return
			}

			stats := totalcloud.GetEvaluationStats(evals, 20)
			controlFails := make(map[string]int)
			for _, e := range evals {
				if e.Status == "FAIL" || e.Status == "FAILED" {
					controlFails[e.ControlID]++
				}
			}

			controlMap := make(map[string]totalcloud.Control)
			for _, ctrl := range controls {
				controlMap[ctrl.ControlID] = ctrl
			}

			type ctrlSort struct {
				id    string
				count int
			}
			var sorted []ctrlSort
			for id, count := range controlFails {
				sorted = append(sorted, ctrlSort{id, count})
			}
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].count > sorted[j].count
			})

			mu.Lock()
			result.Summary.FailingControls = stats.FailedControls
			result.Summary.PassingControls = stats.PassedControls
			if stats.FailedControls+stats.PassedControls > 0 {
				result.Summary.PassRate = float64(stats.PassedControls) / float64(stats.FailedControls+stats.PassedControls) * 100
			}
			for i := 0; i < len(sorted) && i < limit; i++ {
				fc := FailingControl{FailCount: sorted[i].count}
				if ctrl, ok := controlMap[sorted[i].id]; ok {
					fc.Name = ctrl.Name
					fc.Criticality = ctrl.Criticality
					fc.Category = ctrl.Category
				} else {
					fc.Name = sorted[i].id
				}
				result.TopFailingCtrls = append(result.TopFailingCtrls, fc)
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	return result, nil
}

// --- GetCloudRiskSummary ---
// Goroutines: All provider connectors, CDR, and container risk run concurrently.

type CloudRiskSummary struct {
	Summary           CloudRiskOverview    `json:"summary"`
	AccountsOverview  []CloudAccountInfo   `json:"accountsOverview"`
	FailedControls    []CloudFailedControl `json:"topFailedControls"`
	Misconfigs        []CloudMisconfig     `json:"misconfigurationsByType,omitempty"`
	ContainerRisks    []CloudContainerRisk `json:"containerRisks,omitempty"`
	CDRFindings       []CloudCDRFinding    `json:"recentThreats,omitempty"`
	TopRiskyResources []CloudRiskyResource `json:"topRiskyResources,omitempty"`
	Warnings          []string             `json:"warnings,omitempty"`
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

	var wg sync.WaitGroup
	var mu sync.Mutex

	if c.totalcloud != nil {
		// Goroutine: Fetch all provider connectors + CDR concurrently
		type providerResult struct {
			provider   string
			connectors []totalcloud.Connector
		}
		providers := []string{"aws", "azure", "gcp"}
		provResults := make([]providerResult, len(providers))

		for idx, p := range providers {
			wg.Add(1)
			go func(i int, prov string) {
				defer wg.Done()
				conns, err := c.totalcloud.ListConnectors(ctx, prov, 50)
				if err == nil {
					mu.Lock()
					provResults[i] = providerResult{provider: prov, connectors: conns}
					mu.Unlock()
				}
			}(idx, p)
		}

		// CDR findings concurrent
		var cdrFindings []totalcloud.CDRFinding
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, err := c.totalcloud.ListCDRFindings(ctx, "", "", 7, limit)
			if err == nil {
				mu.Lock()
				cdrFindings = findings
				mu.Unlock()
			}
		}()

		// Container risk concurrent
		if c.container != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				filter := container.VulnContainerFilter{Severity: 5}
				vc, err := c.container.ListVulnerableContainers(ctx, filter, 100)
				if err == nil {
					mu.Lock()
					result.Summary.ContainersAtRisk = len(vc)
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		// Process connectors
		var firstAccountID, firstProvider string
		for _, pr := range provResults {
			for _, conn := range pr.connectors {
				accountID := ""
				switch pr.provider {
				case "aws":
					accountID = conn.AwsAccountID
				case "azure":
					accountID = conn.AzureSubID
				case "gcp":
					accountID = conn.GcpProjectID
				}
				result.AccountsOverview = append(result.AccountsOverview, CloudAccountInfo{
					AccountID: accountID, Provider: strings.ToUpper(pr.provider),
					Name: conn.Name, State: conn.State, TotalAssets: conn.TotalAssets,
				})
				result.Summary.TotalAccounts++
				result.Summary.TotalResources += conn.TotalAssets
				if firstAccountID == "" && accountID != "" {
					firstAccountID = accountID
					firstProvider = pr.provider
				}
			}
		}

		// Fetch evaluations + controls for first account (sequential, needs accountID)
		if firstAccountID != "" {
			var evals []totalcloud.Evaluation
			var controls []totalcloud.Control
			var evalWg sync.WaitGroup
			evalWg.Add(2)
			go func() {
				defer evalWg.Done()
				e, err := c.totalcloud.ListEvaluations(ctx, firstAccountID, firstProvider, 500)
				if err == nil {
					evals = e
				}
			}()
			go func() {
				defer evalWg.Done()
				ctrl, _ := c.totalcloud.ListControls(ctx, firstProvider, 500)
				controls = ctrl
			}()
			evalWg.Wait()

			controlFails := make(map[string]int)
			resourceFails := make(map[string]int)
			for _, e := range evals {
				if e.Status == "FAIL" || e.Status == "FAILED" {
					controlFails[e.ControlID]++
					resourceFails[e.ResourceID]++
					result.Summary.FailedControlCount++
				}
			}

			controlMap := make(map[string]totalcloud.Control)
			for _, ctrl := range controls {
				controlMap[ctrl.ControlID] = ctrl
			}

			type sortItem struct {
				id    string
				count int
			}
			var sortedCtrls []sortItem
			for id, count := range controlFails {
				sortedCtrls = append(sortedCtrls, sortItem{id, count})
			}
			sort.Slice(sortedCtrls, func(i, j int) bool {
				return sortedCtrls[i].count > sortedCtrls[j].count
			})
			for i := 0; i < len(sortedCtrls) && i < limit; i++ {
				fc := CloudFailedControl{
					ControlID: sortedCtrls[i].id, FailCount: sortedCtrls[i].count,
				}
				if ctrl, ok := controlMap[sortedCtrls[i].id]; ok {
					fc.Name = ctrl.Name
					fc.Criticality = ctrl.Criticality
					fc.Service = ctrl.Service
				}
				result.FailedControls = append(result.FailedControls, fc)
			}

			var sortedRes []sortItem
			for id, count := range resourceFails {
				sortedRes = append(sortedRes, sortItem{id, count})
			}
			sort.Slice(sortedRes, func(i, j int) bool {
				return sortedRes[i].count > sortedRes[j].count
			})
			for i := 0; i < len(sortedRes) && i < limit; i++ {
				result.TopRiskyResources = append(result.TopRiskyResources, CloudRiskyResource{
					ResourceID: sortedRes[i].id, Provider: strings.ToUpper(firstProvider),
					FailedCtrls: sortedRes[i].count,
				})
			}
		}

		// Process CDR findings
		for _, f := range cdrFindings {
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
				Severity: sev, Category: f.Category, Message: f.EventMessage,
				ResourceID: f.ResourceID, Timestamp: f.Timestamp, Provider: f.CloudType,
			})
		}
	} else {
		result.Warnings = append(result.Warnings, "TotalCloud unavailable")
	}

	return result, nil
}

// --- Helper functions ---

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func interfaceToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch id := v.(type) {
	case string:
		return id
	case float64:
		return fmt.Sprintf("%.0f", id)
	case int:
		return fmt.Sprintf("%d", id)
	default:
		return fmt.Sprintf("%v", id)
	}
}

func extractCriticality(v interface{}) int {
	if v == nil {
		return 2
	}
	switch c := v.(type) {
	case float64:
		return int(c)
	case int:
		return c
	case map[string]interface{}:
		if score, ok := c["score"].(float64); ok {
			return int(score)
		}
	}
	return 2
}

// countDetectionQIDs counts total detections per QID across all hosts.
func countDetectionQIDs(detections []vmdr.HostDetection) map[int]int {
	counts := make(map[int]int)
	for _, host := range detections {
		for _, det := range host.Detections {
			counts[det.QID]++
		}
	}
	return counts
}

func sumCounts(m map[int]int) int {
	total := 0
	for _, c := range m {
		total += c
	}
	return total
}

// buildInfraVulns creates sorted InfraVulnPriority list from QID counts + KB data.
func buildInfraVulns(qidCounts map[int]int, kbData map[int]*knowledgebase.QIDInfo, severity int, limit int) []InfraVulnPriority {
	type qidSort struct {
		qid   int
		count int
	}
	var sortable []qidSort
	for qid, count := range qidCounts {
		sortable = append(sortable, qidSort{qid, count})
	}
	sort.Slice(sortable, func(i, j int) bool {
		return sortable[i].count > sortable[j].count
	})

	var result []InfraVulnPriority
	for i := 0; i < len(sortable) && i < limit; i++ {
		vuln := InfraVulnPriority{
			QID: sortable[i].qid, Severity: severity,
			AffectedHosts: sortable[i].count,
		}
		if kbData != nil {
			if kb, ok := kbData[sortable[i].qid]; ok {
				vuln.Title = kb.Title
				vuln.CVEs = kb.CVEs
				vuln.Fix = truncate(kb.Solution, 150)
				vuln.PatchAvailable = kb.PatchAvailable
			}
		}
		result = append(result, vuln)
	}
	return result
}
