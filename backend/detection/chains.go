package detection

import (
	"fmt"
	"math"
	"strings"
)

// AttackChain represents a correlated group of deviations that together
// indicate a multi-step attack pattern.
type AttackChain struct {
	Name       string            `json:"name"`
	Techniques []string          `json:"techniques"`
	Deviations []ScoredDeviation `json:"deviations"`
	ChainScore float64           `json:"chain_score"`
	Severity   string            `json:"severity"`
}

// ChainDetector correlates individual deviations into multi-step attack chains.
type ChainDetector struct{}

// NewChainDetector creates a new chain detector.
func NewChainDetector() *ChainDetector {
	return &ChainDetector{}
}

// DetectChains analyzes deviations for multi-step attack patterns.
// Returns detected chains; individual deviations may appear in multiple chains.
func (cd *ChainDetector) DetectChains(deviations []ScoredDeviation) []AttackChain {
	if len(deviations) < 2 {
		return nil
	}

	var chains []AttackChain

	// Index deviations by type for fast lookup
	byType := make(map[DeviationType][]ScoredDeviation)
	for _, d := range deviations {
		byType[d.DeviationType] = append(byType[d.DeviationType], d)
	}

	// Pattern 1: Credential Theft + Exfiltration
	// sensitive_path (T1552) + new_network (T1041)
	if chain := cd.detectCredentialExfil(byType); chain != nil {
		chains = append(chains, *chain)
	}

	// Pattern 2: Payload Drop + Execution
	// new_file write to /tmp + new_process from /tmp
	if chain := cd.detectPayloadDrop(byType); chain != nil {
		chains = append(chains, *chain)
	}

	// Pattern 3: Reconnaissance + Lateral Movement
	// network tools (nmap, nc, etc.) + new_network to unusual ports
	if chain := cd.detectReconLateral(byType, deviations); chain != nil {
		chains = append(chains, *chain)
	}

	// Pattern 4: Persistence Installation
	// write to .bashrc/cron + shell tool execution
	if chain := cd.detectPersistence(byType, deviations); chain != nil {
		chains = append(chains, *chain)
	}

	return chains
}

func (cd *ChainDetector) detectCredentialExfil(byType map[DeviationType][]ScoredDeviation) *AttackChain {
	sensitives := byType[DeviationSensitivePath]
	networks := byType[DeviationNewNetwork]

	if len(sensitives) == 0 || len(networks) == 0 {
		return nil
	}

	var chainDevs []ScoredDeviation
	chainDevs = append(chainDevs, sensitives...)
	chainDevs = append(chainDevs, networks...)

	maxScore := maxDeviationScore(chainDevs)

	return &AttackChain{
		Name:       "credential_theft_exfiltration",
		Techniques: collectTechniques(chainDevs),
		Deviations: chainDevs,
		ChainScore: math.Min(1.0, maxScore*1.5),
		Severity:   "critical",
	}
}

func (cd *ChainDetector) detectPayloadDrop(byType map[DeviationType][]ScoredDeviation) *AttackChain {
	newFiles := byType[DeviationNewFile]
	newProcs := byType[DeviationNewProcess]

	if len(newFiles) == 0 || len(newProcs) == 0 {
		return nil
	}

	// Look for write to /tmp + execution from /tmp
	var tmpWrites []ScoredDeviation
	for _, f := range newFiles {
		if strings.HasPrefix(f.Event.FilePath, "/tmp/") &&
			(f.Event.AccessType == "write" || f.Event.AccessType == "create") {
			tmpWrites = append(tmpWrites, f)
		}
	}

	var tmpExecs []ScoredDeviation
	for _, p := range newProcs {
		if strings.HasPrefix(p.Event.Binary, "/tmp/") {
			tmpExecs = append(tmpExecs, p)
		}
	}

	if len(tmpWrites) == 0 || len(tmpExecs) == 0 {
		return nil
	}

	var chainDevs []ScoredDeviation
	chainDevs = append(chainDevs, tmpWrites...)
	chainDevs = append(chainDevs, tmpExecs...)

	maxScore := maxDeviationScore(chainDevs)

	return &AttackChain{
		Name:       "payload_drop_execution",
		Techniques: collectTechniques(chainDevs),
		Deviations: chainDevs,
		ChainScore: math.Min(1.0, maxScore*1.4),
		Severity:   "critical",
	}
}

func (cd *ChainDetector) detectReconLateral(byType map[DeviationType][]ScoredDeviation, all []ScoredDeviation) *AttackChain {
	networks := byType[DeviationNewNetwork]
	if len(networks) == 0 {
		return nil
	}

	// Look for network recon tools in process deviations
	reconTools := map[string]bool{
		"nmap": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	}

	var reconProcs []ScoredDeviation
	for _, d := range all {
		if d.DeviationType == DeviationNewProcess || d.DeviationType == DeviationSuspiciousArgs {
			base := binaryBasename(d.Event.Binary)
			if reconTools[base] {
				reconProcs = append(reconProcs, d)
			}
		}
	}

	if len(reconProcs) == 0 {
		return nil
	}

	// Look for connections on unusual ports
	var unusualPorts []ScoredDeviation
	for _, n := range networks {
		if !isCommonPort(n.Event.DestPort) {
			unusualPorts = append(unusualPorts, n)
		}
	}

	if len(unusualPorts) == 0 {
		return nil
	}

	var chainDevs []ScoredDeviation
	chainDevs = append(chainDevs, reconProcs...)
	chainDevs = append(chainDevs, unusualPorts...)

	maxScore := maxDeviationScore(chainDevs)

	return &AttackChain{
		Name:       "reconnaissance_lateral_movement",
		Techniques: collectTechniques(chainDevs),
		Deviations: chainDevs,
		ChainScore: math.Min(1.0, maxScore*1.3),
		Severity:   "high",
	}
}

func (cd *ChainDetector) detectPersistence(byType map[DeviationType][]ScoredDeviation, all []ScoredDeviation) *AttackChain {
	newFiles := byType[DeviationNewFile]
	if len(newFiles) == 0 {
		return nil
	}

	persistPaths := []string{"/.bashrc", "/.bash_profile", "/.profile", "/.zshrc",
		"/crontab", "/cron.d/", "/cron.daily/", "/cron.hourly/"}

	var persistWrites []ScoredDeviation
	for _, f := range newFiles {
		if f.Event.AccessType != "write" && f.Event.AccessType != "create" {
			continue
		}
		for _, p := range persistPaths {
			if strings.Contains(f.Event.FilePath, p) {
				persistWrites = append(persistWrites, f)
				break
			}
		}
	}

	if len(persistWrites) == 0 {
		return nil
	}

	// Look for shell tool usage
	shellTools := map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true,
		"chmod": true, "chown": true,
	}

	var shellDevs []ScoredDeviation
	for _, d := range all {
		if d.DeviationType == DeviationNewProcess || d.DeviationType == DeviationSuspiciousArgs {
			base := binaryBasename(d.Event.Binary)
			if shellTools[base] {
				shellDevs = append(shellDevs, d)
			}
		}
	}

	if len(shellDevs) == 0 {
		return nil
	}

	var chainDevs []ScoredDeviation
	chainDevs = append(chainDevs, persistWrites...)
	chainDevs = append(chainDevs, shellDevs...)

	maxScore := maxDeviationScore(chainDevs)

	return &AttackChain{
		Name:       "persistence_installation",
		Techniques: collectTechniques(chainDevs),
		Deviations: chainDevs,
		ChainScore: math.Min(1.0, maxScore*1.4),
		Severity:   "critical",
	}
}

func maxDeviationScore(devs []ScoredDeviation) float64 {
	max := 0.0
	for _, d := range devs {
		if d.Score > max {
			max = d.Score
		}
	}
	return max
}

func collectTechniques(devs []ScoredDeviation) []string {
	seen := make(map[string]bool)
	var techniques []string
	for _, d := range devs {
		for _, t := range d.MITRETechniques {
			if t != "" && !seen[t] {
				seen[t] = true
				techniques = append(techniques, t)
			}
		}
	}
	return techniques
}

// SeverityFromChains computes the overall severity considering attack chains.
// Chains elevate severity one level above individual deviation max.
func SeverityFromChains(deviations []ScoredDeviation, chains []AttackChain) string {
	baseSeverity := severityFromScore(maxDeviationScore(deviations))

	if len(chains) > 0 {
		baseSeverity = elevateSeverity(baseSeverity)
	}

	// 3+ distinct MITRE techniques → at least "high"
	allTechniques := make(map[string]bool)
	for _, d := range deviations {
		for _, t := range d.MITRETechniques {
			allTechniques[t] = true
		}
	}
	if len(allTechniques) >= 3 && severityRank(baseSeverity) < severityRank("high") {
		baseSeverity = "high"
	}

	// Static-only detections present → boost at least to "medium"
	for _, d := range deviations {
		if d.StaticOnly && severityRank(baseSeverity) < severityRank("medium") {
			baseSeverity = "medium"
			break
		}
	}

	return baseSeverity
}

func severityFromScore(score float64) string {
	return SuggestSeverity(score)
}

func elevateSeverity(sev string) string {
	switch sev {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	default:
		return sev
	}
}

func severityRank(sev string) int {
	switch sev {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// FormatChainsSummary produces a human-readable summary of detected chains.
func FormatChainsSummary(chains []AttackChain) string {
	if len(chains) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, c := range chains {
		sb.WriteString(fmt.Sprintf("- %s (score: %.2f, severity: %s, techniques: %s)\n",
			c.Name, c.ChainScore, c.Severity, strings.Join(c.Techniques, ", ")))
	}
	return sb.String()
}
