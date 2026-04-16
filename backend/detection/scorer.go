package detection

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"strings"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/baseline"
)

// DeviationType categorizes what kind of deviation was detected.
type DeviationType string

const (
	DeviationNewProcess       DeviationType = "new_process"
	DeviationNewNetwork       DeviationType = "new_network"
	DeviationNewFile          DeviationType = "new_file"
	DeviationAnomalousArgs    DeviationType = "anomalous_args"
	DeviationSensitivePath    DeviationType = "sensitive_path"
	DeviationSuspiciousArgs   DeviationType = "suspicious_args"
	DeviationUnexpectedParent DeviationType = "unexpected_parent"
)

// Weights for different deviation types.
// Network events are weighted highest because secret exfiltration is the #1
// supply chain attack goal.
var deviationWeights = map[DeviationType]float64{
	DeviationNewNetwork:       1.0,
	DeviationSensitivePath:    0.9,
	DeviationSuspiciousArgs:   0.85,
	DeviationUnexpectedParent: 0.8,
	DeviationNewProcess:       0.7,
	DeviationAnomalousArgs:    0.5,
	DeviationNewFile:          0.3,
}

// ScoredDeviation represents an event that deviates from the baseline.
type ScoredDeviation struct {
	Event             sensor.Event
	Score             float64
	DeviationType     DeviationType
	Description       string
	MITRETechniques   []string          `json:"mitre_techniques,omitempty"`
	SuggestedSeverity string            `json:"suggested_severity,omitempty"`
	StaticOnly        bool              `json:"static_only,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// Scorer compares job events against a repository baseline and scores deviations.
type Scorer struct {
	logger *slog.Logger
}

// NewScorer creates a new deviation scorer.
func NewScorer(logger *slog.Logger) *Scorer {
	return &Scorer{logger: logger}
}

// ScoreJob scores all events in a job against the given baseline.
// Returns only events that deviate from the baseline.
// During learning mode, only static rules are applied (known-bad patterns).
func (s *Scorer) ScoreJob(bl *baseline.RepositoryBaseline, events []sensor.Event) []ScoredDeviation {
	if bl == nil {
		return nil
	}

	var deviations []ScoredDeviation

	if bl.IsLearning() {
		// Static-only detection: catch known-bad patterns even without a trained baseline
		for _, evt := range events {
			devs := s.scoreEventStatic(evt)
			deviations = append(deviations, devs...)
		}
	} else {
		// Full baseline-aware scoring
		for _, evt := range events {
			devs := s.scoreEvent(bl, evt)
			deviations = append(deviations, devs...)
		}
	}

	if len(deviations) > 0 {
		// Log deviation breakdown for debugging
		typeCounts := make(map[DeviationType]int)
		for _, d := range deviations {
			typeCounts[d.DeviationType]++
		}
		s.logger.Debug("deviation breakdown",
			"total", len(deviations),
			"by_type", typeCounts)
	}

	return deviations
}

// scoreEventStatic applies only static detection rules (no baseline comparison).
// Used during the learning phase to catch known-bad patterns like reverse shells,
// credential access, and suspicious argument patterns.
func (s *Scorer) scoreEventStatic(evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

	switch evt.Type {
	case sensor.EventTypeProcessExec:
		// Check for suspicious binaries
		if isSuspiciousBinary(evt.Binary) {
			deviations = append(deviations, ScoredDeviation{
				Event:         evt,
				Score:         1.0,
				DeviationType: DeviationNewProcess,
				Description:   fmt.Sprintf("Suspicious binary detected (static rule): %s", evt.Binary),
				StaticOnly:    true,
			})
		}

		// Check for suspicious argument patterns
		if match, desc := matchSuspiciousArgRules(evt.Binary, evt.Args); match {
			deviations = append(deviations, ScoredDeviation{
				Event:         evt,
				Score:         deviationWeights[DeviationSuspiciousArgs],
				DeviationType: DeviationSuspiciousArgs,
				Description:   desc + " (static rule)",
				StaticOnly:    true,
			})
		}

		// Check for high-risk parent→child combos
		if evt.ParentBinary != "" && isHighRiskParentCombo(evt.ParentBinary, evt.Binary) {
			deviations = append(deviations, ScoredDeviation{
				Event:         evt,
				Score:         1.0,
				DeviationType: DeviationUnexpectedParent,
				Description: fmt.Sprintf(
					"High-risk process chain (static rule): %s → %s",
					evt.ParentBinary, evt.Binary,
				),
				StaticOnly: true,
			})
		}

	case sensor.EventTypeFileAccess:
		// Check for sensitive path access
		if isSensitivePath(evt.FilePath) {
			deviations = append(deviations, ScoredDeviation{
				Event:         evt,
				Score:         deviationWeights[DeviationSensitivePath],
				DeviationType: DeviationSensitivePath,
				Description: fmt.Sprintf(
					"Access to sensitive path (static rule): %s by %s",
					evt.FilePath, evt.Binary,
				),
				StaticOnly: true,
			})
		}
	}

	// Enrich static deviations with MITRE mappings and severity
	for i := range deviations {
		enrichDeviation(&deviations[i])
	}

	return deviations
}

func (s *Scorer) scoreEvent(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

	switch evt.Type {
	case sensor.EventTypeProcessExec:
		devs := s.scoreProcessExec(bl, evt)
		deviations = append(deviations, devs...)

	case sensor.EventTypeNetworkConnect:
		devs := s.scoreNetworkConnect(bl, evt)
		deviations = append(deviations, devs...)

	case sensor.EventTypeFileAccess:
		devs := s.scoreFileAccess(bl, evt)
		deviations = append(deviations, devs...)
	}

	// Enrich all deviations with MITRE mappings and severity
	for i := range deviations {
		enrichDeviation(&deviations[i])
	}

	return deviations
}

func (s *Scorer) scoreProcessExec(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

	profile := bl.FindProcessProfile(evt.Binary)

	if profile == nil {
		// Never-before-seen binary
		score := deviationWeights[DeviationNewProcess]

		// Boost score for particularly suspicious binaries
		if isSuspiciousBinary(evt.Binary) {
			score = 1.0
		}

		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         score,
			DeviationType: DeviationNewProcess,
			Description: fmt.Sprintf(
				"New binary never seen in baseline: %s (args: %v)",
				evt.Binary, evt.Args,
			),
		})
	} else if profile.Frequency < 0.05 {
		// Rare binary (seen in less than 5% of builds)
		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         deviationWeights[DeviationNewProcess] * (1 - profile.Frequency),
			DeviationType: DeviationNewProcess,
			Description: fmt.Sprintf(
				"Rare binary (frequency: %.2f%%): %s",
				profile.Frequency*100, evt.Binary,
			),
		})
	}

	// Score suspicious argument patterns (static rules)
	argDevs := s.scoreProcessArgs(bl, evt)
	deviations = append(deviations, argDevs...)

	// Score anomalous args (statistical — based on baseline arg signatures)
	anomalousDevs := s.scoreAnomalousArgs(bl, evt)
	deviations = append(deviations, anomalousDevs...)

	// Score unexpected parent process
	parentDevs := s.scoreProcessParent(bl, evt)
	deviations = append(deviations, parentDevs...)

	// Apply step-context modifier: boost scores when binary appears in unexpected step
	s.applyStepModifier(profile, evt, deviations)

	return deviations
}

// scoreProcessArgs detects dangerous argument patterns for both known and unknown binaries.
func (s *Scorer) scoreProcessArgs(_ *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

	if match, desc := matchSuspiciousArgRules(evt.Binary, evt.Args); match {
		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         deviationWeights[DeviationSuspiciousArgs],
			DeviationType: DeviationSuspiciousArgs,
			Description:   desc,
		})
	}

	return deviations
}

// scoreAnomalousArgs detects when a known binary is invoked with an argument
// pattern never seen in the baseline.
func (s *Scorer) scoreAnomalousArgs(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	// Only score anomalous args once baseline has enough observations
	// to have meaningful arg signature data
	if bl.TotalJobsObserved < 5 {
		return nil
	}

	profile := bl.FindProcessProfile(evt.Binary)
	if profile == nil || len(profile.ArgSignatures) == 0 {
		return nil // No arg baseline data
	}

	argPattern := baseline.NormalizeArgs(evt.Binary, evt.Args)
	if argPattern == "" {
		return nil
	}

	sig := profile.FindArgSignature(argPattern)
	if sig == nil {
		// Never-seen arg pattern for a known binary
		return []ScoredDeviation{{
			Event:         evt,
			Score:         deviationWeights[DeviationAnomalousArgs],
			DeviationType: DeviationAnomalousArgs,
			Description: fmt.Sprintf(
				"Known binary %s invoked with unseen argument pattern: %s",
				evt.Binary, argPattern,
			),
		}}
	} else if sig.Frequency < 0.05 {
		// Rare arg pattern — lower score
		return []ScoredDeviation{{
			Event:         evt,
			Score:         deviationWeights[DeviationAnomalousArgs] * 0.6,
			DeviationType: DeviationAnomalousArgs,
			Description: fmt.Sprintf(
				"Known binary %s with rare argument pattern (freq: %.2f%%): %s",
				evt.Binary, sig.Frequency*100, argPattern,
			),
		}}
	}

	return nil
}

// scoreProcessParent detects when a process is spawned by an unexpected parent.
func (s *Scorer) scoreProcessParent(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	if evt.ParentBinary == "" {
		return nil // No parent info — skip
	}

	profile := bl.FindProcessProfile(evt.Binary)
	if profile == nil || len(profile.KnownParents) == 0 {
		return nil // Not enough baseline data
	}

	// Only flag unexpected parents after sufficient observations —
	// parent sets are sparse in early jobs.
	if profile.ObservedCount < 3 {
		return nil
	}

	// Check if this parent is known
	for _, knownParent := range profile.KnownParents {
		if knownParent == evt.ParentBinary {
			return nil // Expected parent
		}
	}

	score := deviationWeights[DeviationUnexpectedParent]

	// Boost for high-risk parent→child combinations
	if isHighRiskParentCombo(evt.ParentBinary, evt.Binary) {
		score = 1.0
	}

	return []ScoredDeviation{{
		Event:         evt,
		Score:         score,
		DeviationType: DeviationUnexpectedParent,
		Description: fmt.Sprintf(
			"Binary %s spawned by unexpected parent %s (known parents: %v)",
			evt.Binary, evt.ParentBinary, profile.KnownParents,
		),
	}}
}

// applyStepModifier boosts deviation scores when a binary appears in an unexpected workflow step.
func (s *Scorer) applyStepModifier(profile *baseline.ProcessProfile, evt sensor.Event, deviations []ScoredDeviation) {
	if profile == nil || evt.StepName == "" || len(profile.StepFrequency) == 0 || len(deviations) == 0 {
		return
	}

	stepFreq, knownStep := profile.StepFrequency[evt.StepName]

	if !knownStep {
		// This binary has never run in this step before — strong signal
		for i := range deviations {
			deviations[i].Score = math.Min(1.0, deviations[i].Score*1.3)
			deviations[i].Description += fmt.Sprintf(" [unexpected step: %s]", evt.StepName)
		}
	} else if stepFreq < 0.1 {
		// Rare in this step — mild boost
		for i := range deviations {
			deviations[i].Score = math.Min(1.0, deviations[i].Score*1.15)
		}
	}
}

// trustedDomainSuffixes are domains commonly used by package registries
// and CI/CD services. Connections to these reduce network deviation scores.
var trustedDomainSuffixes = map[string]bool{
	"github.com":       true,
	"githubusercontent.com": true,
	"npmjs.org":        true,
	"npmjs.com":        true,
	"yarnpkg.com":      true,
	"pypi.org":         true,
	"pythonhosted.org": true,
	"rubygems.org":     true,
	"crates.io":        true,
	"docker.io":        true,
	"docker.com":       true,
	"gcr.io":           true,
	"amazonaws.com":    true,
	"cloudfront.net":   true,
	"googleapis.com":   true,
	"registry.npmjs.org": true,
	"gitlab.com":       true,
	"bitbucket.org":    true,
	"nuget.org":        true,
	"maven.org":        true,
	"gradle.org":       true,
	"golang.org":       true,
	"proxy.golang.org": true,
	"sum.golang.org":   true,
}

func (s *Scorer) scoreNetworkConnect(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

	if evt.DestIP == nil {
		return nil
	}
	destIP := evt.DestIP.String()

	profile := bl.FindNetworkProfile(destIP)

	if profile == nil {
		// Connection to a never-before-seen IP
		score := deviationWeights[DeviationNewNetwork]

		// Boost for connections to non-standard ports
		if !isCommonPort(evt.DestPort) {
			score = 1.0
		}

		// Check if any nearby baseline profile resolves to a trusted domain
		// that could cover this IP (e.g., CDN/load balancer changes)
		if isTrustedDomain := checkTrustedDomainForIP(bl, destIP); isTrustedDomain {
			score *= 0.5 // Reduce score by 50% for trusted domains
		}

		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         score,
			DeviationType: DeviationNewNetwork,
			Description: fmt.Sprintf(
				"Network connection to unknown destination: %s:%d (%s) from %s",
				destIP, evt.DestPort, evt.Protocol, evt.Binary,
			),
		})
	} else if !containsPort(profile.TypicalPorts, uint32(evt.DestPort)) {
		// Known IP but unusual port
		score := deviationWeights[DeviationNewNetwork] * 0.6
		// Reduce for trusted domains
		if profile.DomainSuffix != "" && trustedDomainSuffixes[profile.DomainSuffix] {
			score *= 0.5
		}
		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         score,
			DeviationType: DeviationNewNetwork,
			Description: fmt.Sprintf(
				"Known destination %s but unusual port %d (typical: %v)",
				destIP, evt.DestPort, profile.TypicalPorts,
			),
		})
	}

	return deviations
}

// checkTrustedDomainForIP does a best-effort reverse DNS lookup on the IP
// and checks if it resolves to a trusted domain suffix.
func checkTrustedDomainForIP(bl *baseline.RepositoryBaseline, ip string) bool {
	// First check if any existing profile with the same domain suffix is trusted
	// (avoids DNS lookup if we already know the domain from the baseline)
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return false
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		parts := strings.Split(name, ".")
		if len(parts) >= 2 {
			suffix := strings.Join(parts[len(parts)-2:], ".")
			if trustedDomainSuffixes[suffix] {
				return true
			}
		}
	}
	return false
}

func (s *Scorer) scoreFileAccess(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

	// Static check: always flag sensitive paths regardless of baseline
	if isSensitivePath(evt.FilePath) {
		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         deviationWeights[DeviationSensitivePath],
			DeviationType: DeviationSensitivePath,
			Description: fmt.Sprintf(
				"Access to sensitive path: %s by %s (access: %s)",
				evt.FilePath, evt.Binary, evt.AccessType,
			),
		})
	}

	// Baseline-aware file access scoring — only if baseline has learned file patterns
	if len(bl.FileAccessProfiles) == 0 {
		return deviations // No file profiles learned yet, skip baseline comparison
	}

	pattern := baseline.NormalizePathPattern(evt.FilePath)
	if pattern == "" {
		return deviations
	}

	profile := bl.FindFileAccessProfile(pattern)
	if profile == nil {
		// New path pattern never seen in baseline
		score := deviationWeights[DeviationNewFile]
		// Boost for write/create operations on new paths
		if evt.AccessType == "write" || evt.AccessType == "create" {
			score = 0.6
		}
		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         score,
			DeviationType: DeviationNewFile,
			Description: fmt.Sprintf(
				"New file access pattern: %s by %s (access: %s)",
				evt.FilePath, evt.Binary, evt.AccessType,
			),
		})
	} else {
		// Known pattern — check for new access type or new binary
		if evt.AccessType != "" && !containsString(profile.AccessTypes, evt.AccessType) {
			deviations = append(deviations, ScoredDeviation{
				Event:         evt,
				Score:         0.5,
				DeviationType: DeviationNewFile,
				Description: fmt.Sprintf(
					"New access type '%s' on known path pattern %s by %s (known types: %v)",
					evt.AccessType, pattern, evt.Binary, profile.AccessTypes,
				),
			})
		}
		if evt.Binary != "" && !containsString(profile.BinaryPaths, evt.Binary) {
			deviations = append(deviations, ScoredDeviation{
				Event:         evt,
				Score:         0.4,
				DeviationType: DeviationNewFile,
				Description: fmt.Sprintf(
					"New binary '%s' accessing known path pattern %s (known binaries: %v)",
					evt.Binary, pattern, profile.BinaryPaths,
				),
			})
		}
	}

	return deviations
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// matchSuspiciousArgRules checks for known-dangerous argument patterns.
// Returns true and a description if a pattern matches.
func matchSuspiciousArgRules(binary string, args []string) (bool, string) {
	binaryBase := binaryBasename(binary)
	argsJoined := strings.Join(args, " ")

	// curl/wget downloading to /tmp
	if binaryBase == "curl" || binaryBase == "wget" {
		if strings.Contains(argsJoined, "-o /tmp") || strings.Contains(argsJoined, "--output /tmp") ||
			strings.Contains(argsJoined, "-O /tmp") {
			return true, fmt.Sprintf("Suspicious download to /tmp: %s %s", binary, argsJoined)
		}
		// Pipe-to-shell pattern
		if strings.Contains(argsJoined, "| bash") || strings.Contains(argsJoined, "| sh") ||
			strings.Contains(argsJoined, "|bash") || strings.Contains(argsJoined, "|sh") {
			return true, fmt.Sprintf("Pipe-to-shell pattern: %s %s", binary, argsJoined)
		}
	}

	// base64 decode (often used to unpack payloads)
	if binaryBase == "base64" {
		if strings.Contains(argsJoined, "-d") || strings.Contains(argsJoined, "--decode") {
			return true, fmt.Sprintf("Base64 decode operation: %s %s", binary, argsJoined)
		}
	}

	// python/python3 inline execution
	if binaryBase == "python" || binaryBase == "python3" {
		if strings.Contains(argsJoined, " -c ") || (len(args) > 0 && args[0] == "-c") {
			return true, fmt.Sprintf("Inline Python execution: %s %s", binary, argsJoined)
		}
	}

	// chmod +x on /tmp paths
	if binaryBase == "chmod" {
		if strings.Contains(argsJoined, "+x") && strings.Contains(argsJoined, "/tmp") {
			return true, fmt.Sprintf("Making /tmp file executable: %s %s", binary, argsJoined)
		}
	}

	// nc/ncat with exec flag (reverse shell)
	if binaryBase == "nc" || binaryBase == "ncat" || binaryBase == "netcat" {
		if strings.Contains(argsJoined, "-e") || strings.Contains(argsJoined, "-c") {
			return true, fmt.Sprintf("Netcat with exec flag (possible reverse shell): %s %s", binary, argsJoined)
		}
	}

	// bash/sh -i (interactive shell, typical reverse shell)
	if binaryBase == "bash" || binaryBase == "sh" {
		if strings.Contains(argsJoined, " -i") || strings.Contains(argsJoined, "/dev/tcp") ||
			strings.Contains(argsJoined, "/dev/udp") {
			return true, fmt.Sprintf("Interactive/reverse shell pattern: %s %s", binary, argsJoined)
		}
	}

	return false, ""
}

// isHighRiskParentCombo returns true for parent→child combinations
// that are strong signals of compromise.
func isHighRiskParentCombo(parent, child string) bool {
	parentBase := binaryBasename(parent)
	childBase := binaryBasename(child)

	// Interpreters spawning network tools
	interpreters := map[string]bool{
		"node": true, "python": true, "python3": true,
		"ruby": true, "perl": true, "php": true,
	}
	networkTools := map[string]bool{
		"nc": true, "ncat": true, "netcat": true,
		"nmap": true, "socat": true,
	}
	if interpreters[parentBase] && networkTools[childBase] {
		return true
	}

	// Package managers spawning reverse shell tools
	packageManagers := map[string]bool{
		"npm": true, "pip": true, "pip3": true,
		"yarn": true, "pnpm": true, "gem": true,
		"composer": true,
	}
	shellTools := map[string]bool{
		"nc": true, "ncat": true, "netcat": true,
		"bash": true, "sh": true, "dash": true,
	}
	if packageManagers[parentBase] && shellTools[childBase] {
		// Only bash/sh are suspicious from package managers if it's install scripts
		// npm install can legitimately spawn sh, but nc is always suspicious
		if networkTools[childBase] {
			return true
		}
	}

	return false
}

// isSuspiciousBinary returns true for binaries commonly used in attacks.
func isSuspiciousBinary(binary string) bool {
	suspicious := []string{
		"nc", "ncat", "netcat",
		"nmap",
		"wget", // when not in baseline
		"base64",
		"xxd",
		"python", "python3", // when not in baseline
		"perl",
		"ruby",
	}
	for _, s := range suspicious {
		if binary == s || hasSuffix(binary, "/"+s) {
			return true
		}
	}
	return false
}

// isCommonPort returns true for ports commonly used by package registries and services.
func isCommonPort(port uint16) bool {
	common := []uint16{80, 443, 22, 53}
	for _, p := range common {
		if port == p {
			return true
		}
	}
	return false
}

// isSensitivePath returns true for paths that indicate credential or secret access.
func isSensitivePath(path string) bool {
	sensitive := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/.ssh/",
		"/proc/self/environ",
		"/.docker/config.json",
		"/.npmrc",
		"/.pypirc",
		"/.aws/credentials",
		"/.kube/config",
		"/.gnupg/",
		"/.netrc",
	}
	for _, s := range sensitive {
		if containsStr(path, s) {
			return true
		}
	}
	return false
}

func binaryBasename(binary string) string {
	idx := strings.LastIndex(binary, "/")
	if idx >= 0 && idx < len(binary)-1 {
		return binary[idx+1:]
	}
	return binary
}

func containsPort(ports []uint32, port uint32) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func containsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}

func hasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}

// enrichDeviation populates MITRE techniques and suggested severity.
func enrichDeviation(d *ScoredDeviation) {
	d.MITRETechniques = MITREForDeviation(*d)
	d.SuggestedSeverity = SuggestSeverity(d.Score)
}
