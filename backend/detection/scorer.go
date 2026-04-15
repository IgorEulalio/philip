package detection

import (
	"fmt"
	"log/slog"
	"math"
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
	Event         sensor.Event
	Score         float64
	DeviationType DeviationType
	Description   string
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
func (s *Scorer) ScoreJob(bl *baseline.RepositoryBaseline, events []sensor.Event) []ScoredDeviation {
	if bl == nil || bl.IsLearning() {
		return nil // No scoring during learning mode
	}

	var deviations []ScoredDeviation

	for _, evt := range events {
		devs := s.scoreEvent(bl, evt)
		deviations = append(deviations, devs...)
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

// scoreProcessParent detects when a process is spawned by an unexpected parent.
func (s *Scorer) scoreProcessParent(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	if evt.ParentBinary == "" {
		return nil // No parent info — skip
	}

	profile := bl.FindProcessProfile(evt.Binary)
	if profile == nil || len(profile.KnownParents) == 0 {
		return nil // Not enough baseline data
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
		deviations = append(deviations, ScoredDeviation{
			Event:         evt,
			Score:         deviationWeights[DeviationNewNetwork] * 0.6,
			DeviationType: DeviationNewNetwork,
			Description: fmt.Sprintf(
				"Known destination %s but unusual port %d (typical: %v)",
				destIP, evt.DestPort, profile.TypicalPorts,
			),
		})
	}

	return deviations
}

func (s *Scorer) scoreFileAccess(bl *baseline.RepositoryBaseline, evt sensor.Event) []ScoredDeviation {
	var deviations []ScoredDeviation

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

	return deviations
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
