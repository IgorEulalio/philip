package detection

import (
	"fmt"
	"log/slog"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/baseline"
)

// DeviationType categorizes what kind of deviation was detected.
type DeviationType string

const (
	DeviationNewProcess    DeviationType = "new_process"
	DeviationNewNetwork    DeviationType = "new_network"
	DeviationNewFile       DeviationType = "new_file"
	DeviationAnomalousArgs DeviationType = "anomalous_args"
	DeviationSensitivePath DeviationType = "sensitive_path"
)

// Weights for different deviation types.
// Network events are weighted highest because secret exfiltration is the #1
// supply chain attack goal.
var deviationWeights = map[DeviationType]float64{
	DeviationNewNetwork:    1.0,
	DeviationSensitivePath: 0.9,
	DeviationNewProcess:    0.7,
	DeviationAnomalousArgs: 0.5,
	DeviationNewFile:       0.3,
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

	return deviations
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

func containsPort(ports []uint32, port uint32) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func hasSuffix(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
