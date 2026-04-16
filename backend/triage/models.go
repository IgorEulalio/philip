package triage

import (
	"github.com/IgorEulalio/philip/backend/baseline"
	"github.com/IgorEulalio/philip/backend/detection"
)

// Verdict represents the triage outcome.
type Verdict string

const (
	VerdictBenign     Verdict = "benign"
	VerdictSuspicious Verdict = "suspicious"
	VerdictCritical   Verdict = "critical"
)

// TriageRequest contains all context needed for AI triage.
type TriageRequest struct {
	Deviations   []detection.ScoredDeviation
	AttackChains []detection.AttackChain
	Baseline     *baseline.RepositoryBaseline
	Repository   string
	JobID        string
}

// TriageResponse is the structured output from a triage layer.
type TriageResponse struct {
	Verdict           Verdict  `json:"verdict"`
	Confidence        float64  `json:"confidence"`
	Reasoning         string   `json:"reasoning"`
	MITREMappings     []string `json:"mitre_mappings,omitempty"`
	Severity          string   `json:"severity"` // "low", "medium", "high", "critical"
	RecommendedAction string   `json:"recommended_action,omitempty"`
}

// LLMProvider is the pluggable interface for AI triage backends.
type LLMProvider interface {
	// Analyze performs deep contextual analysis on deviations.
	Analyze(req TriageRequest) (*TriageResponse, error)

	// Name returns the provider name (e.g., "openai", "claude", "ollama").
	Name() string
}
