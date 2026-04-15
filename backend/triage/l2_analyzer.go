package triage

import (
	"fmt"
	"log/slog"

	"github.com/IgorEulalio/philip/backend/detection"
)

// L2Analyzer performs deep contextual analysis using an LLM provider.
// It is only invoked for deviations that L1 cannot classify as benign.
type L2Analyzer struct {
	provider LLMProvider
	logger   *slog.Logger
}

// NewL2Analyzer creates a new L2 analyzer with the given LLM provider.
func NewL2Analyzer(provider LLMProvider, logger *slog.Logger) *L2Analyzer {
	return &L2Analyzer{
		provider: provider,
		logger:   logger,
	}
}

// Analyze runs L2 deep analysis on deviations.
func (a *L2Analyzer) Analyze(req TriageRequest) (*TriageResponse, error) {
	a.logger.Info("running L2 analysis",
		"provider", a.provider.Name(),
		"deviations", len(req.Deviations),
		"repository", req.Repository)

	resp, err := a.provider.Analyze(req)
	if err != nil {
		return nil, fmt.Errorf("L2 analysis failed (%s): %w", a.provider.Name(), err)
	}

	a.logger.Info("L2 analysis complete",
		"verdict", resp.Verdict,
		"confidence", resp.Confidence,
		"severity", resp.Severity)

	return resp, nil
}

// Pipeline orchestrates the full L1 -> L2 triage flow.
type Pipeline struct {
	l1     *L1Classifier
	l2     *L2Analyzer
	logger *slog.Logger
}

// NewPipeline creates a new triage pipeline.
func NewPipeline(l1 *L1Classifier, l2 *L2Analyzer, logger *slog.Logger) *Pipeline {
	return &Pipeline{
		l1:     l1,
		l2:     l2,
		logger: logger,
	}
}

// Triage runs the full L1 -> L2 triage pipeline on deviations.
// Returns the final triage result and whether L2 was invoked.
func (p *Pipeline) Triage(req TriageRequest) (*TriageResult, error) {
	// L1 fast classification
	l1Result := p.l1.Classify(req)

	if l1Result != nil && l1Result.Verdict == VerdictBenign {
		p.logger.Info("L1 classified as benign, skipping L2",
			"repository", req.Repository,
			"deviations", len(req.Deviations))
		return &TriageResult{
			L1Response: l1Result,
			L2Response: nil,
			Final:      l1Result,
			L2Invoked:  false,
		}, nil
	}

	// L1 found something critical — still run L2 for enrichment
	// L1 returned nil — needs L2 analysis
	p.logger.Info("escalating to L2 analysis",
		"repository", req.Repository,
		"l1_verdict", verdictStr(l1Result))

	l2Result, err := p.l2.Analyze(req)
	if err != nil {
		// L2 failed — fall back to L1 result or conservative default
		p.logger.Error("L2 analysis failed, using conservative fallback", "error", err)
		fallback := &TriageResponse{
			Verdict:    VerdictSuspicious,
			Confidence: 0.5,
			Reasoning:  fmt.Sprintf("L2 analysis unavailable: %v. Flagging as suspicious based on deviation scores.", err),
			Severity:   severityFromDeviations(req.Deviations),
		}
		if l1Result != nil {
			fallback = l1Result
		}
		return &TriageResult{
			L1Response: l1Result,
			L2Response: nil,
			Final:      fallback,
			L2Invoked:  true,
		}, nil
	}

	return &TriageResult{
		L1Response: l1Result,
		L2Response: l2Result,
		Final:      l2Result,
		L2Invoked:  true,
	}, nil
}

// TriageResult contains the full result of the triage pipeline.
type TriageResult struct {
	L1Response *TriageResponse
	L2Response *TriageResponse
	Final      *TriageResponse
	L2Invoked  bool
}

func verdictStr(resp *TriageResponse) string {
	if resp == nil {
		return "unclassified"
	}
	return string(resp.Verdict)
}

func severityFromDeviations(deviations []detection.ScoredDeviation) string {
	maxScore := 0.0
	for _, d := range deviations {
		if d.Score > maxScore {
			maxScore = d.Score
		}
	}
	switch {
	case maxScore >= 0.9:
		return "critical"
	case maxScore >= 0.7:
		return "high"
	case maxScore >= 0.4:
		return "medium"
	default:
		return "low"
	}
}
