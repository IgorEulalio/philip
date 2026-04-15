package alerting

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/IgorEulalio/philip/backend/detection"
	"github.com/IgorEulalio/philip/backend/triage"
)

// mockIntegration records alerts sent to it.
type mockIntegration struct {
	mu     sync.Mutex
	name   string
	alerts []Alert
	err    error
}

func newMockIntegration(name string) *mockIntegration {
	return &mockIntegration{name: name}
}

func (m *mockIntegration) Name() string { return m.name }

func (m *mockIntegration) Send(alert Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.alerts = append(m.alerts, alert)
	return nil
}

func (m *mockIntegration) alertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.alerts)
}

func (m *mockIntegration) lastAlert() Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.alerts[len(m.alerts)-1]
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRouter_Route_SendsToAllIntegrations(t *testing.T) {
	slack := newMockIntegration("slack")
	webhook := newMockIntegration("webhook")

	router := NewRouter([]Integration{slack, webhook}, newTestLogger())

	alert := Alert{
		ID:         "test-1",
		Repository: "owner/repo",
		JobID:      "job-1",
		Verdict:    triage.VerdictCritical,
		Severity:   "critical",
		Confidence: 0.95,
		Reasoning:  "reverse shell detected",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 1.0},
		},
		CreatedAt: time.Now(),
	}

	err := router.Route(alert)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	if slack.alertCount() != 1 {
		t.Errorf("slack got %d alerts, want 1", slack.alertCount())
	}
	if webhook.alertCount() != 1 {
		t.Errorf("webhook got %d alerts, want 1", webhook.alertCount())
	}
}

func TestRouter_Route_Deduplication(t *testing.T) {
	mock := newMockIntegration("test")
	router := NewRouter([]Integration{mock}, newTestLogger())

	alert := Alert{
		ID:         "test-1",
		Repository: "owner/repo",
		Severity:   "high",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 0.8},
		},
		CreatedAt: time.Now(),
	}

	// First send should go through
	err := router.Route(alert)
	if err != nil {
		t.Fatalf("first Route failed: %v", err)
	}
	if mock.alertCount() != 1 {
		t.Fatalf("expected 1 alert after first route, got %d", mock.alertCount())
	}

	// Second send with same repo+severity+types should be deduplicated
	alert.ID = "test-2"
	err = router.Route(alert)
	if err != nil {
		t.Fatalf("second Route failed: %v", err)
	}
	if mock.alertCount() != 1 {
		t.Errorf("expected 1 alert after dedup, got %d", mock.alertCount())
	}
}

func TestRouter_Route_DifferentSeverityNotDeduplicated(t *testing.T) {
	mock := newMockIntegration("test")
	router := NewRouter([]Integration{mock}, newTestLogger())

	alert1 := Alert{
		ID:         "test-1",
		Repository: "owner/repo",
		Severity:   "high",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 0.8},
		},
		CreatedAt: time.Now(),
	}
	alert2 := Alert{
		ID:         "test-2",
		Repository: "owner/repo",
		Severity:   "critical", // different severity
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 1.0},
		},
		CreatedAt: time.Now(),
	}

	router.Route(alert1)
	router.Route(alert2)

	if mock.alertCount() != 2 {
		t.Errorf("expected 2 alerts (different severity), got %d", mock.alertCount())
	}
}

func TestRouter_Route_DifferentRepoNotDeduplicated(t *testing.T) {
	mock := newMockIntegration("test")
	router := NewRouter([]Integration{mock}, newTestLogger())

	alert1 := Alert{
		ID:         "test-1",
		Repository: "owner/repo-a",
		Severity:   "high",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 0.8},
		},
		CreatedAt: time.Now(),
	}
	alert2 := Alert{
		ID:         "test-2",
		Repository: "owner/repo-b", // different repo
		Severity:   "high",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 0.8},
		},
		CreatedAt: time.Now(),
	}

	router.Route(alert1)
	router.Route(alert2)

	if mock.alertCount() != 2 {
		t.Errorf("expected 2 alerts (different repos), got %d", mock.alertCount())
	}
}

func TestRouter_Route_IntegrationErrorPartialFailure(t *testing.T) {
	good := newMockIntegration("good")
	bad := newMockIntegration("bad")
	bad.err = fmt.Errorf("connection refused")

	router := NewRouter([]Integration{good, bad}, newTestLogger())

	alert := Alert{
		ID:         "test-1",
		Repository: "owner/repo",
		Severity:   "critical",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewNetwork, Score: 1.0},
		},
		CreatedAt: time.Now(),
	}

	err := router.Route(alert)
	if err == nil {
		t.Error("expected error when one integration fails")
	}

	// Good integration should still have received the alert
	if good.alertCount() != 1 {
		t.Errorf("good integration got %d alerts, want 1", good.alertCount())
	}
}

func TestRouter_Route_NoIntegrations(t *testing.T) {
	router := NewRouter(nil, newTestLogger())

	alert := Alert{
		ID:         "test-1",
		Repository: "owner/repo",
		Severity:   "high",
		Deviations: []detection.ScoredDeviation{
			{DeviationType: detection.DeviationNewProcess, Score: 0.8},
		},
		CreatedAt: time.Now(),
	}

	err := router.Route(alert)
	if err != nil {
		t.Errorf("Route with no integrations should not error, got: %v", err)
	}
}

func TestRouter_Route_AlertFieldsPreserved(t *testing.T) {
	mock := newMockIntegration("test")
	router := NewRouter([]Integration{mock}, newTestLogger())

	alert := Alert{
		ID:                "alert-123",
		Repository:        "owner/critical-repo",
		JobID:             "job-456",
		Verdict:           triage.VerdictCritical,
		Severity:          "critical",
		Confidence:        0.97,
		Reasoning:         "Exfiltration attempt detected",
		MITREMappings:     []string{"T1567.002"},
		RecommendedAction: "Isolate runner immediately",
		Deviations: []detection.ScoredDeviation{
			{
				DeviationType: detection.DeviationNewNetwork,
				Score:         1.0,
				Description:   "Connection to unknown IP",
			},
		},
		CreatedAt: time.Now(),
	}

	router.Route(alert)

	received := mock.lastAlert()
	if received.ID != alert.ID {
		t.Errorf("ID = %q, want %q", received.ID, alert.ID)
	}
	if received.Repository != alert.Repository {
		t.Errorf("Repository = %q, want %q", received.Repository, alert.Repository)
	}
	if received.Verdict != alert.Verdict {
		t.Errorf("Verdict = %s, want %s", received.Verdict, alert.Verdict)
	}
	if received.Confidence != alert.Confidence {
		t.Errorf("Confidence = %.2f, want %.2f", received.Confidence, alert.Confidence)
	}
	if len(received.MITREMappings) != 1 || received.MITREMappings[0] != "T1567.002" {
		t.Errorf("MITREMappings = %v, want [T1567.002]", received.MITREMappings)
	}
}
