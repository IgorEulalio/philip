package alerting

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/IgorEulalio/philip/backend/detection"
	"github.com/IgorEulalio/philip/backend/metrics"
	"github.com/IgorEulalio/philip/backend/triage"
)

// Alert represents a security alert to be sent to integrations.
type Alert struct {
	ID                string
	Repository        string
	JobID             string
	Verdict           triage.Verdict
	Severity          string
	Confidence        float64
	Reasoning         string
	MITREMappings     []string
	RecommendedAction string
	Deviations        []detection.ScoredDeviation
	CreatedAt         time.Time
}

// Integration is the interface for alert delivery backends.
type Integration interface {
	Send(alert Alert) error
	Name() string
}

// Router dispatches alerts to configured integrations with deduplication.
type Router struct {
	integrations []Integration
	dedup        *deduplicator
	logger       *slog.Logger
}

// NewRouter creates a new alert router.
func NewRouter(integrations []Integration, logger *slog.Logger) *Router {
	return &Router{
		integrations: integrations,
		dedup:        newDeduplicator(30 * time.Minute),
		logger:       logger,
	}
}

// Route sends an alert to all configured integrations.
// Returns nil if the alert was deduplicated.
func (r *Router) Route(alert Alert) error {
	// Deduplication: same repo + same deviation types within window = skip
	dedupKey := fmt.Sprintf("%s:%s:%s", alert.Repository, alert.Severity, deviationTypesKey(alert.Deviations))
	if r.dedup.isDuplicate(dedupKey) {
		r.logger.Info("alert deduplicated", "repository", alert.Repository, "severity", alert.Severity)
		metrics.AlertsDeduplicated.WithLabelValues(alert.Repository).Inc()
		return nil
	}
	r.dedup.record(dedupKey)

	r.logger.Info("routing alert",
		"repository", alert.Repository,
		"severity", alert.Severity,
		"verdict", alert.Verdict,
		"integrations", len(r.integrations))

	var errs []error
	for _, integration := range r.integrations {
		if err := integration.Send(alert); err != nil {
			r.logger.Error("failed to send alert",
				"integration", integration.Name(),
				"error", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to send alert to %d/%d integrations", len(errs), len(r.integrations))
	}
	metrics.AlertsRouted.WithLabelValues(alert.Repository, alert.Severity).Inc()
	return nil
}

func deviationTypesKey(deviations []detection.ScoredDeviation) string {
	types := make(map[string]bool)
	for _, d := range deviations {
		types[string(d.DeviationType)] = true
	}
	key := ""
	for t := range types {
		key += t + ","
	}
	return key
}

// deduplicator tracks recently sent alerts to prevent duplicates.
type deduplicator struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	window  time.Duration
}

func newDeduplicator(window time.Duration) *deduplicator {
	d := &deduplicator{
		seen:   make(map[string]time.Time),
		window: window,
	}
	go d.cleanup()
	return d
}

func (d *deduplicator) isDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.seen[key]; ok {
		return time.Since(t) < d.window
	}
	return false
}

func (d *deduplicator) record(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[key] = time.Now()
}

func (d *deduplicator) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		d.mu.Lock()
		for key, t := range d.seen {
			if time.Since(t) > d.window {
				delete(d.seen, key)
			}
		}
		d.mu.Unlock()
	}
}
