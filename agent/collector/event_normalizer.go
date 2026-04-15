package collector

import (
	"context"
	"log/slog"

	"github.com/IgorEulalio/philip/agent/sensor"
)

// EventNormalizer receives raw sensor events, filters them to the runner's
// process tree, and enriches them before passing to the job buffer.
type EventNormalizer struct {
	tree        *ProcessTree
	output      chan NormalizedEvent
	runnerName  string
	logger      *slog.Logger
}

// NormalizedEvent is a sensor event enriched with process tree context.
type NormalizedEvent struct {
	sensor.Event
	// Ancestry is the process chain from this event's PID up to the runner root.
	Ancestry []ProcessNode
	// InRunnerTree indicates whether this event belongs to the runner's process tree.
	InRunnerTree bool
}

// NewEventNormalizer creates a new event normalizer.
func NewEventNormalizer(tree *ProcessTree, runnerName string, logger *slog.Logger) *EventNormalizer {
	return &EventNormalizer{
		tree:       tree,
		output:     make(chan NormalizedEvent, 10000),
		runnerName: runnerName,
		logger:     logger,
	}
}

// Output returns the channel of normalized events.
func (n *EventNormalizer) Output() <-chan NormalizedEvent {
	return n.output
}

// Run reads events from the sensor and normalizes them.
// It blocks until ctx is cancelled.
func (n *EventNormalizer) Run(ctx context.Context, events <-chan sensor.Event) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			n.handleEvent(evt)
		}
	}
}

func (n *EventNormalizer) handleEvent(evt sensor.Event) {
	// Always update the process tree first
	n.tree.HandleEvent(evt)

	// Auto-detect runner root PID if not yet set
	if _, rootSet := n.tree.RootPID(); !rootSet {
		if n.isRunnerProcess(evt) {
			n.logger.Info("detected runner process", "pid", evt.PID, "binary", evt.Binary)
			n.tree.SetRoot(evt.PID)
		}
	}

	// Only pass through events that belong to the runner's process tree
	if !n.tree.IsDescendant(evt.PID) {
		return
	}

	normalized := NormalizedEvent{
		Event:        evt,
		Ancestry:     n.tree.GetAncestry(evt.PID),
		InRunnerTree: true,
	}

	select {
	case n.output <- normalized:
	default:
		n.logger.Warn("event normalizer output channel full, dropping event",
			"event_type", evt.Type, "pid", evt.PID)
	}
}

// isRunnerProcess detects whether this process is a GitHub Actions runner.
func (n *EventNormalizer) isRunnerProcess(evt sensor.Event) bool {
	if evt.Type != sensor.EventTypeProcessExec {
		return false
	}

	// GitHub Actions runner binary patterns
	runnerBinaries := []string{
		"Runner.Worker",
		"Runner.Listener",
	}

	// Allow custom runner process name
	if n.runnerName != "" {
		runnerBinaries = append(runnerBinaries, n.runnerName)
	}

	for _, name := range runnerBinaries {
		if containsSuffix(evt.Binary, name) {
			return true
		}
	}

	return false
}

func containsSuffix(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
