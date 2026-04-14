package collector

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/philip-ai/philip/agent/sensor"
)

func TestEventNormalizer_IsRunnerProcess(t *testing.T) {
	tests := []struct {
		name       string
		runnerName string
		event      sensor.Event
		want       bool
	}{
		{
			name: "Runner.Worker binary detected",
			event: sensor.Event{
				Type:   sensor.EventTypeProcessExec,
				Binary: "/home/runner/actions-runner/bin/Runner.Worker",
			},
			want: true,
		},
		{
			name: "Runner.Listener binary detected",
			event: sensor.Event{
				Type:   sensor.EventTypeProcessExec,
				Binary: "/opt/actions-runner/bin/Runner.Listener",
			},
			want: true,
		},
		{
			name:       "custom runner process name",
			runnerName: "my-runner",
			event: sensor.Event{
				Type:   sensor.EventTypeProcessExec,
				Binary: "/usr/local/bin/my-runner",
			},
			want: true,
		},
		{
			name: "non-runner process",
			event: sensor.Event{
				Type:   sensor.EventTypeProcessExec,
				Binary: "/usr/bin/npm",
			},
			want: false,
		},
		{
			name: "non-exec event ignored",
			event: sensor.Event{
				Type:   sensor.EventTypeNetworkConnect,
				Binary: "/home/runner/actions-runner/bin/Runner.Worker",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			tree := NewProcessTree()
			n := NewEventNormalizer(tree, tc.runnerName, logger)

			got := n.isRunnerProcess(tc.event)
			if got != tc.want {
				t.Errorf("isRunnerProcess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEventNormalizer_FiltersNonRunnerEvents(t *testing.T) {
	tests := []struct {
		name     string
		events   []sensor.Event
		wantPass int // number of events that should pass through to output
	}{
		{
			name: "events from runner tree pass through",
			events: []sensor.Event{
				{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/actions-runner/bin/Runner.Worker"},
				{Type: sensor.EventTypeProcessExec, PID: 200, ParentPID: 100, Binary: "/usr/bin/npm"},
				{Type: sensor.EventTypeProcessExec, PID: 300, ParentPID: 200, Binary: "/usr/bin/node"},
			},
			wantPass: 3, // root (100) + descendants (200, 300) all pass through
		},
		{
			name: "events outside runner tree are filtered",
			events: []sensor.Event{
				{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/actions-runner/bin/Runner.Worker"},
				{Type: sensor.EventTypeProcessExec, PID: 999, ParentPID: 50, Binary: "/usr/sbin/sshd"},
			},
			wantPass: 1, // root (100) passes, 999 is not a descendant
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			tree := NewProcessTree()
			n := NewEventNormalizer(tree, "", logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			inputCh := make(chan sensor.Event, len(tc.events))
			for _, evt := range tc.events {
				inputCh <- evt
			}
			close(inputCh)

			go n.Run(ctx, inputCh)

			// Collect output with timeout
			var received []NormalizedEvent
			timeout := time.After(500 * time.Millisecond)
		loop:
			for {
				select {
				case evt, ok := <-n.Output():
					if !ok {
						break loop
					}
					received = append(received, evt)
				case <-timeout:
					break loop
				}
			}

			if len(received) != tc.wantPass {
				t.Errorf("got %d events through normalizer, want %d", len(received), tc.wantPass)
			}
		})
	}
}

func TestEventNormalizer_AutoDetectsRunnerRoot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tree := NewProcessTree()
	n := NewEventNormalizer(tree, "", logger)

	// Before runner detection, root should not be set
	if _, set := tree.RootPID(); set {
		t.Fatal("root should not be set initially")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inputCh := make(chan sensor.Event, 1)
	inputCh <- sensor.Event{
		Type:   sensor.EventTypeProcessExec,
		PID:    100,
		Binary: "/actions-runner/bin/Runner.Worker",
	}

	go n.Run(ctx, inputCh)
	time.Sleep(100 * time.Millisecond)

	rootPID, set := tree.RootPID()
	if !set {
		t.Fatal("root should be set after runner process detected")
	}
	if rootPID != 100 {
		t.Errorf("root PID = %d, want 100", rootPID)
	}
}
