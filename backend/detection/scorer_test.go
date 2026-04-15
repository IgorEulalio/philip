package detection

import (
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/baseline"
)

func TestScorer_ScoreJob_LearningMode(t *testing.T) {
	scorer := NewScorer(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	bl := &baseline.RepositoryBaseline{
		Status: "learning",
	}

	events := []sensor.Event{
		{Type: sensor.EventTypeProcessExec, Binary: "/usr/bin/curl"},
	}

	deviations := scorer.ScoreJob(bl, events)
	if len(deviations) != 0 {
		t.Errorf("expected no deviations during learning mode, got %d", len(deviations))
	}
}

func TestScorer_ScoreJob_NilBaseline(t *testing.T) {
	scorer := NewScorer(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	events := []sensor.Event{
		{Type: sensor.EventTypeProcessExec, Binary: "/usr/bin/curl"},
	}

	deviations := scorer.ScoreJob(nil, events)
	if len(deviations) != 0 {
		t.Errorf("expected no deviations with nil baseline, got %d", len(deviations))
	}
}

func TestScorer_ScoreProcessExec(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	scorer := NewScorer(logger)

	tests := []struct {
		name           string
		baseline       *baseline.RepositoryBaseline
		event          sensor.Event
		wantDeviations int
		wantType       DeviationType
		wantMinScore   float64
	}{
		{
			name: "known binary no deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
				ProcessProfiles: []baseline.ProcessProfile{
					{BinaryPath: "/usr/bin/npm", Frequency: 0.95},
				},
			},
			event:          sensor.Event{Type: sensor.EventTypeProcessExec, Binary: "/usr/bin/npm"},
			wantDeviations: 0,
		},
		{
			name: "new binary produces deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
				ProcessProfiles: []baseline.ProcessProfile{
					{BinaryPath: "/usr/bin/npm", Frequency: 0.95},
				},
			},
			event:          sensor.Event{Type: sensor.EventTypeProcessExec, Binary: "/usr/bin/curl"},
			wantDeviations: 1,
			wantType:       DeviationNewProcess,
			wantMinScore:   0.5,
		},
		{
			name: "suspicious binary gets max score",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
			},
			event:          sensor.Event{Type: sensor.EventTypeProcessExec, Binary: "/usr/bin/nc"},
			wantDeviations: 1,
			wantType:       DeviationNewProcess,
			wantMinScore:   1.0,
		},
		{
			name: "rare binary produces deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
				ProcessProfiles: []baseline.ProcessProfile{
					{BinaryPath: "/usr/bin/rare-tool", Frequency: 0.02},
				},
			},
			event:          sensor.Event{Type: sensor.EventTypeProcessExec, Binary: "/usr/bin/rare-tool"},
			wantDeviations: 1,
			wantType:       DeviationNewProcess,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deviations := scorer.ScoreJob(tc.baseline, []sensor.Event{tc.event})

			if len(deviations) != tc.wantDeviations {
				t.Fatalf("got %d deviations, want %d", len(deviations), tc.wantDeviations)
			}

			if tc.wantDeviations > 0 {
				dev := deviations[0]
				if dev.DeviationType != tc.wantType {
					t.Errorf("deviation type = %s, want %s", dev.DeviationType, tc.wantType)
				}
				if tc.wantMinScore > 0 && dev.Score < tc.wantMinScore {
					t.Errorf("score = %.2f, want >= %.2f", dev.Score, tc.wantMinScore)
				}
			}
		})
	}
}

func TestScorer_ScoreNetworkConnect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	scorer := NewScorer(logger)

	tests := []struct {
		name           string
		baseline       *baseline.RepositoryBaseline
		event          sensor.Event
		wantDeviations int
		wantMinScore   float64
	}{
		{
			name: "known destination no deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
				NetworkProfiles: []baseline.NetworkProfile{
					{DestinationCIDRs: []string{"93.184.216.34"}, TypicalPorts: []uint32{443}},
				},
			},
			event: sensor.Event{
				Type:     sensor.EventTypeNetworkConnect,
				Binary:   "/usr/bin/curl",
				DestIP:   net.ParseIP("93.184.216.34"),
				DestPort: 443,
			},
			wantDeviations: 0,
		},
		{
			name: "unknown destination produces deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
				NetworkProfiles: []baseline.NetworkProfile{
					{DestinationCIDRs: []string{"93.184.216.34"}, TypicalPorts: []uint32{443}},
				},
			},
			event: sensor.Event{
				Type:     sensor.EventTypeNetworkConnect,
				Binary:   "/usr/bin/curl",
				DestIP:   net.ParseIP("198.51.100.1"),
				DestPort: 443,
			},
			wantDeviations: 1,
		},
		{
			name: "unknown destination on non-standard port gets max score",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
			},
			event: sensor.Event{
				Type:     sensor.EventTypeNetworkConnect,
				Binary:   "/usr/bin/curl",
				DestIP:   net.ParseIP("198.51.100.1"),
				DestPort: 4444,
			},
			wantDeviations: 1,
			wantMinScore:   1.0,
		},
		{
			name: "known IP unusual port produces deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
				NetworkProfiles: []baseline.NetworkProfile{
					{DestinationCIDRs: []string{"93.184.216.34"}, TypicalPorts: []uint32{443}},
				},
			},
			event: sensor.Event{
				Type:     sensor.EventTypeNetworkConnect,
				Binary:   "/usr/bin/curl",
				DestIP:   net.ParseIP("93.184.216.34"),
				DestPort: 8080,
			},
			wantDeviations: 1,
		},
		{
			name: "nil DestIP no deviation",
			baseline: &baseline.RepositoryBaseline{
				Status: "active",
			},
			event: sensor.Event{
				Type:   sensor.EventTypeNetworkConnect,
				Binary: "/usr/bin/curl",
			},
			wantDeviations: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deviations := scorer.ScoreJob(tc.baseline, []sensor.Event{tc.event})

			if len(deviations) != tc.wantDeviations {
				t.Fatalf("got %d deviations, want %d", len(deviations), tc.wantDeviations)
			}

			if tc.wantDeviations > 0 && tc.wantMinScore > 0 {
				if deviations[0].Score < tc.wantMinScore {
					t.Errorf("score = %.2f, want >= %.2f", deviations[0].Score, tc.wantMinScore)
				}
			}
		})
	}
}

func TestScorer_ScoreFileAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	scorer := NewScorer(logger)

	tests := []struct {
		name           string
		event          sensor.Event
		wantDeviations int
	}{
		{
			name: "sensitive path /etc/shadow",
			event: sensor.Event{
				Type:       sensor.EventTypeFileAccess,
				Binary:     "/usr/bin/cat",
				FilePath:   "/etc/shadow",
				AccessType: "read",
			},
			wantDeviations: 1,
		},
		{
			name: "sensitive path ssh key",
			event: sensor.Event{
				Type:       sensor.EventTypeFileAccess,
				Binary:     "/usr/bin/cat",
				FilePath:   "/home/runner/.ssh/id_rsa",
				AccessType: "read",
			},
			wantDeviations: 1,
		},
		{
			name: "sensitive path aws credentials",
			event: sensor.Event{
				Type:       sensor.EventTypeFileAccess,
				Binary:     "/usr/bin/cat",
				FilePath:   "/home/runner/.aws/credentials",
				AccessType: "read",
			},
			wantDeviations: 1,
		},
		{
			name: "sensitive path proc environ",
			event: sensor.Event{
				Type:       sensor.EventTypeFileAccess,
				Binary:     "/usr/bin/cat",
				FilePath:   "/proc/self/environ",
				AccessType: "read",
			},
			wantDeviations: 1,
		},
		{
			name: "non-sensitive path no deviation",
			event: sensor.Event{
				Type:       sensor.EventTypeFileAccess,
				Binary:     "/usr/bin/cat",
				FilePath:   "/home/runner/work/src/main.go",
				AccessType: "read",
			},
			wantDeviations: 0,
		},
	}

	bl := &baseline.RepositoryBaseline{Status: "active"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deviations := scorer.ScoreJob(bl, []sensor.Event{tc.event})
			if len(deviations) != tc.wantDeviations {
				t.Errorf("got %d deviations, want %d", len(deviations), tc.wantDeviations)
			}
		})
	}
}

func TestIsSuspiciousBinary(t *testing.T) {
	tests := []struct {
		binary string
		want   bool
	}{
		{"/usr/bin/nc", true},
		{"/usr/bin/ncat", true},
		{"nc", true},
		{"nmap", true},
		{"/usr/bin/base64", true},
		{"/usr/bin/npm", false},
		{"/usr/bin/go", false},
		{"/bin/bash", false},
	}

	for _, tc := range tests {
		t.Run(tc.binary, func(t *testing.T) {
			if got := isSuspiciousBinary(tc.binary); got != tc.want {
				t.Errorf("isSuspiciousBinary(%q) = %v, want %v", tc.binary, got, tc.want)
			}
		})
	}
}

func TestIsCommonPort(t *testing.T) {
	tests := []struct {
		port uint16
		want bool
	}{
		{80, true},
		{443, true},
		{22, true},
		{53, true},
		{4444, false},
		{8080, false},
		{1337, false},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			if got := isCommonPort(tc.port); got != tc.want {
				t.Errorf("isCommonPort(%d) = %v, want %v", tc.port, got, tc.want)
			}
		})
	}
}

func TestIsSensitivePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/shadow", true},
		{"/home/user/.ssh/id_rsa", true},
		{"/proc/self/environ", true},
		{"/home/runner/.aws/credentials", true},
		{"/home/runner/.kube/config", true},
		{"/home/runner/work/main.go", false},
		{"/tmp/build.log", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isSensitivePath(tc.path); got != tc.want {
				t.Errorf("isSensitivePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
