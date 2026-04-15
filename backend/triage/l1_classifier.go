package triage

import (
	"log/slog"
	"strings"

	"github.com/IgorEulalio/philip/backend/detection"
)

// L1Classifier is a fast, rule-based classifier that filters obvious
// benign deviations before invoking the expensive L2 LLM analysis.
type L1Classifier struct {
	rules  []L1Rule
	logger *slog.Logger
}

// L1Rule is a single classification rule.
type L1Rule struct {
	Name        string
	Description string
	// Match returns true if this rule applies to the deviation.
	Match func(d detection.ScoredDeviation) bool
	// Verdict is the result if the rule matches.
	Verdict    Verdict
	Confidence float64
	Reasoning  string
}

// NewL1Classifier creates an L1 classifier with the default rule set.
func NewL1Classifier(logger *slog.Logger) *L1Classifier {
	return &L1Classifier{
		rules:  defaultL1Rules(),
		logger: logger,
	}
}

// Classify runs the L1 rule engine on a set of deviations.
// Returns a TriageResponse if the rules can classify all deviations as benign,
// or nil if L2 analysis is needed.
func (c *L1Classifier) Classify(req TriageRequest) *TriageResponse {
	if len(req.Deviations) == 0 {
		return &TriageResponse{
			Verdict:    VerdictBenign,
			Confidence: 1.0,
			Reasoning:  "No deviations detected",
			Severity:   "low",
		}
	}

	var unclassified []detection.ScoredDeviation
	var maxScore float64

	for _, dev := range req.Deviations {
		classified := false
		for _, rule := range c.rules {
			if rule.Match(dev) {
				c.logger.Debug("L1 rule matched",
					"rule", rule.Name,
					"binary", dev.Event.Binary,
					"verdict", rule.Verdict)
				if rule.Verdict == VerdictBenign {
					classified = true
					break
				}
			}
		}
		if !classified {
			unclassified = append(unclassified, dev)
			if dev.Score > maxScore {
				maxScore = dev.Score
			}
		}
	}

	// If all deviations were classified as benign by rules
	if len(unclassified) == 0 {
		return &TriageResponse{
			Verdict:    VerdictBenign,
			Confidence: 0.9,
			Reasoning:  "All deviations matched known benign patterns",
			Severity:   "low",
		}
	}

	// Check for immediately critical patterns
	for _, dev := range unclassified {
		for _, rule := range c.rules {
			if rule.Match(dev) && rule.Verdict == VerdictCritical {
				return &TriageResponse{
					Verdict:    VerdictCritical,
					Confidence: rule.Confidence,
					Reasoning:  rule.Reasoning,
					Severity:   "critical",
				}
			}
		}
	}

	// Can't fully classify — needs L2 analysis
	return nil
}

// defaultL1Rules returns the built-in rule set for L1 classification.
func defaultL1Rules() []L1Rule {
	return []L1Rule{
		// --- Benign rules ---
		{
			Name:        "known_package_manager",
			Description: "Package manager binaries are expected to run during builds",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				managers := []string{"npm", "yarn", "pnpm", "pip", "pip3", "poetry",
					"cargo", "go", "maven", "mvn", "gradle", "bundler", "gem",
					"composer", "nuget", "dotnet"}
				for _, m := range managers {
					if d.Event.Binary == m || strings.HasSuffix(d.Event.Binary, "/"+m) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.95,
			Reasoning:  "Known package manager binary",
		},
		{
			Name:        "known_build_tool",
			Description: "Build tools are expected during CI/CD jobs",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				tools := []string{"make", "cmake", "gcc", "g++", "clang", "ld",
					"ar", "as", "rustc", "javac", "tsc", "node", "deno", "bun"}
				for _, t := range tools {
					if d.Event.Binary == t || strings.HasSuffix(d.Event.Binary, "/"+t) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.95,
			Reasoning:  "Known build tool binary",
		},
		{
			Name:        "known_registry_connection",
			Description: "Connections to known package registries are expected",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewNetwork {
					return false
				}
				// Note: in production this would use reverse DNS.
				// For MVP, we check common ports on known behavior.
				return d.Event.DestPort == 443 || d.Event.DestPort == 80
			},
			Verdict:    VerdictBenign,
			Confidence: 0.7, // Lower confidence — new IP on 443 could still be exfil
			Reasoning:  "Connection on standard HTTPS/HTTP port",
		},
		{
			Name:        "git_operations",
			Description: "Git operations are normal during CI/CD",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				return d.Event.Binary == "git" || strings.HasSuffix(d.Event.Binary, "/git")
			},
			Verdict:    VerdictBenign,
			Confidence: 0.99,
			Reasoning:  "Git binary execution is expected in CI/CD",
		},

		// --- Critical rules ---
		{
			Name:        "reverse_shell_pattern",
			Description: "Detect potential reverse shell patterns",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				binary := d.Event.Binary
				args := strings.Join(d.Event.Args, " ")
				// nc/ncat with -e flag
				if (binary == "nc" || binary == "ncat" || strings.HasSuffix(binary, "/nc") ||
					strings.HasSuffix(binary, "/ncat")) &&
					(strings.Contains(args, "-e") || strings.Contains(args, "-c")) {
					return true
				}
				// bash -i >& /dev/tcp
				if strings.Contains(args, "/dev/tcp") || strings.Contains(args, "/dev/udp") {
					return true
				}
				return false
			},
			Verdict:    VerdictCritical,
			Confidence: 0.95,
			Reasoning:  "Reverse shell pattern detected — possible active exploitation",
		},
		{
			Name:        "credential_exfiltration",
			Description: "Detect attempts to read and exfiltrate credentials",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationSensitivePath {
					return false
				}
				criticalPaths := []string{"/etc/shadow", "/.ssh/id_", "/.aws/credentials"}
				for _, p := range criticalPaths {
					if strings.Contains(d.Event.FilePath, p) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictCritical,
			Confidence: 0.9,
			Reasoning:  "Access to critical credential file detected",
		},
		{
			Name:        "environment_dump",
			Description: "Detect attempts to dump process environment (secrets)",
			Match: func(d detection.ScoredDeviation) bool {
				return d.DeviationType == detection.DeviationSensitivePath &&
					strings.Contains(d.Event.FilePath, "/proc/self/environ")
			},
			Verdict:    VerdictCritical,
			Confidence: 0.85,
			Reasoning:  "Process environment dump detected — may expose CI/CD secrets",
		},
		{
			Name:        "suspicious_args_critical",
			Description: "Suspicious argument patterns are strong attack indicators",
			Match: func(d detection.ScoredDeviation) bool {
				return d.DeviationType == detection.DeviationSuspiciousArgs && d.Score >= 0.85
			},
			Verdict:    VerdictCritical,
			Confidence: 0.85,
			Reasoning:  "Suspicious command-line argument pattern detected — possible supply chain attack",
		},
		{
			Name:        "unexpected_parent_high_risk",
			Description: "High-risk parent-child process relationship",
			Match: func(d detection.ScoredDeviation) bool {
				return d.DeviationType == detection.DeviationUnexpectedParent && d.Score >= 0.95
			},
			Verdict:    VerdictCritical,
			Confidence: 0.9,
			Reasoning:  "High-risk process spawning pattern — unexpected parent-child relationship",
		},
	}
}
