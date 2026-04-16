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
	Name            string
	Description     string
	MITRETechniques []string // MITRE ATT&CK techniques this rule relates to
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
				// Collect MITRE techniques from both the rule and the deviation
				mitre := append([]string{}, rule.MITRETechniques...)
				mitre = append(mitre, dev.MITRETechniques...)
				mitre = dedup(mitre)
				return &TriageResponse{
					Verdict:       VerdictCritical,
					Confidence:    rule.Confidence,
					Reasoning:     rule.Reasoning,
					MITREMappings: mitre,
					Severity:      "critical",
				}
			}
		}
	}

	// Can't fully classify — needs L2 analysis
	return nil
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := ss[:0]
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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
					"ar", "as", "rustc", "javac", "tsc", "node", "deno", "bun",
					"ld.gold", "ld.lld", "cc1", "cc1plus", "collect2",
					"xcodebuild", "swiftc", "kotlinc", "scalac",
					"lld", "mold", "ninja", "scons", "bazel"}
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

		{
			Name:        "known_test_runner",
			Description: "Test runners are expected during CI/CD jobs",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				runners := []string{"pytest", "jest", "mocha", "vitest", "karma",
					"phpunit", "rspec", "minitest", "junit", "testng",
					"gotestsum", "ginkgo", "delve"}
				binary := d.Event.Binary
				for _, r := range runners {
					if binary == r || strings.HasSuffix(binary, "/"+r) {
						return true
					}
				}
				// "go test" appears as "go" with "test" arg — handled by known_build_tool
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.95,
			Reasoning:  "Known test runner binary",
		},
		{
			Name:        "known_ci_tool",
			Description: "CI/CD and container tools are expected in pipelines",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				tools := []string{"docker", "podman", "buildah", "skopeo",
					"kubectl", "helm", "terraform", "ansible",
					"aws", "gcloud", "az", "gh",
					"jq", "yq", "envsubst", "gettext"}
				binary := d.Event.Binary
				for _, t := range tools {
					if binary == t || strings.HasSuffix(binary, "/"+t) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.9,
			Reasoning:  "Known CI/CD or infrastructure tool",
		},
		{
			Name:        "known_linter_formatter",
			Description: "Linters and formatters are expected during CI/CD",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewProcess {
					return false
				}
				tools := []string{"eslint", "prettier", "gofmt", "goimports",
					"golangci-lint", "staticcheck", "black", "flake8",
					"pylint", "mypy", "rubocop", "shellcheck", "hadolint",
					"clippy", "rustfmt"}
				binary := d.Event.Binary
				for _, t := range tools {
					if binary == t || strings.HasSuffix(binary, "/"+t) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.95,
			Reasoning:  "Known linter or formatter binary",
		},
		{
			Name:        "safe_package_manager_args",
			Description: "Standard package manager install commands should not trigger suspicious_args",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationSuspiciousArgs {
					return false
				}
				binary := d.Event.Binary
				if strings.HasSuffix(binary, "/") {
					return false
				}
				base := binary
				if idx := strings.LastIndex(binary, "/"); idx >= 0 {
					base = binary[idx+1:]
				}
				argsJoined := strings.Join(d.Event.Args, " ")
				// npm install, yarn install, pip install -r, go mod download
				safePatterns := map[string][]string{
					"npm":  {"install", "ci", "run", "test"},
					"yarn": {"install", "add", "run", "test"},
					"pnpm": {"install", "add", "run", "test"},
					"pip":  {"install -r", "install --requirement", "install -e"},
					"pip3": {"install -r", "install --requirement", "install -e"},
					"go":   {"mod download", "mod tidy", "build", "test", "install"},
				}
				patterns, ok := safePatterns[base]
				if !ok {
					return false
				}
				for _, p := range patterns {
					if strings.Contains(argsJoined, p) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.85,
			Reasoning:  "Standard package manager command with expected arguments",
		},

		// Benign file access rules
		{
			Name:        "workspace_file_access",
			Description: "File access within workspace directories is expected during builds",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewFile {
					return false
				}
				workspacePrefixes := []string{
					"/home/runner/",
					"/github/workspace/",
					"/opt/hostedtoolcache/",
					"/home/igoreul/",
				}
				for _, prefix := range workspacePrefixes {
					if strings.HasPrefix(d.Event.FilePath, prefix) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.9,
			Reasoning:  "File access within build workspace directory",
		},
		{
			Name:        "tmp_by_package_manager",
			Description: "Package managers writing to /tmp is expected",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewFile {
					return false
				}
				if !strings.HasPrefix(d.Event.FilePath, "/tmp/") {
					return false
				}
				managers := []string{"npm", "yarn", "pnpm", "pip", "pip3", "poetry",
					"cargo", "go", "maven", "mvn", "gradle", "bundler", "gem",
					"composer", "nuget", "dotnet"}
				binary := d.Event.Binary
				for _, m := range managers {
					if binary == m || strings.HasSuffix(binary, "/"+m) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.85,
			Reasoning:  "Package manager writing to temp directory",
		},
		{
			Name:        "cache_dir_access",
			Description: "Cache directory access is normal during builds",
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewFile {
					return false
				}
				cachePaths := []string{"/var/cache/", "/.cache/", "/.npm/", "/.yarn/",
					"/.cargo/registry/", "/.local/share/", "/go/pkg/"}
				for _, p := range cachePaths {
					if strings.Contains(d.Event.FilePath, p) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictBenign,
			Confidence: 0.9,
			Reasoning:  "File access in cache directory",
		},

		// --- Critical rules ---
		{
			Name:            "reverse_shell_pattern",
			Description:     "Detect potential reverse shell patterns",
			MITRETechniques: []string{"T1059.004", "T1571"},
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
			Name:            "credential_exfiltration",
			Description:     "Detect attempts to read and exfiltrate credentials",
			MITRETechniques: []string{"T1552.001"},
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
			Name:            "environment_dump",
			Description:     "Detect attempts to dump process environment (secrets)",
			MITRETechniques: []string{"T1552.007"},
			Match: func(d detection.ScoredDeviation) bool {
				return d.DeviationType == detection.DeviationSensitivePath &&
					strings.Contains(d.Event.FilePath, "/proc/self/environ")
			},
			Verdict:    VerdictCritical,
			Confidence: 0.85,
			Reasoning:  "Process environment dump detected — may expose CI/CD secrets",
		},
		{
			Name:            "suspicious_args_critical",
			Description:     "Suspicious argument patterns are strong attack indicators",
			MITRETechniques: []string{"T1059.004", "T1105"},
			Match: func(d detection.ScoredDeviation) bool {
				return d.DeviationType == detection.DeviationSuspiciousArgs && d.Score >= 0.85
			},
			Verdict:    VerdictCritical,
			Confidence: 0.85,
			Reasoning:  "Suspicious command-line argument pattern detected — possible supply chain attack",
		},
		{
			Name:            "unexpected_parent_high_risk",
			Description:     "High-risk parent-child process relationship",
			MITRETechniques: []string{"T1059"},
			Match: func(d detection.ScoredDeviation) bool {
				return d.DeviationType == detection.DeviationUnexpectedParent && d.Score >= 0.95
			},
			Verdict:    VerdictCritical,
			Confidence: 0.9,
			Reasoning:  "High-risk process spawning pattern — unexpected parent-child relationship",
		},
		{
			Name:            "write_to_etc",
			Description:     "Write to /etc/ directory outside of expected tools",
			MITRETechniques: []string{"T1546"},
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewFile {
					return false
				}
				if !strings.HasPrefix(d.Event.FilePath, "/etc/") {
					return false
				}
				return d.Event.AccessType == "write" || d.Event.AccessType == "create"
			},
			Verdict:    VerdictCritical,
			Confidence: 0.85,
			Reasoning:  "Write to /etc/ directory detected — possible persistence mechanism",
		},
		{
			Name:            "persistence_via_profile",
			Description:     "Write to shell profile files for persistence",
			MITRETechniques: []string{"T1546"},
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewFile {
					return false
				}
				if d.Event.AccessType != "write" && d.Event.AccessType != "create" {
					return false
				}
				persistPaths := []string{"/.bashrc", "/.bash_profile", "/.profile",
					"/.zshrc", "/crontab", "/cron.d/"}
				for _, p := range persistPaths {
					if strings.Contains(d.Event.FilePath, p) {
						return true
					}
				}
				return false
			},
			Verdict:    VerdictCritical,
			Confidence: 0.9,
			Reasoning:  "Write to shell profile or cron detected — possible persistence",
		},
		{
			Name:            "private_key_access",
			Description:     "Access to private key or certificate files outside workspace",
			MITRETechniques: []string{"T1552.001"},
			Match: func(d detection.ScoredDeviation) bool {
				if d.DeviationType != detection.DeviationNewFile && d.DeviationType != detection.DeviationSensitivePath {
					return false
				}
				// Only flag outside workspace directories
				if strings.HasPrefix(d.Event.FilePath, "/home/runner/work/") ||
					strings.HasPrefix(d.Event.FilePath, "/github/workspace/") {
					return false
				}
				return strings.HasSuffix(d.Event.FilePath, ".pem") ||
					strings.HasSuffix(d.Event.FilePath, ".key") ||
					strings.HasSuffix(d.Event.FilePath, ".p12") ||
					strings.HasSuffix(d.Event.FilePath, ".pfx")
			},
			Verdict:    VerdictCritical,
			Confidence: 0.85,
			Reasoning:  "Access to private key/certificate file outside workspace",
		},
	}
}
