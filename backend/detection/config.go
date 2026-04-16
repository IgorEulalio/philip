package detection

// ScorerConfig holds configurable lists used by the scorer.
// This allows customization of detection rules without code changes.
type ScorerConfig struct {
	SuspiciousBinaries    []string          `json:"suspicious_binaries"`
	SensitivePaths        []string          `json:"sensitive_paths"`
	CommonPorts           []uint16          `json:"common_ports"`
	TrustedDomainSuffixes map[string]bool   `json:"trusted_domain_suffixes"`
	DeviationWeights      map[DeviationType]float64 `json:"deviation_weights,omitempty"`
}

// DefaultScorerConfig returns the default scorer configuration.
func DefaultScorerConfig() ScorerConfig {
	return ScorerConfig{
		SuspiciousBinaries: []string{
			"nc", "ncat", "netcat",
			"nmap",
			"wget",
			"base64",
			"xxd",
			"python", "python3",
			"perl",
			"ruby",
		},
		SensitivePaths: []string{
			"/etc/shadow",
			"/etc/passwd",
			"/.ssh/",
			"/proc/self/environ",
			"/.docker/config.json",
			"/.npmrc",
			"/.pypirc",
			"/.aws/credentials",
			"/.kube/config",
			"/.gnupg/",
			"/.netrc",
		},
		CommonPorts: []uint16{80, 443, 22, 53},
		TrustedDomainSuffixes: map[string]bool{
			"github.com":             true,
			"githubusercontent.com":  true,
			"npmjs.org":              true,
			"npmjs.com":              true,
			"yarnpkg.com":            true,
			"pypi.org":               true,
			"pythonhosted.org":       true,
			"rubygems.org":           true,
			"crates.io":              true,
			"docker.io":              true,
			"docker.com":             true,
			"gcr.io":                 true,
			"amazonaws.com":          true,
			"cloudfront.net":         true,
			"googleapis.com":         true,
			"registry.npmjs.org":     true,
			"gitlab.com":             true,
			"bitbucket.org":          true,
			"nuget.org":              true,
			"maven.org":              true,
			"gradle.org":             true,
			"golang.org":             true,
			"proxy.golang.org":       true,
			"sum.golang.org":         true,
		},
		DeviationWeights: map[DeviationType]float64{
			DeviationNewNetwork:       1.0,
			DeviationSensitivePath:    0.9,
			DeviationSuspiciousArgs:   0.85,
			DeviationUnexpectedParent: 0.8,
			DeviationNewProcess:       0.7,
			DeviationAnomalousArgs:    0.5,
			DeviationNewFile:          0.3,
		},
	}
}
