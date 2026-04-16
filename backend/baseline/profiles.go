package baseline

import (
	"strings"
	"time"
)

// ArgSignature tracks the frequency of a normalized argument pattern.
type ArgSignature struct {
	Pattern       string  `json:"pattern"`
	Frequency     float64 `json:"frequency"`
	ObservedCount int     `json:"observed_count"`
}

// ProcessProfile tracks the behavioral profile of a binary in a job's builds.
type ProcessProfile struct {
	BinaryPath          string             `json:"binary_path"`
	TypicalArgsPatterns []string           `json:"typical_args_patterns"`
	ArgSignatures       []ArgSignature     `json:"arg_signatures,omitempty"`
	TypicalParent       string             `json:"typical_parent"`
	KnownParents        []string           `json:"known_parents,omitempty"`
	StepFrequency       map[string]float64 `json:"step_frequency,omitempty"` // step_name -> frequency
	Frequency           float64            `json:"frequency"`                // 0.0-1.0
	ObservedCount       int                `json:"observed_count"`
	TotalJobs           int                `json:"total_jobs"`
	FirstSeen           time.Time          `json:"first_seen"`
	LastSeen            time.Time          `json:"last_seen"`
}

// FindArgSignature looks up an arg signature by pattern.
func (p *ProcessProfile) FindArgSignature(pattern string) *ArgSignature {
	for i := range p.ArgSignatures {
		if p.ArgSignatures[i].Pattern == pattern {
			return &p.ArgSignatures[i]
		}
	}
	return nil
}

// NetworkProfile tracks the network connection profile for a repository's builds.
type NetworkProfile struct {
	DestinationCIDRs []string  `json:"destination_cidrs"`
	TypicalPorts     []uint32  `json:"typical_ports"`
	Hostnames        []string  `json:"hostnames,omitempty"`
	DomainSuffix     string    `json:"domain_suffix,omitempty"` // e.g. "github.com"
	Frequency        float64   `json:"frequency"`
	ObservedCount    int       `json:"observed_count"`
	TotalJobs        int       `json:"total_jobs"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// FileAccessProfile tracks file access patterns for a repository's builds.
// Keyed by normalized path pattern (e.g., "/home/runner/work/**").
type FileAccessProfile struct {
	PathPattern   string   `json:"path_pattern"`
	AccessTypes   []string `json:"access_types"`   // observed: "read", "write", "create", "delete"
	BinaryPaths   []string `json:"binary_paths"`   // which binaries access this pattern
	Frequency     float64  `json:"frequency"`       // 0.0-1.0
	ObservedCount int      `json:"observed_count"`
	TotalJobs     int      `json:"total_jobs"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// RepositoryBaseline is the complete behavioral baseline for a specific job
// within a repository. Keyed by (Repository, WorkflowFile, JobName).
type RepositoryBaseline struct {
	Repository         string              `json:"repository"`
	WorkflowFile       string              `json:"workflow_file"`
	JobName            string              `json:"job_name"`
	TotalJobsObserved  int                 `json:"total_jobs_observed"`
	Status             string              `json:"status"` // "learning", "active"
	LearningThreshold  int                 `json:"learning_threshold"`
	FirstObserved      time.Time           `json:"first_observed"`
	LastUpdated        time.Time           `json:"last_updated"`
	ProcessProfiles    []ProcessProfile    `json:"process_profiles"`
	NetworkProfiles    []NetworkProfile    `json:"network_profiles"`
	FileAccessProfiles []FileAccessProfile `json:"file_access_profiles"`
}

// Key returns a display string for this baseline's composite key.
func (b *RepositoryBaseline) Key() string {
	return b.Repository + "/" + b.WorkflowFile + "/" + b.JobName
}

// IsLearning returns true if the baseline is still in learning mode.
func (b *RepositoryBaseline) IsLearning() bool {
	return b.Status == "learning"
}

// IsActive returns true if the baseline has enough data for detection.
func (b *RepositoryBaseline) IsActive() bool {
	return b.Status == "active"
}

// FindProcessProfile looks up a process profile by binary path.
func (b *RepositoryBaseline) FindProcessProfile(binaryPath string) *ProcessProfile {
	for i := range b.ProcessProfiles {
		if b.ProcessProfiles[i].BinaryPath == binaryPath {
			return &b.ProcessProfiles[i]
		}
	}
	return nil
}

// FindNetworkProfile looks up a network profile by destination IP.
func (b *RepositoryBaseline) FindNetworkProfile(destIP string) *NetworkProfile {
	for i := range b.NetworkProfiles {
		for _, cidr := range b.NetworkProfiles[i].DestinationCIDRs {
			if cidr == destIP {
				return &b.NetworkProfiles[i]
			}
		}
	}
	return nil
}

// FindFileAccessProfile looks up a file access profile by normalized path pattern.
func (b *RepositoryBaseline) FindFileAccessProfile(pathPattern string) *FileAccessProfile {
	for i := range b.FileAccessProfiles {
		if b.FileAccessProfiles[i].PathPattern == pathPattern {
			return &b.FileAccessProfiles[i]
		}
	}
	return nil
}

// NormalizePathPattern normalizes a file path into a pattern for baseline matching.
// Preserves first 2 directory levels, replaces deeper paths with globs.
// Examples:
//
//	"/home/runner/work/repo/src/main.go" → "/home/runner/**"
//	"/tmp/build-xyz/output.bin"          → "/tmp/**"
//	"/etc/shadow"                        → "/etc/shadow"
//	"/proc/self/environ"                 → "/proc/self/**"
func NormalizePathPattern(path string) string {
	if path == "" {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) <= 2 {
		return "/" + strings.Join(parts, "/")
	}
	return "/" + strings.Join(parts[:2], "/") + "/**"
}

// NormalizeArgs normalizes command arguments for baseline comparison.
// Strips variable parts (paths, versions, hashes) while preserving flag structure.
func NormalizeArgs(binary string, args []string) string {
	if len(args) == 0 {
		return ""
	}
	base := binary
	if idx := strings.LastIndex(binary, "/"); idx >= 0 {
		base = binary[idx+1:]
	}

	var normalized []string
	for _, arg := range args {
		switch {
		// Preserve flags as-is
		case strings.HasPrefix(arg, "-"):
			normalized = append(normalized, arg)
		// Replace paths with pattern
		case strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./"):
			normalized = append(normalized, "<path>")
		// Replace version-like strings
		case isVersionLike(arg):
			normalized = append(normalized, "<version>")
		// Replace hex hashes (git SHAs, checksums)
		case isHexHash(arg):
			normalized = append(normalized, "<hash>")
		// Replace URLs
		case strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://"):
			normalized = append(normalized, "<url>")
		default:
			// For known commands, preserve subcommands
			if isSubcommand(base, arg) {
				normalized = append(normalized, arg)
			} else {
				normalized = append(normalized, "<arg>")
			}
		}
	}
	return strings.Join(normalized, " ")
}

func isVersionLike(s string) bool {
	// Match patterns like "1.2.3", "v1.0.0", "20231201"
	if len(s) == 0 {
		return false
	}
	dotCount := 0
	digitCount := 0
	for _, c := range s {
		if c == '.' {
			dotCount++
		} else if c >= '0' && c <= '9' {
			digitCount++
		} else if c != 'v' && c != '-' && c != '_' {
			return false
		}
	}
	return dotCount >= 1 && digitCount >= 1
}

func isHexHash(s string) bool {
	if len(s) < 7 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isSubcommand(binary, arg string) bool {
	subcommands := map[string]map[string]bool{
		"git":    {"clone": true, "checkout": true, "pull": true, "push": true, "commit": true, "add": true, "status": true, "log": true, "fetch": true, "merge": true, "rebase": true},
		"npm":    {"install": true, "ci": true, "run": true, "test": true, "build": true, "publish": true},
		"yarn":   {"install": true, "add": true, "run": true, "test": true, "build": true},
		"go":     {"build": true, "test": true, "install": true, "mod": true, "run": true, "vet": true, "fmt": true, "get": true},
		"pip":    {"install": true, "uninstall": true, "freeze": true, "list": true},
		"pip3":   {"install": true, "uninstall": true, "freeze": true, "list": true},
		"cargo":  {"build": true, "test": true, "run": true, "install": true, "check": true, "clippy": true},
		"docker": {"build": true, "run": true, "push": true, "pull": true, "tag": true, "login": true, "compose": true},
		"kubectl": {"apply": true, "get": true, "describe": true, "delete": true, "logs": true},
	}
	if cmds, ok := subcommands[binary]; ok {
		return cmds[arg]
	}
	return false
}

// PruneStaleProfiles removes profiles that haven't been seen within maxAge.
// Returns the number of profiles pruned per type.
func (b *RepositoryBaseline) PruneStaleProfiles(maxAge time.Duration) (processCount, networkCount, fileCount int) {
	cutoff := time.Now().Add(-maxAge)

	// Prune process profiles
	kept := b.ProcessProfiles[:0]
	for _, p := range b.ProcessProfiles {
		if p.LastSeen.After(cutoff) || p.LastSeen.IsZero() {
			kept = append(kept, p)
		}
	}
	processCount = len(b.ProcessProfiles) - len(kept)
	b.ProcessProfiles = kept

	// Prune network profiles
	keptNet := b.NetworkProfiles[:0]
	for _, p := range b.NetworkProfiles {
		if p.LastSeen.After(cutoff) || p.LastSeen.IsZero() {
			keptNet = append(keptNet, p)
		}
	}
	networkCount = len(b.NetworkProfiles) - len(keptNet)
	b.NetworkProfiles = keptNet

	// Prune file access profiles
	keptFile := b.FileAccessProfiles[:0]
	for _, p := range b.FileAccessProfiles {
		if p.LastSeen.After(cutoff) || p.LastSeen.IsZero() {
			keptFile = append(keptFile, p)
		}
	}
	fileCount = len(b.FileAccessProfiles) - len(keptFile)
	b.FileAccessProfiles = keptFile

	return
}
