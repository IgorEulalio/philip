package baseline

import (
	"time"
)

// ProcessProfile tracks the behavioral profile of a binary in a repository's builds.
type ProcessProfile struct {
	BinaryPath          string    `json:"binary_path"`
	TypicalArgsPatterns []string  `json:"typical_args_patterns"`
	TypicalParent       string    `json:"typical_parent"`
	Frequency           float64   `json:"frequency"` // 0.0-1.0
	ObservedCount       int       `json:"observed_count"`
	TotalJobs           int       `json:"total_jobs"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// NetworkProfile tracks the network connection profile for a repository's builds.
type NetworkProfile struct {
	DestinationCIDRs []string  `json:"destination_cidrs"`
	TypicalPorts     []uint32  `json:"typical_ports"`
	Frequency        float64   `json:"frequency"`
	ObservedCount    int       `json:"observed_count"`
	TotalJobs        int       `json:"total_jobs"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// FileAccessProfile tracks file access patterns for a repository's builds.
type FileAccessProfile struct {
	PathPatterns           []string  `json:"path_patterns"`
	SensitivePathsAccessed []string  `json:"sensitive_paths_accessed"`
	Frequency              float64   `json:"frequency"`
	ObservedCount          int       `json:"observed_count"`
	TotalJobs              int       `json:"total_jobs"`
	FirstSeen              time.Time `json:"first_seen"`
	LastSeen               time.Time `json:"last_seen"`
}

// RepositoryBaseline is the complete behavioral baseline for a repository.
type RepositoryBaseline struct {
	Repository         string              `json:"repository"`
	TotalJobsObserved  int                 `json:"total_jobs_observed"`
	Status             string              `json:"status"` // "learning", "active"
	LearningThreshold  int                 `json:"learning_threshold"`
	FirstObserved      time.Time           `json:"first_observed"`
	LastUpdated        time.Time           `json:"last_updated"`
	ProcessProfiles    []ProcessProfile    `json:"process_profiles"`
	NetworkProfiles    []NetworkProfile    `json:"network_profiles"`
	FileAccessProfiles []FileAccessProfile `json:"file_access_profiles"`
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
