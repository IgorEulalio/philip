package baseline

import (
	"context"
	"log/slog"
	"math"
	"net"
	"strings"
	"time"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/storage"
)

const (
	defaultLearningThreshold = 10
	// Exponential decay factor — recent builds are weighted more heavily.
	// A factor of 0.95 means each older job's weight decreases by 5%.
	decayFactor = 0.95
	// Default max age for profile pruning (90 days).
	defaultMaxProfileAge = 90 * 24 * time.Hour
)

// Engine builds and updates behavioral baselines per repository.
type Engine struct {
	store             storage.StoreInterface
	learningThreshold int
	maxProfileAge     time.Duration
	logger            *slog.Logger
}

// EngineConfig holds configurable parameters for the baseline engine.
type EngineConfig struct {
	LearningThreshold int           `json:"learning_threshold"`
	MaxProfileAgeDays int           `json:"max_profile_age_days"`
}

// DefaultEngineConfig returns defaults for the baseline engine.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		LearningThreshold: defaultLearningThreshold,
		MaxProfileAgeDays: 90,
	}
}

// NewEngine creates a new baseline engine.
func NewEngine(store storage.StoreInterface, logger *slog.Logger) *Engine {
	return NewEngineWithConfig(store, DefaultEngineConfig(), logger)
}

// NewEngineWithConfig creates a new baseline engine with explicit config.
func NewEngineWithConfig(store storage.StoreInterface, cfg EngineConfig, logger *slog.Logger) *Engine {
	threshold := cfg.LearningThreshold
	if threshold <= 0 {
		threshold = defaultLearningThreshold
	}
	maxAge := time.Duration(cfg.MaxProfileAgeDays) * 24 * time.Hour
	if maxAge <= 0 {
		maxAge = defaultMaxProfileAge
	}
	return &Engine{
		store:             store,
		learningThreshold: threshold,
		maxProfileAge:     maxAge,
		logger:            logger,
	}
}

// UpdateBaseline updates the baseline for a specific job based on new events.
// The baseline is keyed by (repository, workflowFile, jobName).
func (e *Engine) UpdateBaseline(ctx context.Context, repository, workflowFile, jobName string, events []sensor.Event) (*RepositoryBaseline, error) {
	// Load existing baseline
	existing, err := e.loadBaseline(ctx, repository, workflowFile, jobName)
	if err != nil {
		return nil, err
	}

	if existing == nil {
		existing = &RepositoryBaseline{
			Repository:        repository,
			WorkflowFile:      workflowFile,
			JobName:           jobName,
			Status:            "learning",
			LearningThreshold: e.learningThreshold,
			FirstObserved:     time.Now(),
		}
	}

	existing.TotalJobsObserved++
	existing.LastUpdated = time.Now()

	// Update profiles from this job's events
	e.updateProcessProfiles(existing, events)
	e.updateNetworkProfiles(existing, events)
	e.updateFileAccessProfiles(existing, events)

	// Transition from learning to active if threshold is met
	if existing.Status == "learning" && existing.TotalJobsObserved >= existing.LearningThreshold {
		existing.Status = "active"
		e.logger.Info("baseline activated",
			"repository", repository,
			"workflow_file", workflowFile,
			"job_name", jobName,
			"jobs_observed", existing.TotalJobsObserved)
	}

	// Prune stale profiles
	pProc, pNet, pFile := existing.PruneStaleProfiles(e.maxProfileAge)
	if pProc+pNet+pFile > 0 {
		e.logger.Info("pruned stale profiles",
			"repository", repository,
			"job_name", jobName,
			"process", pProc, "network", pNet, "file", pFile)
	}

	// Persist
	if err := e.saveBaseline(ctx, existing); err != nil {
		return nil, err
	}

	e.logger.Info("baseline updated",
		"repository", repository,
		"workflow_file", workflowFile,
		"job_name", jobName,
		"status", existing.Status,
		"jobs_observed", existing.TotalJobsObserved,
		"process_profiles", len(existing.ProcessProfiles),
		"network_profiles", len(existing.NetworkProfiles))

	return existing, nil
}

// GetBaseline retrieves the current baseline for a specific job.
func (e *Engine) GetBaseline(ctx context.Context, repository, workflowFile, jobName string) (*RepositoryBaseline, error) {
	return e.loadBaseline(ctx, repository, workflowFile, jobName)
}

func (e *Engine) updateProcessProfiles(baseline *RepositoryBaseline, events []sensor.Event) {
	// Collect all unique arg patterns, parents, and steps per binary
	type binaryInfo struct {
		args        []string   // first occurrence args (for TypicalArgsPatterns)
		argPatterns []string   // all unique normalized arg patterns
		parents     []string   // all unique parents
		steps       []string   // all unique steps
	}
	seenBinaries := make(map[string]*binaryInfo)

	for _, evt := range events {
		if evt.Type != sensor.EventTypeProcessExec {
			continue
		}
		info, exists := seenBinaries[evt.Binary]
		if !exists {
			info = &binaryInfo{args: evt.Args}
			seenBinaries[evt.Binary] = info
		}
		// Collect all unique arg patterns
		argPattern := NormalizeArgs(evt.Binary, evt.Args)
		if argPattern != "" {
			found := false
			for _, p := range info.argPatterns {
				if p == argPattern {
					found = true
					break
				}
			}
			if !found {
				info.argPatterns = append(info.argPatterns, argPattern)
			}
		}
		// Collect unique parents
		if evt.ParentBinary != "" {
			found := false
			for _, p := range info.parents {
				if p == evt.ParentBinary {
					found = true
					break
				}
			}
			if !found {
				info.parents = append(info.parents, evt.ParentBinary)
			}
		}
		// Collect unique steps
		if evt.StepName != "" {
			found := false
			for _, s := range info.steps {
				if s == evt.StepName {
					found = true
					break
				}
			}
			if !found {
				info.steps = append(info.steps, evt.StepName)
			}
		}
	}

	totalJobs := baseline.TotalJobsObserved

	for binary, info := range seenBinaries {
		profile := baseline.FindProcessProfile(binary)
		if profile == nil {
			// New binary — add to baseline
			stepFreq := make(map[string]float64)
			for _, step := range info.steps {
				stepFreq[step] = 1.0 / float64(totalJobs)
			}
			var argSigs []ArgSignature
			for _, pattern := range info.argPatterns {
				argSigs = append(argSigs, ArgSignature{
					Pattern:       pattern,
					Frequency:     1.0 / float64(totalJobs),
					ObservedCount: 1,
				})
			}
			parent := ""
			if len(info.parents) > 0 {
				parent = info.parents[0]
			}
			baseline.ProcessProfiles = append(baseline.ProcessProfiles, ProcessProfile{
				BinaryPath:          binary,
				TypicalArgsPatterns: info.args,
				ArgSignatures:       argSigs,
				TypicalParent:       parent,
				KnownParents:        info.parents,
				StepFrequency:       stepFreq,
				Frequency:           1.0 / float64(totalJobs),
				ObservedCount:       1,
				TotalJobs:           totalJobs,
				FirstSeen:           time.Now(),
				LastSeen:            time.Now(),
			})
		} else {
			// Existing binary — update with exponential decay
			profile.ObservedCount++
			profile.TotalJobs = totalJobs
			profile.Frequency = exponentialDecayFrequency(
				profile.Frequency, profile.ObservedCount, totalJobs,
			)
			profile.LastSeen = time.Now()
			// Merge new arg patterns
			profile.TypicalArgsPatterns = mergeStringSlice(
				profile.TypicalArgsPatterns, info.args,
			)
			// Track parent binaries
			profile.KnownParents = mergeStringSlice(profile.KnownParents, info.parents)
			if profile.TypicalParent == "" && len(info.parents) > 0 {
				profile.TypicalParent = info.parents[0]
			}
			// Track ALL arg signatures from this job
			for _, argPattern := range info.argPatterns {
				sig := profile.FindArgSignature(argPattern)
				if sig == nil {
					profile.ArgSignatures = append(profile.ArgSignatures, ArgSignature{
						Pattern:       argPattern,
						Frequency:     1.0 / float64(totalJobs),
						ObservedCount: 1,
					})
				} else {
					sig.ObservedCount++
					sig.Frequency = exponentialDecayFrequency(
						sig.Frequency, sig.ObservedCount, totalJobs,
					)
				}
			}
			// Track step frequency
			for _, step := range info.steps {
				if profile.StepFrequency == nil {
					profile.StepFrequency = make(map[string]float64)
				}
				profile.StepFrequency[step] = exponentialDecayFrequency(
					profile.StepFrequency[step], profile.ObservedCount, totalJobs,
				)
			}
		}
	}

	// Decay frequency of profiles NOT seen in this job
	for i := range baseline.ProcessProfiles {
		if _, seen := seenBinaries[baseline.ProcessProfiles[i].BinaryPath]; !seen {
			baseline.ProcessProfiles[i].TotalJobs = totalJobs
			baseline.ProcessProfiles[i].Frequency = exponentialDecayFrequency(
				baseline.ProcessProfiles[i].Frequency,
				baseline.ProcessProfiles[i].ObservedCount,
				totalJobs,
			)
		}
	}
}

func (e *Engine) updateNetworkProfiles(baseline *RepositoryBaseline, events []sensor.Event) {
	seenDestinations := make(map[string]uint32) // IP -> port

	for _, evt := range events {
		if evt.Type != sensor.EventTypeNetworkConnect {
			continue
		}
		if evt.DestIP != nil {
			seenDestinations[evt.DestIP.String()] = uint16To32(evt.DestPort)
		}
	}

	totalJobs := baseline.TotalJobsObserved

	for destIP, port := range seenDestinations {
		profile := baseline.FindNetworkProfile(destIP)
		if profile == nil {
			// Best-effort reverse DNS for new IPs
			hostnames, domainSuffix := reverseLookup(destIP)
			baseline.NetworkProfiles = append(baseline.NetworkProfiles, NetworkProfile{
				DestinationCIDRs: []string{destIP},
				TypicalPorts:     []uint32{port},
				Hostnames:        hostnames,
				DomainSuffix:     domainSuffix,
				Frequency:        1.0 / float64(totalJobs),
				ObservedCount:    1,
				TotalJobs:        totalJobs,
				FirstSeen:        time.Now(),
				LastSeen:         time.Now(),
			})
		} else {
			profile.ObservedCount++
			profile.TotalJobs = totalJobs
			profile.Frequency = exponentialDecayFrequency(
				profile.Frequency, profile.ObservedCount, totalJobs,
			)
			profile.LastSeen = time.Now()
			if !containsUint32(profile.TypicalPorts, port) {
				profile.TypicalPorts = append(profile.TypicalPorts, port)
			}
			// Update hostname if we didn't have one
			if len(profile.Hostnames) == 0 {
				hostnames, domainSuffix := reverseLookup(destIP)
				profile.Hostnames = hostnames
				if domainSuffix != "" {
					profile.DomainSuffix = domainSuffix
				}
			}
		}
	}
}

// reverseLookup performs a best-effort reverse DNS lookup.
// Returns hostnames and the domain suffix (last 2 parts of the hostname).
func reverseLookup(ip string) ([]string, string) {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return nil, ""
	}
	// Clean trailing dots from reverse DNS results
	var hostnames []string
	for _, name := range names {
		hostnames = append(hostnames, strings.TrimSuffix(name, "."))
	}
	// Extract domain suffix from the first hostname
	suffix := extractDomainSuffix(hostnames[0])
	return hostnames, suffix
}

// extractDomainSuffix returns the last 2 parts of a hostname (e.g., "github.com" from "lb.github.com").
func extractDomainSuffix(hostname string) string {
	parts := strings.Split(strings.TrimSuffix(hostname, "."), ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}

func (e *Engine) updateFileAccessProfiles(bl *RepositoryBaseline, events []sensor.Event) {
	// Collect file access events grouped by normalized path pattern
	type accessInfo struct {
		accessTypes map[string]bool
		binaries    map[string]bool
	}
	seenPatterns := make(map[string]*accessInfo)

	for _, evt := range events {
		if evt.Type != sensor.EventTypeFileAccess {
			continue
		}
		pattern := NormalizePathPattern(evt.FilePath)
		if pattern == "" {
			continue
		}
		info, exists := seenPatterns[pattern]
		if !exists {
			info = &accessInfo{
				accessTypes: make(map[string]bool),
				binaries:    make(map[string]bool),
			}
			seenPatterns[pattern] = info
		}
		if evt.AccessType != "" {
			info.accessTypes[evt.AccessType] = true
		}
		if evt.Binary != "" {
			info.binaries[evt.Binary] = true
		}
	}

	totalJobs := bl.TotalJobsObserved

	for pattern, info := range seenPatterns {
		accessTypes := mapKeys(info.accessTypes)
		binaries := mapKeys(info.binaries)

		profile := bl.FindFileAccessProfile(pattern)
		if profile == nil {
			bl.FileAccessProfiles = append(bl.FileAccessProfiles, FileAccessProfile{
				PathPattern:   pattern,
				AccessTypes:   accessTypes,
				BinaryPaths:   binaries,
				Frequency:     1.0 / float64(totalJobs),
				ObservedCount: 1,
				TotalJobs:     totalJobs,
				FirstSeen:     time.Now(),
				LastSeen:      time.Now(),
			})
		} else {
			profile.ObservedCount++
			profile.TotalJobs = totalJobs
			profile.Frequency = exponentialDecayFrequency(
				profile.Frequency, profile.ObservedCount, totalJobs,
			)
			profile.LastSeen = time.Now()
			profile.AccessTypes = mergeStringSlice(profile.AccessTypes, accessTypes)
			profile.BinaryPaths = mergeStringSlice(profile.BinaryPaths, binaries)
		}
	}

	// Decay frequency of profiles NOT seen in this job
	for i := range bl.FileAccessProfiles {
		if _, seen := seenPatterns[bl.FileAccessProfiles[i].PathPattern]; !seen {
			bl.FileAccessProfiles[i].TotalJobs = totalJobs
			bl.FileAccessProfiles[i].Frequency = exponentialDecayFrequency(
				bl.FileAccessProfiles[i].Frequency,
				bl.FileAccessProfiles[i].ObservedCount,
				totalJobs,
			)
		}
	}
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (e *Engine) loadBaseline(ctx context.Context, repository, workflowFile, jobName string) (*RepositoryBaseline, error) {
	record, err := e.store.GetBaseline(ctx, repository, workflowFile, jobName)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}

	bl := &RepositoryBaseline{
		Repository:        record.Repository,
		WorkflowFile:      record.WorkflowFile,
		JobName:           record.JobName,
		TotalJobsObserved: record.TotalJobsObserved,
		Status:            record.Status,
		LearningThreshold: defaultLearningThreshold,
		FirstObserved:     record.FirstObserved,
		LastUpdated:       record.LastUpdated,
	}

	for _, p := range record.ProcessProfiles {
		var argSigs []ArgSignature
		for _, s := range p.ArgSignatures {
			argSigs = append(argSigs, ArgSignature{
				Pattern:       s.Pattern,
				Frequency:     s.Frequency,
				ObservedCount: s.ObservedCount,
			})
		}
		bl.ProcessProfiles = append(bl.ProcessProfiles, ProcessProfile{
			BinaryPath:          p.BinaryPath,
			TypicalArgsPatterns: p.TypicalArgsPatterns,
			ArgSignatures:       argSigs,
			TypicalParent:       p.TypicalParent,
			KnownParents:        p.KnownParents,
			StepFrequency:       p.StepFrequency,
			Frequency:           p.Frequency,
			FirstSeen:           p.FirstSeen,
			LastSeen:            p.LastSeen,
		})
	}

	for _, n := range record.NetworkProfiles {
		bl.NetworkProfiles = append(bl.NetworkProfiles, NetworkProfile{
			DestinationCIDRs: n.DestinationCIDRs,
			TypicalPorts:     n.TypicalPorts,
			Hostnames:        n.Hostnames,
			DomainSuffix:     n.DomainSuffix,
			Frequency:        n.Frequency,
			FirstSeen:        n.FirstSeen,
			LastSeen:         n.LastSeen,
		})
	}

	for _, f := range record.FileAccessProfiles {
		bl.FileAccessProfiles = append(bl.FileAccessProfiles, FileAccessProfile{
			PathPattern: f.PathPattern,
			AccessTypes: f.AccessTypes,
			BinaryPaths: f.BinaryPaths,
			Frequency:   f.Frequency,
			FirstSeen:   f.FirstSeen,
			LastSeen:    f.LastSeen,
		})
	}

	return bl, nil
}

func (e *Engine) saveBaseline(ctx context.Context, baseline *RepositoryBaseline) error {
	record := &storage.BaselineRecord{
		Repository:        baseline.Repository,
		WorkflowFile:      baseline.WorkflowFile,
		JobName:           baseline.JobName,
		TotalJobsObserved: baseline.TotalJobsObserved,
		Status:            baseline.Status,
		FirstObserved:     baseline.FirstObserved,
		LastUpdated:       baseline.LastUpdated,
	}

	for _, p := range baseline.ProcessProfiles {
		var argSigs []storage.ArgSignatureDB
		for _, s := range p.ArgSignatures {
			argSigs = append(argSigs, storage.ArgSignatureDB{
				Pattern:       s.Pattern,
				Frequency:     s.Frequency,
				ObservedCount: s.ObservedCount,
			})
		}
		record.ProcessProfiles = append(record.ProcessProfiles, storage.ProcessProfileDB{
			BinaryPath:          p.BinaryPath,
			TypicalArgsPatterns: p.TypicalArgsPatterns,
			ArgSignatures:       argSigs,
			TypicalParent:       p.TypicalParent,
			KnownParents:        p.KnownParents,
			StepFrequency:       p.StepFrequency,
			Frequency:           p.Frequency,
			FirstSeen:           p.FirstSeen,
			LastSeen:            p.LastSeen,
		})
	}

	for _, n := range baseline.NetworkProfiles {
		record.NetworkProfiles = append(record.NetworkProfiles, storage.NetworkProfileDB{
			DestinationCIDRs: n.DestinationCIDRs,
			TypicalPorts:     n.TypicalPorts,
			Hostnames:        n.Hostnames,
			DomainSuffix:     n.DomainSuffix,
			Frequency:        n.Frequency,
			FirstSeen:        n.FirstSeen,
			LastSeen:         n.LastSeen,
		})
	}

	for _, f := range baseline.FileAccessProfiles {
		record.FileAccessProfiles = append(record.FileAccessProfiles, storage.FileAccessProfileDB{
			PathPattern: f.PathPattern,
			AccessTypes: f.AccessTypes,
			BinaryPaths: f.BinaryPaths,
			Frequency:   f.Frequency,
			FirstSeen:   f.FirstSeen,
			LastSeen:    f.LastSeen,
		})
	}

	return e.store.UpsertBaseline(ctx, record)
}

// exponentialDecayFrequency calculates frequency with exponential decay.
// More recent observations are weighted more heavily.
func exponentialDecayFrequency(currentFreq float64, observedCount, totalJobs int) float64 {
	if totalJobs == 0 {
		return 0
	}
	// Weighted frequency: blend current with raw ratio using decay
	rawFreq := float64(observedCount) / float64(totalJobs)
	decayed := currentFreq*decayFactor + rawFreq*(1-decayFactor)
	return math.Min(1.0, math.Max(0.0, decayed))
}

func mergeStringSlice(existing, new []string) []string {
	seen := make(map[string]bool)
	for _, s := range existing {
		seen[s] = true
	}
	for _, s := range new {
		if !seen[s] {
			existing = append(existing, s)
			seen[s] = true
		}
	}
	return existing
}

func containsUint32(slice []uint32, val uint32) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func uint16To32(v uint16) uint32 {
	return uint32(v)
}
