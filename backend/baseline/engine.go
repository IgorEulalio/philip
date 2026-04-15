package baseline

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/storage"
)

const (
	defaultLearningThreshold = 10
	// Exponential decay factor — recent builds are weighted more heavily.
	// A factor of 0.95 means each older job's weight decreases by 5%.
	decayFactor = 0.95
)

// Engine builds and updates behavioral baselines per repository.
type Engine struct {
	store             storage.StoreInterface
	learningThreshold int
	logger            *slog.Logger
}

// NewEngine creates a new baseline engine.
func NewEngine(store storage.StoreInterface, logger *slog.Logger) *Engine {
	return &Engine{
		store:             store,
		learningThreshold: defaultLearningThreshold,
		logger:            logger,
	}
}

// UpdateBaseline updates the baseline for a repository based on a new job's events.
func (e *Engine) UpdateBaseline(ctx context.Context, repository string, events []sensor.Event) (*RepositoryBaseline, error) {
	// Load existing baseline
	existing, err := e.loadBaseline(ctx, repository)
	if err != nil {
		return nil, err
	}

	if existing == nil {
		existing = &RepositoryBaseline{
			Repository:        repository,
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
		e.logger.Info("baseline activated", "repository", repository,
			"jobs_observed", existing.TotalJobsObserved)
	}

	// Persist
	if err := e.saveBaseline(ctx, existing); err != nil {
		return nil, err
	}

	e.logger.Info("baseline updated",
		"repository", repository,
		"status", existing.Status,
		"jobs_observed", existing.TotalJobsObserved,
		"process_profiles", len(existing.ProcessProfiles),
		"network_profiles", len(existing.NetworkProfiles))

	return existing, nil
}

// GetBaseline retrieves the current baseline for a repository.
func (e *Engine) GetBaseline(ctx context.Context, repository string) (*RepositoryBaseline, error) {
	return e.loadBaseline(ctx, repository)
}

func (e *Engine) updateProcessProfiles(baseline *RepositoryBaseline, events []sensor.Event) {
	// Count unique binaries in this job
	seenBinaries := make(map[string]struct {
		args   []string
		parent string
	})

	for _, evt := range events {
		if evt.Type != sensor.EventTypeProcessExec {
			continue
		}
		if _, seen := seenBinaries[evt.Binary]; !seen {
			parentBinary := "" // would need process tree for parent binary
			seenBinaries[evt.Binary] = struct {
				args   []string
				parent string
			}{args: evt.Args, parent: parentBinary}
		}
	}

	totalJobs := baseline.TotalJobsObserved

	for binary, info := range seenBinaries {
		profile := baseline.FindProcessProfile(binary)
		if profile == nil {
			// New binary — add to baseline
			baseline.ProcessProfiles = append(baseline.ProcessProfiles, ProcessProfile{
				BinaryPath:          binary,
				TypicalArgsPatterns: info.args,
				TypicalParent:       info.parent,
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
			baseline.NetworkProfiles = append(baseline.NetworkProfiles, NetworkProfile{
				DestinationCIDRs: []string{destIP},
				TypicalPorts:     []uint32{port},
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
		}
	}
}

func (e *Engine) updateFileAccessProfiles(baseline *RepositoryBaseline, events []sensor.Event) {
	// File access profiling — Phase 2 enhancement
	// For MVP, we only track process and network profiles
}

func (e *Engine) loadBaseline(ctx context.Context, repository string) (*RepositoryBaseline, error) {
	record, err := e.store.GetBaseline(ctx, repository)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}

	baseline := &RepositoryBaseline{
		Repository:        record.Repository,
		TotalJobsObserved: record.TotalJobsObserved,
		Status:            record.Status,
		LearningThreshold: defaultLearningThreshold,
		FirstObserved:     record.FirstObserved,
		LastUpdated:       record.LastUpdated,
	}

	for _, p := range record.ProcessProfiles {
		baseline.ProcessProfiles = append(baseline.ProcessProfiles, ProcessProfile{
			BinaryPath:          p.BinaryPath,
			TypicalArgsPatterns: p.TypicalArgsPatterns,
			TypicalParent:       p.TypicalParent,
			Frequency:           p.Frequency,
			FirstSeen:           p.FirstSeen,
			LastSeen:            p.LastSeen,
		})
	}

	for _, n := range record.NetworkProfiles {
		baseline.NetworkProfiles = append(baseline.NetworkProfiles, NetworkProfile{
			DestinationCIDRs: n.DestinationCIDRs,
			TypicalPorts:     n.TypicalPorts,
			Frequency:        n.Frequency,
			FirstSeen:        n.FirstSeen,
			LastSeen:         n.LastSeen,
		})
	}

	return baseline, nil
}

func (e *Engine) saveBaseline(ctx context.Context, baseline *RepositoryBaseline) error {
	record := &storage.BaselineRecord{
		Repository:        baseline.Repository,
		TotalJobsObserved: baseline.TotalJobsObserved,
		Status:            baseline.Status,
		FirstObserved:     baseline.FirstObserved,
		LastUpdated:       baseline.LastUpdated,
	}

	for _, p := range baseline.ProcessProfiles {
		record.ProcessProfiles = append(record.ProcessProfiles, storage.ProcessProfileDB{
			BinaryPath:          p.BinaryPath,
			TypicalArgsPatterns: p.TypicalArgsPatterns,
			TypicalParent:       p.TypicalParent,
			Frequency:           p.Frequency,
			FirstSeen:           p.FirstSeen,
			LastSeen:            p.LastSeen,
		})
	}

	for _, n := range baseline.NetworkProfiles {
		record.NetworkProfiles = append(record.NetworkProfiles, storage.NetworkProfileDB{
			DestinationCIDRs: n.DestinationCIDRs,
			TypicalPorts:     n.TypicalPorts,
			Frequency:        n.Frequency,
			FirstSeen:        n.FirstSeen,
			LastSeen:         n.LastSeen,
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
