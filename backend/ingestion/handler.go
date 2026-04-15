package ingestion

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/metrics"
	"github.com/IgorEulalio/philip/backend/storage"
)

// JobReadyFunc is the callback signature when a job is ready for analysis.
// It receives the job ID, baseline key (repository, workflowFile, jobName), and the raw events.
type JobReadyFunc func(jobID, repository, workflowFile, jobName string, events []sensor.Event)

// Handler processes incoming job event records from agents.
type Handler struct {
	store      storage.StoreInterface
	onJobReady JobReadyFunc
	logger     *slog.Logger
}

// NewHandler creates a new ingestion handler.
func NewHandler(store storage.StoreInterface, onJobReady JobReadyFunc, logger *slog.Logger) *Handler {
	return &Handler{
		store:      store,
		onJobReady: onJobReady,
		logger:     logger,
	}
}

// IngestJobRecord stores a complete job event record and triggers analysis.
func (h *Handler) IngestJobRecord(ctx context.Context, jobID string, metadata JobMetadata,
	events []sensor.Event, startTime, endTime time.Time, processTree map[string]interface{}) error {

	h.logger.Info("ingesting job record",
		"job_id", jobID,
		"repository", metadata.Repository,
		"event_count", len(events))

	// Store the job record
	err := h.store.InsertJobRecord(ctx,
		jobID,
		metadata.Repository,
		metadata.WorkflowName,
		metadata.WorkflowFile,
		metadata.RunID,
		metadata.RunNumber,
		metadata.Branch,
		metadata.CommitSHA,
		metadata.TriggerEvent,
		metadata.RunnerName,
		len(events),
		startTime,
		endTime,
		processTree,
	)
	if err != nil {
		return fmt.Errorf("storing job record: %w", err)
	}

	// Store individual events
	for _, evt := range events {
		destIP := ""
		if evt.DestIP != nil {
			destIP = evt.DestIP.String()
		}

		err := h.store.InsertEvent(ctx,
			evt.ID,
			jobID,
			evt.Type.String(),
			evt.Timestamp,
			int(evt.PID),
			int(evt.ParentPID),
			evt.Binary,
			evt.Args,
			evt.CWD,
			int(evt.UID),
			destIP,
			int(evt.DestPort),
			evt.Protocol,
			evt.FilePath,
			int(evt.FileFlags),
			evt.AccessType,
			int(evt.ExitCode),
			evt.DurationMs,
		)
		if err != nil {
			h.logger.Warn("failed to store event", "event_id", evt.ID, "error", err)
		}
	}

	// Record ingestion metrics
	for _, evt := range events {
		metrics.EventsIngested.WithLabelValues(metadata.Repository, evt.Type.String()).Inc()
	}

	// Resolve workflow_file: prefer WorkflowFile, fall back to WorkflowName
	workflowFile := metadata.WorkflowFile
	if workflowFile == "" {
		workflowFile = metadata.WorkflowName
	}

	// Notify that this job is ready for baseline update and analysis
	if h.onJobReady != nil {
		h.onJobReady(jobID, metadata.Repository, workflowFile, metadata.JobName, events)
	}

	return nil
}

// JobMetadata mirrors the agent's JobInfo for the backend context.
type JobMetadata struct {
	Repository   string
	WorkflowName string
	WorkflowFile string
	JobName      string
	RunID        string
	RunNumber    string
	Branch       string
	CommitSHA    string
	TriggerEvent string
	RunnerName   string
	RunnerOS     string
}
