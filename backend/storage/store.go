package storage

import (
	"context"
	"time"
)

// StoreInterface defines the persistence contract for Philip's backend.
// Implementations: Store (PostgreSQL), MockStore (tests).
type StoreInterface interface {
	// Agents
	UpsertAgent(ctx context.Context, agentID, hostname, version, sensorType string) error
	UpdateAgentHeartbeat(ctx context.Context, agentID string) error

	// Job records
	InsertJobRecord(ctx context.Context, jobID, repository, workflowName, workflowFile,
		runID, runNumber, branch, commitSHA, triggerEvent, runnerName string,
		eventCount int, startTime, endTime time.Time, processTree map[string]interface{}) error
	InsertEvent(ctx context.Context, id, jobID, eventType string, timestamp time.Time,
		pid, parentPID int, binaryPath string, args []string, cwd string, uid int,
		destIP string, destPort int, protocol string,
		filePath string, fileFlags int, accessType string,
		exitCode int, durationMs int64) error

	// Baselines
	GetBaseline(ctx context.Context, repository, workflowFile, jobName string) (*BaselineRecord, error)
	ListBaselines(ctx context.Context) ([]BaselineSummary, error)
	UpsertBaseline(ctx context.Context, b *BaselineRecord) error

	// Findings
	InsertFinding(ctx context.Context, f *FindingRecord) error
	ListFindings(ctx context.Context, repository, severity, status string, limit int) ([]FindingRecord, error)
}

// Verify that Store implements StoreInterface at compile time.
var _ StoreInterface = (*Store)(nil)
