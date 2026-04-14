package collector

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/philip-ai/philip/agent/sensor"
)

// JobEventRecord is the complete record of all events during a single CI/CD job run.
type JobEventRecord struct {
	JobID      string
	Metadata   JobInfo
	Events     []sensor.Event
	StartTime  time.Time
	EndTime    time.Time
	Tree       map[uint32]ProcessNode
	EventCount int
}

// JobBuffer accumulates events for the current CI/CD job and produces
// a complete JobEventRecord when the job ends.
type JobBuffer struct {
	mu            sync.Mutex
	events        []sensor.Event
	maxEvents     int
	startTime     time.Time
	correlator    *StepCorrelator
	tree          *ProcessTree
	onJobComplete func(JobEventRecord)
	logger        *slog.Logger
}

// NewJobBuffer creates a new job event buffer.
func NewJobBuffer(
	correlator *StepCorrelator,
	tree *ProcessTree,
	maxEvents int,
	onJobComplete func(JobEventRecord),
	logger *slog.Logger,
) *JobBuffer {
	if maxEvents <= 0 {
		maxEvents = 100000
	}
	return &JobBuffer{
		events:        make([]sensor.Event, 0, 1024),
		maxEvents:     maxEvents,
		correlator:    correlator,
		tree:          tree,
		onJobComplete: onJobComplete,
		logger:        logger,
	}
}

// Run consumes normalized events and buffers them.
// When a job_end signal is received via the correlator, it flushes the buffer.
func (jb *JobBuffer) Run(ctx context.Context, events <-chan NormalizedEvent) error {
	for {
		select {
		case <-ctx.Done():
			// Flush any remaining events on shutdown
			jb.flush()
			return ctx.Err()
		case evt, ok := <-events:
			if !ok {
				jb.flush()
				return nil
			}
			jb.addEvent(evt)
		}
	}
}

func (jb *JobBuffer) addEvent(evt NormalizedEvent) {
	jb.mu.Lock()
	defer jb.mu.Unlock()

	// Track job start time
	if len(jb.events) == 0 {
		jb.startTime = evt.Timestamp
	}

	// Enforce max events with priority-based dropping
	if len(jb.events) >= jb.maxEvents {
		if !isHighPriority(evt.Event) {
			return // Drop low-priority events under backpressure
		}
		// Drop the oldest low-priority event to make room
		jb.dropLowestPriority()
	}

	jb.events = append(jb.events, evt.Event)
}

// Flush creates a JobEventRecord from buffered events and calls the completion handler.
func (jb *JobBuffer) flush() {
	jb.mu.Lock()
	defer jb.mu.Unlock()

	if len(jb.events) == 0 {
		return
	}

	jobInfo := JobInfo{}
	if job := jb.correlator.CurrentJob(); job != nil {
		jobInfo = *job
	}

	record := JobEventRecord{
		JobID:      jobInfo.JobID,
		Metadata:   jobInfo,
		Events:     make([]sensor.Event, len(jb.events)),
		StartTime:  jb.startTime,
		EndTime:    time.Now(),
		Tree:       jb.tree.AllNodes(),
		EventCount: len(jb.events),
	}
	copy(record.Events, jb.events)

	// Reset buffer
	jb.events = jb.events[:0]
	jb.startTime = time.Time{}

	jb.logger.Info("flushing job buffer",
		"job_id", record.JobID,
		"event_count", record.EventCount,
		"duration", record.EndTime.Sub(record.StartTime))

	if jb.onJobComplete != nil {
		go jb.onJobComplete(record)
	}
}

// FlushIfJobEnded checks if the current job has ended and flushes if so.
func (jb *JobBuffer) FlushIfJobEnded() {
	// This is called periodically or on job_end signal from the correlator
	jb.flush()
}

// EventCount returns the current number of buffered events.
func (jb *JobBuffer) EventCount() int {
	jb.mu.Lock()
	defer jb.mu.Unlock()
	return len(jb.events)
}

// isHighPriority determines if an event should be kept under backpressure.
func isHighPriority(evt sensor.Event) bool {
	switch evt.Type {
	case sensor.EventTypeNetworkConnect:
		return true // Network events are always high priority
	case sensor.EventTypeProcessExec:
		return true // Process exec is always high priority
	case sensor.EventTypeFileAccess:
		return false // File access can be dropped under pressure
	case sensor.EventTypeProcessExit:
		return false // Exit events are supplementary
	default:
		return false
	}
}

// dropLowestPriority removes the first low-priority event from the buffer.
func (jb *JobBuffer) dropLowestPriority() {
	for i, evt := range jb.events {
		if !isHighPriority(evt) {
			jb.events = append(jb.events[:i], jb.events[i+1:]...)
			return
		}
	}
}
