package sensor

import (
	"context"
	"net"
	"time"
)

// EventType enumerates the kinds of events Philip tracks.
type EventType int

const (
	EventTypeProcessExec EventType = iota + 1
	EventTypeProcessExit
	EventTypeNetworkConnect
	EventTypeFileAccess
)

func (t EventType) String() string {
	switch t {
	case EventTypeProcessExec:
		return "process_exec"
	case EventTypeProcessExit:
		return "process_exit"
	case EventTypeNetworkConnect:
		return "network_connect"
	case EventTypeFileAccess:
		return "file_access"
	default:
		return "unknown"
	}
}

// Event represents a single observable action during a CI/CD job.
type Event struct {
	ID        string
	Timestamp time.Time
	Type      EventType

	// Process context (always present)
	PID       uint32
	ParentPID uint32
	Binary    string
	Args      []string
	CWD       string
	UID       uint32

	// Network fields (for NetworkConnect)
	DestIP   net.IP
	DestPort uint16
	Protocol string // "tcp", "udp"

	// File fields (for FileAccess)
	FilePath   string
	FileFlags  uint32
	AccessType string // "read", "write", "create", "delete"

	// Exit fields (for ProcessExit)
	ExitCode   int32
	DurationMs int64

	// Step context — populated by EventNormalizer from StepCorrelator
	StepName   string
	StepNumber int

	// Process lineage — populated by EventNormalizer from ProcessTree
	ParentBinary string
}

// Sensor is the abstraction layer for different event sources.
// Tetragon consumer implements this interface for MVP.
// Native eBPF sensor will implement it in Phase 2.
type Sensor interface {
	// Start begins collecting events. Blocks until ctx is cancelled or an error occurs.
	Start(ctx context.Context) error

	// Events returns a channel of events. Must be called after Start.
	Events() <-chan Event

	// Stop gracefully shuts down the sensor.
	Stop() error

	// Name returns the sensor implementation name (e.g., "tetragon", "native_ebpf").
	Name() string
}
