package collector

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"sync"
)

// StepInfo contains metadata about a workflow step, received from the GitHub Action.
type StepInfo struct {
	StepName   string `json:"step_name"`
	StepNumber int    `json:"step_number"`
	ActionRef  string `json:"action_ref,omitempty"` // e.g., "actions/checkout@v4"
}

// JobInfo contains metadata about the current CI/CD job, sent by the GitHub Action.
type JobInfo struct {
	JobID        string `json:"job_id"`
	Repository   string `json:"repository"`
	WorkflowName string `json:"workflow_name"`
	WorkflowFile string `json:"workflow_file"`
	RunID        string `json:"run_id"`
	RunNumber    string `json:"run_number"`
	Branch       string `json:"branch"`
	CommitSHA    string `json:"commit_sha"`
	TriggerEvent string `json:"trigger_event"`
	RunnerName   string `json:"runner_name"`
	RunnerOS     string `json:"runner_os"`
}

// StepCorrelator receives workflow metadata from the Philip GitHub Action
// via a unix socket and correlates events to workflow steps.
type StepCorrelator struct {
	mu          sync.RWMutex
	currentJob  *JobInfo
	steps       []StepInfo
	currentStep int
	socketPath  string
	onJobEnd    func()
	logger      *slog.Logger
}

// NewStepCorrelator creates a new step correlator.
func NewStepCorrelator(socketPath string, logger *slog.Logger) *StepCorrelator {
	return &StepCorrelator{
		socketPath: socketPath,
		logger:     logger,
	}
}

// SetOnJobEnd registers a callback that fires when a job_end message is received.
func (sc *StepCorrelator) SetOnJobEnd(fn func()) {
	sc.onJobEnd = fn
}

// SocketPath returns the unix socket path this correlator listens on.
func (sc *StepCorrelator) SocketPath() string {
	return sc.socketPath
}

// CurrentJob returns the current job info, if available.
func (sc *StepCorrelator) CurrentJob() *JobInfo {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.currentJob
}

// CurrentStep returns the current step name.
func (sc *StepCorrelator) CurrentStep() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.currentStep >= 0 && sc.currentStep < len(sc.steps) {
		return sc.steps[sc.currentStep].StepName
	}
	return ""
}

// ListenAndServe starts the unix socket server that receives metadata from the GitHub Action.
func (sc *StepCorrelator) ListenAndServe() error {
	// Remove stale socket file if it exists
	os.Remove(sc.socketPath)

	listener, err := net.Listen("unix", sc.socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	// Make socket world-writable so the runner (ec2-user) can connect
	if err := os.Chmod(sc.socketPath, 0777); err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go sc.handleConnection(conn)
	}
}

func (sc *StepCorrelator) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)

	var msg struct {
		Type string          `json:"type"` // "job_start", "step_start", "step_end", "job_end"
		Data json.RawMessage `json:"data"`
	}

	if err := decoder.Decode(&msg); err != nil {
		sc.logger.Error("failed to decode message from action", "error", err)
		return
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	switch msg.Type {
	case "job_start":
		var job JobInfo
		if err := json.Unmarshal(msg.Data, &job); err == nil {
			sc.currentJob = &job
			sc.steps = nil
			sc.currentStep = -1
			sc.logger.Info("job started", "job_id", job.JobID, "repo", job.Repository)
		}

	case "step_start":
		var step StepInfo
		if err := json.Unmarshal(msg.Data, &step); err == nil {
			sc.steps = append(sc.steps, step)
			sc.currentStep = len(sc.steps) - 1
			sc.logger.Info("step started", "step", step.StepName, "number", step.StepNumber)
		}

	case "step_end":
		sc.logger.Info("step ended", "step_number", sc.currentStep)

	case "job_end":
		sc.logger.Info("job ended", "job_id", sc.currentJob.JobID)
		if sc.onJobEnd != nil {
			go sc.onJobEnd()
		}

	default:
		sc.logger.Warn("unknown message type from action", "type", msg.Type)
	}

	// Send acknowledgement
	conn.Write([]byte(`{"status":"ok"}`))
}
