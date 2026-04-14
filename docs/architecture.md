# Philip — Architecture Reference

Philip is a supply chain attack detector for self-hosted CI/CD runners. It uses eBPF (via Tetragon) to observe every process execution, network connection, and file access that occurs on the runner host, correlates that telemetry to specific workflow jobs and steps, and uses a combination of behavioral baselines, rule-based classifiers, and an LLM to determine whether the observed behavior represents a supply chain compromise.

This document is the authoritative technical reference for Philip's architecture. It is intended to give a new engineer a full, working mental model of the system.

---

## Table of Contents

1. System Architecture Overview
2. Communication Protocols
3. GitHub Actions Integration
4. Baseline Behavior Modeling
5. Detection and Deviation Scoring
6. AI Triage Pipeline
7. Alert Delivery

---

## 1. System Architecture Overview

### Component Diagram

```
  Self-Hosted Runner Host
  +---------------------------------------------------------------+
  |                                                               |
  |  GitHub Actions Runner Process (Runner.Worker)                |
  |  +----------------------------------------------------------+ |
  |  |  step 1: actions/checkout@v4                             | |
  |  |  step 2: npm install                                     | |
  |  |  step 3: npm run build                                   | |
  |  +----------------------------------------------------------+ |
  |         |                                                      |
  |         | (spawns child processes)                             |
  |         v                                                      |
  |   [kernel: eBPF hooks via Tetragon]                           |
  |         |                                                      |
  |         | gRPC / unix socket                                   |
  |         | unix:///var/run/tetragon/tetragon.sock               |
  |         v                                                      |
  |  +-------------------------+                                   |
  |  | philip-agent            |  <---- unix socket               |
  |  |                         |  /var/run/philip/action.sock      |
  |  |  TetragonConsumer       |        ^                          |
  |  |  ProcessTree            |        |                          |
  |  |  EventNormalizer        |        |  JSON messages           |
  |  |  StepCorrelator         |        | (job_start, step_start,  |
  |  |  JobBuffer              |        |  step_end, job_end)      |
  |  |  BackendClient          |        |                          |
  |  +-------------------------+        |                          |
  |         |                   philip-action (TypeScript)        |
  |         |                   (runs as a workflow step)         |
  +---------|-----------------------------------------------+-----+
            |
            | gRPC over TCP
            | SubmitJobEvents (batched, post-job)
            | RegisterAgent / Heartbeat
            v
  +---------------------------------------------------------------+
  |  philip-server (backend)                                      |
  |                                                               |
  |  gRPC API (:9090)     REST API (:8080)                       |
  |  IngestionHandler     /api/v1/baselines                      |
  |                       /api/v1/findings                       |
  |        |              /health                                 |
  |        v                                                      |
  |  BaselineEngine  -->  PostgreSQL (baselines, findings)        |
  |        |                                                      |
  |        v                                                      |
  |  DeviationScorer                                             |
  |        |                                                      |
  |        v                                                      |
  |  TriagePipeline                                               |
  |    L1Classifier (rules)                                       |
  |    L2Analyzer (LLM)  --> HTTPS --> api.openai.com            |
  |        |                                                      |
  |        v                                                      |
  |  AlertRouter                                                  |
  |    Slack integration  --> HTTPS --> hooks.slack.com           |
  |    Webhook integration --> HTTPS --> user-configured URL      |
  +---------------------------------------------------------------+
```

### Data Flow: eBPF Event to Alert Delivery

The end-to-end path of a single suspicious event follows these stages:

```
1. Kernel syscall (execve / connect / openat)
        |
        v
2. Tetragon eBPF probe fires, generates GetEventsResponse (protobuf)
        |
        v gRPC stream, unix socket
3. TetragonConsumer.translateEvent() -> sensor.Event{Type, PID, Binary, ...}
        |
        v buffered channel (size 10000)
4. EventNormalizer.handleEvent()
     - updates ProcessTree (every event)
     - detects Runner.Worker as root if not yet set
     - drops events NOT in runner's process tree
     - attaches Ancestry []ProcessNode
     - emits NormalizedEvent
        |
        v buffered channel (size 10000)
5. JobBuffer.addEvent()
     - stores sensor.Event in memory slice
     - enforces priority-based backpressure (network/exec > file/exit)
     - on job_end signal: calls flush()
        |
        v (after job ends)
6. BackendClient.SubmitJobRecord()
     - serializes JobEventRecord -> pb.JobEventRecord (protobuf)
     - sends via gRPC SubmitJobEvents RPC
        |
        v TCP
7. Backend IngestionHandler receives JobEventRecord
     - persists raw events to PostgreSQL
     - triggers async analysis callback
        |
        v
8. BaselineEngine.UpdateBaseline()
     - loads existing RepositoryBaseline from PostgreSQL
     - updates ProcessProfiles, NetworkProfiles with exponential decay
     - transitions "learning" -> "active" at threshold (default: 10 jobs)
        |
        v (only if baseline.Status == "active")
9. DeviationScorer.ScoreJob()
     - compares each event against baseline profiles
     - produces []ScoredDeviation with score 0.0-1.0
        |
        v (only if deviations exist)
10. TriagePipeline.Triage()
     - L1: rule-based classifier runs first (fast, free)
     - if all deviations match benign rules -> stop, no alert
     - if critical pattern matched -> escalate with high confidence
     - otherwise -> L2 LLM analysis via OpenAI API
        |
        v (only if verdict != benign AND confidence >= 0.6)
11. AlertRouter.Route()
     - deduplication check (30-minute window, key = repo+severity+deviation_types)
     - dispatch to all configured integrations in parallel
     - Slack webhook -> formatted blocks message
     - Generic webhook -> JSON payload
```

---

## 2. Communication Protocols

Philip uses four distinct communication channels. Each is described below with its transport, direction, and message schema.

### 2.1 Agent <-> Tetragon (gRPC over Unix Socket)

**Transport:** gRPC, insecure (no TLS), over a Unix domain socket.
**Default address:** `unix:///var/run/tetragon/tetragon.sock`
**Direction:** Agent reads from Tetragon (unidirectional stream).
**API:** Tetragon's `FineGuidanceSensors` gRPC service, `GetEvents` RPC.

The agent calls `GetEvents` with an empty `AllowList` (receives all events) and enters a blocking receive loop. Tetragon pushes `GetEventsResponse` messages, each containing a `oneof` event payload:

| Tetragon message type | Translated to sensor.Event |
|---|---|
| `GetEventsResponse_ProcessExec` | `EventTypeProcessExec` — PID, ParentPID, Binary, Args, CWD, UID, StartTime |
| `GetEventsResponse_ProcessExit` | `EventTypeProcessExit` — PID, ParentPID, Binary, ExitCode |
| `GetEventsResponse_ProcessKprobe` (tcp_connect / __sys_connect) | `EventTypeNetworkConnect` — PID, Binary, DestIP (from KprobeArgument.SockArg.Daddr), DestPort, Protocol |
| `GetEventsResponse_ProcessKprobe` (do_sys_openat2 / __x64_sys_openat) | `EventTypeFileAccess` — PID, Binary, FilePath (from KprobeArgument.StringArg), FileFlags, AccessType |

Kprobe function names recognized for network: `tcp_connect`, `__sys_connect`, `sys_connect`.
Kprobe function names recognized for file: `do_sys_openat2`, `__x64_sys_openat`, `sys_openat`.

File flags are interpreted as follows: `O_CREAT` (bit 64) -> "create", `O_RDWR` (bit 2) or `O_WRONLY` (bit 1) -> "write", default -> "read".

The agent's event channel has a buffer of 10,000 events. If the channel is full when a new event arrives, the event is silently dropped (backpressure, not blocking).

### 2.2 Agent <-> Backend (gRPC over TCP)

**Transport:** gRPC, insecure (TLS is a TODO), over TCP.
**Default backend address:** configurable via `PHILIP_GRPC_ADDRESS`, default `:9090`.
**Service:** `philip.v1.AgentService` (defined in `proto/philip/v1/agent.proto`).

The `AgentService` exposes four RPCs:

**RegisterAgent** — Called once at agent startup. Registers the agent with the backend and receives initial configuration.

```protobuf
message RegisterAgentRequest {
  string agent_id = 1;       // hostname of the runner
  string hostname = 2;
  string version = 3;        // agent binary version
  string sensor_type = 6;    // "tetragon"
  Timestamp started_at = 7;
}
message RegisterAgentResponse {
  bool accepted = 1;
  AgentConfig config = 3;    // backend can push config overrides
}
message AgentConfig {
  string runner_process_name = 1;
  int32 heartbeat_interval_seconds = 2;
  int32 max_events_per_job = 3;
  repeated EventType enabled_event_types = 4;
}
```

**Heartbeat** — Sent periodically (default interval configurable). Carries live agent metrics and receives updated configuration if needed.

```protobuf
message HeartbeatRequest {
  string agent_id = 1;
  AgentStatus status = 2;   // active_jobs, events_collected, events_shipped,
                             // cpu_usage_percent, memory_usage_bytes
}
message HeartbeatResponse {
  bool ok = 1;
  AgentConfig updated_config = 2;  // non-nil if backend wants to change behavior
}
```

**SubmitJobEvents** — The primary data-plane RPC. Called once per completed job, carrying the complete event record for that job. This is the main path for behavioral analysis.

```protobuf
message SubmitJobEventsRequest {
  JobEventRecord job_record = 1;
}
message JobEventRecord {
  string job_id = 1;
  JobMetadata metadata = 2;
  repeated Event events = 3;
  Timestamp start_time = 4;
  Timestamp end_time = 5;
  map<uint32, ProcessInfo> process_tree = 6;  // PID -> ProcessInfo adjacency map
}
message JobMetadata {
  string repository = 1;      // "owner/repo"
  string workflow_name = 2;
  string workflow_file = 3;   // ".github/workflows/ci.yml"
  string run_id = 4;
  string run_number = 5;
  string branch = 6;
  string commit_sha = 7;
  string trigger_event = 8;   // "push", "pull_request", "schedule"
  string runner_name = 9;
  string runner_os = 10;
}
message SubmitJobEventsResponse {
  bool accepted = 1;
  repeated DeviationSummary deviations = 3;
}
```

Each `Event` in the record carries the common process fields (id, type, timestamp, pid, parent_pid, binary_path, args, cwd, uid) plus a type-specific oneof sub-message:

```protobuf
message Event {
  string id = 1;
  EventType type = 2;
  Timestamp timestamp = 3;
  uint32 pid = 4;
  uint32 parent_pid = 5;
  string binary_path = 6;
  repeated string args = 7;
  string cwd = 8;
  uint32 uid = 9;

  ProcessExecEvent process_exec = 10;
  ProcessExitEvent process_exit = 11;
  NetworkConnectEvent network_connect = 12;
  FileAccessEvent file_access = 13;
}
message NetworkConnectEvent {
  string dest_ip = 1;
  uint32 dest_port = 2;
  string protocol = 3;
  string dest_hostname = 4;  // reverse DNS if available
}
message FileAccessEvent {
  string file_path = 1;
  uint32 flags = 2;
  string access_type = 3;
}
```

**StreamEvents** — A client-streaming RPC for long-running jobs that need real-time event delivery instead of waiting for job completion. Currently defined but not the primary path.

### 2.3 GitHub Action <-> Agent (Unix Socket, JSON)

**Transport:** Unix domain socket.
**Default path:** `/var/run/philip/action.sock`
**Direction:** The GitHub Action (TypeScript) writes to the socket; the agent reads and acknowledges.
**Protocol:** One JSON object per connection (one message per TCP-like connect/write/read/close cycle).

The message envelope is:

```json
{
  "type": "job_start" | "step_start" | "step_end" | "job_end",
  "data": { ... }
}
```

The agent's `StepCorrelator.handleConnection()` decodes one message per connection, processes it, and writes back `{"status":"ok"}` as acknowledgement. The action treats any non-OK or error response as a warning but never fails the workflow.

**Message types and their data payloads:**

`job_start` — Sent by `action/src/index.ts` as the very first step in the workflow. Contains all GitHub Actions environment metadata:

```json
{
  "type": "job_start",
  "data": {
    "job_id":        "7891234567-build",
    "repository":    "acme/payments-service",
    "workflow_name": "CI",
    "workflow_file": "refs/heads/main/.github/workflows/ci.yml",
    "run_id":        "7891234567",
    "run_number":    "42",
    "branch":        "main",
    "commit_sha":    "a3f9c2...",
    "trigger_event": "push",
    "runner_name":   "runner-prod-01",
    "runner_os":     "Linux"
  }
}
```

The `job_id` field is constructed as `GITHUB_RUN_ID + "-" + GITHUB_JOB`. This combination is unique per job execution.

`step_start` — Currently reserved in the protocol but not actively emitted by the action. The correlator tracks it when received:

```json
{
  "type": "step_start",
  "data": {
    "step_name":   "Install dependencies",
    "step_number": 2,
    "action_ref":  "actions/checkout@v4"
  }
}
```

`step_end` — Marks the end of a step. The correlator logs it but does not yet take additional action.

`job_end` — Sent by `action/src/post.ts` as the final cleanup step after all other steps have run. This is the signal to the agent's `JobBuffer` to flush buffered events and ship them to the backend.

```json
{
  "type": "job_end",
  "data": {
    "job_id": "7891234567-build",
    "status": "success"
  }
}
```

In `enforce` mode, the post-action also reads the agent's response to `job_end`. If the response contains `{"verdict":"critical"}`, the action calls `core.setFailed()` to fail the workflow. If `verdict` is `suspicious` with `confidence > 0.8`, it emits a warning annotation.

### 2.4 Backend <-> OpenAI (HTTPS REST)

**Transport:** HTTPS, POST to `https://api.openai.com/v1/chat/completions`.
**Default model:** `gpt-4o`.
**Authentication:** Bearer token from `OPENAI_API_KEY`.
**Timeout:** 30 seconds.

The request uses structured JSON output mode (`"response_format": {"type": "json_object"}`), temperature 0.1 (low, for consistency), and a fixed two-message conversation: a system prompt that establishes the Philip analyst persona and a user prompt containing the specific deviations to analyze.

The expected JSON response shape from OpenAI:

```json
{
  "verdict": "benign" | "suspicious" | "critical",
  "confidence": 0.0,
  "reasoning": "string",
  "mitre_mappings": ["T1195.001"],
  "severity": "low" | "medium" | "high" | "critical",
  "recommended_action": "string"
}
```

If the OpenAI call fails, the backend falls back to the L1 result or flags the job as `suspicious` with 0.5 confidence rather than silently dropping the finding.

### 2.5 Backend <-> Alert Integrations (HTTPS Webhooks)

Both integrations use `POST` with `Content-Type: application/json` and a 10-second timeout.

**Slack:** Posts to the configured Slack Incoming Webhook URL. The payload is a Slack Block Kit message with five blocks: a header block (severity + title), a section block (repository, job ID, verdict, confidence, MITRE techniques), a reasoning block, a deviations block (up to 5 deviations), and a recommended action block.

**Generic webhook:** Posts a structured JSON payload. See Section 7 for the full schema.

---

## 3. GitHub Actions Integration

### Overview

The Philip GitHub Action (`philip-ai/philip@v1`) is a composite JavaScript action placed as the first and last step in every workflow job you want to monitor. It acts as the bridge between GitHub Actions' metadata environment and the Philip agent running on the self-hosted runner host. Without it, the agent has no knowledge of which workflow job it is observing or what metadata (repository, branch, commit SHA) to attach to the event record.

### Action Lifecycle within a Workflow Job

```
Workflow job begins
        |
        v
[Step: philip-ai/philip@v1]  <- action/src/index.ts runs
    Collects GitHub env vars
    Sends job_start to agent unix socket
    Saves state to core.saveState()
        |
        v
[Step: actions/checkout@v4]
[Step: npm install]
[Step: npm run build]
[Step: npm test]
  ...all user-defined steps run...
        |
        v
[Post: philip-ai/philip@v1]  <- action/src/post.ts runs (always, even on failure)
    Reads saved state from core.getState()
    Sends job_end to agent unix socket
    In enforce mode: reads verdict from agent response
    Optionally calls core.setFailed() if verdict == "critical"
```

The pre/post split is handled by GitHub Actions' `post` lifecycle. The `index.ts` file runs at the beginning of the job, `post.ts` runs at the very end. This guarantees job_end is sent even if intermediate steps fail.

### GitHub Actions Environment Variables

The action collects the following environment variables at job_start time and sends them as `JobInfo` / `JobMetadata`:

| Environment Variable | JobInfo field | Description |
|---|---|---|
| `GITHUB_RUN_ID` (+ `GITHUB_JOB`) | `job_id` | Unique job execution identifier |
| `GITHUB_REPOSITORY` | `repository` | "owner/repo" format |
| `GITHUB_WORKFLOW` | `workflow_name` | Human-readable workflow name |
| `GITHUB_WORKFLOW_REF` | `workflow_file` | Full ref path to workflow YAML |
| `GITHUB_RUN_ID` | `run_id` | Numeric run identifier |
| `GITHUB_RUN_NUMBER` | `run_number` | Sequential run counter for the workflow |
| `GITHUB_REF_NAME` | `branch` | Branch or tag name |
| `GITHUB_SHA` | `commit_sha` | Commit hash that triggered the run |
| `GITHUB_EVENT_NAME` | `trigger_event` | "push", "pull_request", "schedule", etc. |
| `RUNNER_NAME` | `runner_name` | Name of the specific runner host |
| `RUNNER_OS` | `runner_os` | "Linux", "Windows", "macOS" |

All of these fields propagate through the entire system: from the `JobInfo` struct in the agent's `StepCorrelator`, into the `JobEventRecord`, across gRPC as `JobMetadata`, into PostgreSQL's findings table, and ultimately into alert messages.

### Runner Process Detection

The EventNormalizer is responsible for discovering which process on the host is the GitHub Actions runner. It does this automatically without pre-configuration by watching all incoming `ProcessExec` events for binaries matching known runner patterns.

The detection logic in `EventNormalizer.isRunnerProcess()` checks whether the event's `Binary` field ends with one of these suffixes:

- `Runner.Worker` — the main GitHub Actions worker process that executes job steps
- `Runner.Listener` — the listener process that polls for queued jobs
- Any custom name set via `cfg.Runner.ProcessName`

The suffix check (`containsSuffix`) handles full absolute paths gracefully. For example, `/home/runner/actions-runner/bin/Runner.Worker` matches the `Runner.Worker` pattern.

Once the runner PID is detected, it is set as the root of the `ProcessTree` via `SetRoot(pid)`. From that point forward, only events with a PID that is a descendant of that root will be passed through to the `JobBuffer`.

Note: detection is opportunistic. If the runner was already running before the Philip agent started, the agent will not see the runner's `ProcessExec` event and root detection will fail. To handle this, the agent can be configured with the runner process name, and a future enhancement would scan `/proc` on startup to find existing runner processes.

### Process Tree Construction

The `ProcessTree` maintains an in-memory adjacency map of all processes seen on the host. It has two roles:

1. **Ancestry tracking** — For every event emitted to the `JobBuffer`, the `EventNormalizer` calls `GetAncestry(pid)` to attach the full process chain (from the event's PID up to the runner root) as the `Ancestry` field of `NormalizedEvent`. This allows the backend to understand which parent process spawned a suspicious binary.

2. **Descendant filtering** — `IsDescendant(pid)` walks the parent chain from a given PID up toward the root. If it finds the root PID, the process belongs to the runner's job. If it reaches a node not in the map, or detects a cycle, it returns false. Events from unrelated processes on the host are dropped at this stage.

```
ProcessTree nodes map:
  PID 1000 (Runner.Worker)       <- root
    PID 1010 (bash)
      PID 1020 (node)            <- npm install
        PID 1030 (node)          <- package post-install script
          PID 1040 (sh)
            PID 1050 (curl)      <- suspicious network call
```

`IsDescendant(1050)` walks: 1050 -> parent 1040 -> parent 1030 -> parent 1020 -> parent 1010 -> parent 1000 == root -> returns true.

### Step Correlation

The `StepCorrelator` tracks which workflow step is currently executing by listening on the unix socket for `step_start` and `step_end` messages from the GitHub Action. It maintains a `steps []StepInfo` slice and a `currentStep int` index.

Each `StepInfo` contains:

```go
type StepInfo struct {
    StepName   string  // e.g. "Install dependencies"
    StepNumber int     // sequential within the job
    ActionRef  string  // e.g. "actions/checkout@v4" (optional)
}
```

The `CurrentStep()` method returns the name of the currently active step. This is used by the `JobBuffer` at flush time to annotate which step was running when each batch of events was observed.

The correlator also holds the `currentJob *JobInfo` which contains the full job metadata. This is the single source of truth for what job is running; the `JobBuffer` reads it during `flush()` to populate the `JobEventRecord.Metadata` field.

### JobBuffer Flush Mechanics

The `JobBuffer` accumulates `sensor.Event` values in a `[]sensor.Event` slice with a default maximum capacity of 100,000 events. When capacity is reached under backpressure, a priority-based eviction policy applies:

- **High priority (kept):** `EventTypeProcessExec`, `EventTypeNetworkConnect`
- **Low priority (dropped first):** `EventTypeFileAccess`, `EventTypeProcessExit`

The rationale is that process executions and network connections are the most security-relevant events. File access events are voluminous and can be dropped without losing the key signal of a supply chain attack.

`flush()` is called when either:
- A `job_end` message is received via the unix socket (normal path)
- The agent shuts down gracefully (ctx.Done())
- The event channel closes (sensor disconnected)

On flush, the buffer:
1. Reads the current `JobInfo` from `StepCorrelator.CurrentJob()`
2. Snapshots `ProcessTree.AllNodes()` into the record
3. Calls `onJobComplete(JobEventRecord)` in a goroutine (non-blocking)
4. Resets the internal slice to zero length (reuses backing array)

The `onJobComplete` callback is set at agent startup and calls `BackendClient.SubmitJobRecord()` with a 30-second timeout.

---

## 4. Baseline Behavior Modeling

### What a Baseline Represents

A `RepositoryBaseline` is a statistical model of what is "normal" for a given repository's CI/CD jobs. It is not a per-run snapshot — it is a continuously updated profile that aggregates behavior across many runs, using exponential decay to weight recent observations more heavily than old ones.

The baseline is keyed by `repository` (the "owner/repo" string from `GITHUB_REPOSITORY`). This means all jobs for a repository share a single baseline. Future enhancement: per-workflow or per-job-name granularity.

### Schema

```go
type RepositoryBaseline struct {
    Repository         string              `json:"repository"`
    TotalJobsObserved  int                 `json:"total_jobs_observed"`
    Status             string              `json:"status"` // "learning" or "active"
    LearningThreshold  int                 `json:"learning_threshold"` // default: 10
    FirstObserved      time.Time           `json:"first_observed"`
    LastUpdated        time.Time           `json:"last_updated"`
    ProcessProfiles    []ProcessProfile    `json:"process_profiles"`
    NetworkProfiles    []NetworkProfile    `json:"network_profiles"`
    FileAccessProfiles []FileAccessProfile `json:"file_access_profiles"`
}

type ProcessProfile struct {
    BinaryPath          string    `json:"binary_path"`
    TypicalArgsPatterns []string  `json:"typical_args_patterns"`
    TypicalParent       string    `json:"typical_parent"`
    Frequency           float64   `json:"frequency"`      // 0.0-1.0
    ObservedCount       int       `json:"observed_count"`
    TotalJobs           int       `json:"total_jobs"`
    FirstSeen           time.Time `json:"first_seen"`
    LastSeen            time.Time `json:"last_seen"`
}

type NetworkProfile struct {
    DestinationCIDRs []string  `json:"destination_cidrs"`
    TypicalPorts     []uint32  `json:"typical_ports"`
    Frequency        float64   `json:"frequency"`
    ObservedCount    int       `json:"observed_count"`
    TotalJobs        int       `json:"total_jobs"`
    FirstSeen        time.Time `json:"first_seen"`
    LastSeen         time.Time `json:"last_seen"`
}
```

The `Frequency` field is the central signal for detection. It is a value between 0.0 and 1.0 representing how often this binary or network destination appears across recent job runs.

### Learning Mode vs. Active Mode

Every new repository starts in `Status: "learning"`. During learning mode:
- Baselines are updated after every job.
- The `DeviationScorer` will not produce any deviations (`ScoreJob` returns nil when `bl.IsLearning()` is true).
- No alerts are generated.

Once `TotalJobsObserved >= LearningThreshold` (default: 10), the baseline transitions to `Status: "active"`. From that point, every new job is scored against the established baseline.

The threshold of 10 is the minimum viable sample size. In practice, running Philip in learning mode for 20-30 jobs before enabling active detection provides better baseline fidelity, especially for repositories with diverse workflow triggers (push, PR, schedule, manual).

### Exponential Decay Frequency

The `Frequency` field of each profile is not a simple ratio of (jobs_seen / total_jobs). It uses exponential decay, implemented in `exponentialDecayFrequency()`:

```go
const decayFactor = 0.95

func exponentialDecayFrequency(currentFreq float64, observedCount, totalJobs int) float64 {
    rawFreq := float64(observedCount) / float64(totalJobs)
    decayed := currentFreq*decayFactor + rawFreq*(1-decayFactor)
    return math.Min(1.0, math.Max(0.0, decayed))
}
```

This is an exponential moving average: 95% of the previous frequency value plus 5% of the raw ratio. The effect is that a binary seen in 50 consecutive jobs has a high frequency (~1.0), but if it disappears for 10 jobs, its frequency begins decaying toward its raw ratio. Conversely, a binary that only appears occasionally will have a low frequency even if it has been seen many times.

Decay is applied in two ways:
- **When a binary IS seen** in the new job: `observedCount++`, then `exponentialDecayFrequency(currentFreq, observedCount, totalJobs)`.
- **When a binary IS NOT seen** in the new job: `exponentialDecayFrequency(currentFreq, observedCount_unchanged, totalJobs)`. The raw ratio decreases (denominator grows, numerator stays fixed), so the frequency decays.

This means a binary that was seen in jobs 1-10 but not in jobs 11-20 will have its frequency decay from ~1.0 toward a lower value, making it increasingly suspicious if it reappears with unusual arguments in job 30.

### Concrete Example: "build, test, deploy" Workflow

Consider the repository `acme/payments-service` with a workflow that runs three jobs: `build`, `test`, and `deploy`.

**After 10 builds (end of learning mode), the baseline might look like:**

```json
{
  "repository": "acme/payments-service",
  "total_jobs_observed": 10,
  "status": "active",
  "learning_threshold": 10,
  "process_profiles": [
    {
      "binary_path": "/usr/local/bin/node",
      "typical_args_patterns": ["node_modules/.bin/webpack", "--mode", "production"],
      "frequency": 0.98,
      "observed_count": 10,
      "total_jobs": 10
    },
    {
      "binary_path": "/usr/local/bin/npm",
      "typical_args_patterns": ["install", "--frozen-lockfile"],
      "frequency": 0.98,
      "observed_count": 10,
      "total_jobs": 10
    },
    {
      "binary_path": "/usr/bin/git",
      "typical_args_patterns": ["checkout", "fetch", "clone"],
      "frequency": 0.98,
      "observed_count": 10,
      "total_jobs": 10
    },
    {
      "binary_path": "/usr/local/bin/jest",
      "typical_args_patterns": ["--ci", "--coverage"],
      "frequency": 0.65,
      "observed_count": 7,
      "total_jobs": 10
    },
    {
      "binary_path": "/usr/local/bin/docker",
      "typical_args_patterns": ["build", "-t", "acme/payments"],
      "frequency": 0.32,
      "observed_count": 3,
      "total_jobs": 10
    }
  ],
  "network_profiles": [
    {
      "destination_cidrs": ["104.16.0.0"],
      "typical_ports": [443],
      "frequency": 0.95,
      "observed_count": 10,
      "total_jobs": 10
    },
    {
      "destination_cidrs": ["185.199.108.0"],
      "typical_ports": [443],
      "frequency": 0.95,
      "observed_count": 10,
      "total_jobs": 10
    },
    {
      "destination_cidrs": ["151.101.0.0"],
      "typical_ports": [443],
      "frequency": 0.88,
      "observed_count": 9,
      "total_jobs": 10
    }
  ]
}
```

In this baseline: `104.16.0.0` is a Cloudflare CDN IP seen for `registry.npmjs.org`; `185.199.108.0` is `objects.githubusercontent.com` used by `actions/checkout`; `151.101.0.0` is Fastly used by `registry.yarnpkg.com`. The frequency of 0.98 vs. 0.65 for jest reflects that jest only runs in the test job, not in build-only runs.

**On job 11 (first active-mode run), if `curl` suddenly executes and connects to `198.51.100.42`:**

- `curl` has no `ProcessProfile` in the baseline. Its default score is `deviationWeights[DeviationNewProcess]` = 0.7. Because `curl` also appears in `isSuspiciousBinary()` is not listed (that list includes `wget` but not `curl` directly), the score stays at 0.7.
- `198.51.100.42:4444` has no `NetworkProfile`. Its score is `deviationWeights[DeviationNewNetwork]` = 1.0. Port 4444 is not a common port (not in `{80, 443, 22, 53}`), so the score gets boosted to 1.0.
- Both deviations go to the triage pipeline. L1 rules: `known_registry_connection` would match only if the port were 443 or 80; port 4444 does not match. No L1 rule clears these deviations. L2 is invoked. The LLM sees the full context and almost certainly returns `verdict: critical`.

### Cold Start and Future Community Baselines

When a repository first installs Philip, the system has zero behavioral history. The 10-job learning threshold means alerts are suppressed for the first 10 jobs. For critical security-sensitive repositories, this is a known gap.

A planned future enhancement is "community baselines": pre-built profiles for common build patterns (Node.js/npm, Python/pip, Java/Maven, Go modules, Docker builds). A repository could opt into a community baseline that immediately activates detection with reasonable defaults, accepting that false-positive rates may be slightly higher until the per-repository baseline matures.

### Incremental Baseline Updates

After every job — regardless of whether it is in learning or active mode — `BaselineEngine.UpdateBaseline()` is called. The update process is:

1. Load the existing `RepositoryBaseline` from PostgreSQL.
2. Increment `TotalJobsObserved`.
3. Call `updateProcessProfiles()`: iterate all `ProcessExec` events, deduplicate by binary path, update or create `ProcessProfile` entries with exponential decay, and decay all profiles for binaries NOT seen in this job.
4. Call `updateNetworkProfiles()`: same pattern for `NetworkConnect` events, keyed by destination IP.
5. Check if `TotalJobsObserved >= LearningThreshold` and transition to `active` if so.
6. Persist the updated baseline via `store.UpsertBaseline()`.

File access profiling (`updateFileAccessProfiles`) is stubbed and marked as a Phase 2 enhancement.

---

## 5. Detection and Deviation Scoring

### How Scoring Works

The `DeviationScorer` (`backend/detection/scorer.go`) takes a `RepositoryBaseline` and a `[]sensor.Event` and returns `[]ScoredDeviation`. It only runs when `baseline.IsActive()` is true.

For each event, the scorer looks for one of five deviation types:

| Deviation Type | Weight | Trigger Condition |
|---|---|---|
| `new_network` | 1.0 | Destination IP not in `NetworkProfiles` |
| `sensitive_path` | 0.9 | File path matches a known sensitive path pattern |
| `new_process` | 0.7 | Binary path not in `ProcessProfiles` |
| `anomalous_args` | 0.5 | (Future) Arguments differ significantly from baseline |
| `new_file` | 0.3 | File path not in `FileAccessProfiles` |

The weight is the base score. It can be boosted to 1.0 in specific circumstances:
- `new_network`: non-standard port (not in `{80, 443, 22, 53}`) -> score = 1.0
- `new_process`: binary matches `isSuspiciousBinary()` list -> score = 1.0

For processes with a known profile but very low frequency (`profile.Frequency < 0.05`), the scorer produces a scaled score: `deviationWeights[DeviationNewProcess] * (1 - profile.Frequency)`. This catches binaries that were seen once early in the project's history but are otherwise absent.

For network connections, if the IP is known but the port is new, the score is `deviationWeights[DeviationNewNetwork] * 0.6` = 0.6.

### Sensitive Path List

The following paths trigger `DeviationSensitivePath` (score 0.9) regardless of baseline status:

```
/etc/shadow
/etc/passwd
/.ssh/
/proc/self/environ
/.docker/config.json
/.npmrc
/.pypirc
/.aws/credentials
/.kube/config
/.gnupg/
/.netrc
```

The check is a substring match, so `/.aws/credentials/aws_access_key_id` matches the `/.aws/credentials` pattern.

### Suspicious Binary List

The following binaries, when seen for the first time (no profile), have their score boosted to 1.0:

```
nc, ncat, netcat, nmap, wget (when not in baseline), base64, xxd, python, python3, perl, ruby
```

Note: `python` and `python3` are only suspicious when they are not already in the baseline. A Python-heavy project will have these in its `ProcessProfiles` with high frequency and will not trigger this rule.

### Concrete Deviation Examples

**Example 1: New binary — cryptominer**

A compromised npm package spawns `xmrig` (a Monero miner binary):

```
Event: ProcessExec
  Binary: /tmp/.x/xmrig
  Args: ["--pool", "pool.supportxmr.com:3333", "--wallet", "..."]

Scoring:
  FindProcessProfile("/tmp/.x/xmrig") -> nil
  isSuspiciousBinary("xmrig") -> false (not in list)
  Score: 0.7 (DeviationNewProcess base weight)
  Description: "New binary never seen in baseline: /tmp/.x/xmrig (args: [--pool ...])"
```

**Example 2: New network destination — secret exfiltration**

A malicious package reads `GITHUB_TOKEN` from the environment and POSTs it to an attacker server:

```
Event: NetworkConnect
  Binary: /usr/bin/curl
  DestIP: 198.51.100.42
  DestPort: 443
  Protocol: tcp

Scoring:
  FindNetworkProfile("198.51.100.42") -> nil
  isCommonPort(443) -> true
  Score: 1.0 (base weight, common port does not downgrade to 1.0, but new IP gets full weight)
  Description: "Network connection to unknown destination: 198.51.100.42:443 (tcp) from /usr/bin/curl"
```

Wait — re-reading the scorer: for new IPs on common ports, the score is `deviationWeights[DeviationNewNetwork]` = 1.0 without the boost (the boost only applies to non-common ports). Common ports still get the full 1.0 weight because the scorer does not reduce the score for common ports; it only boosts to 1.0 for non-common ports. So any new IP gets a score of 1.0, which is correct — any unknown network destination during a build is high-priority.

**Example 3: Sensitive path access — credential read**

A malicious package reads the runner's AWS credentials:

```
Event: FileAccess
  Binary: /usr/bin/python3
  FilePath: /home/runner/.aws/credentials
  AccessType: read

Scoring:
  isSensitivePath("/home/runner/.aws/credentials") -> true (matches "/.aws/credentials")
  Score: 0.9 (DeviationSensitivePath weight)
  Description: "Access to sensitive path: /home/runner/.aws/credentials by /usr/bin/python3 (access: read)"
```

---

## 6. AI Triage Pipeline

### Overview

The triage pipeline reduces alert fatigue by filtering deviations through two stages before generating an alert:

```
[]ScoredDeviation
        |
        v
  L1Classifier.Classify()
        |
        +-- All benign? -> TriageResponse{Verdict: benign} -> STOP (no alert)
        |
        +-- Any critical pattern? -> TriageResponse{Verdict: critical} -> L2 enrichment
        |
        +-- Unclassified? -> L2 analysis needed
        |
        v (if L2 needed or critical pattern for enrichment)
  L2Analyzer.Analyze()
        |
        v
  TriageResult{L1Response, L2Response, Final}
        |
        v
  Final.Verdict != benign AND Final.Confidence >= 0.6?
        |
        +-- Yes -> AlertRouter.Route(alert)
        +-- No  -> STOP (log only)
```

### L1 Rule-Based Classifier

The `L1Classifier` runs first because it is synchronous, has zero cost, and can definitively classify a large fraction of deviations as benign. This is critical for avoiding unnecessary OpenAI API calls and reducing latency.

The default rule set (`defaultL1Rules()`) contains seven rules divided into benign and critical categories:

**Benign rules:**

| Rule Name | Verdict | Match Logic | Confidence |
|---|---|---|---|
| `known_package_manager` | Benign | Binary is one of: npm, yarn, pnpm, pip, pip3, poetry, cargo, go, maven, mvn, gradle, bundler, gem, composer, nuget, dotnet | 0.95 |
| `known_build_tool` | Benign | Binary is one of: make, cmake, gcc, g++, clang, ld, ar, as, rustc, javac, tsc, node, deno, bun | 0.95 |
| `known_registry_connection` | Benign | DeviationType is `new_network` AND DestPort is 443 or 80 | 0.70 |
| `git_operations` | Benign | Binary is `git` | 0.99 |

Note: `known_registry_connection` has confidence 0.70 because HTTPS connections to new IPs could still be exfiltration. This rule is intentionally conservative.

**Critical rules:**

| Rule Name | Verdict | Match Logic | Confidence |
|---|---|---|---|
| `reverse_shell_pattern` | Critical | Binary is nc/ncat with `-e` or `-c` args, OR any binary with `/dev/tcp` or `/dev/udp` in args | 0.95 |
| `credential_exfiltration` | Critical | DeviationType is `sensitive_path` AND FilePath contains `/etc/shadow`, `/.ssh/id_`, or `/.aws/credentials` | 0.90 |
| `environment_dump` | Critical | DeviationType is `sensitive_path` AND FilePath contains `/proc/self/environ` | 0.85 |

The `Classify()` method logic:
1. Iterate all deviations. For each, check all benign rules. If a benign rule matches, mark the deviation as classified.
2. If all deviations are classified as benign, return `TriageResponse{Verdict: benign, Confidence: 0.9}`.
3. Check unclassified deviations against critical rules. If any match, return `TriageResponse{Verdict: critical}` immediately.
4. If there are unclassified deviations with no critical rule match, return `nil` (meaning "L2 is needed").

### L2 LLM Analysis

The `L2Analyzer` wraps a `LLMProvider` interface:

```go
type LLMProvider interface {
    Analyze(req TriageRequest) (*TriageResponse, error)
    Name() string
}
```

This interface is the extension point for alternative LLM backends. The current implementation is `openai.Provider`, but a `claude.Provider`, `ollama.Provider` (local model), or `anthropic.Provider` could be plugged in without changing any triage or pipeline code.

**The prompt structure:**

The `buildPrompt()` function in `openai/provider.go` constructs the user message as a structured markdown document:

```
## Repository: acme/payments-service
## Job ID: 7891234567-build

## Baseline Status
- Total jobs observed: 25
- Known processes: 18
- Known network destinations: 7

## Deviations to Analyze

### Deviation 1 (score: 0.70, type: new_process)
- Description: New binary never seen in baseline: /tmp/.x/xmrig (args: [--pool ...])
- Binary: /tmp/.x/xmrig
- PID: 5432, Parent PID: 5100
- Args: [--pool, pool.supportxmr.com:3333, --wallet, ...]

### Deviation 2 (score: 1.00, type: new_network)
- Description: Network connection to unknown destination: 104.21.44.12:3333 (tcp) from /tmp/.x/xmrig
- Binary: /tmp/.x/xmrig
- Destination: 104.21.44.12:3333 (tcp)

Analyze these deviations and respond with a JSON object:
{
  "verdict": "benign" | "suspicious" | "critical",
  "confidence": 0.0-1.0,
  "reasoning": "detailed explanation",
  "mitre_mappings": ["T1496", ...],
  "severity": "low" | "medium" | "high" | "critical",
  "recommended_action": "what the security team should do"
}
```

The system prompt instructs the model to act as Philip, minimize false positives, and provides the canonical list of supply chain attack patterns to consider:
- Dependency confusion (T1195.001)
- Compromised dependencies (T1195.002)
- Secret exfiltration (T1552.001)
- Backdoor installation (T1543)
- Cryptomining (T1496)
- Code injection into build artifacts (T1195.002)

And the list of common benign deviation causes:
- Dependency version updates
- Build tool updates
- Cache misses
- New CI/CD workflow steps
- Infrastructure changes (registry mirrors, CDN changes)

**Pipeline fallback behavior:**

If the OpenAI call fails (network error, timeout, rate limit), the pipeline does not silently suppress the finding. Instead it produces a conservative `TriageResponse{Verdict: suspicious, Confidence: 0.5}` with a reasoning message indicating that L2 was unavailable. Since the alerting threshold requires `Confidence >= 0.6`, this fallback result does NOT trigger an alert, but it is stored in the findings database for manual review.

### Pipeline Flow Example

1. A job produces 3 deviations: `new_process: npm` (score 0.7), `new_network: 104.16.0.0:443` (score 1.0), `new_process: /tmp/xmrig` (score 0.7).
2. L1 runs:
   - `npm` matches `known_package_manager` -> classified benign.
   - `104.16.0.0:443` matches `known_registry_connection` (port 443) -> classified benign.
   - `/tmp/xmrig` matches no benign rule.
   - Unclassified: [/tmp/xmrig]. No critical rule matches (it doesn't match reverse_shell, credential, or environ patterns).
   - L1 returns `nil` (L2 needed).
3. L2 runs with only `/tmp/xmrig` in context. The LLM sees binary name `xmrig` in a temp path and pool mining args, returns `{verdict: critical, confidence: 0.97, mitre_mappings: ["T1496"], ...}`.
4. `Final.Verdict == critical`, `Confidence == 0.97 >= 0.6` -> alert fires.

---

## 7. Alert Delivery

### Deduplication

The `AlertRouter` deduplicates alerts using an in-memory `deduplicator` with a 30-minute sliding window. The deduplication key is:

```
"{repository}:{severity}:{deviation_types_concatenated}"
```

For example: `acme/payments-service:critical:new_process,new_network,`

If the same repository produces the same severity + deviation type combination within 30 minutes, the second alert is suppressed. The deduplicator runs a background cleanup goroutine every 5 minutes to evict expired keys.

This design prevents alert storms during active incidents (a compromised package may execute the same miner on every job for hours), but it does mean that a second attack with the same characteristics within the window will be silently skipped. The finding is still written to PostgreSQL regardless of deduplication.

### Slack Message Format

The Slack integration (`integrations.Slack`) builds a Block Kit message with six sections:

1. **Header block** (plain_text): severity badge + "Philip: Supply Chain Alert — CRITICAL"
2. **Section block** (mrkdwn): Repository, Job ID, Verdict with confidence percentage, MITRE ATT&CK techniques
3. **Reasoning block** (mrkdwn): The LLM's or L1's reasoning text
4. **Deviations block** (mrkdwn): Up to 5 deviations, formatted as:
   ```
   - `new_process` (score: 0.70): New binary never seen in baseline: /tmp/.x/xmrig
   - `new_network` (score: 1.00): Network connection to unknown destination: 104.21.44.12:3333
   ... and 1 more deviations
   ```
5. **Recommended action block** (mrkdwn): The LLM's recommended action string
6. **Context block**: "Philip Supply Chain Detector | 2026-04-13T12:34:56Z"

### Webhook Payload Schema

The generic webhook integration posts a JSON payload structured as:

```json
{
  "id":                 "f_1713009296000000000",
  "repository":         "acme/payments-service",
  "job_id":             "7891234567-build",
  "verdict":            "critical",
  "severity":           "critical",
  "confidence":         0.97,
  "reasoning":          "The binary xmrig located in /tmp/.x/ with Monero pool mining arguments...",
  "mitre_mappings":     ["T1496"],
  "recommended_action": "Immediately quarantine the runner, revoke all secrets, and inspect build artifacts.",
  "deviation_count":    2,
  "deviations": [
    {
      "type":        "new_process",
      "score":       0.70,
      "description": "New binary never seen in baseline: /tmp/.x/xmrig (args: [--pool ...])",
      "binary":      "/tmp/.x/xmrig"
    },
    {
      "type":        "new_network",
      "score":       1.00,
      "description": "Network connection to unknown destination: 104.21.44.12:3333 (tcp) from /tmp/.x/xmrig",
      "binary":      "/tmp/.x/xmrig"
    }
  ],
  "created_at": "2026-04-13T12:34:56Z"
}
```

The `User-Agent` header is set to `Philip/1.0`. Custom headers can be configured for authentication (e.g., `Authorization: Bearer token`).

### Finding Persistence

Before routing to alert integrations, the backend writes a `FindingRecord` to PostgreSQL:

```go
type FindingRecord struct {
    ID                string    // "f_{unix_nano}"
    Repository        string
    JobID             string
    Verdict           string
    Confidence        float64
    Severity          string
    MITREMappings     []string
    Reasoning         string
    RecommendedAction string
    Status            string    // "open", "resolved", "false_positive"
}
```

Findings are queryable via the REST API at `GET /api/v1/findings?repository=owner/repo&severity=critical&status=open`. The REST API returns up to 50 findings per query.

---

## Appendix: Key Configuration Reference

### Agent (`philip-agent`)

| Environment Variable | Default | Description |
|---|---|---|
| `PHILIP_BACKEND_ADDRESS` | `:9090` | Backend gRPC address |
| `PHILIP_ACTION_SOCKET` | `/var/run/philip/action.sock` | Unix socket for GitHub Action |
| `PHILIP_TETRAGON_ADDRESS` | `unix:///var/run/tetragon/tetragon.sock` | Tetragon gRPC address |
| `PHILIP_RUNNER_PROCESS` | `Runner.Worker` | Runner binary name to detect |
| `PHILIP_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |

### Backend (`philip-server`)

| Environment Variable | Default | Description |
|---|---|---|
| `PHILIP_GRPC_ADDRESS` | `:9090` | gRPC listen address |
| `PHILIP_REST_ADDRESS` | `:8080` | REST API listen address |
| `PHILIP_DB_HOST` | `localhost` | PostgreSQL host |
| `PHILIP_DB_USER` | `philip` | PostgreSQL user |
| `PHILIP_DB_PASSWORD` | `philip` | PostgreSQL password |
| `PHILIP_DB_NAME` | `philip` | PostgreSQL database name |
| `OPENAI_API_KEY` | — | OpenAI API key (L2 disabled if not set) |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model to use |
| `PHILIP_SLACK_WEBHOOK` | — | Slack Incoming Webhook URL |
| `PHILIP_WEBHOOK_URL` | — | Generic webhook URL |
| `PHILIP_LOG_LEVEL` | `info` | Log level |
