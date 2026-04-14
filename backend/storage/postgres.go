package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Store provides persistence for Philip's backend data.
type Store struct {
	db *sql.DB
}

// Config holds database connection settings.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// New creates a new Store connected to PostgreSQL.
func New(cfg Config) (*Store, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying sql.DB for use by other packages.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Migrate runs database migrations.
func (s *Store) Migrate(ctx context.Context) error {
	migrations := []string{
		migrationCreateAgents,
		migrationCreateJobRecords,
		migrationCreateEvents,
		migrationCreateBaselines,
		migrationCreateFindings,
	}

	for i, m := range migrations {
		if _, err := s.db.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("running migration %d: %w", i, err)
		}
	}

	return nil
}

const migrationCreateAgents = `
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    version TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'online',
    last_heartbeat TIMESTAMPTZ,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_events_collected BIGINT NOT NULL DEFAULT 0,
    total_jobs_processed BIGINT NOT NULL DEFAULT 0
);`

const migrationCreateJobRecords = `
CREATE TABLE IF NOT EXISTS job_records (
    job_id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    workflow_name TEXT NOT NULL,
    workflow_file TEXT,
    run_id TEXT,
    run_number TEXT,
    branch TEXT,
    commit_sha TEXT,
    trigger_event TEXT,
    runner_name TEXT,
    event_count INT NOT NULL DEFAULT 0,
    deviation_count INT NOT NULL DEFAULT 0,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    process_tree JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_job_records_repository ON job_records(repository);
CREATE INDEX IF NOT EXISTS idx_job_records_start_time ON job_records(start_time);`

const migrationCreateEvents = `
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES job_records(job_id),
    type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    pid INT NOT NULL,
    parent_pid INT NOT NULL,
    binary_path TEXT,
    args TEXT[],
    cwd TEXT,
    uid INT,
    -- Network fields
    dest_ip TEXT,
    dest_port INT,
    protocol TEXT,
    -- File fields
    file_path TEXT,
    file_flags INT,
    access_type TEXT,
    -- Exit fields
    exit_code INT,
    duration_ms BIGINT
);

CREATE INDEX IF NOT EXISTS idx_events_job_id ON events(job_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);`

const migrationCreateBaselines = `
CREATE TABLE IF NOT EXISTS baselines (
    repository TEXT PRIMARY KEY,
    total_jobs_observed INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'learning',
    first_observed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    process_profiles JSONB NOT NULL DEFAULT '[]',
    network_profiles JSONB NOT NULL DEFAULT '[]',
    file_access_profiles JSONB NOT NULL DEFAULT '[]'
);`

const migrationCreateFindings = `
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES job_records(job_id),
    deviations JSONB NOT NULL,
    l1_result JSONB,
    l2_result JSONB,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    mitre_mappings TEXT[],
    reasoning TEXT,
    recommended_action TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_repository ON findings(repository);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);`

// --- Agent operations ---

// UpsertAgent inserts or updates an agent record.
func (s *Store) UpsertAgent(ctx context.Context, agentID, hostname, version, sensorType string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (agent_id, hostname, version, sensor_type, last_heartbeat)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			version = EXCLUDED.version,
			sensor_type = EXCLUDED.sensor_type,
			last_heartbeat = NOW(),
			status = 'online'
	`, agentID, hostname, version, sensorType)
	return err
}

// UpdateAgentHeartbeat updates the last heartbeat time for an agent.
func (s *Store) UpdateAgentHeartbeat(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_heartbeat = NOW(), status = 'online' WHERE agent_id = $1`,
		agentID,
	)
	return err
}

// --- Job record operations ---

// InsertJobRecord stores a complete job event record.
func (s *Store) InsertJobRecord(ctx context.Context, jobID, repository, workflowName, workflowFile,
	runID, runNumber, branch, commitSHA, triggerEvent, runnerName string,
	eventCount int, startTime, endTime time.Time, processTree map[string]interface{}) error {

	treeJSON, _ := json.Marshal(processTree)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO job_records (job_id, repository, workflow_name, workflow_file,
			run_id, run_number, branch, commit_sha, trigger_event, runner_name,
			event_count, start_time, end_time, process_tree)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (job_id) DO NOTHING
	`, jobID, repository, workflowName, workflowFile,
		runID, runNumber, branch, commitSHA, triggerEvent, runnerName,
		eventCount, startTime, endTime, treeJSON)
	return err
}

// InsertEvent stores a single event.
func (s *Store) InsertEvent(ctx context.Context, id, jobID, eventType string, timestamp time.Time,
	pid, parentPID int, binaryPath string, args []string, cwd string, uid int,
	destIP string, destPort int, protocol string,
	filePath string, fileFlags int, accessType string,
	exitCode int, durationMs int64) error {

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events (id, job_id, type, timestamp, pid, parent_pid, binary_path, args, cwd, uid,
			dest_ip, dest_port, protocol, file_path, file_flags, access_type, exit_code, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT (id) DO NOTHING
	`, id, jobID, eventType, timestamp, pid, parentPID, binaryPath, args, cwd, uid,
		destIP, destPort, protocol, filePath, fileFlags, accessType, exitCode, durationMs)
	return err
}

// --- Baseline operations ---

// GetBaseline retrieves the baseline for a repository.
func (s *Store) GetBaseline(ctx context.Context, repository string) (*BaselineRecord, error) {
	var b BaselineRecord
	var processJSON, networkJSON, fileJSON []byte

	err := s.db.QueryRowContext(ctx, `
		SELECT repository, total_jobs_observed, status, first_observed, last_updated,
			process_profiles, network_profiles, file_access_profiles
		FROM baselines WHERE repository = $1
	`, repository).Scan(
		&b.Repository, &b.TotalJobsObserved, &b.Status, &b.FirstObserved, &b.LastUpdated,
		&processJSON, &networkJSON, &fileJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal(processJSON, &b.ProcessProfiles)
	json.Unmarshal(networkJSON, &b.NetworkProfiles)
	json.Unmarshal(fileJSON, &b.FileAccessProfiles)

	return &b, nil
}

// UpsertBaseline creates or updates a baseline.
func (s *Store) UpsertBaseline(ctx context.Context, b *BaselineRecord) error {
	processJSON, _ := json.Marshal(b.ProcessProfiles)
	networkJSON, _ := json.Marshal(b.NetworkProfiles)
	fileJSON, _ := json.Marshal(b.FileAccessProfiles)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO baselines (repository, total_jobs_observed, status, first_observed, last_updated,
			process_profiles, network_profiles, file_access_profiles)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (repository) DO UPDATE SET
			total_jobs_observed = EXCLUDED.total_jobs_observed,
			status = EXCLUDED.status,
			last_updated = EXCLUDED.last_updated,
			process_profiles = EXCLUDED.process_profiles,
			network_profiles = EXCLUDED.network_profiles,
			file_access_profiles = EXCLUDED.file_access_profiles
	`, b.Repository, b.TotalJobsObserved, b.Status, b.FirstObserved, b.LastUpdated,
		processJSON, networkJSON, fileJSON)
	return err
}

// --- Finding operations ---

// InsertFinding stores a new finding.
func (s *Store) InsertFinding(ctx context.Context, f *FindingRecord) error {
	deviationsJSON, _ := json.Marshal(f.Deviations)
	l1JSON, _ := json.Marshal(f.L1Result)
	l2JSON, _ := json.Marshal(f.L2Result)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO findings (id, repository, job_id, deviations, l1_result, l2_result,
			verdict, confidence, severity, mitre_mappings, reasoning, recommended_action, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, f.ID, f.Repository, f.JobID, deviationsJSON, l1JSON, l2JSON,
		f.Verdict, f.Confidence, f.Severity, f.MITREMappings, f.Reasoning, f.RecommendedAction, f.Status)
	return err
}

// ListFindings returns findings matching the given filters.
func (s *Store) ListFindings(ctx context.Context, repository, severity, status string, limit int) ([]FindingRecord, error) {
	query := `SELECT id, repository, job_id, deviations, l1_result, l2_result,
		verdict, confidence, severity, mitre_mappings, reasoning, recommended_action, status, created_at
		FROM findings WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if repository != "" {
		query += fmt.Sprintf(" AND repository = $%d", argIdx)
		args = append(args, repository)
		argIdx++
	}
	if severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, severity)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []FindingRecord
	for rows.Next() {
		var f FindingRecord
		var devJSON, l1JSON, l2JSON []byte
		err := rows.Scan(&f.ID, &f.Repository, &f.JobID, &devJSON, &l1JSON, &l2JSON,
			&f.Verdict, &f.Confidence, &f.Severity, &f.MITREMappings, &f.Reasoning,
			&f.RecommendedAction, &f.Status, &f.CreatedAt)
		if err != nil {
			return nil, err
		}
		json.Unmarshal(devJSON, &f.Deviations)
		json.Unmarshal(l1JSON, &f.L1Result)
		json.Unmarshal(l2JSON, &f.L2Result)
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// --- Record types ---

// BaselineRecord is the database representation of a repository baseline.
type BaselineRecord struct {
	Repository         string                `json:"repository"`
	TotalJobsObserved  int                   `json:"total_jobs_observed"`
	Status             string                `json:"status"` // "learning", "active"
	FirstObserved      time.Time             `json:"first_observed"`
	LastUpdated        time.Time             `json:"last_updated"`
	ProcessProfiles    []ProcessProfileDB    `json:"process_profiles"`
	NetworkProfiles    []NetworkProfileDB    `json:"network_profiles"`
	FileAccessProfiles []FileAccessProfileDB `json:"file_access_profiles"`
}

// ProcessProfileDB is a process profile stored in the database.
type ProcessProfileDB struct {
	BinaryPath          string    `json:"binary_path"`
	TypicalArgsPatterns []string  `json:"typical_args_patterns"`
	TypicalParent       string    `json:"typical_parent"`
	Frequency           float64   `json:"frequency"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// NetworkProfileDB is a network profile stored in the database.
type NetworkProfileDB struct {
	DestinationCIDRs []string  `json:"destination_cidrs"`
	TypicalPorts     []uint32  `json:"typical_ports"`
	Frequency        float64   `json:"frequency"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// FileAccessProfileDB is a file access profile stored in the database.
type FileAccessProfileDB struct {
	PathPatterns          []string  `json:"path_patterns"`
	SensitivePathsAccessed []string `json:"sensitive_paths_accessed"`
	Frequency             float64   `json:"frequency"`
	FirstSeen             time.Time `json:"first_seen"`
	LastSeen              time.Time `json:"last_seen"`
}

// FindingRecord is the database representation of a finding.
type FindingRecord struct {
	ID                string                 `json:"id"`
	Repository        string                 `json:"repository"`
	JobID             string                 `json:"job_id"`
	Deviations        []map[string]interface{} `json:"deviations"`
	L1Result          map[string]interface{} `json:"l1_result"`
	L2Result          map[string]interface{} `json:"l2_result"`
	Verdict           string                 `json:"verdict"`
	Confidence        float64                `json:"confidence"`
	Severity          string                 `json:"severity"`
	MITREMappings     []string               `json:"mitre_mappings"`
	Reasoning         string                 `json:"reasoning"`
	RecommendedAction string                 `json:"recommended_action"`
	Status            string                 `json:"status"`
	CreatedAt         time.Time              `json:"created_at"`
}
