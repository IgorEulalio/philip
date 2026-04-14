package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// AgentConfig holds the Philip agent configuration.
type AgentConfig struct {
	// Sensor configuration
	Sensor SensorConfig `json:"sensor"`

	// Backend connection
	Backend BackendConfig `json:"backend"`

	// Runner detection
	Runner RunnerConfig `json:"runner"`

	// Socket for GitHub Action communication
	ActionSocketPath string `json:"action_socket_path"`

	// Logging
	LogLevel string `json:"log_level"`
}

// SensorConfig configures the event sensor.
type SensorConfig struct {
	// Type is the sensor backend: "tetragon" (MVP) or "native_ebpf" (Phase 2).
	Type string `json:"type"`

	// Tetragon-specific settings
	TetragonAddress string `json:"tetragon_address"`
}

// BackendConfig configures the connection to the Philip backend.
type BackendConfig struct {
	// Address is the gRPC address of the backend server.
	Address string `json:"address"`

	// TLS settings
	TLSEnabled bool   `json:"tls_enabled"`
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`
	TLSCA      string `json:"tls_ca"`

	// HeartbeatIntervalSeconds is how often the agent sends heartbeats.
	HeartbeatIntervalSeconds int `json:"heartbeat_interval_seconds"`
}

// RunnerConfig configures how the agent detects the CI/CD runner process.
type RunnerConfig struct {
	// ProcessName is the runner binary name to look for (default: "Runner.Worker").
	ProcessName string `json:"process_name"`

	// MaxEventsPerJob is the maximum events to buffer per job.
	MaxEventsPerJob int `json:"max_events_per_job"`
}

// DefaultConfig returns the default agent configuration.
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		Sensor: SensorConfig{
			Type:            "tetragon",
			TetragonAddress: "unix:///var/run/tetragon/tetragon.sock",
		},
		Backend: BackendConfig{
			Address:                  "localhost:9090",
			HeartbeatIntervalSeconds: 30,
		},
		Runner: RunnerConfig{
			ProcessName:     "Runner.Worker",
			MaxEventsPerJob: 100000,
		},
		ActionSocketPath: "/var/run/philip/action.sock",
		LogLevel:         "info",
	}
}

// LoadFromFile loads configuration from a JSON file.
func LoadFromFile(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}

// LoadFromEnv overrides configuration values from environment variables.
func (c *AgentConfig) LoadFromEnv() {
	if v := os.Getenv("PHILIP_SENSOR_TYPE"); v != "" {
		c.Sensor.Type = v
	}
	if v := os.Getenv("PHILIP_TETRAGON_ADDRESS"); v != "" {
		c.Sensor.TetragonAddress = v
	}
	if v := os.Getenv("PHILIP_BACKEND_ADDRESS"); v != "" {
		c.Backend.Address = v
	}
	if v := os.Getenv("PHILIP_RUNNER_PROCESS"); v != "" {
		c.Runner.ProcessName = v
	}
	if v := os.Getenv("PHILIP_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("PHILIP_ACTION_SOCKET"); v != "" {
		c.ActionSocketPath = v
	}
}
