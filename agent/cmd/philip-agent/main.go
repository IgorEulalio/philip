package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IgorEulalio/philip/agent/collector"
	"github.com/IgorEulalio/philip/agent/config"
	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/agent/sensor/tetragon"
	"github.com/IgorEulalio/philip/agent/transport"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	// Load configuration
	cfg := config.DefaultConfig()
	if *configPath != "" {
		loaded, err := config.LoadFromFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
			os.Exit(1)
		}
		cfg = loaded
	}
	cfg.LoadFromEnv()

	// Setup logger
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	logger.Info("starting philip agent",
		"sensor", cfg.Sensor.Type,
		"backend", cfg.Backend.Address)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := run(ctx, cfg, logger); err != nil && ctx.Err() == nil {
		logger.Error("agent failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.AgentConfig, logger *slog.Logger) error {
	// Initialize sensor
	var s sensor.Sensor
	switch cfg.Sensor.Type {
	case "tetragon":
		s = tetragon.New(tetragon.Config{
			ServerAddress: cfg.Sensor.TetragonAddress,
		})
	default:
		return fmt.Errorf("unsupported sensor type: %s", cfg.Sensor.Type)
	}

	// Initialize process tree, step correlator, and event normalizer
	tree := collector.NewProcessTree()
	correlator := collector.NewStepCorrelator(cfg.ActionSocketPath, logger)
	normalizer := collector.NewEventNormalizer(tree, correlator, cfg.Runner.ProcessName, logger)

	// Initialize backend client
	backendClient, err := transport.NewBackendClient(
		cfg.Backend.Address,
		hostname(),
		logger,
	)
	if err != nil {
		return fmt.Errorf("creating backend client: %w", err)
	}
	defer backendClient.Close()

	// Register with backend
	if err := backendClient.Register(ctx, hostname(), "dev", s.Name()); err != nil {
		logger.Warn("failed to register with backend (will retry)", "error", err)
	}

	// Initialize job buffer
	jobBuffer := collector.NewJobBuffer(
		correlator,
		tree,
		cfg.Runner.MaxEventsPerJob,
		func(record collector.JobEventRecord) {
			submitCtx, submitCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer submitCancel()
			if err := backendClient.SubmitJobRecord(submitCtx, record); err != nil {
				logger.Error("failed to submit job record", "error", err, "job_id", record.JobID)
			}
		},
		logger,
	)

	// Wire job_end signal from correlator to flush the job buffer
	correlator.SetOnJobEnd(func() {
		logger.Info("job_end received, flushing job buffer")
		jobBuffer.FlushIfJobEnded()
	})

	// Start components
	errCh := make(chan error, 4)

	// Start sensor
	go func() {
		logger.Info("starting sensor", "type", s.Name())
		errCh <- s.Start(ctx)
	}()

	// Start event normalizer
	go func() {
		errCh <- normalizer.Run(ctx, s.Events())
	}()

	// Start job buffer
	go func() {
		errCh <- jobBuffer.Run(ctx, normalizer.Output())
	}()

	// Start step correlator (unix socket server)
	go func() {
		logger.Info("starting step correlator", "socket", cfg.ActionSocketPath)
		errCh <- correlator.ListenAndServe()
	}()

	// Start heartbeat
	go backendClient.RunHeartbeat(ctx, time.Duration(cfg.Backend.HeartbeatIntervalSeconds)*time.Second)

	// Wait for first error or context cancellation
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return err
		}
	case <-ctx.Done():
	}

	// Graceful shutdown
	logger.Info("shutting down agent")
	if err := s.Stop(); err != nil {
		logger.Error("error stopping sensor", "error", err)
	}

	return nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
