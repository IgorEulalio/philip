package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IgorEulalio/philip/agent/sensor"
	"github.com/IgorEulalio/philip/backend/alerting"
	"github.com/IgorEulalio/philip/backend/alerting/integrations"
	grpcserver "github.com/IgorEulalio/philip/backend/api/grpc"
	"github.com/IgorEulalio/philip/backend/baseline"
	"github.com/IgorEulalio/philip/backend/detection"
	"github.com/IgorEulalio/philip/backend/ingestion"
	"github.com/IgorEulalio/philip/backend/metrics"
	"github.com/IgorEulalio/philip/backend/storage"
	"github.com/IgorEulalio/philip/backend/triage"
	"github.com/IgorEulalio/philip/backend/triage/openai"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServerConfig holds backend server configuration.
type ServerConfig struct {
	// gRPC address for agent communication
	GRPCAddress string `json:"grpc_address"`
	// REST address for CLI/dashboard
	RESTAddress string `json:"rest_address"`

	// Database
	DB storage.Config `json:"db"`

	// OpenAI
	OpenAIAPIKey string `json:"openai_api_key"`
	OpenAIModel  string `json:"openai_model"`

	// Alerting
	SlackWebhookURL string `json:"slack_webhook_url"`
	WebhookURL      string `json:"webhook_url"`

	// Logging
	LogLevel string `json:"log_level"`
}

func defaultServerConfig() *ServerConfig {
	return &ServerConfig{
		GRPCAddress: ":9090",
		RESTAddress: ":8080",
		DB: storage.Config{
			Host:     "localhost",
			Port:     5432,
			User:     "philip",
			Password: "philip",
			DBName:   "philip",
			SSLMode:  "disable",
		},
		OpenAIModel: "gpt-4o",
		LogLevel:    "info",
	}
}

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	cfg := defaultServerConfig()
	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read config: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse config: %v\n", err)
			os.Exit(1)
		}
	}
	loadEnvConfig(cfg)

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

	logger.Info("starting philip server",
		"grpc", cfg.GRPCAddress,
		"rest", cfg.RESTAddress)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := run(ctx, cfg, logger); err != nil && ctx.Err() == nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *ServerConfig, logger *slog.Logger) error {
	// Initialize storage
	store, err := storage.New(cfg.DB)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	logger.Info("database migrations complete")

	// Register Prometheus metrics
	metrics.Register()

	// Initialize components
	baselineEngine := baseline.NewEngine(store, logger)
	scorer := detection.NewScorer(logger)

	// Initialize triage pipeline
	l1 := triage.NewL1Classifier(logger)

	var llmProvider triage.LLMProvider
	if cfg.OpenAIAPIKey != "" {
		llmProvider = openai.New(openai.Config{
			APIKey: cfg.OpenAIAPIKey,
			Model:  cfg.OpenAIModel,
		})
		logger.Info("L2 triage enabled", "provider", "openai", "model", cfg.OpenAIModel)
	} else {
		logger.Warn("OPENAI_API_KEY not set — L2 triage disabled, only L1 rules active")
	}

	// Initialize alert router
	var alertIntegrations []alerting.Integration
	if cfg.SlackWebhookURL != "" {
		alertIntegrations = append(alertIntegrations, integrations.NewSlack(cfg.SlackWebhookURL))
		logger.Info("slack alerting enabled")
	}
	if cfg.WebhookURL != "" {
		alertIntegrations = append(alertIntegrations, integrations.NewWebhook(cfg.WebhookURL, nil))
		logger.Info("webhook alerting enabled")
	}
	alertRouter := alerting.NewRouter(alertIntegrations, logger)

	// Job analysis callback — triggered when a new job record is ingested
	analyzeJob := func(jobID string, repository string) {
		analyzeCtx, analyzeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer analyzeCancel()

		// Get events for this job from storage
		// In a production system, this would use a proper query
		events := []sensor.Event{} // Placeholder — events come from the ingestion handler

		// Update baseline
		bl, err := baselineEngine.UpdateBaseline(analyzeCtx, repository, events)
		if err != nil {
			logger.Error("failed to update baseline", "error", err, "repository", repository)
			return
		}

		// Update baseline metrics
		metrics.BaselineStatus.WithLabelValues(repository, "learning").Set(0)
		metrics.BaselineStatus.WithLabelValues(repository, "active").Set(0)
		metrics.BaselineStatus.WithLabelValues(repository, bl.Status).Set(1)
		metrics.BaselineJobsObserved.WithLabelValues(repository).Set(float64(bl.TotalJobsObserved))
		metrics.BaselineProcessProfiles.WithLabelValues(repository).Set(float64(len(bl.ProcessProfiles)))
		metrics.BaselineNetworkProfiles.WithLabelValues(repository).Set(float64(len(bl.NetworkProfiles)))

		// Score deviations
		deviations := scorer.ScoreJob(bl, events)
		if len(deviations) == 0 {
			metrics.JobsAnalyzed.WithLabelValues(repository, "clean").Inc()
			return
		}

		// Record deviation metrics
		for _, dev := range deviations {
			metrics.DeviationsTotal.WithLabelValues(repository, string(dev.DeviationType)).Inc()
			metrics.DeviationScore.WithLabelValues(repository, string(dev.DeviationType)).Observe(dev.Score)
		}

		logger.Info("deviations detected",
			"repository", repository,
			"count", len(deviations))

		// Run triage
		triageReq := triage.TriageRequest{
			Deviations: deviations,
			Baseline:   bl,
			Repository: repository,
			JobID:      jobID,
		}

		// L1 classification
		l1Result := l1.Classify(triageReq)
		if l1Result != nil {
			metrics.TriageVerdicts.WithLabelValues(repository, "l1", string(l1Result.Verdict)).Inc()
		}
		if l1Result != nil && l1Result.Verdict == triage.VerdictBenign {
			logger.Info("L1 classified all deviations as benign", "repository", repository)
			metrics.JobsAnalyzed.WithLabelValues(repository, "benign").Inc()
			return
		}

		// L2 analysis (if provider configured)
		var finalResult *triage.TriageResponse
		if llmProvider != nil {
			l2 := triage.NewL2Analyzer(llmProvider, logger)
			pipeline := triage.NewPipeline(l1, l2, logger)
			result, err := pipeline.Triage(triageReq)
			if err != nil {
				logger.Error("triage pipeline failed", "error", err)
				return
			}
			finalResult = result.Final
			metrics.TriageVerdicts.WithLabelValues(repository, "l2", string(finalResult.Verdict)).Inc()
		} else if l1Result != nil {
			finalResult = l1Result
		} else {
			// No L2 and L1 couldn't classify — flag as suspicious
			finalResult = &triage.TriageResponse{
				Verdict:    triage.VerdictSuspicious,
				Confidence: 0.5,
				Severity:   "medium",
				Reasoning:  "Unclassified deviations detected, L2 analysis unavailable",
			}
		}

		// Only alert on suspicious or critical with sufficient confidence
		if finalResult.Verdict == triage.VerdictBenign {
			metrics.JobsAnalyzed.WithLabelValues(repository, "benign").Inc()
			return
		}
		if finalResult.Confidence < 0.6 {
			logger.Info("low confidence finding, not alerting",
				"verdict", finalResult.Verdict,
				"confidence", finalResult.Confidence)
			metrics.JobsAnalyzed.WithLabelValues(repository, "low_confidence").Inc()
			return
		}

		// Store finding
		finding := &storage.FindingRecord{
			ID:                fmt.Sprintf("f_%d", time.Now().UnixNano()),
			Repository:        repository,
			JobID:             jobID,
			Verdict:           string(finalResult.Verdict),
			Confidence:        finalResult.Confidence,
			Severity:          finalResult.Severity,
			MITREMappings:     finalResult.MITREMappings,
			Reasoning:         finalResult.Reasoning,
			RecommendedAction: finalResult.RecommendedAction,
			Status:            "open",
		}
		if err := store.InsertFinding(analyzeCtx, finding); err != nil {
			logger.Error("failed to store finding", "error", err)
		}
		metrics.FindingsTotal.WithLabelValues(repository, string(finalResult.Verdict), finalResult.Severity).Inc()

		// Route alert
		alert := alerting.Alert{
			ID:                finding.ID,
			Repository:        repository,
			JobID:             jobID,
			Verdict:           finalResult.Verdict,
			Severity:          finalResult.Severity,
			Confidence:        finalResult.Confidence,
			Reasoning:         finalResult.Reasoning,
			MITREMappings:     finalResult.MITREMappings,
			RecommendedAction: finalResult.RecommendedAction,
			Deviations:        deviations,
			CreatedAt:         time.Now(),
		}
		if err := alertRouter.Route(alert); err != nil {
			logger.Error("failed to route alert", "error", err)
		}
		metrics.JobsAnalyzed.WithLabelValues(repository, string(finalResult.Verdict)).Inc()
	}

	// Initialize ingestion handler
	ingester := ingestion.NewHandler(store, analyzeJob, logger)

	// Start gRPC server
	grpcSrv := grpcserver.NewServer(store, ingester, logger)
	errCh := make(chan error, 2)

	go func() {
		errCh <- grpcSrv.Serve(cfg.GRPCAddress)
	}()

	// Start REST API server
	restMux := http.NewServeMux()
	restMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	restMux.HandleFunc("/api/v1/baselines", func(w http.ResponseWriter, r *http.Request) {
		repo := r.URL.Query().Get("repository")
		if repo == "" {
			http.Error(w, "repository parameter required", http.StatusBadRequest)
			return
		}
		bl, err := baselineEngine.GetBaseline(r.Context(), repo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if bl == nil {
			http.Error(w, "baseline not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bl)
	})
	restMux.HandleFunc("/api/v1/findings", func(w http.ResponseWriter, r *http.Request) {
		repo := r.URL.Query().Get("repository")
		severity := r.URL.Query().Get("severity")
		status := r.URL.Query().Get("status")
		findings, err := store.ListFindings(r.Context(), repo, severity, status, 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(findings)
	})

	restMux.Handle("/metrics", promhttp.Handler())

	httpSrv := &http.Server{Addr: cfg.RESTAddress, Handler: restMux}
	go func() {
		logger.Info("REST API server listening", "address", cfg.RESTAddress)
		errCh <- httpSrv.ListenAndServe()
	}()

	// Wait for shutdown
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return err
		}
	case <-ctx.Done():
	}

	// Graceful shutdown
	logger.Info("shutting down server")
	grpcSrv.Stop()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	httpSrv.Shutdown(shutdownCtx)

	return nil
}

func loadEnvConfig(cfg *ServerConfig) {
	if v := os.Getenv("PHILIP_GRPC_ADDRESS"); v != "" {
		cfg.GRPCAddress = v
	}
	if v := os.Getenv("PHILIP_REST_ADDRESS"); v != "" {
		cfg.RESTAddress = v
	}
	if v := os.Getenv("PHILIP_DB_HOST"); v != "" {
		cfg.DB.Host = v
	}
	if v := os.Getenv("PHILIP_DB_USER"); v != "" {
		cfg.DB.User = v
	}
	if v := os.Getenv("PHILIP_DB_PASSWORD"); v != "" {
		cfg.DB.Password = v
	}
	if v := os.Getenv("PHILIP_DB_NAME"); v != "" {
		cfg.DB.DBName = v
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		cfg.OpenAIAPIKey = v
	}
	if v := os.Getenv("OPENAI_MODEL"); v != "" {
		cfg.OpenAIModel = v
	}
	if v := os.Getenv("PHILIP_SLACK_WEBHOOK"); v != "" {
		cfg.SlackWebhookURL = v
	}
	if v := os.Getenv("PHILIP_WEBHOOK_URL"); v != "" {
		cfg.WebhookURL = v
	}
	if v := os.Getenv("PHILIP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
}
