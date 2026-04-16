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

	// Detection
	Detection DetectionConfig `json:"detection"`

	// OpenAI
	OpenAIAPIKey string `json:"openai_api_key"`
	OpenAIModel  string `json:"openai_model"`

	// Alerting
	SlackWebhookURL string `json:"slack_webhook_url"`
	WebhookURL      string `json:"webhook_url"`

	// Logging
	LogLevel string `json:"log_level"`
}

// DetectionConfig holds detection-specific configuration.
type DetectionConfig struct {
	Baseline baseline.EngineConfig `json:"baseline"`
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
		Detection: DetectionConfig{
			Baseline: baseline.DefaultEngineConfig(),
		},
		OpenAIModel: "gpt-4o",
		LogLevel:    "info",
	}
}

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.StringVar(configPath, "c", "", "path to config file (shorthand)")
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
	baselineEngine := baseline.NewEngineWithConfig(store, cfg.Detection.Baseline, logger)
	logger.Info("detection config",
		"learning_threshold", cfg.Detection.Baseline.LearningThreshold,
		"max_profile_age_days", cfg.Detection.Baseline.MaxProfileAgeDays)
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

	// Job analysis callback — triggered when a new job record is ingested.
	// Receives events directly from the ingestion handler (no DB round-trip).
	analyzeJob := func(jobID, repository, workflowFile, jobName string, events []sensor.Event) {
		analyzeCtx, analyzeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer analyzeCancel()

		logger.Info("analyzing job",
			"job_id", jobID,
			"repository", repository,
			"workflow_file", workflowFile,
			"job_name", jobName,
			"event_count", len(events))

		// Update baseline (per-job key)
		bl, err := baselineEngine.UpdateBaseline(analyzeCtx, repository, workflowFile, jobName, events)
		if err != nil {
			logger.Error("failed to update baseline", "error", err,
				"repository", repository, "job_name", jobName)
			return
		}

		// Update baseline metrics
		metrics.BaselineStatus.WithLabelValues(repository, jobName, "learning").Set(0)
		metrics.BaselineStatus.WithLabelValues(repository, jobName, "active").Set(0)
		metrics.BaselineStatus.WithLabelValues(repository, jobName, bl.Status).Set(1)
		metrics.BaselineJobsObserved.WithLabelValues(repository, jobName).Set(float64(bl.TotalJobsObserved))
		metrics.BaselineProcessProfiles.WithLabelValues(repository, jobName).Set(float64(len(bl.ProcessProfiles)))
		metrics.BaselineNetworkProfiles.WithLabelValues(repository, jobName).Set(float64(len(bl.NetworkProfiles)))
		metrics.BaselineFileAccessProfiles.WithLabelValues(repository, jobName).Set(float64(len(bl.FileAccessProfiles)))

		// Set per-execution gauges (always, regardless of verdict)
		runID := metrics.RunIDFromJobID(jobID)
		metrics.JobExecTimestamp.WithLabelValues(repository, jobName, jobID, runID).Set(float64(time.Now().Unix()))
		metrics.JobExecEventCount.WithLabelValues(repository, jobName, jobID, runID).Set(float64(len(events)))

		// Score deviations
		deviations := scorer.ScoreJob(bl, events)

		// Compute job-level score (max deviation score)
		var maxScore float64
		for _, dev := range deviations {
			if dev.Score > maxScore {
				maxScore = dev.Score
			}
		}
		metrics.JobExecScore.WithLabelValues(repository, jobName, jobID, runID).Set(maxScore)
		metrics.JobExecDeviationCount.WithLabelValues(repository, jobName, jobID, runID).Set(float64(len(deviations)))

		if len(deviations) == 0 {
			metrics.JobsAnalyzed.WithLabelValues(repository, jobName, "clean").Inc()
			metrics.JobExecVerdict.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.VerdictToNumeric("clean"))
			metrics.JobExecSeverity.WithLabelValues(repository, jobName, jobID, runID).Set(0)
			return
		}

		// Record deviation metrics
		for _, dev := range deviations {
			metrics.DeviationsTotal.WithLabelValues(repository, jobName, string(dev.DeviationType)).Inc()
			metrics.DeviationScore.WithLabelValues(repository, jobName, string(dev.DeviationType)).Observe(dev.Score)
			if dev.StaticOnly {
				metrics.StaticDetections.WithLabelValues(repository, string(dev.DeviationType)).Inc()
			}
		}

		// Detect attack chains
		chainDetector := detection.NewChainDetector()
		chains := chainDetector.DetectChains(deviations)
		for _, chain := range chains {
			metrics.AttackChainsDetected.WithLabelValues(repository, chain.Name).Inc()
		}
		if len(chains) > 0 {
			logger.Warn("attack chains detected",
				"repository", repository,
				"job_name", jobName,
				"chains", len(chains),
				"summary", detection.FormatChainsSummary(chains))
		}

		// Build deviation type breakdown
		deviationTypes := make(map[string]int)
		for _, dev := range deviations {
			deviationTypes[string(dev.DeviationType)]++
		}
		logger.Info("deviations detected",
			"repository", repository,
			"job_name", jobName,
			"count", len(deviations),
			"chains", len(chains),
			"max_score", maxScore,
			"types", deviationTypes)

		// Run triage
		triageReq := triage.TriageRequest{
			Deviations:   deviations,
			AttackChains: chains,
			Baseline:     bl,
			Repository:   repository,
			JobID:        jobID,
		}

		// L1 classification
		l1Result := l1.Classify(triageReq)
		if l1Result != nil {
			metrics.TriageVerdicts.WithLabelValues(repository, "l1", string(l1Result.Verdict)).Inc()
		}
		if l1Result != nil && l1Result.Verdict == triage.VerdictBenign {
			logger.Info("L1 classified all deviations as benign",
				"repository", repository, "job_name", jobName)
			metrics.JobsAnalyzed.WithLabelValues(repository, jobName, "benign").Inc()
			metrics.JobExecVerdict.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.VerdictToNumeric("benign"))
			metrics.JobExecSeverity.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.SeverityToNumeric(l1Result.Severity))
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
			metrics.JobsAnalyzed.WithLabelValues(repository, jobName, "benign").Inc()
			metrics.JobExecVerdict.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.VerdictToNumeric("benign"))
			metrics.JobExecSeverity.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.SeverityToNumeric(finalResult.Severity))
			return
		}
		if finalResult.Confidence < 0.6 {
			logger.Info("low confidence finding, not alerting",
				"verdict", finalResult.Verdict,
				"confidence", finalResult.Confidence)
			metrics.JobsAnalyzed.WithLabelValues(repository, jobName, "low_confidence").Inc()
			metrics.JobExecVerdict.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.VerdictToNumeric("low_confidence"))
			metrics.JobExecSeverity.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.SeverityToNumeric(finalResult.Severity))
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
		metrics.JobsAnalyzed.WithLabelValues(repository, jobName, string(finalResult.Verdict)).Inc()
		metrics.JobExecVerdict.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.VerdictToNumeric(string(finalResult.Verdict)))
		metrics.JobExecSeverity.WithLabelValues(repository, jobName, jobID, runID).Set(metrics.SeverityToNumeric(finalResult.Severity))
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
		// If no repository param, list all baselines
		if repo == "" {
			summaries, err := store.ListBaselines(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Add learning_threshold to each summary for dashboard display
			type summaryWithThreshold struct {
				storage.BaselineSummary
				LearningThreshold int `json:"learning_threshold"`
			}
			result := make([]summaryWithThreshold, len(summaries))
			for i, s := range summaries {
				result[i] = summaryWithThreshold{
					BaselineSummary:   s,
					LearningThreshold: cfg.Detection.Baseline.LearningThreshold,
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}
		workflowFile := r.URL.Query().Get("workflow_file")
		jobName := r.URL.Query().Get("job_name")
		bl, err := baselineEngine.GetBaseline(r.Context(), repo, workflowFile, jobName)
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
