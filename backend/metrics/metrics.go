package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// --- Counters (cumulative totals) ---

	// EventsIngested counts total events ingested, labeled by repository and event type.
	EventsIngested = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_events_ingested_total",
		Help: "Total events ingested",
	}, []string{"repository", "event_type"})

	// JobsAnalyzed counts jobs analyzed, labeled by repository, job name, and verdict.
	JobsAnalyzed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_jobs_analyzed_total",
		Help: "Jobs analyzed by verdict",
	}, []string{"repository", "job_name", "verdict"})

	// DeviationsTotal counts deviations detected, labeled by repository, job name, and type.
	DeviationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_deviations_total",
		Help: "Total deviations detected",
	}, []string{"repository", "job_name", "type"})

	// FindingsTotal counts findings stored, labeled by repository, verdict, and severity.
	FindingsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_findings_total",
		Help: "Total findings stored",
	}, []string{"repository", "verdict", "severity"})

	// TriageVerdicts counts triage verdicts by source (l1/l2) and verdict.
	TriageVerdicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_triage_verdicts_total",
		Help: "Triage verdicts by source and outcome",
	}, []string{"repository", "source", "verdict"})

	// AlertsRouted counts alerts successfully routed to integrations.
	AlertsRouted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_alerts_routed_total",
		Help: "Total alerts routed to integrations",
	}, []string{"repository", "severity"})

	// AlertsDeduplicated counts alerts skipped due to deduplication.
	AlertsDeduplicated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "philip_alerts_deduplicated_total",
		Help: "Total alerts deduplicated",
	}, []string{"repository"})

	// --- Histogram ---

	// DeviationScore tracks the distribution of deviation scores.
	DeviationScore = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "philip_deviation_score",
		Help:    "Distribution of deviation scores",
		Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	}, []string{"repository", "job_name", "type"})

	// --- Gauges (baseline state) ---

	// BaselineStatus tracks baseline status per job (1 for current status, 0 otherwise).
	BaselineStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_baseline_status",
		Help: "Baseline status per job (1=current, 0=not)",
	}, []string{"repository", "job_name", "status"})

	// BaselineJobsObserved tracks total jobs observed per baseline.
	BaselineJobsObserved = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_baseline_jobs_observed",
		Help: "Total jobs observed in baseline",
	}, []string{"repository", "job_name"})

	// BaselineProcessProfiles tracks number of process profiles per baseline.
	BaselineProcessProfiles = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_baseline_process_profiles",
		Help: "Number of process profiles in baseline",
	}, []string{"repository", "job_name"})

	// BaselineNetworkProfiles tracks number of network profiles per baseline.
	BaselineNetworkProfiles = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_baseline_network_profiles",
		Help: "Number of network profiles in baseline",
	}, []string{"repository", "job_name"})

	// --- Gauges (per-execution state, keyed by job_id) ---

	// JobExecTimestamp is the unix timestamp of the execution.
	JobExecTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_job_exec_timestamp_seconds",
		Help: "Unix timestamp of the job execution",
	}, []string{"repository", "job_name", "job_id"})

	// JobExecVerdict is the numeric verdict of the execution.
	// 0=clean, 1=benign, 2=suspicious, 3=critical, 4=low_confidence
	JobExecVerdict = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_job_exec_verdict",
		Help: "Verdict of the execution (0=clean, 1=benign, 2=suspicious, 3=critical)",
	}, []string{"repository", "job_name", "job_id"})

	// JobExecEventCount is the number of events in the execution.
	JobExecEventCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_job_exec_event_count",
		Help: "Number of events in the execution",
	}, []string{"repository", "job_name", "job_id"})

	// JobExecDeviationCount is the number of deviations in the execution.
	JobExecDeviationCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_job_exec_deviation_count",
		Help: "Number of deviations in the execution",
	}, []string{"repository", "job_name", "job_id"})

	// JobExecScore is the highest deviation score in the execution (0.0 = clean, 1.0 = max risk).
	JobExecScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_job_exec_score",
		Help: "Highest deviation score in the execution (0=clean, 1=max risk)",
	}, []string{"repository", "job_name", "job_id"})

	// JobExecSeverity is the numeric severity of the execution.
	// 0=none, 1=low, 2=medium, 3=high, 4=critical
	JobExecSeverity = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "philip_job_exec_severity",
		Help: "Severity of the execution (0=none, 1=low, 2=medium, 3=high, 4=critical)",
	}, []string{"repository", "job_name", "job_id"})

	allCollectors = []prometheus.Collector{
		EventsIngested,
		JobsAnalyzed,
		DeviationsTotal,
		FindingsTotal,
		TriageVerdicts,
		AlertsRouted,
		AlertsDeduplicated,
		DeviationScore,
		BaselineStatus,
		BaselineJobsObserved,
		BaselineProcessProfiles,
		BaselineNetworkProfiles,
		JobExecTimestamp,
		JobExecVerdict,
		JobExecEventCount,
		JobExecDeviationCount,
		JobExecScore,
		JobExecSeverity,
	}
)

// VerdictToNumeric converts a verdict string to a numeric value for gauges.
func VerdictToNumeric(verdict string) float64 {
	switch verdict {
	case "clean":
		return 0
	case "benign":
		return 1
	case "suspicious":
		return 2
	case "critical":
		return 3
	case "low_confidence":
		return 4
	default:
		return -1
	}
}

// SeverityToNumeric converts a severity string to a numeric value for gauges.
func SeverityToNumeric(severity string) float64 {
	switch severity {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// Register registers all Philip metrics with the default Prometheus registry.
func Register() {
	for _, c := range allCollectors {
		prometheus.MustRegister(c)
	}
}
