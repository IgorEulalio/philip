package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IgorEulalio/philip/backend/triage"
)

const (
	defaultModel    = "gpt-4o"
	defaultEndpoint = "https://api.openai.com/v1/chat/completions"
	defaultTimeout  = 30 * time.Second
)

// Provider implements the triage.LLMProvider interface using OpenAI.
type Provider struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

// Config holds OpenAI provider configuration.
type Config struct {
	APIKey   string
	Model    string // defaults to "gpt-4o"
	Endpoint string // defaults to OpenAI API
}

// New creates a new OpenAI triage provider.
func New(cfg Config) *Provider {
	model := cfg.Model
	if model == "" {
		model = defaultModel
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	return &Provider{
		apiKey:   cfg.APIKey,
		model:    model,
		endpoint: endpoint,
		client:   &http.Client{Timeout: defaultTimeout},
	}
}

func (p *Provider) Name() string {
	return "openai"
}

// Analyze sends deviations to OpenAI for deep contextual analysis.
func (p *Provider) Analyze(req triage.TriageRequest) (*triage.TriageResponse, error) {
	prompt := buildPrompt(req)

	chatReq := chatCompletionRequest{
		Model: p.model,
		Messages: []message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1, // Low temperature for consistent analysis
		ResponseFormat: &responseFormat{
			Type: "json_object",
		},
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("calling OpenAI: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatCompletionResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from OpenAI")
	}

	content := chatResp.Choices[0].Message.Content

	var analysis analysisResponse
	if err := json.Unmarshal([]byte(content), &analysis); err != nil {
		return nil, fmt.Errorf("parsing analysis: %w", err)
	}

	return &triage.TriageResponse{
		Verdict:           toVerdict(analysis.Verdict),
		Confidence:        analysis.Confidence,
		Reasoning:         analysis.Reasoning,
		MITREMappings:     analysis.MITREMappings,
		Severity:          analysis.Severity,
		RecommendedAction: analysis.RecommendedAction,
	}, nil
}

const systemPrompt = `You are Philip, an AI security analyst specializing in CI/CD supply chain attack detection.

You analyze behavioral deviations from established baselines in CI/CD pipeline executions on self-hosted runners.

Your primary objectives:
1. Accurately classify whether deviations indicate a supply chain attack or benign changes
2. MINIMIZE FALSE POSITIVES — alert fatigue is the #1 enemy. Only flag events you are confident are malicious.
3. Provide clear reasoning that a human security engineer can act on
4. Map findings to MITRE ATT&CK framework techniques where applicable

Known supply chain attack patterns:
- Dependency confusion: malicious packages installed from public registry instead of private
- Compromised dependencies: legitimate packages with injected malicious code
- Secret exfiltration: reading CI/CD secrets and sending them to external servers
- Backdoor installation: dropping persistent access tools during build
- Cryptomining: using CI/CD compute for cryptocurrency mining
- Code injection: modifying build artifacts to include malicious code

Common benign deviations:
- Dependency version updates (new binaries from updated packages)
- Build tool updates (new compiler versions, new linters)
- Cache misses causing additional downloads
- New CI/CD steps or workflow changes
- Infrastructure changes (new registry mirrors, CDN changes)

Respond with a JSON object matching the analysis schema.`

func buildPrompt(req triage.TriageRequest) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## Repository: %s\n", req.Repository))
	sb.WriteString(fmt.Sprintf("## Job ID: %s\n\n", req.JobID))

	// Baseline context
	if req.Baseline != nil {
		sb.WriteString(fmt.Sprintf("## Baseline Status\n"))
		sb.WriteString(fmt.Sprintf("- Total jobs observed: %d\n", req.Baseline.TotalJobsObserved))
		sb.WriteString(fmt.Sprintf("- Known processes: %d\n", len(req.Baseline.ProcessProfiles)))
		sb.WriteString(fmt.Sprintf("- Known network destinations: %d\n\n", len(req.Baseline.NetworkProfiles)))
	}

	// Deviations
	sb.WriteString("## Deviations to Analyze\n\n")
	for i, dev := range req.Deviations {
		sb.WriteString(fmt.Sprintf("### Deviation %d (score: %.2f, type: %s)\n", i+1, dev.Score, dev.DeviationType))
		sb.WriteString(fmt.Sprintf("- Description: %s\n", dev.Description))
		sb.WriteString(fmt.Sprintf("- Binary: %s\n", dev.Event.Binary))
		sb.WriteString(fmt.Sprintf("- PID: %d, Parent PID: %d\n", dev.Event.PID, dev.Event.ParentPID))
		if dev.Event.Args != nil {
			sb.WriteString(fmt.Sprintf("- Args: %v\n", dev.Event.Args))
		}
		if dev.Event.DestIP != nil {
			sb.WriteString(fmt.Sprintf("- Destination: %s:%d (%s)\n", dev.Event.DestIP, dev.Event.DestPort, dev.Event.Protocol))
		}
		if dev.Event.FilePath != "" {
			sb.WriteString(fmt.Sprintf("- File: %s (access: %s)\n", dev.Event.FilePath, dev.Event.AccessType))
		}
		if len(dev.MITRETechniques) > 0 {
			sb.WriteString(fmt.Sprintf("- Pre-mapped MITRE ATT&CK: %s\n", strings.Join(dev.MITRETechniques, ", ")))
		}
		if dev.SuggestedSeverity != "" {
			sb.WriteString(fmt.Sprintf("- Suggested severity: %s\n", dev.SuggestedSeverity))
		}
		if dev.StaticOnly {
			sb.WriteString("- Note: detected via static rules only (baseline still in learning phase)\n")
		}
		sb.WriteString("\n")
	}

	// Attack chains
	if len(req.AttackChains) > 0 {
		sb.WriteString("## Detected Attack Chains\n\n")
		sb.WriteString("The following multi-step attack patterns were detected by correlating deviations:\n\n")
		for _, chain := range req.AttackChains {
			sb.WriteString(fmt.Sprintf("- **%s** (composite score: %.2f, severity: %s)\n", chain.Name, chain.ChainScore, chain.Severity))
			sb.WriteString(fmt.Sprintf("  MITRE techniques: %s\n", strings.Join(chain.Techniques, ", ")))
			sb.WriteString(fmt.Sprintf("  Involves %d correlated deviations\n\n", len(chain.Deviations)))
		}
	}

	sb.WriteString(`Analyze these deviations and respond with a JSON object:
{
  "verdict": "benign" | "suspicious" | "critical",
  "confidence": 0.0-1.0,
  "reasoning": "detailed explanation",
  "mitre_mappings": ["T1195.001", ...],
  "severity": "low" | "medium" | "high" | "critical",
  "recommended_action": "what the security team should do"
}

The deviations above have been pre-mapped to MITRE ATT&CK techniques where applicable.
Please confirm, adjust, or add to the pre-mapped techniques in your mitre_mappings response.
If a deviation was detected via static rules only (no baseline context), factor that into your confidence — static-only detections may have higher false positive rates.`)

	return sb.String()
}

func toVerdict(s string) triage.Verdict {
	switch s {
	case "benign":
		return triage.VerdictBenign
	case "suspicious":
		return triage.VerdictSuspicious
	case "critical":
		return triage.VerdictCritical
	default:
		return triage.VerdictSuspicious
	}
}

// --- OpenAI API types ---

type chatCompletionRequest struct {
	Model          string          `json:"model"`
	Messages       []message       `json:"messages"`
	Temperature    float64         `json:"temperature"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatCompletionResponse struct {
	Choices []choice `json:"choices"`
}

type choice struct {
	Message message `json:"message"`
}

type analysisResponse struct {
	Verdict           string   `json:"verdict"`
	Confidence        float64  `json:"confidence"`
	Reasoning         string   `json:"reasoning"`
	MITREMappings     []string `json:"mitre_mappings"`
	Severity          string   `json:"severity"`
	RecommendedAction string   `json:"recommended_action"`
}
