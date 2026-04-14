package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/philip-ai/philip/backend/alerting"
)

// Webhook sends alerts to a generic webhook endpoint as JSON.
type Webhook struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhook creates a new generic webhook integration.
func NewWebhook(url string, headers map[string]string) *Webhook {
	return &Webhook{
		url:     url,
		headers: headers,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *Webhook) Name() string {
	return "webhook"
}

// Send posts an alert to the configured webhook endpoint.
func (w *Webhook) Send(alert alerting.Alert) error {
	payload := webhookPayload{
		ID:                alert.ID,
		Repository:        alert.Repository,
		JobID:             alert.JobID,
		Verdict:           string(alert.Verdict),
		Severity:          alert.Severity,
		Confidence:        alert.Confidence,
		Reasoning:         alert.Reasoning,
		MITREMappings:     alert.MITREMappings,
		RecommendedAction: alert.RecommendedAction,
		DeviationCount:    len(alert.Deviations),
		CreatedAt:         alert.CreatedAt,
	}

	for _, dev := range alert.Deviations {
		payload.Deviations = append(payload.Deviations, webhookDeviation{
			Type:        string(dev.DeviationType),
			Score:       dev.Score,
			Description: dev.Description,
			Binary:      dev.Event.Binary,
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Philip/1.0")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

type webhookPayload struct {
	ID                string             `json:"id"`
	Repository        string             `json:"repository"`
	JobID             string             `json:"job_id"`
	Verdict           string             `json:"verdict"`
	Severity          string             `json:"severity"`
	Confidence        float64            `json:"confidence"`
	Reasoning         string             `json:"reasoning"`
	MITREMappings     []string           `json:"mitre_mappings"`
	RecommendedAction string             `json:"recommended_action"`
	DeviationCount    int                `json:"deviation_count"`
	Deviations        []webhookDeviation `json:"deviations"`
	CreatedAt         time.Time          `json:"created_at"`
}

type webhookDeviation struct {
	Type        string  `json:"type"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
	Binary      string  `json:"binary"`
}
