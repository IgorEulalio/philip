package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/IgorEulalio/philip/backend/alerting"
)

// Slack sends alerts to a Slack channel via webhook.
type Slack struct {
	webhookURL string
	client     *http.Client
}

// NewSlack creates a new Slack integration.
func NewSlack(webhookURL string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Slack) Name() string {
	return "slack"
}

// Send posts an alert to the configured Slack webhook.
func (s *Slack) Send(alert alerting.Alert) error {
	msg := buildSlackMessage(alert)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling slack message: %w", err)
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func buildSlackMessage(alert alerting.Alert) slackMessage {
	severityEmoji := map[string]string{
		"critical": ":rotating_light:",
		"high":     ":warning:",
		"medium":   ":large_yellow_circle:",
		"low":      ":information_source:",
	}

	emoji := severityEmoji[alert.Severity]
	if emoji == "" {
		emoji = ":question:"
	}

	// Build deviations summary
	var devSummary strings.Builder
	for i, dev := range alert.Deviations {
		if i >= 5 { // Limit to 5 deviations in the message
			devSummary.WriteString(fmt.Sprintf("\n... and %d more deviations", len(alert.Deviations)-5))
			break
		}
		devSummary.WriteString(fmt.Sprintf("- `%s` (score: %.2f): %s\n", dev.DeviationType, dev.Score, dev.Description))
	}

	// Build MITRE mapping string
	mitre := "None"
	if len(alert.MITREMappings) > 0 {
		mitre = strings.Join(alert.MITREMappings, ", ")
	}

	return slackMessage{
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackText{
					Type: "plain_text",
					Text: fmt.Sprintf("%s Philip: Supply Chain Alert — %s", emoji, strings.ToUpper(alert.Severity)),
				},
			},
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*Repository:* `%s`\n*Job ID:* `%s`\n*Verdict:* %s (confidence: %.0f%%)\n*MITRE ATT&CK:* %s",
						alert.Repository, alert.JobID,
						alert.Verdict, alert.Confidence*100, mitre),
				},
			},
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*Reasoning:*\n%s", alert.Reasoning),
				},
			},
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*Deviations:*\n%s", devSummary.String()),
				},
			},
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*Recommended Action:*\n%s", alert.RecommendedAction),
				},
			},
			{
				Type: "context",
				Elements: []slackText{
					{Type: "mrkdwn", Text: fmt.Sprintf("Philip Supply Chain Detector | %s", alert.CreatedAt.Format(time.RFC3339))},
				},
			},
		},
	}
}

// Slack API types
type slackMessage struct {
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
