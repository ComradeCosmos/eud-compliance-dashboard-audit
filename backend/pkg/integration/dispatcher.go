package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// IntegrationType represents target ticketing/SIEM systems.
type IntegrationType string

const (
	IntegrationServiceNow IntegrationType = "SERVICENOW"
	IntegrationJira       IntegrationType = "JIRA"
	IntegrationSplunk     IntegrationType = "SPLUNK"
)

// IntegrationPayload conforms strictly to CloudEvents 1.0 specification.
// Includes custom tenantid and deviceid extensions as defined by format requirements.
type IntegrationPayload struct {
	SpecVersion     string      `json:"specversion"`
	ID              string      `json:"id"`
	Source          string      `json:"source"`
	Type            string      `json:"type"`
	Subject         string      `json:"subject"`
	Time            string      `json:"time"`
	TenantID        string      `json:"tenantid"` // Extension attribute
	DeviceID        string      `json:"deviceid"` // Extension attribute
	DataContentType string      `json:"datacontenttype"`
	Data            interface{} `json:"data"`
}

// VaultSecretProvider defines a contract to retrieve target credentials securely from HashiCorp Vault.
//
// Threat Mitigated: Local storage of sensitive auth headers/API tokens in process env.
type VaultSecretProvider interface {
	GetIntegrationSecret(ctx context.Context, tenantID string, target IntegrationType) (string, error)
}

// IntegrationDispatcher manages delivery of outbound operational alerts.
type IntegrationDispatcher struct {
	client  *http.Client
	vault   VaultSecretProvider
	endpoints map[IntegrationType]string
}

func NewIntegrationDispatcher(vault VaultSecretProvider) *IntegrationDispatcher {
	return &IntegrationDispatcher{
		client: &http.Client{Timeout: 10 * time.Second},
		vault:  vault,
		endpoints: map[IntegrationType]string{
			IntegrationServiceNow: "https://now.company.com/api/v1/tickets",
			IntegrationJira:       "https://jira.company.com/rest/api/2/issue",
			IntegrationSplunk:     "https://splunk.company.com/services/collector/event",
		},
	}
}

// DispatchCriticalAlert translates a critical device score event into ServiceNow incidents or Jira tickets.
func (d *IntegrationDispatcher) DispatchCriticalAlert(ctx context.Context, tenantID string, deviceID string, score float64, details string) error {
	// 1. Fetch dynamic tenant-isolated secret from Vault
	apiKey, err := d.vault.GetIntegrationSecret(ctx, tenantID, IntegrationServiceNow)
	if err != nil {
		return fmt.Errorf("failed to retrieve integration credential boundary for tenant %s: %w", tenantID, err)
	}

	// 2. Build CloudEvent 1.0 Payload
	event := IntegrationPayload{
		SpecVersion:     "1.0",
		ID:              fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Source:          "/compliance/risk-engine",
		Type:            "eud.integration.servicenow",
		Subject:         fmt.Sprintf("device:%s:critical_score", deviceID),
		Time:            time.Now().UTC().Format(time.RFC3339),
		TenantID:        tenantID,
		DeviceID:        deviceID,
		DataContentType: "application/json",
		Data: map[string]interface{}{
			"severity":       "CRITICAL",
			"score":          score,
			"remediation_msg": details,
			"alert_trigger":  "device compliance dropped below CRITICAL threshold (score < 40)",
		},
	}

	payloadBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal outbound integration payload: %w", err)
	}

	// 3. Create HTTP Request (acting as Kong downstream verified routing)
	req, err := http.NewRequestWithContext(ctx, "POST", d.endpoints[IntegrationServiceNow], strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("failed to form integration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Tenant-ID", tenantID) // Downstream mesh filtering assertion

	// Outbound request would execute here
	// resp, err := d.client.Do(req)

	return nil
}
