package evaluator

import (
	"context"
	"encoding/json"
	"time"
)

// SentinelOneData represents the structure of S1 source records in the device JSONB payload.
type SentinelOneData struct {
	AgentActive       bool      `json:"agent_active"`
	ThreatActiveCount int       `json:"threat_active_count"`
	PolicyVersion     string    `json:"policy_version"`
	RequiredPolicyVer string    `json:"required_policy_version"`
	LastSeenTime      time.Time `json:"last_seen_time"`
}

// EdrEvaluator evaluates Endpoint Protection (EDR) compliance via SentinelOne state.
type EdrEvaluator struct{}

func NewEdrEvaluator() *EdrEvaluator {
	return &EdrEvaluator{}
}

// Evaluate performs compliance checks on raw SentinelOne JSON payloads.
//
// Controls evaluated:
// 1. SentinelOne Agent status: Inactive -> CRITICAL fail (score = 0)
// 2. Active threats count: > 0 -> HIGH fail (score = 40)
// 3. Outdated policy version: Mismatch -> MEDIUM fail (score = 70)
func (e *EdrEvaluator) Evaluate(ctx context.Context, tenantID string, deviceID string, rawData []byte) (ControlResult, error) {
	var data SentinelOneData
	result := ControlResult{
		ControlID:   "CTRL-EDR-S1-001",
		ControlName: "SentinelOne Endpoint Protection Status",
		EvaluatedAt: time.Now().UTC(),
	}

	if len(rawData) == 0 {
		result.Status = StatusError
		result.Severity = SeverityCritical
		result.Evidence = map[string]string{"error": "empty data source"}
		result.Score = 0.0
		return result, nil
	}

	if err := json.Unmarshal(rawData, &data); err != nil {
		result.Status = StatusError
		result.Severity = SeverityHigh
		result.Evidence = map[string]string{"error": "malformed JSON payload: " + err.Error()}
		result.Score = 0.0
		return result, nil
	}

	evidence := map[string]interface{}{
		"agent_active":            data.AgentActive,
		"threat_active_count":     data.ThreatActiveCount,
		"policy_version":          data.PolicyVersion,
		"required_policy_version": data.RequiredPolicyVer,
		"last_seen_time":          data.LastSeenTime,
	}
	result.Evidence = evidence

	// Rule 1: Agent status is inactive -> CRITICAL fail
	if !data.AgentActive {
		result.Status = StatusNonCompliant
		result.Severity = SeverityCritical
		result.Score = 0.0
		evidence["failure_reason"] = "SentinelOne agent is inactive or disabled"
		return result, nil
	}

	// Rule 2: Active threat detected -> HIGH fail
	if data.ThreatActiveCount > 0 {
		result.Status = StatusNonCompliant
		result.Severity = SeverityHigh
		result.Score = 40.0
		evidence["failure_reason"] = "Active security threats detected on device"
		return result, nil
	}

	// Rule 3: Policy version outdated -> MEDIUM compliance warning
	if data.PolicyVersion != "" && data.RequiredPolicyVer != "" && data.PolicyVersion != data.RequiredPolicyVer {
		result.Status = StatusNonCompliant
		result.Severity = SeverityMedium
		result.Score = 70.0
		evidence["failure_reason"] = "SentinelOne security policy version mismatch"
		return result, nil
	}

	// Fully compliant
	result.Status = StatusCompliant
	result.Severity = SeverityNone
	result.Score = 100.0
	return result, nil
}
