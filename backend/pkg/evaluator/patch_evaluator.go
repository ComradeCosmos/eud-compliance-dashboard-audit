package evaluator

import (
	"context"
	"encoding/json"
	"time"
)

// PatchData represents SCCM / OS Lifecycle raw records inside the device JSONB source.
type PatchData struct {
	OSFamily            string    `json:"os_family"`
	OSVersion           string    `json:"os_version"`
	OSBuild             string    `json:"os_build"`
	OSEndOfLife         bool      `json:"os_end_of_life"`
	LastPatchApplied    time.Time `json:"last_patch_applied"`
	MissingPatchesCount int       `json:"missing_patches_count"`
	DaysSinceLastPatch  int       `json:"days_since_last_patch"` // Calculated from last scan date
}

// PatchEvaluator evaluates patch and OS lifecycle compliance.
type PatchEvaluator struct{}

func NewPatchEvaluator() *PatchEvaluator {
	return &PatchEvaluator{}
}

// Evaluate analyzes operating system version, EOL status, and patch currency.
//
// Controls evaluated:
// 1. OS End-of-Life: True -> CRITICAL fail (score = 0)
// 2. OS Patches Late: DaysSinceLastPatch > 30 -> HIGH fail (score = 40)
// 3. High number of missing patches: MissingPatchesCount > 5 -> MEDIUM fail (score = 70)
func (p *PatchEvaluator) Evaluate(ctx context.Context, tenantID string, deviceID string, rawData []byte) (ControlResult, error) {
	var data PatchData
	result := ControlResult{
		ControlID:   "CTRL-PAT-SCCM-002",
		ControlName: "OS Patch Currency and Lifecycle Support",
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
		"os_family":             data.OSFamily,
		"os_version":            data.OSVersion,
		"os_build":              data.OSBuild,
		"os_end_of_life":        data.OSEndOfLife,
		"last_patch_applied":    data.LastPatchApplied,
		"missing_patches_count": data.MissingPatchesCount,
		"days_since_last_patch": data.DaysSinceLastPatch,
	}
	result.Evidence = evidence

	// Rule 1: OS End of Life -> CRITICAL fail
	if data.OSEndOfLife {
		result.Status = StatusNonCompliant
		result.Severity = SeverityCritical
		result.Score = 0.0
		evidence["failure_reason"] = "Operating system has reached End-of-Life (EOL) and is unsupported"
		return result, nil
	}

	// Rule 2: Patches > 30 days late -> HIGH fail
	if data.DaysSinceLastPatch > 30 {
		result.Status = StatusNonCompliant
		result.Severity = SeverityHigh
		result.Score = 40.0
		evidence["failure_reason"] = "Operating system patches are outstanding for more than 30 days"
		return result, nil
	}

	// Rule 3: High outstanding missing patch count (> 5) -> MEDIUM compliance warning
	if data.MissingPatchesCount > 5 {
		result.Status = StatusNonCompliant
		result.Severity = SeverityMedium
		result.Score = 70.0
		evidence["failure_reason"] = "Device is missing a significant number of security updates (> 5)"
		return result, nil
	}

	// Compliant
	result.Status = StatusCompliant
	result.Severity = SeverityNone
	result.Score = 100.0
	return result, nil
}
