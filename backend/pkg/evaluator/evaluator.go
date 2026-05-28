package evaluator

import (
	"context"
	"time"
)

// ControlStatus defines the compliance status of a specific security control.
type ControlStatus string

const (
	StatusCompliant    ControlStatus = "COMPLIANT"
	StatusNonCompliant ControlStatus = "NON_COMPLIANT"
	StatusError        ControlStatus = "ERROR"
	StatusNotApplicable ControlStatus = "NOT_APPLICABLE"
)

// Severity defines the risk impact of a control failure.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// ControlResult represents the detailed outcome of a security control evaluation.
type ControlResult struct {
	ControlID   string        `json:"control_id"`
	ControlName string        `json:"control_name"`
	Status      ControlStatus `json:"status"`
	Severity    Severity      `json:"severity"`
	Evidence    interface{}   `json:"evidence"` // Structured metadata of the evaluation
	Score       float64       `json:"score"`    // 0.0 to 100.0
	EvaluatedAt time.Time     `json:"evaluated_at"`
}

// ControlEvaluator defines the contract for analyzing a specific security dimension.
// Dimensions include: Endpoint Protection (EDR), Vulnerability Management, Patch Management,
// Encryption, Network Security (ZTA), and Identity & Access.
type ControlEvaluator interface {
	// Evaluate analyzes the raw source data for a device and returns the compliance score/result.
	// Always context-aware and isolated per tenant.
	Evaluate(ctx context.Context, tenantID string, deviceID string, rawData []byte) (ControlResult, error)
}
