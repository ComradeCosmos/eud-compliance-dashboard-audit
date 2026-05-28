package evaluator

import (
	"context"
	"testing"
	"time"
)

func TestEdrEvaluator(t *testing.T) {
	eval := NewEdrEvaluator()
	ctx := context.Background()

	t.Run("Compliant Agent", func(t *testing.T) {
		raw := []byte(`{
			"agent_active": true,
			"threat_active_count": 0,
			"policy_version": "v1.2.3",
			"required_policy_version": "v1.2.3",
			"last_seen_time": "2026-05-26T22:00:00Z"
		}`)

		res, err := eval.Evaluate(ctx, "tenant-abc", "device-123", raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != StatusCompliant {
			t.Errorf("expected compliant, got %v", res.Status)
		}
		if res.Score != 100.0 {
			t.Errorf("expected 100.0 score, got %v", res.Score)
		}
		if res.Severity != SeverityNone {
			t.Errorf("expected SeverityNone, got %v", res.Severity)
		}
	})

	t.Run("Active Threats - High Severity Failure", func(t *testing.T) {
		raw := []byte(`{
			"agent_active": true,
			"threat_active_count": 2,
			"policy_version": "v1.2.3",
			"required_policy_version": "v1.2.3"
		}`)

		res, err := eval.Evaluate(ctx, "tenant-abc", "device-123", raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != StatusNonCompliant {
			t.Errorf("expected non-compliant, got %v", res.Status)
		}
		if res.Score != 40.0 {
			t.Errorf("expected 40.0 score, got %v", res.Score)
		}
		if res.Severity != SeverityHigh {
			t.Errorf("expected SeverityHigh, got %v", res.Severity)
		}
	})

	t.Run("Inactive Agent - Critical Severity Failure", func(t *testing.T) {
		raw := []byte(`{
			"agent_active": false,
			"threat_active_count": 0,
			"policy_version": "v1.2.3",
			"required_policy_version": "v1.2.3"
		}`)

		res, err := eval.Evaluate(ctx, "tenant-abc", "device-123", raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != StatusNonCompliant {
			t.Errorf("expected non-compliant, got %v", res.Status)
		}
		if res.Score != 0.0 {
			t.Errorf("expected 0.0 score, got %v", res.Score)
		}
		if res.Severity != SeverityCritical {
			t.Errorf("expected SeverityCritical, got %v", res.Severity)
		}
	})
}

func TestPatchEvaluator(t *testing.T) {
	eval := NewPatchEvaluator()
	ctx := context.Background()

	t.Run("Compliant OS patching", func(t *testing.T) {
		raw := []byte(`{
			"os_family": "Windows",
			"os_version": "11",
			"os_build": "22631",
			"os_end_of_life": false,
			"last_patch_applied": "2026-05-20T00:00:00Z",
			"missing_patches_count": 1,
			"days_since_last_patch": 6
		}`)

		res, err := eval.Evaluate(ctx, "tenant-abc", "device-123", raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != StatusCompliant {
			t.Errorf("expected compliant status, got %v", res.Status)
		}
		if res.Score != 100.0 {
			t.Errorf("expected 100.0 score, got %v", res.Score)
		}
	})

	t.Run("Out of date > 30 days - High Severity Failure", func(t *testing.T) {
		raw := []byte(`{
			"os_family": "Windows",
			"os_version": "11",
			"os_build": "22621",
			"os_end_of_life": false,
			"days_since_last_patch": 35
		}`)

		res, err := eval.Evaluate(ctx, "tenant-abc", "device-123", raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != StatusNonCompliant {
			t.Errorf("expected non-compliant status, got %v", res.Status)
		}
		if res.Score != 40.0 {
			t.Errorf("expected 40.0 score, got %v", res.Score)
		}
		if res.Severity != SeverityHigh {
			t.Errorf("expected SeverityHigh, got %v", res.Severity)
		}
	})

	t.Run("OS EOL - Critical Severity Failure", func(t *testing.T) {
		raw := []byte(`{
			"os_family": "Windows",
			"os_version": "10 Enterprise 2015 LTSB",
			"os_build": "10240",
			"os_end_of_life": true,
			"days_since_last_patch": 2
		}`)

		res, err := eval.Evaluate(ctx, "tenant-abc", "device-123", raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Status != StatusNonCompliant {
			t.Errorf("expected non-compliant status, got %v", res.Status)
		}
		if res.Score != 0.0 {
			t.Errorf("expected 0.0 score, got %v", res.Score)
		}
		if res.Severity != SeverityCritical {
			t.Errorf("expected SeverityCritical, got %v", res.Severity)
		}
	})
}

func TestRiskEngineScoring(t *testing.T) {
	engine := NewRiskEngine()
	ctx := context.Background()

	t.Run("Fully Compliant Fleet Standard", func(t *testing.T) {
		scores := map[Dimension]float64{
			DimensionEDR:        100.0,
			DimensionPatch:      100.0,
			DimensionVulnerability: 100.0,
			DimensionEncryption: 100.0,
			DimensionNetwork:    100.0,
			DimensionIdentity:   100.0,
		}

		finalScore := engine.CalculateDeviceScore(ctx, scores, 0)
		if finalScore != 100.0 {
			t.Errorf("expected 100.0 score, got %v", finalScore)
		}

		risk := engine.GetRiskLevel(finalScore)
		if risk != SeverityLow {
			t.Errorf("expected LOW risk, got %v", risk)
		}
	})

	t.Run("Non-compliant Patching, No Critical Failures", func(t *testing.T) {
		// EDR = 100 (25%), Patch = 40 (20%)
		// Sum weights = 0.45. Expected base = (25 + 8) / 0.45 = 73.33333333333333
		scores := map[Dimension]float64{
			DimensionEDR:   100.0,
			DimensionPatch: 40.0,
		}

		finalScore := engine.CalculateDeviceScore(ctx, scores, 0)
		expected := 73.33
		if math.Abs(finalScore-expected) > 0.01 {
			t.Errorf("expected ~73.33, got %v", finalScore)
		}

		risk := engine.GetRiskLevel(finalScore)
		if risk != SeverityMedium {
			t.Errorf("expected MEDIUM risk, got %v", risk)
		}
	})

	t.Run("One Critical Dimension Failure Penalty", func(t *testing.T) {
		// EDR = 0 (Critical), Patch = 100
		// Base score = (25*0 + 20*100) / 0.45 = 44.4444
		// Penalty = 1 critical (penalty = 25%): 44.4444 * 0.75 = 33.3333
		scores := map[Dimension]float64{
			DimensionEDR:   0.0,
			DimensionPatch: 100.0,
		}

		finalScore := engine.CalculateDeviceScore(ctx, scores, 1)
		expected := 33.33
		if math.Abs(finalScore-expected) > 0.01 {
			t.Errorf("expected ~33.33 score, got %v", finalScore)
		}

		risk := engine.GetRiskLevel(finalScore)
		if risk != SeverityCritical {
			t.Errorf("expected CRITICAL risk, got %v", risk)
		}
	})
}
