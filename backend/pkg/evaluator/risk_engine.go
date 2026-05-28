package evaluator

import (
	"context"
	"math"
)

// Dimension represents the categories evaluated by the Risk Scoring Engine.
type Dimension string

const (
	DimensionEDR        Dimension = "EDR"
	DimensionPatch      Dimension = "PATCH"
	DimensionVulnerability Dimension = "VULNERABILITY"
	DimensionEncryption Dimension = "ENCRYPTION"
	DimensionNetwork    Dimension = "NETWORK"
	DimensionIdentity   Dimension = "IDENTITY"
)

// RiskEngine manages the composite compliance scoring of devices.
type RiskEngine struct {
	DimensionWeights map[Dimension]float64
}

// NewRiskEngine initializes a RiskEngine with the platform's default dimension weights.
func NewRiskEngine() *RiskEngine {
	return &RiskEngine{
		DimensionWeights: map[Dimension]float64{
			DimensionEDR:        0.25,
			DimensionVulnerability: 0.20,
			DimensionPatch:      0.20,
			DimensionEncryption: 0.15,
			DimensionNetwork:    0.10,
			DimensionIdentity:   0.10,
		},
	}
}

// CalculateDeviceScore computes the overall compliance score of a device based on
// individual dimension scores and applies the critical failure penalties.
//
// Formula:
//   baseDeviceScore = Σ(dimensionWeight × dimensionScore)
//   criticalCount = number of dimensions that resulted in a CRITICAL status
//   finalScore = baseDeviceScore × (1 - min(criticalCount × 0.25, 0.75))
func (r *RiskEngine) CalculateDeviceScore(ctx context.Context, scores map[Dimension]float64, criticalCount int) float64 {
	var baseScore float64
	var totalWeight float64

	for dim, score := range scores {
		weight, ok := r.DimensionWeights[dim]
		if !ok {
			continue // Unrecognized dimension ignored to preserve extensibility
		}
		baseScore += weight * score
		totalWeight += weight
	}

	// Normalize if any weights are missing (e.g. partial dimension assessment)
	if totalWeight > 0.0 && totalWeight < 1.0 {
		baseScore = baseScore / totalWeight
	}

	// Apply critical failure penalty: score × (1 - min(criticalCount × 0.25, 0.75))
	penaltyMultiplier := 1.0
	if criticalCount > 0 {
		penalty := math.Min(float64(criticalCount)*0.25, 0.75)
		penaltyMultiplier = 1.0 - penalty
	}

	finalScore := baseScore * penaltyMultiplier

	// Return score bound within 0.0 - 100.0
	if finalScore < 0.0 {
		return 0.0
	}
	if finalScore > 100.0 {
		return 100.0
	}
	return finalScore
}

// GetRiskLevel converts a numeric score into a standardized risk tier.
// Risk Tiers:
//   CRITICAL: 0 - 39
//   HIGH:     40 - 64
//   MEDIUM:   65 - 84
//   LOW:      85 - 100
func (r *RiskEngine) GetRiskLevel(score float64) Severity {
	switch {
	case score < 40.0:
		return SeverityCritical
	case score < 65.0:
		return SeverityHigh
	case score < 85.0:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
