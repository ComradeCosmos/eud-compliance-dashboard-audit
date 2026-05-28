package reconciler

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// IngestedDevice represents a device record arriving from one of the collectors.
type IngestedDevice struct {
	Name         string   `json:"name"`
	SerialNumber string   `json:"serial_number"`
	MacAddresses []string `json:"mac_addresses"`
	Manufacturer string   `json:"manufacturer"`
	OSFamily     string   `json:"os_family"`
	OSVersion    string   `json:"os_version"`
	OSBuild      string   `json:"os_build"`
	SourceSystem string   `json:"source_system"`
	RawPayload   []byte   `json:"raw_payload"`
}

// ReconciledDevice represents the canonical database structure.
type ReconciledDevice struct {
	ID            string    `json:"id"`
	CanonicalName string    `json:"canonical_name"`
	Aliases       []string  `json:"aliases"`
	SerialNumber  string    `json:"serial_number"`
	MacAddresses  []string  `json:"mac_addresses"`
	Fingerprint   string    `json:"fingerprint"`
	OSFamily      string    `json:"os_family"`
	OSVersion     string    `json:"os_version"`
	OSBuild       string    `json:"os_build"`
	OSEndOfLife   bool      `json:"os_end_of_life"`
	RiskScore     float64   `json:"risk_score"`
	RiskLevel     string    `json:"risk_level"`
	LastSeen      time.Time `json:"last_seen"`
}

// DeviceReconciler handles the 5-stage identity reconciliation pipeline.
type DeviceReconciler struct {
	db *sql.DB
}

func NewDeviceReconciler(db *sql.DB) *DeviceReconciler {
	return &DeviceReconciler{db: db}
}

// NormalizeName strips non-alphanumeric characters and converts to lowercase.
func NormalizeName(name string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9]`)
	return strings.ToLower(reg.ReplaceAllString(name, ""))
}

// ComputeFingerprint calculates SHA256(serial + MAC[0] + manufacturer).
func ComputeFingerprint(serial, mac0, manufacturer string) string {
	raw := fmt.Sprintf("%s:%s:%s",
		strings.TrimSpace(strings.ToLower(serial)),
		strings.TrimSpace(strings.ToLower(mac0)),
		strings.TrimSpace(strings.ToLower(manufacturer)),
	)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// LevenshteinDistance calculates the edit distance between two strings.
func LevenshteinDistance(s, t string) int {
	d := make([][]int, len(s)+1)
	for i := range d {
		d[i] = make([]int, len(t)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for j := 1; j <= len(t); j++ {
		for i := 1; i <= len(s); i++ {
			cost := 1
			if s[i-1] == t[j-1] {
				cost = 0
			}
			d[i][j] = int(math.Min(math.Min(
				float64(d[i-1][j]+1),
				float64(d[i][j-1]+1)),
				float64(d[i-1][j-1]+cost),
			))
		}
	}
	return d[len(s)][len(t)]
}

// ReconcileResult represents the decision of the pipeline.
type ReconcileResult struct {
	StageMatched    int           `json:"stage_matched"`
	ConfidenceScore float64       `json:"confidence_score"`
	Action          string        `json:"action"` // "AUTO_MERGE" or "HUMAN_QUEUE"
	MatchedDeviceID string        `json:"matched_device_id,omitempty"`
	AuditLogID      string        `json:"audit_log_id"`
}

// ReconcileDevice evaluates an incoming record and either merges or flags it for review.
//
// Stage 1: Exact Name Match (Normalized lower index lookup) -> 100% confidence -> AUTO_MERGE
// Stage 2: Hardware Fingerprint Match -> 95% confidence -> AUTO_MERGE
// Stage 3: Levenshtein Distance -> thresh: max(2, len/5), conf: 100 - (dist*15)% -> If >= 90% AUTO_MERGE, else HUMAN_QUEUE
// Stage 4: Semantic Cosine Similarity (Staged interface to Python ML sidecar)
// Stage 5: Human review queue routing
func (dr *DeviceReconciler) ReconcileDevice(ctx context.Context, tenantSchema string, device IngestedDevice) (ReconcileResult, error) {
	normName := NormalizeName(device.Name)
	var mac0 string
	if len(device.MacAddresses) > 0 {
		mac0 = device.MacAddresses[0]
	}
	fingerprint := ComputeFingerprint(device.SerialNumber, mac0, device.Manufacturer)

	// Establish search path context for tenant isolation
	// Validate tenantSchema strictly to prevent SQL injection in dynamic schema commands
	if !regexp.MustCompile(`^[a-z0-9_\-]+$`).MatchString(tenantSchema) {
		return ReconcileResult{}, fmt.Errorf("isolation context error: invalid schema identifier structure %q", tenantSchema)
	}

	setPathQuery := fmt.Sprintf("SET LOCAL search_path TO %s;", tenantSchema)
	_, err := dr.db.ExecContext(ctx, setPathQuery)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("isolation context error: %w", err)
	}

	// ----------------------------------------------------
	// Stage 1: Exact Normalized Name Match
	// ----------------------------------------------------
	var s1DeviceID string
	var s1Name string
	err = dr.db.QueryRowContext(ctx,
		"SELECT id, canonical_name FROM devices WHERE LOWER(canonical_name) = $1 OR $1 = ANY(aliases) LIMIT 1",
		normName).Scan(&s1DeviceID, &s1Name)
	if err == nil {
		return dr.processMerge(ctx, s1DeviceID, device.Name, 1, 100.0, "AUTO_MERGE")
	}

	// ----------------------------------------------------
	// Stage 2: Hardware Fingerprint Match (SHA256)
	// ----------------------------------------------------
	if fingerprint != "" {
		var s2DeviceID string
		err = dr.db.QueryRowContext(ctx,
			"SELECT id FROM devices WHERE fingerprint = $1 OR serial_number = $2 LIMIT 1",
			fingerprint, device.SerialNumber).Scan(&s2DeviceID)
		if err == nil {
			return dr.processMerge(ctx, s2DeviceID, device.Name, 2, 95.0, "AUTO_MERGE")
		}
	}

	// ----------------------------------------------------
	// Stage 3: Levenshtein Name Distance Match
	// ----------------------------------------------------
	rows, err := dr.db.QueryContext(ctx, "SELECT id, canonical_name FROM devices LIMIT 200") // Controlled subset
	if err == nil {
		defer rows.Close()
		bestDist := 999
		var bestDeviceID string
		var bestName string

		for rows.Next() {
			var dID, dName string
			if err := rows.Scan(&dID, &dName); err == nil {
				normDbName := NormalizeName(dName)
				dist := LevenshteinDistance(normName, normDbName)
				if dist < bestDist {
					bestDist = dist
					bestDeviceID = dID
					bestName = dName
				}
			}
		}

		if bestDeviceID != "" {
			nameLen := len(normName)
			threshold := int(math.Max(2, math.Floor(float64(nameLen)/5.0)))
			if bestDist <= threshold {
				confidence := 100.0 - float64(bestDist*15)
				action := "HUMAN_QUEUE"
				if confidence >= 90.0 { // Rule #8 boundary
					action = "AUTO_MERGE"
				}
				return dr.processMerge(ctx, bestDeviceID, device.Name, 3, confidence, action)
			}
		}
	}

	// ----------------------------------------------------
	// Stage 4/5: No matches found -> Route to Human Queue
	// ----------------------------------------------------
	// Create new canonical entry but flag it as unverified
	var newDeviceID string
	err = dr.db.QueryRowContext(ctx,
		`INSERT INTO devices (canonical_name, serial_number, mac_addresses, fingerprint, os_family, os_version, os_build, source_records) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		device.Name, device.SerialNumber, device.MacAddresses, fingerprint, device.OSFamily, device.OSVersion, device.OSBuild, []byte("{}")).Scan(&newDeviceID)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("failed to register new device: %w", err)
	}

	// Log queue routing to audit logs
	var auditID string
	err = dr.db.QueryRowContext(ctx,
		`INSERT INTO reconciliation_audit_log (source_device_name, target_device_id, stage_matched, confidence_score, decision, metadata) 
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		device.Name, newDeviceID, 5, 0.0, "HUMAN_QUEUE", []byte(`{"status": "needs_reconciliation_review"}`)).Scan(&auditID)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("failed to log audit entry: %w", err)
	}

	return ReconcileResult{
		StageMatched:    5,
		ConfidenceScore: 0.0,
		Action:          "HUMAN_QUEUE",
		MatchedDeviceID: newDeviceID,
		AuditLogID:      auditID,
	}, nil
}

// processMerge writes an audit record and executes the final action state.
func (dr *DeviceReconciler) processMerge(ctx context.Context, targetID, sourceName string, stage int, confidence float64, action string) (ReconcileResult, error) {
	var auditID string
	err := dr.db.QueryRowContext(ctx,
		`INSERT INTO reconciliation_audit_log (source_device_name, target_device_id, stage_matched, confidence_score, decision, metadata) 
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		sourceName, targetID, stage, confidence, action, []byte(fmt.Sprintf(`{"matched_stage": %d, "confidence": %.2f}`, stage, confidence))).Scan(&auditID)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("failed to write reconciliation audit log: %w", err)
	}

	return ReconcileResult{
		StageMatched:    stage,
		ConfidenceScore: confidence,
		Action:          action,
		MatchedDeviceID: targetID,
		AuditLogID:      auditID,
	}, nil
}
