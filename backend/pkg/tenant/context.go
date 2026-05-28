package tenant

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
)

type contextKey string

const TenantIDKey contextKey = "tenant_id"

var tenantSchemaRegex = regexp.MustCompile(`^[a-z0-9_\-]+$`)

// WithTenant injects a validated tenant ID into the context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// FromContext extracts the tenant ID from the context.
func FromContext(ctx context.Context) (string, bool) {
	tenantID, ok := ctx.Value(TenantIDKey).(string)
	return tenantID, ok
}

// GetSchemaName constructs a standardized schema name for a tenant.
// Includes strict validation to prevent SQL injection in dynamic schema commands.
func GetSchemaName(tenantID string) (string, error) {
	if !tenantSchemaRegex.MatchString(tenantID) {
		return "", fmt.Errorf("invalid tenant identifier structure: %q", tenantID)
	}
	return fmt.Sprintf("tenant_%s", tenantID), nil
}

// ExecuteInTenantContext runs a query block with the schema search_path set strictly
// to the tenant's isolated database schema.
//
// Threat Mitigated: Cross-tenant data leakage due to default or mixed schema queries.
func ExecuteInTenantContext(ctx context.Context, db *sql.DB, fn func(ctx context.Context, tx *sql.Tx) error) error {
	tenantID, ok := FromContext(ctx)
	if !ok {
		return fmt.Errorf("tenant isolation violation: tenant ID missing from evaluation context")
	}

	schemaName, err := GetSchemaName(tenantID)
	if err != nil {
		return fmt.Errorf("tenant context validation failure: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tenant transaction: %w", err)
	}
	defer tx.Rollback()

	// Set search_path dynamically. Using schemaName which is strictly validated against a clean regex pattern.
	setSchemaQuery := fmt.Sprintf("SET LOCAL search_path TO %s;", schemaName)
	if _, err := tx.ExecContext(ctx, setSchemaQuery); err != nil {
		return fmt.Errorf("failed to restrict search_path to isolated tenant schema %q: %w", schemaName, err)
	}

	// Execute transaction block
	if err := fn(ctx, tx); err != nil {
		return err
	}

	return tx.Commit()
}
