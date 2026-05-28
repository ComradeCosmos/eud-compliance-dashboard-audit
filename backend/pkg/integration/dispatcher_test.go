package integration

import (
	"context"
	"testing"
)

type MockVault struct {
	mockSecrets map[string]string
}

func (m *MockVault) GetIntegrationSecret(ctx context.Context, tenantID string, target IntegrationType) (string, error) {
	key := string(target) + "-" + tenantID
	secret, ok := m.mockSecrets[key]
	if !ok {
		return "", context.Canceled // Mocking unauthorized error boundary
	}
	return secret, nil
}

func TestDispatchCriticalAlert_Success(t *testing.T) {
	vault := &MockVault{
		mockSecrets: map[string]string{
			"SERVICENOW-tenant-xyz": "vault-dynamic-session-token-xyz",
		},
	}

	dispatcher := NewIntegrationDispatcher(vault)
	ctx := context.Background()

	err := dispatcher.DispatchCriticalAlert(ctx, "tenant-xyz", "device-456", 24.50, "SentinelOne inactive, BitLocker disabled")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDispatchCriticalAlert_VaultAuthFailure(t *testing.T) {
	vault := &MockVault{
		mockSecrets: map[string]string{}, // Empty, auth boundary fail
	}

	dispatcher := NewIntegrationDispatcher(vault)
	ctx := context.Background()

	err := dispatcher.DispatchCriticalAlert(ctx, "tenant-unauthorized", "device-456", 12.00, "BitLocker disabled")
	if err == nil {
		t.Fatalf("expected vault authorization failure error, got nil")
	}
}
