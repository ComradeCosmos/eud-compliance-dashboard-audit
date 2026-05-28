package reconciler

import (
	"testing"
)

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"DESKTOP-A1B2C3", "desktopa1b2c3"},
		{"LAPTOP_USER_12", "laptopuser12"},
		{"MacBook Pro 16\"", "macbookpro16"},
		{"  EUD-992!@# ", "eud992"},
	}

	for _, tc := range tests {
		actual := NormalizeName(tc.input)
		if actual != tc.expected {
			t.Errorf("NormalizeName(%q) = %q; expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s        string
		t        string
		expected int
	}{
		{"desktop", "desktop", 0},
		{"desktop", "desktob", 1},
		{"laptop", "lap", 3},
		{"macbook", "mcbook", 1},
		{"", "test", 4},
		{"test", "", 4},
	}

	for _, tc := range tests {
		actual := LevenshteinDistance(tc.s, tc.t)
		if actual != tc.expected {
			t.Errorf("LevenshteinDistance(%q, %q) = %d; expected %d", tc.s, tc.t, actual, tc.expected)
		}
	}
}

func TestComputeFingerprint(t *testing.T) {
	serial := "SN12345678"
	mac0 := "00:1A:2B:3C:4D:5E"
	manufacturer := "Dell Inc."

	fp1 := ComputeFingerprint(serial, mac0, manufacturer)
	fp2 := ComputeFingerprint("SN12345678", "00:1A:2B:3C:4D:5E", "Dell Inc.")
	fp3 := ComputeFingerprint("sn12345678", "00:1a:2b:3c:4d:5e", "dell inc.")

	if len(fp1) != 64 {
		t.Errorf("expected SHA256 hex string of length 64, got length %d", len(fp1))
	}

	if fp1 != fp2 {
		t.Errorf("expected deterministic fingerprint generation, fp1 != fp2")
	}

	if fp1 != fp3 {
		t.Errorf("expected case-insensitive normalization before fingerprint generation")
	}
}
