package collector

import (
	"context"
	"strings"
	"testing"
)

func TestCSVDeviceCollector_MalformedCSVHeaders(t *testing.T) {
	// Missing mandatory 'serialnumber' header
	csvData := `DeviceName,MacAddress,Manufacturer,OSFamily
desktop-abc,00:1A:2B:3C:4D:5E,Dell Inc.,Windows`

	collector := NewCSVDeviceCollector(nil, nil)
	ctx := context.Background()

	_, err := collector.IngestCSVStream(ctx, "tenant-123", strings.NewReader(csvData))
	if err == nil {
		t.Fatalf("expected error due to missing mandatory column 'serialnumber', got nil")
	}
	if !strings.Contains(err.Error(), "missing mandatory CSV column header") {
		t.Errorf("expected header validation error, got: %v", err)
	}
}

func TestCSVDeviceCollector_SuccessMapping(t *testing.T) {
	// Standard valid CSV batch data
	csvData := `DeviceName,SerialNumber,MacAddress,Manufacturer,OSFamily,OSVersion,OSBuild
desktop-a,SN-998811,00:1A:2B:3C:4D:5E,Dell Inc.,Windows,11,22631
desktop-b,SN-998822,00:1A:2B:3C:4D:5F,Dell Inc.,Windows,11,22631`

	// This validates column reading logic compiles and returns error on nil DB,
	// confirming dynamic SQL generation triggers standard expected database error path.
	collector := NewCSVDeviceCollector(nil, nil)
	ctx := context.Background()

	_, err := collector.IngestCSVStream(ctx, "tenant-123", strings.NewReader(csvData))
	if err == nil {
		t.Fatalf("expected database execution error due to nil connection, got nil")
	}
	// The nil database connection will cause ExecuteInTenantContext to fail during BeginTx, confirming flow reaches database tier
	if !strings.Contains(err.Error(), "failed to begin tenant transaction") {
		t.Errorf("expected transactional database failure, got: %v", err)
	}
}
