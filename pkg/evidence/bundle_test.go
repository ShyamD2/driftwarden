package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestSaveAndLoadEvidenceBundle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dw-evidence-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	report := &models.ScanReport{
		ReportSchemaVersion: "1.0.0",
		ToolVersion:         "1.0.0",
		ScanID:              "scan-bundle-test",
		Timestamp:           "2026-10-05T12:00:00Z",
		AccountID:           "123456789012",
		Regions:             []string{"us-east-1"},
		Status:              "COMPLETE",
		TotalScanned:        2,
		TotalDrift:          1,
		Items: []models.DriftItem{
			{
				Type:     models.DriftShadow,
				Severity: models.SeverityHigh,
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue",
					Type:        "aws_instance",
					ProviderID:  "i-rogue",
				},
			},
		},
	}

	resources := []models.CanonicalResource{
		{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-managed",
			Type:        "aws_instance",
		},
		{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue",
			Type:        "aws_instance",
		},
	}

	// 1. Save
	if err := SaveEvidenceBundle(tmpDir, report, resources); err != nil {
		t.Fatalf("SaveEvidenceBundle failed: %v", err)
	}

	// Verify all 6 required forensic files exist
	expectedFiles := []string{
		"report.json",
		"resources.ndjson",
		"provenance.json",
		"manifest.json",
		"schema_version.txt",
		"checksums.txt",
	}
	for _, f := range expectedFiles {
		p := filepath.Join(tmpDir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("expected evidence file %s does not exist", f)
		}
	}

	// Verify Checksums File Integrity
	checksumsData, err := os.ReadFile(filepath.Join(tmpDir, "checksums.txt"))
	if err != nil {
		t.Fatalf("failed to read checksums.txt: %v", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(checksumsData)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		expectedHash := parts[0]
		fileName := parts[1]

		fileBytes, err := os.ReadFile(filepath.Join(tmpDir, fileName))
		if err != nil {
			t.Fatalf("failed to read %s: %v", fileName, err)
		}
		actualHashBytes := sha256.Sum256(fileBytes)
		actualHash := hex.EncodeToString(actualHashBytes[:])

		if expectedHash != actualHash {
			t.Errorf("checksum mismatch for %s: expected %s, got %s", fileName, expectedHash, actualHash)
		}
	}

	// 2. Load
	loadedReport, loadedResources, err := LoadEvidenceBundle(tmpDir)
	if err != nil {
		t.Fatalf("LoadEvidenceBundle failed: %v", err)
	}

	if loadedReport.ScanID != "scan-bundle-test" {
		t.Errorf("expected ScanID scan-bundle-test, got %s", loadedReport.ScanID)
	}
	if len(loadedResources) != 2 {
		t.Errorf("expected 2 resources loaded from ndjson, got %d", len(loadedResources))
	}
	if len(loadedReport.Items) != 1 {
		t.Errorf("expected 1 drift item in loaded report, got %d", len(loadedReport.Items))
	}
}
