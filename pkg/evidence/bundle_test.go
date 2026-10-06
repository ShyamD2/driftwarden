package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	// 3. Verify Manifest Metadata & Cryptographic Hashes
	manifest, err := LoadManifest(tmpDir)
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}
	if manifest.ToolVersion != "1.0.0" {
		t.Errorf("expected manifest tool_version 1.0.0, got %s", manifest.ToolVersion)
	}
	if manifest.GitCommit == "" {
		t.Errorf("expected non-empty git_commit in manifest")
	}
	if manifest.StateHash == "" {
		t.Errorf("expected non-empty state_hash in manifest")
	}
	if manifest.ResourceCount != 2 {
		t.Errorf("expected manifest resource_count 2, got %d", manifest.ResourceCount)
	}
	if manifest.ScanID != "scan-bundle-test" {
		t.Errorf("expected manifest scan_id scan-bundle-test, got %s", manifest.ScanID)
	}
}

func TestManifestCryptographicHashesAndMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dw-manifest-hash-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mockTFState := []byte(`{"version":4,"serial":10,"resources":[{"type":"aws_vpc","name":"main"}]}`)
	expectedStateHash := ComputeStateHash(mockTFState)
	testCommit := "abc123456789def0123456789abc123456789def"

	report := &models.ScanReport{
		ToolVersion: "1.2.3",
		ScanID:      "scan-crypto-hash-99",
		Timestamp:   "2026-10-06T12:00:00Z",
		AccountID:   "123456789012",
		Regions:     []string{"us-east-1"},
		Status:      "COMPLETE",
	}

	resources := []models.CanonicalResource{
		{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:vpc/vpc-1",
			Type:        "aws_vpc",
		},
		{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:subnet/sub-1",
			Type:        "aws_subnet",
		},
		{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-1",
			Type:        "aws_instance",
		},
	}

	err = SaveEvidenceBundle(tmpDir, report, resources,
		WithStateContent(mockTFState),
		WithGitCommit(testCommit),
	)
	if err != nil {
		t.Fatalf("SaveEvidenceBundle with state content failed: %v", err)
	}

	manifest, err := LoadManifest(tmpDir)
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}

	// Verify all 5 required manifest fields
	if manifest.ToolVersion != "1.2.3" {
		t.Errorf("expected tool_version 1.2.3, got %s", manifest.ToolVersion)
	}
	if manifest.GitCommit != testCommit {
		t.Errorf("expected git_commit %s, got %s", testCommit, manifest.GitCommit)
	}
	if manifest.StateHash != expectedStateHash {
		t.Errorf("expected state_hash %s, got %s", expectedStateHash, manifest.StateHash)
	}
	if manifest.ResourceCount != 3 {
		t.Errorf("expected resource_count 3, got %d", manifest.ResourceCount)
	}
	if manifest.ScanID != "scan-crypto-hash-99" {
		t.Errorf("expected scan_id scan-crypto-hash-99, got %s", manifest.ScanID)
	}

	// Verify raw JSON schema keys
	manifestBytes, err := os.ReadFile(filepath.Join(tmpDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read raw manifest.json: %v", err)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(manifestBytes, &rawMap); err != nil {
		t.Fatalf("failed to unmarshal raw manifest: %v", err)
	}

	requiredKeys := []string{"tool_version", "git_commit", "state_hash", "resource_count", "scan_id"}
	for _, key := range requiredKeys {
		val, exists := rawMap[key]
		if !exists || val == nil {
			t.Errorf("manifest.json missing required key %q in JSON payload", key)
		}
	}
}

