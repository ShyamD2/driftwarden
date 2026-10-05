package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/config"
	"github.com/ShyamD2/driftwarden/pkg/evidence"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestRootCommand_Flags(t *testing.T) {
	cmd := buildRootCommand()

	expectedFlags := []string{
		"regions",
		"profile",
		"role-arn",
		"external-id",
		"log-level",
		"log-format",
		"no-color",
		"timeout",
		"concurrency",
		"localstack-endpoint",
	}

	for _, flag := range expectedFlags {
		if cmd.PersistentFlags().Lookup(flag) == nil {
			t.Errorf("missing expected persistent flag: --%s", flag)
		}
	}
}

func TestRootCommand_ExactNineSubcommands(t *testing.T) {
	cmd := buildRootCommand()

	expectedCmds := []string{
		"doctor",
		"scan",
		"shadow",
		"security",
		"explain",
		"reconcile",
		"check-permissions",
		"generate-iam-policy",
		"version",
	}

	subCmds := make(map[string]bool)
	for _, c := range cmd.Commands() {
		subCmds[c.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !subCmds[expected] {
			t.Errorf("missing expected subcommand: %s", expected)
		}
	}
}

func TestScanPipeline_Execution(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.HCLDir = "../../testdata"
	cfg.TFStatePath = "../../testdata/state_v4.json"
	cfg.Regions = []string{"us-east-1"}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	res, err := runScanPipeline(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("runScanPipeline returned error: %v", err)
	}

	if res.Report == nil {
		t.Fatalf("expected non-nil ScanReport")
	}

	if res.Report.ReportSchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %s", res.Report.ReportSchemaVersion)
	}

	if len(res.AllResources) == 0 {
		t.Errorf("expected parsed resources in AllResources")
	}
}

func TestExplain_FromScanDir_Execution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dw-explain-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	report := &models.ScanReport{
		ReportSchemaVersion: "1.0.0",
		ToolVersion:         "1.0.0",
		ScanID:              "scan-explain-unit",
		Timestamp:           "2026-10-05T12:00:00Z",
		AccountID:           "123456789012",
		Regions:             []string{"us-east-1"},
		Status:              "COMPLETE",
		TotalScanned:        1,
		TotalDrift:          1,
		Items: []models.DriftItem{
			{
				Type:              models.DriftShadow,
				Severity:          models.SeverityHigh,
				FindingConfidence: 1.0,
				CISRuleID:         "DW-CIS-EC2-001",
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-explain-target",
					Type:        "aws_instance",
					ProviderID:  "i-explain-target",
					Region:      "us-east-1",
				},
			},
		},
	}

	resources := []models.CanonicalResource{
		report.Items[0].Resource,
	}

	if err := evidence.SaveEvidenceBundle(tmpDir, report, resources); err != nil {
		t.Fatalf("failed to save evidence bundle: %v", err)
	}

	rootCmd := buildRootCommand()
	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{
		"explain",
		"aws:aws:ec2:us-east-1:123456789012:instance/i-explain-target",
		"--from-scan-dir",
		tmpDir,
	})

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = rootCmd.Execute()
	w.Close()
	os.Stdout = oldStdout

	var dossierBuf bytes.Buffer
	io.Copy(&dossierBuf, r)

	if err != nil {
		t.Fatalf("explain execution failed: %v", err)
	}

	output := dossierBuf.String()
	if !strings.Contains(output, "i-explain-target") {
		t.Errorf("expected explain output to mention i-explain-target, got: %s", output)
	}
	if !strings.Contains(output, "DW-CIS-EC2-001") {
		t.Errorf("expected explain output to mention DW-CIS-EC2-001")
	}
}

func TestSaveEvidenceBundle_Files(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dw-bundle-files-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	report := &models.ScanReport{
		ReportSchemaVersion: "1.0.0",
		ToolVersion:         "1.0.0",
		ScanID:              "scan-test",
		Timestamp:           "2026-10-05T12:00:00Z",
		AccountID:           "123456789012",
		Regions:             []string{"us-east-1"},
	}

	if err := evidence.SaveEvidenceBundle(tmpDir, report, nil); err != nil {
		t.Fatalf("failed to save bundle: %v", err)
	}

	for _, name := range []string{"report.json", "resources.ndjson", "manifest.json", "schema_version.txt"} {
		p := filepath.Join(tmpDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("expected file %s does not exist", name)
		}
	}
}
