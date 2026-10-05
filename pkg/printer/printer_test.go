package printer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func sampleReport() *models.ScanReport {
	return &models.ScanReport{
		ReportSchemaVersion: "1.0.0",
		ToolVersion:         "1.0.0",
		ScanID:              "scan-test-123",
		Timestamp:           "2026-10-05T12:00:00Z",
		AccountID:           "123456789012",
		Regions:             []string{"us-east-1"},
		Status:              "COMPLETE",
		TotalScanned:        5,
		TotalDrift:          1,
		ExecutionTimeMs:     125,
		Items: []models.DriftItem{
			{
				Type:              models.DriftShadow,
				Severity:          models.SeverityHigh,
				FindingConfidence: 0.95,
				CISRuleID:         "DW-CIS-EC2-001",
				Cost: &models.CostEstimate{
					AmountMonthly: 7.59,
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue123",
					Type:        "aws_instance",
				},
			},
		},
	}
}

func TestPrintTable(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := PrintTable(&buf, report, false); err != nil {
		t.Fatalf("PrintTable failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "scan-test-123") {
		t.Errorf("expected table output to contain scan-test-123")
	}
	if !strings.Contains(out, "SHADOW_RESOURCE") {
		t.Errorf("expected table output to contain SHADOW_RESOURCE")
	}
	if !strings.Contains(out, "$7.59") {
		t.Errorf("expected table output to contain monthly cost $7.59")
	}
}

func TestPrintJSON(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := PrintJSON(&buf, report); err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}

	var parsed models.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse emitted JSON: %v", err)
	}

	if parsed.ScanID != "scan-test-123" {
		t.Errorf("expected scan_id scan-test-123, got %s", parsed.ScanID)
	}
	if parsed.ReportSchemaVersion != "1.0.0" {
		t.Errorf("expected schema_version 1.0.0, got %s", parsed.ReportSchemaVersion)
	}
	if len(parsed.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(parsed.Items))
	}
}

func TestPrintJUnit(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := PrintJUnit(&buf, report); err != nil {
		t.Fatalf("PrintJUnit failed: %v", err)
	}

	xmlStr := buf.String()
	if !strings.Contains(xmlStr, "<testsuites") {
		t.Errorf("expected <testsuites> in JUnit output")
	}
	if !strings.Contains(xmlStr, "<failure") {
		t.Errorf("expected <failure> element for drift item")
	}
	if !strings.Contains(xmlStr, "SHADOW_RESOURCE") {
		t.Errorf("expected failure message with SHADOW_RESOURCE")
	}
}

func TestPrintExplainDossier(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	err := PrintExplainDossier(&buf, "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue123", report, nil)
	if err != nil {
		t.Fatalf("PrintExplainDossier failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "DRIFTWARDEN DIAGNOSTIC DOSSIER") {
		t.Errorf("expected dossier header")
	}
	if !strings.Contains(out, "i-rogue123") {
		t.Errorf("expected provider ID in dossier")
	}
	if !strings.Contains(out, "DW-CIS-EC2-001") {
		t.Errorf("expected CIS rule in dossier")
	}
	if !strings.Contains(out, "$7.59") {
		t.Errorf("expected cost waste in dossier")
	}
}
