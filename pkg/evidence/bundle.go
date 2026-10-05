package evidence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// Manifest defines the inventory and integrity metadata for a saved scan bundle.
type Manifest struct {
	SchemaVersion  string   `json:"schema_version"`
	ToolVersion    string   `json:"tool_version"`
	ScanID         string   `json:"scan_id"`
	Timestamp      string   `json:"timestamp"`
	AccountID      string   `json:"account_id"`
	Regions        []string `json:"regions"`
	TotalResources int      `json:"total_resources"`
	TotalDrift     int      `json:"total_drift"`
	Status         string   `json:"status"`
	Files          []string `json:"files"`
}

// SaveEvidenceBundle writes the four required evidence bundle artifacts to targetDir.
func SaveEvidenceBundle(targetDir string, report *models.ScanReport, allResources []models.CanonicalResource) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create evidence directory: %w", err)
	}

	// 1. report.json
	reportPath := filepath.Join(targetDir, "report.json")
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize report.json: %w", err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0644); err != nil {
		return fmt.Errorf("failed to write report.json: %w", err)
	}

	// 2. resources.ndjson
	ndjsonPath := filepath.Join(targetDir, "resources.ndjson")
	ndFile, err := os.Create(ndjsonPath)
	if err != nil {
		return fmt.Errorf("failed to create resources.ndjson: %w", err)
	}
	defer ndFile.Close()

	ndWriter := bufio.NewWriter(ndFile)
	for _, res := range allResources {
		line, err := json.Marshal(res)
		if err != nil {
			return fmt.Errorf("failed to serialize resource line: %w", err)
		}
		if _, err := ndWriter.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("failed to write to resources.ndjson: %w", err)
		}
	}
	if err := ndWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush resources.ndjson: %w", err)
	}

	// 3. schema_version.txt
	schemaVersionPath := filepath.Join(targetDir, "schema_version.txt")
	if err := os.WriteFile(schemaVersionPath, []byte("1.0.0\n"), 0644); err != nil {
		return fmt.Errorf("failed to write schema_version.txt: %w", err)
	}

	// 4. manifest.json
	manifest := Manifest{
		SchemaVersion:  "1.0.0",
		ToolVersion:    report.ToolVersion,
		ScanID:         report.ScanID,
		Timestamp:      report.Timestamp,
		AccountID:      report.AccountID,
		Regions:        report.Regions,
		TotalResources: len(allResources),
		TotalDrift:     report.TotalDrift,
		Status:         report.Status,
		Files: []string{
			"report.json",
			"resources.ndjson",
			"manifest.json",
			"schema_version.txt",
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize manifest.json: %w", err)
	}
	manifestPath := filepath.Join(targetDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0644); err != nil {
		return fmt.Errorf("failed to write manifest.json: %w", err)
	}

	return nil
}

// LoadEvidenceBundle reads and deserializes an evidence bundle from targetDir.
func LoadEvidenceBundle(targetDir string) (*models.ScanReport, []models.CanonicalResource, error) {
	reportPath := filepath.Join(targetDir, "report.json")
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read report.json from evidence dir: %w", err)
	}

	var report models.ScanReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal report.json: %w", err)
	}

	ndjsonPath := filepath.Join(targetDir, "resources.ndjson")
	ndFile, err := os.Open(ndjsonPath)
	if err != nil {
		// If ndjson is missing, return report with empty resources
		return &report, nil, nil
	}
	defer ndFile.Close()

	var resources []models.CanonicalResource
	scanner := bufio.NewScanner(ndFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var res models.CanonicalResource
		if err := json.Unmarshal(line, &res); err == nil {
			resources = append(resources, res)
		}
	}

	return &report, resources, scanner.Err()
}
