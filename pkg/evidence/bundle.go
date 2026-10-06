package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/version"
)

// Manifest defines the inventory, provenance, and cryptographic integrity metadata.
type Manifest struct {
	SchemaVersion  string            `json:"schema_version"`
	ToolVersion    string            `json:"tool_version"`
	GitCommit      string            `json:"git_commit"`
	StateHash      string            `json:"state_hash"`
	ResourceCount  int               `json:"resource_count"`
	ScanID         string            `json:"scan_id"`
	Timestamp      string            `json:"timestamp"`
	AccountID      string            `json:"account_id"`
	Regions        []string          `json:"regions"`
	TotalResources int               `json:"total_resources"`
	TotalDrift     int               `json:"total_drift"`
	Status         string            `json:"status"`
	Files          []string          `json:"files"`
	Checksums      map[string]string `json:"checksums"` // SHA-256 per file
}

// FindingProvenance captures cryptographic reproducibility for an individual finding.
type FindingProvenance struct {
	FindingID         string  `json:"finding_id"`
	ResourceID        string  `json:"resource_id"`
	CanonicalID       string  `json:"canonical_id"`
	DriftType         string  `json:"drift_type"`
	Severity          string  `json:"severity"`
	ObservedAt        string  `json:"observed_at"`
	FindingConfidence float64 `json:"confidence"`
	CISRuleID         string  `json:"cis_rule_id,omitempty"`
	EvidenceHash      string  `json:"evidence_hash"`
}

// ProvenanceReport groups provenance across all scan findings.
type ProvenanceReport struct {
	ScanID      string              `json:"scan_id"`
	ToolVersion string              `json:"tool_version"`
	GeneratedAt string              `json:"generated_at"`
	Findings    []FindingProvenance `json:"findings"`
}

type bundleOptions struct {
	gitCommit  string
	stateBytes []byte
	stateHash  string
}

// BundleOption configures evidence bundle packaging.
type BundleOption func(*bundleOptions)

// WithGitCommit explicitly overrides the git commit recorded in the manifest.
func WithGitCommit(commit string) BundleOption {
	return func(o *bundleOptions) {
		o.gitCommit = commit
	}
}

// WithStateContent supplies the raw tfstate content bytes and computes its SHA-256 state_hash.
func WithStateContent(content []byte) BundleOption {
	return func(o *bundleOptions) {
		o.stateBytes = content
		o.stateHash = ComputeStateHash(content)
	}
}

// WithStateHash explicitly sets the state_hash hexadecimal string.
func WithStateHash(hash string) BundleOption {
	return func(o *bundleOptions) {
		o.stateHash = hash
	}
}

// ComputeStateHash calculates the SHA-256 hex digest of terraform state content.
func ComputeStateHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// HashBytes computes the SHA-256 hex digest of arbitrary bytes.
func HashBytes(data []byte) string {
	return ComputeStateHash(data)
}

// SaveEvidenceBundle writes comprehensive forensic artifacts to targetDir.
func SaveEvidenceBundle(targetDir string, report *models.ScanReport, allResources []models.CanonicalResource, opts ...BundleOption) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	var optCfg bundleOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&optCfg)
		}
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create evidence directory: %w", err)
	}

	checksums := make(map[string]string)

	// 1. report.json
	reportPath := filepath.Join(targetDir, "report.json")
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize report.json: %w", err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0644); err != nil {
		return fmt.Errorf("failed to write report.json: %w", err)
	}
	checksums["report.json"] = hashBytes(reportBytes)

	// 2. resources.ndjson
	ndjsonPath := filepath.Join(targetDir, "resources.ndjson")
	ndFile, err := os.Create(ndjsonPath)
	if err != nil {
		return fmt.Errorf("failed to create resources.ndjson: %w", err)
	}
	defer ndFile.Close()

	ndWriter := bufio.NewWriter(ndFile)
	var ndBuffer []byte
	for _, res := range allResources {
		line, err := json.Marshal(res)
		if err != nil {
			return fmt.Errorf("failed to serialize resource line: %w", err)
		}
		ndBuffer = append(ndBuffer, append(line, '\n')...)
		if _, err := ndWriter.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("failed to write to resources.ndjson: %w", err)
		}
	}
	if err := ndWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush resources.ndjson: %w", err)
	}
	checksums["resources.ndjson"] = hashBytes(ndBuffer)

	// 3. provenance.json
	provReport := ProvenanceReport{
		ScanID:      report.ScanID,
		ToolVersion: report.ToolVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:    make([]FindingProvenance, 0, len(report.Items)),
	}

	for i, item := range report.Items {
		itemBytes, _ := json.Marshal(item)
		prov := FindingProvenance{
			FindingID:         fmt.Sprintf("finding-%s-%04d", report.ScanID, i+1),
			ResourceID:        item.Resource.ProviderID,
			CanonicalID:       item.Resource.CanonicalID,
			DriftType:         string(item.Type),
			Severity:          string(item.Severity),
			ObservedAt:        report.Timestamp,
			FindingConfidence: item.FindingConfidence,
			CISRuleID:         item.CISRuleID,
			EvidenceHash:      hashBytes(itemBytes),
		}
		provReport.Findings = append(provReport.Findings, prov)
	}

	provBytes, err := json.MarshalIndent(provReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal provenance.json: %w", err)
	}
	provPath := filepath.Join(targetDir, "provenance.json")
	if err := os.WriteFile(provPath, provBytes, 0644); err != nil {
		return fmt.Errorf("failed to write provenance.json: %w", err)
	}
	checksums["provenance.json"] = hashBytes(provBytes)

	// 4. schema_version.txt
	schemaVersionPath := filepath.Join(targetDir, "schema_version.txt")
	schemaVersionBytes := []byte("1.0.0\n")
	if err := os.WriteFile(schemaVersionPath, schemaVersionBytes, 0644); err != nil {
		return fmt.Errorf("failed to write schema_version.txt: %w", err)
	}
	checksums["schema_version.txt"] = hashBytes(schemaVersionBytes)

	// Determine metadata for manifest
	toolVer := report.ToolVersion
	if toolVer == "" {
		toolVer = version.GetVersion()
	}

	commit := optCfg.gitCommit
	if commit == "" {
		commit = version.GetGitCommit()
	}
	if commit == "" {
		commit = "dev"
	}

	stateHash := optCfg.stateHash
	if stateHash == "" && report.StateHash != "" {
		stateHash = report.StateHash
	}
	if stateHash == "" {
		if content, err := os.ReadFile("terraform.tfstate"); err == nil {
			stateHash = ComputeStateHash(content)
		}
	}
	if stateHash == "" {
		stateHash = ComputeStateHash([]byte{})
	}

	// 5. manifest.json
	manifest := Manifest{
		SchemaVersion:  "1.0.0",
		ToolVersion:    toolVer,
		GitCommit:      commit,
		StateHash:      stateHash,
		ResourceCount:  len(allResources),
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
			"provenance.json",
			"manifest.json",
			"schema_version.txt",
			"checksums.txt",
		},
		Checksums: checksums,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize manifest.json: %w", err)
	}
	manifestPath := filepath.Join(targetDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0644); err != nil {
		return fmt.Errorf("failed to write manifest.json: %w", err)
	}
	checksums["manifest.json"] = hashBytes(manifestBytes)

	// 6. checksums.txt (standard sha256sum format)
	var checksumLines []string
	var sortedFiles []string
	for f := range checksums {
		sortedFiles = append(sortedFiles, f)
	}
	sort.Strings(sortedFiles)

	for _, f := range sortedFiles {
		checksumLines = append(checksumLines, fmt.Sprintf("%s  %s", checksums[f], f))
	}
	checksumsPath := filepath.Join(targetDir, "checksums.txt")
	if err := os.WriteFile(checksumsPath, []byte(strings.Join(checksumLines, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write checksums.txt: %w", err)
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

// LoadManifest reads and deserializes the manifest.json from targetDir.
func LoadManifest(targetDir string) (*Manifest, error) {
	manifestPath := filepath.Join(targetDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest.json from evidence dir: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest.json: %w", err)
	}
	return &manifest, nil
}

func hashBytes(data []byte) string {
	return HashBytes(data)
}
