package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"gopkg.in/yaml.v3"

	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	"github.com/ShyamD2/driftwarden/pkg/collector"
	"github.com/ShyamD2/driftwarden/pkg/config"
	"github.com/ShyamD2/driftwarden/pkg/diff"
	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/evidence"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/normalizer"
	"github.com/ShyamD2/driftwarden/pkg/printer"
	"github.com/ShyamD2/driftwarden/pkg/rules"
	"github.com/ShyamD2/driftwarden/pkg/terraform"
)

type scanPipelineResult struct {
	Report       *models.ScanReport
	AllResources []models.CanonicalResource
	Errors       []error
}

func runScanPipeline(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*scanPipelineResult, error) {
	result := &scanPipelineResult{}

	// 1. Desired Plane (HCL)
	var desiredResources []models.CanonicalResource
	defaultRegion := "us-east-1"
	if len(cfg.Regions) > 0 {
		defaultRegion = cfg.Regions[0]
	}
	if cfg.HCLDir != "" {
		if stat, err := os.Stat(cfg.HCLDir); err == nil && stat.IsDir() {
			cp := terraform.NewConfigParser(defaultRegion, "")
			parsedDesired, _, err := cp.ParseDirectory(cfg.HCLDir)
			if err != nil {
				logger.Warn("Failed to parse HCL directory", "hcl_dir", cfg.HCLDir, "error", err)
			} else {
				desiredResources = parsedDesired
				logger.Debug("Parsed desired HCL resources", "count", len(desiredResources))
			}
		}
	}

	// 2. State Plane (tfstate)
	var stateResources []models.CanonicalResource
	if cfg.TFStatePath != "" {
		if _, err := os.Stat(cfg.TFStatePath); err == nil {
			sp := terraform.NewStateParser(defaultRegion, "")
			parsedState, _, err := sp.ParseFile(cfg.TFStatePath)
			if err != nil {
				logger.Warn("Failed to parse local state file", "path", cfg.TFStatePath, "error", err)
				result.Errors = append(result.Errors, err)
			} else {
				stateResources = parsedState
				logger.Debug("Parsed Terraform state resources", "count", len(stateResources))
			}
		}
	}

	// 3. Live Plane (AWS / LocalStack)
	var liveResources []models.CanonicalResource
	awsCfg := aws.Config{
		Region: defaultRegion,
	}
	if cfg.LocalStackEndpoint != "" {
		awsCfg.BaseEndpoint = aws.String(cfg.LocalStackEndpoint)
	}

	dispatcher := collector.NewDispatcher(cfg.Concurrency, cfg.RateLimit, nil)
	discoveredLive, liveErrs := dispatcher.Dispatch(ctx, awsCfg, cfg.Regions, nil)
	if len(liveErrs) > 0 {
		for _, e := range liveErrs {
			classified := dwErrors.Classify(e)
			if classified.Code == dwErrors.ErrAccessDenied {
				logger.Warn("AWS access denied during collection", "error", e)
			} else {
				logger.Debug("Collector error", "error", e)
			}
			result.Errors = append(result.Errors, e)
		}
	}
	liveResources = discoveredLive

	// 4. Policy-as-Code Ignore Engine
	ignoreEngine, _ := normalizer.LoadIgnoreFile(".driftwardenignore")
	if ignoreEngine == nil {
		ignoreEngine = normalizer.NewIgnoreEngine(nil)
	}
	norm := normalizer.NewNormalizer(cfg.IncludeSystemDefaults)

	// 5. Correlate across D, S, L
	comparator := diff.NewComparator(diff.ComparatorOptions{
		IncludeLowConfidence:  cfg.IncludeLowConfidence,
		IncludeSystemDefaults: cfg.IncludeSystemDefaults,
		IgnoreEngine:          ignoreEngine,
		Normalizer:            norm,
	})

	scanID := fmt.Sprintf("scan-%d", time.Now().Unix())
	accountID := resolveAccountID(stateResources, liveResources, desiredResources)
	report := comparator.Correlate(desiredResources, stateResources, liveResources, scanID, accountID, cfg.Regions)

	// Invariant: check if any collection errors had AccessDenied
	for _, e := range result.Errors {
		c := dwErrors.Classify(e)
		if c.Code == dwErrors.ErrAccessDenied {
			report.Status = "PARTIAL_SCAN"
			report.AccessDeniedCount++
		}
	}

	// 6. Security Analysis & Cost Estimation
	var costProvider analyzer.CostProvider
	if cfg.NoCost {
		costProvider = &analyzer.DisabledCostProvider{}
	} else {
		costProvider, _ = analyzer.NewStaticCostProvider(cfg.CostRegion, nil)
	}

	securityEngine := rules.NewDefaultEngine()
	securityEngine.AnalyzeReport(report, liveResources, costProvider)

	// 7. Inventory Merger
	allResources := mergeAllResources(desiredResources, stateResources, liveResources)

	// 8. Evidence Bundling
	if cfg.SaveEvidenceDir != "" {
		if err := evidence.SaveEvidenceBundle(cfg.SaveEvidenceDir, report, allResources); err != nil {
			logger.Error("Failed to save evidence bundle", "dir", cfg.SaveEvidenceDir, "error", err)
		} else {
			logger.Info("Saved audit evidence bundle", "dir", cfg.SaveEvidenceDir)
		}
	}

	result.Report = report
	result.AllResources = allResources
	return result, nil
}

func renderReport(cfg *config.Config, report *models.ScanReport) error {
	var dest io.Writer = os.Stdout
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		dest = f
	}

	switch strings.ToLower(cfg.Format) {
	case "json":
		return printer.PrintJSON(dest, report)
	case "junit", "xml":
		return printer.PrintJUnit(dest, report)
	case "yaml", "yml":
		enc := yaml.NewEncoder(dest)
		return enc.Encode(report)
	default:
		return printer.PrintTable(dest, report, cfg.NoColor)
	}
}

func resolveAccountID(slices ...[]models.CanonicalResource) string {
	for _, s := range slices {
		for _, r := range s {
			if r.AccountID != "" {
				return r.AccountID
			}
		}
	}
	return "123456789012"
}

func mergeAllResources(slices ...[]models.CanonicalResource) []models.CanonicalResource {
	seen := make(map[string]bool)
	var merged []models.CanonicalResource
	for _, s := range slices {
		for _, r := range s {
			key := r.CanonicalID
			if key == "" {
				key = r.Type + ":" + r.Region + ":" + r.ProviderID
			}
			if !seen[key] {
				seen[key] = true
				merged = append(merged, r)
			}
		}
	}
	return merged
}
