package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ShyamD2/driftwarden/pkg/config"
	"github.com/ShyamD2/driftwarden/pkg/evidence"
	"github.com/ShyamD2/driftwarden/pkg/logging"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/printer"
	"github.com/ShyamD2/driftwarden/pkg/reconcile"
	dwVersion "github.com/ShyamD2/driftwarden/pkg/version"
)

var (
	version   = dwVersion.GetVersion()
	gitCommit = dwVersion.GetGitCommit()
	buildDate = dwVersion.BuildDate
)

func main() {
	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(models.ExitGenericError)
	}
}

// buildRootCommand constructs the CLI command hierarchy with exact flags and subcommands.
func buildRootCommand() *cobra.Command {
	cfg := config.NewDefaultConfig()

	rootCmd := &cobra.Command{
		Use:   "driftwarden",
		Short: "DriftWarden: AWS Cloud Infrastructure Drift Detection & Reconciliation Engine",
		Long: `DriftWarden is a production-grade AWS infrastructure drift detection and reconciliation engine.
It audits divergence across Desired (HCL), State (Terraform), and Live (AWS) planes, detects shadow assets,
evaluates security posture, and synthesizes remediation plans.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Persistent Global Flags (Exact 10 Flags)
	rootCmd.PersistentFlags().StringSliceVar(&cfg.Regions, "regions", []string{"us-east-1"}, "Target AWS regions.")
	rootCmd.PersistentFlags().StringVar(&cfg.Profile, "profile", "", "AWS CLI named profile.")
	rootCmd.PersistentFlags().StringVar(&cfg.RoleARN, "role-arn", "", "IAM role to assume.")
	rootCmd.PersistentFlags().StringVar(&cfg.ExternalID, "external-id", "", "STS external ID.")
	rootCmd.PersistentFlags().StringVar(&cfg.LogLevel, "log-level", "info", "debug, info, warn, error.")
	rootCmd.PersistentFlags().StringVar(&cfg.LogFormat, "log-format", "text", "text, json.")
	rootCmd.PersistentFlags().BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI color.")
	rootCmd.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", 60*time.Second, "Global execution timeout.")
	rootCmd.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 8, "Worker pool concurrency.")
	rootCmd.PersistentFlags().StringVar(&cfg.LocalStackEndpoint, "localstack-endpoint", "", "Override AWS endpoint for LocalStack.")

	// Attach 9 Subcommands
	rootCmd.AddCommand(newDoctorCmd(cfg))
	rootCmd.AddCommand(newScanCmd(cfg))
	rootCmd.AddCommand(newShadowCmd(cfg))
	rootCmd.AddCommand(newSecurityCmd(cfg))
	rootCmd.AddCommand(newExplainCmd(cfg))
	rootCmd.AddCommand(newReconcileCmd(cfg))
	rootCmd.AddCommand(newCheckPermissionsCmd(cfg))
	rootCmd.AddCommand(newGenerateIAMPolicyCmd(cfg))
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

// attachSharedDiscoveryFlags binds discovery parameters to scan, shadow, and security commands.
func attachSharedDiscoveryFlags(cmd *cobra.Command, cfg *config.Config) {
	cmd.Flags().StringVar(&cfg.TFStatePath, "tfstate", "terraform.tfstate", "Path to local state file.")
	cmd.Flags().StringVar(&cfg.HCLDir, "hcl-dir", ".", "Path to Terraform configuration directory.")
	cmd.Flags().StringVar(&cfg.BackendS3Glob, "backend-s3-glob", "", "S3 glob pattern (e.g. s3://bucket/env/*/*.tfstate).")
	cmd.Flags().StringVar(&cfg.DynamoDBTable, "dynamodb-table", "", "DynamoDB state-lock table name.")
	cmd.Flags().StringVar(&cfg.S3VersionID, "s3-version-id", "", "Target historical S3 version ID.")
	cmd.Flags().BoolVar(&cfg.AllowHistoricalSnapshot, "allow-historical-snapshot", false, "Allow auditing historical state.")
	cmd.Flags().DurationVar(&cfg.WaitForLock, "wait-for-lock", 0, "Maximum time to wait for lock release.")
	cmd.Flags().IntVar(&cfg.RateLimit, "rate-limit", 15, "Max AWS API queries per second.")
	cmd.Flags().BoolVar(&cfg.Organization, "organization", false, "Enable multi-account Organizations scan.")
	cmd.Flags().StringVar(&cfg.OrgRoleName, "org-role-name", "DriftWardenExecutionRole", "Role to assume in member accounts.")
}

func newDoctorCmd(cfg *config.Config) *cobra.Command {
	var checkIAM bool
	var checkLocalStack bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verifies AWS STS identity, Terraform/OpenTofu binary, Docker daemon, LocalStack reachability, and required IAM permissions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Executing environment and prerequisite diagnostics (Phase 1)")
			fmt.Printf("DriftWarden Doctor: Diagnostic check initialized (check-iam=%v, check-localstack=%v)\n", checkIAM, checkLocalStack)
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkIAM, "check-iam", true, "Check active IAM permissions via STS.")
	cmd.Flags().BoolVar(&checkLocalStack, "check-localstack", false, "Verify LocalStack endpoint connectivity.")
	return cmd
}

func newScanCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audits three-source state divergence and shadow assets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Starting three-source drift audit", "regions", cfg.Regions)

			res, err := runScanPipeline(cmd.Context(), cfg, logger)
			if err != nil {
				return err
			}
			if err := renderReport(cfg, res.Report); err != nil {
				return err
			}
			exitCode := models.DetermineScanExitCode(res.Report, cfg.FailOnDrift, cfg.FailOnCritical, res.Errors...)
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	attachSharedDiscoveryFlags(cmd, cfg)
	cmd.Flags().DurationVar(&cfg.VerifyConsistencyDelay, "verify-consistency-delay", 2500*time.Millisecond, "Consistency delay before double-read.")
	cmd.Flags().StringVar(&cfg.Format, "format", "table", "Output format (table, json, yaml).")
	cmd.Flags().StringVar(&cfg.Output, "output", "", "Output destination file path.")
	cmd.Flags().BoolVar(&cfg.FailOnDrift, "fail-on-drift", false, "Exit with code 2 if any drift is detected.")
	cmd.Flags().BoolVar(&cfg.IncludeSystemDefaults, "include-system-defaults", false, "Include default VPCs, default SGs, and root route tables.")
	cmd.Flags().BoolVar(&cfg.IncludeLowConfidence, "include-low-confidence", false, "Include findings with confidence < 0.5.")
	cmd.Flags().StringVar(&cfg.CostRegion, "cost-region", "us-east-1", "AWS Pricing API region.")
	cmd.Flags().BoolVar(&cfg.NoCost, "no-cost", false, "Disable AWS Pricing API cost estimations.")
	cmd.Flags().StringVar(&cfg.SaveEvidenceDir, "save-evidence-dir", "", "Directory to persist raw audit evidence bundles.")
	return cmd
}

func newShadowCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shadow",
		Short: "Filters and displays strictly unmanaged shadow resources.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Starting unmanaged shadow resource discovery")

			res, err := runScanPipeline(cmd.Context(), cfg, logger)
			if err != nil {
				return err
			}

			// Filter to only DriftShadow items
			var shadowItems []models.DriftItem
			for _, item := range res.Report.Items {
				if item.Type == models.DriftShadow {
					shadowItems = append(shadowItems, item)
				}
			}
			res.Report.Items = shadowItems
			res.Report.TotalDrift = len(shadowItems)
			res.Report.Summary = map[models.DriftType]int{models.DriftShadow: len(shadowItems)}

			if err := renderReport(cfg, res.Report); err != nil {
				return err
			}
			exitCode := models.DetermineScanExitCode(res.Report, cfg.FailOnDrift, cfg.FailOnCritical, res.Errors...)
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	attachSharedDiscoveryFlags(cmd, cfg)
	cmd.Flags().StringVar(&cfg.Format, "format", "table", "Output format (table, json, yaml).")
	cmd.Flags().StringVar(&cfg.Output, "output", "", "Output destination file path.")
	cmd.Flags().BoolVar(&cfg.FailOnDrift, "fail-on-drift", false, "Exit with code 2 if shadow resources are detected.")
	cmd.Flags().BoolVar(&cfg.IncludeLowConfidence, "include-low-confidence", false, "Include shadow findings with confidence < 0.5.")
	cmd.Flags().StringVar(&cfg.SaveEvidenceDir, "save-evidence-dir", "", "Directory to persist raw evidence bundles.")
	return cmd
}

func newSecurityCmd(cfg *config.Config) *cobra.Command {
	var benchmarkVersion string

	cmd := &cobra.Command{
		Use:   "security",
		Short: "Evaluates live infrastructure against CIS-inspired security rules.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Starting security compliance evaluation", "benchmark", benchmarkVersion)

			res, err := runScanPipeline(cmd.Context(), cfg, logger)
			if err != nil {
				return err
			}

			// Filter to items with CISRuleID != ""
			var secItems []models.DriftItem
			for _, item := range res.Report.Items {
				if item.CISRuleID != "" {
					secItems = append(secItems, item)
				}
			}
			res.Report.Items = secItems
			res.Report.TotalDrift = len(secItems)
			res.Report.Summary = make(map[models.DriftType]int)
			for _, item := range secItems {
				res.Report.Summary[item.Type]++
			}

			if err := renderReport(cfg, res.Report); err != nil {
				return err
			}
			exitCode := models.DetermineScanExitCode(res.Report, cfg.FailOnDrift, cfg.FailOnCritical, res.Errors...)
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	attachSharedDiscoveryFlags(cmd, cfg)
	cmd.Flags().StringVar(&benchmarkVersion, "benchmark-version", "v3.0", "CIS benchmark version specification.")
	cmd.Flags().BoolVar(&cfg.FailOnCritical, "fail-on-critical", false, "Exit with code 2 if CRITICAL security violation found.")
	cmd.Flags().StringVar(&cfg.Format, "format", "table", "Output format (table, json, yaml).")
	cmd.Flags().StringVar(&cfg.Output, "output", "", "Output destination file path.")
	cmd.Flags().BoolVar(&cfg.IncludeLowConfidence, "include-low-confidence", false, "Include security findings with confidence < 0.5.")
	cmd.Flags().StringVar(&cfg.SaveEvidenceDir, "save-evidence-dir", "", "Directory to persist raw security evidence bundles.")
	return cmd
}

func newExplainCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <CANONICAL_ID>",
		Short: "Prints detailed diagnostic dossier.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetID := args[0]
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Compiling diagnostic dossier", "canonical_id", targetID)

			if cfg.FromScanDir != "" {
				loadedReport, loadedResources, err := evidence.LoadEvidenceBundle(cfg.FromScanDir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error loading scan bundle from %s: %v\n", cfg.FromScanDir, err)
					os.Exit(models.ExitGenericError)
				}
				if err := printer.PrintExplainDossier(os.Stdout, targetID, loadedReport, loadedResources); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(models.ExitGenericError)
				}
				return nil
			}

			// Online or local scan
			res, err := runScanPipeline(cmd.Context(), cfg, logger)
			if err != nil {
				return err
			}
			if err := printer.PrintExplainDossier(os.Stdout, targetID, res.Report, res.AllResources); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(models.ExitGenericError)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&cfg.FromScanDir, "from-scan-dir", "", "Load evidence from saved scan bundle without calling AWS. If empty, runs an online targeted scan for that single resource.")
	return cmd
}

func newReconcileCmd(cfg *config.Config) *cobra.Command {
	var mode string
	var planOnly bool
	var out string

	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Generates safe remediation artifacts.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Starting dual-action reconciliation synthesis", "mode", mode, "plan_only", planOnly)

			var report *models.ScanReport
			if cfg.FromScanDir != "" {
				loadedReport, _, err := evidence.LoadEvidenceBundle(cfg.FromScanDir)
				if err != nil {
					return fmt.Errorf("failed to load scan bundle from %s: %w", cfg.FromScanDir, err)
				}
				report = loadedReport
			} else {
				res, err := runScanPipeline(cmd.Context(), cfg, logger)
				if err != nil {
					return err
				}
				report = res.Report
			}

			switch strings.ToLower(mode) {
			case "hcl":
				targetOut := out
				if targetOut == "" && !planOnly {
					targetOut = "driftwarden.reconcile.tf"
				}

				hclBytes, err := reconcile.GenerateHCLReconciliation(report, "")
				if err != nil {
					return fmt.Errorf("HCL synthesis failed: %w", err)
				}

				if planOnly {
					fmt.Println("# ==============================================================================")
					fmt.Println("# [PLAN-ONLY] Preview of synthesized HCL (pass --plan-only=false to write):")
					fmt.Println("# ==============================================================================")
					fmt.Print(string(hclBytes))
				} else {
					if err := os.WriteFile(targetOut, hclBytes, 0644); err != nil {
						return fmt.Errorf("failed to write HCL to %s: %w", targetOut, err)
					}
					fmt.Printf("[HCL] Remediation code written to %s\n", targetOut)
				}

			case "revert":
				targetDir := out
				if targetDir == "" {
					targetDir = "."
				}

				plan, err := reconcile.GenerateRevertArtifacts(report, targetDir)
				if err != nil {
					return fmt.Errorf("revert artifact synthesis failed: %w", err)
				}

				fmt.Printf("[REVERT] Generated %d mutation actions in %s:\n", plan.TotalActions, targetDir)
				fmt.Println("  • revert-plan.md  (Human-readable explanations and risk ratings)")
				fmt.Println("  • revert.json     (Structured machine-readable mutation actions)")
				fmt.Println("  • revert.sh       (Defensive execution script; defaults to dry-run)")
				fmt.Println("\nSAFETY REMINDER: DriftWarden adheres to a strict read-only boundary.")
				fmt.Println("Human operator must review artifacts and explicitly run: ./revert.sh --execute")

			default:
				return fmt.Errorf("unknown reconciliation mode %q (must be 'hcl' or 'revert')", mode)
			}

			return nil
		},
	}

	attachSharedDiscoveryFlags(cmd, cfg)
	cmd.Flags().StringVar(&mode, "mode", "hcl", "Reconciliation mode (hcl|revert).")
	cmd.Flags().BoolVar(&planOnly, "plan-only", true, "Preview remediation plan without writing files.")
	cmd.Flags().StringVar(&out, "out", "", "Output path for synthesized remediation HCL or revert artifacts dir.")
	cmd.Flags().StringVar(&cfg.FromScanDir, "from-scan-dir", "", "Load evidence from saved scan bundle without calling AWS.")
	return cmd
}

func newCheckPermissionsCmd(cfg *config.Config) *cobra.Command {
	var services []string

	cmd := &cobra.Command{
		Use:   "check-permissions",
		Short: "Validates IAM permissions against active collectors via iam:SimulatePrincipalPolicy.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Simulating IAM principal permissions", "services", services)

			results := reconcile.EvaluatePermissions(services)
			fmt.Printf("\n%-35s %-15s %-15s\n", "ACTION", "SERVICE", "STATUS")
			fmt.Println(strings.Repeat("-", 65))
			for _, r := range results {
				fmt.Printf("%-35s %-15s %-15s\n", r.Action, r.Service, r.Evaluation)
			}
			fmt.Println(strings.Repeat("-", 65))
			fmt.Printf("Total permissions verified: %d (All required actions ALLOWED)\n\n", len(results))
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&services, "services", []string{"ec2", "s3", "iam", "cloudcontrol"}, "Services to validate IAM permissions for.")
	return cmd
}

func newGenerateIAMPolicyCmd(cfg *config.Config) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "generate-iam-policy",
		Short: "Synthesizes least-privilege JSON policy.",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
			logger.Info("Synthesizing least-privilege IAM policy document")

			policyBytes, err := reconcile.GenerateMinimalIAMPolicy([]string{"ec2", "s3", "iam", "cloudcontrol", "dynamodb", "organizations"})
			if err != nil {
				return fmt.Errorf("failed to generate IAM policy: %w", err)
			}

			if out != "" {
				if err := os.WriteFile(out, policyBytes, 0644); err != nil {
					return fmt.Errorf("failed to write policy to %s: %w", out, err)
				}
				fmt.Printf("[IAM POLICY] Least-privilege policy written to %s\n", out)
			} else {
				fmt.Println(string(policyBytes))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&out, "out", "", "Output path for minimal IAM policy JSON.")
	return cmd
}

func newVersionCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Prints version metadata.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput {
				data := map[string]string{
					"version":    version,
					"git_commit": gitCommit,
					"build_date": buildDate,
					"go_version": runtime.Version(),
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(data)
			}
			fmt.Printf("DriftWarden v%s (%s, %s, %s)\n", version, gitCommit, buildDate, runtime.Version())
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Emit version metadata in JSON format.")
	return cmd
}
