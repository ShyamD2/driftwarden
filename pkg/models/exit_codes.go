package models

import "github.com/ShyamD2/driftwarden/pkg/errors"

// Standard global exit codes for DriftWarden CLI.
const (
	ExitSuccess        = 0 // Clean, in-sync
	ExitGenericError   = 1 // Runtime/system error
	ExitDriftViolation = 2 // Drift detected with --fail-on-drift or CRITICAL security violation with --fail-on-critical
	ExitStateLocked    = 3 // Terraform state locked by another process
	ExitInvalidConfig  = 4 // Invalid CLI flags, bad config file, missing required parameters
	ExitPartialScan    = 5 // AccessDenied or throttling caused an incomplete audit
)

// Precedence rank: higher numerical rank takes precedence.
// ExitInvalidConfig (4) > ExitStateLocked (3) > ExitDriftViolation (2) > ExitPartialScan (5) > ExitGenericError (1) > ExitSuccess (0)
var exitCodePriority = map[int]int{
	ExitInvalidConfig:  6,
	ExitStateLocked:    5,
	ExitDriftViolation: 4,
	ExitPartialScan:    3,
	ExitGenericError:   2,
	ExitSuccess:        1,
}

// ExitPriority returns the hierarchy precedence rank for a given exit code.
func ExitPriority(code int) int {
	if prio, ok := exitCodePriority[code]; ok {
		return prio
	}
	return exitCodePriority[ExitGenericError]
}

// ResolveExitCode resolves multiple candidate exit codes according to the global precedence hierarchy:
// ExitInvalidConfig (4) > ExitStateLocked (3) > ExitDriftViolation (2) > ExitPartialScan (5) > ExitGenericError (1) > ExitSuccess (0)
func ResolveExitCode(codes ...int) int {
	if len(codes) == 0 {
		return ExitSuccess
	}

	bestCode := ExitSuccess
	highestPrio := 0

	for _, code := range codes {
		prio := ExitPriority(code)
		if prio > highestPrio {
			highestPrio = prio
			bestCode = code
		}
	}
	return bestCode
}

// DetermineScanExitCode calculates the final process exit code given a scan report,
// configuration flags, and any runtime errors encountered.
func DetermineScanExitCode(report *ScanReport, failOnDrift bool, failOnCritical bool, errs ...error) int {
	candidates := make([]int, 0)

	// Check runtime errors first for config or state lock
	for _, err := range errs {
		if err == nil {
			continue
		}
		classified := errors.Classify(err)
		switch classified.Code {
		case errors.ErrInvalidConfig:
			candidates = append(candidates, ExitInvalidConfig)
		case errors.ErrStateLocked:
			candidates = append(candidates, ExitStateLocked)
		case errors.ErrAccessDenied, errors.ErrThrottled:
			candidates = append(candidates, ExitPartialScan)
		default:
			candidates = append(candidates, ExitGenericError)
		}
	}

	if report != nil {
		// Drift / Critical security checks
		if failOnDrift && report.TotalDrift > 0 {
			candidates = append(candidates, ExitDriftViolation)
		}

		if failOnCritical {
			for _, item := range report.Items {
				if item.Severity == SeverityCritical && item.Type != DriftInSync {
					candidates = append(candidates, ExitDriftViolation)
					break
				}
			}
		}

		// Partial scan check: AccessDenied or throttling causing partial status
		if report.Status == "PARTIAL_SCAN" || report.AccessDeniedCount > 0 {
			candidates = append(candidates, ExitPartialScan)
		}

		if report.Status == "FAILED" {
			candidates = append(candidates, ExitGenericError)
		}
	}

	if len(candidates) == 0 {
		return ExitSuccess
	}

	return ResolveExitCode(candidates...)
}
