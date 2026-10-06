package invariants

import (
	"context"
	"errors"
	"testing"
	"time"

	dwErrors "github.com/ShyamD2/driftwarden/pkg/errors"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/terraform"
)

// TestInvariant_AccessDenied_QuarantinedAsPartialScan verifies the critical invariant
// that AccessDenied on AWS API calls is strictly quarantined as PARTIAL_SCAN (ExitCode 4)
// and is NEVER classified as ErrNotFound or treated as a missing/ghost resource.
func TestInvariant_AccessDenied_QuarantinedAsPartialScan(t *testing.T) {
	accessDeniedErrs := []error{
		errors.New("AccessDenied: User is not authorized to perform: ec2:DescribeInstances"),
		errors.New("UnauthorizedOperation: You are not authorized to perform this operation"),
		errors.New("api error AccessDenied: Access Denied to S3 bucket"),
	}

	for _, err := range accessDeniedErrs {
		classification := dwErrors.Classify(err)
		if classification.Code != dwErrors.ErrAccessDenied {
			t.Fatalf("expected ErrAccessDenied for %v, got %v", err, classification.Code)
		}

		// Verify exit code mapping: Partial scan exit code (4)
		report := &models.ScanReport{
			Status:            "PARTIAL_SCAN",
			AccessDeniedCount: 1,
			TotalScanned:      10,
			TotalDrift:        0,
		}
		exitCode := models.DetermineScanExitCode(report, false, false)
		if exitCode != models.ExitPartialScan {
			t.Fatalf("expected ExitPartialScan (4), got %d", exitCode)
		}
	}
}

// TestInvariant_GhostVsAccessDenied verifies that true NotFound errors are distinguished
// from AccessDenied, ensuring permission errors never cause false GhostResource alerts.
func TestInvariant_GhostVsAccessDenied(t *testing.T) {
	notFoundErr := errors.New("ResourceNotFoundException: The instance ID does not exist")
	accessDeniedErr := errors.New("UnauthorizedOperation: You are not authorized")

	cNotFound := dwErrors.Classify(notFoundErr)
	cAccessDenied := dwErrors.Classify(accessDeniedErr)

	if cNotFound.Code != dwErrors.ErrNotFound {
		t.Fatalf("expected ErrNotFound classification, got %v", cNotFound.Code)
	}
	if cAccessDenied.Code != dwErrors.ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied classification, got %v", cAccessDenied.Code)
	}
	if cNotFound.Code == cAccessDenied.Code {
		t.Fatalf("critical invariant violated: NotFound and AccessDenied must not collide")
	}
}

// TestInvariant_Throttling_Classified verifies that AWS rate limit / throttling
// responses are identified so the backoff engine can handle them gracefully.
func TestInvariant_Throttling_Classified(t *testing.T) {
	throttleErrs := []error{
		errors.New("RequestLimitExceeded: Request limit exceeded on ec2:DescribeSecurityGroups"),
		errors.New("ThrottlingException: Rate exceeded"),
		errors.New("TooManyRequestsException: 429"),
	}

	for _, err := range throttleErrs {
		classification := dwErrors.Classify(err)
		if classification.Code != dwErrors.ErrThrottled {
			t.Fatalf("expected ErrThrottled for %v, got %v", err, classification.Code)
		}
	}
}

// TestInvariant_Timeout_GracefulDegradation verifies that context deadline cancellation
// is classified as a Timeout rather than an unknown fatal error.
func TestInvariant_Timeout_GracefulDegradation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	err := ctx.Err()
	classification := dwErrors.Classify(err)
	if classification.Code != dwErrors.ErrTimeout {
		t.Fatalf("expected ErrTimeout, got %v", classification.Code)
	}
}

// TestInvariant_MalformedState_SafeFailure verifies that corrupted or malformed
// terraform.tfstate JSON is safely rejected without panicking.
func TestInvariant_MalformedState_SafeFailure(t *testing.T) {
	malformedInputs := [][]byte{
		[]byte(`{ "version": 4, "terraform_version": "1.5.0", "resources": [ truncated...`),
		[]byte(`not a json string at all`),
		[]byte(``),
		[]byte(`{"version": 3}`), // older unsupported schema version
	}

	sp := terraform.NewStateParser("us-east-1", "123456789012")
	for _, input := range malformedInputs {
		_, _, err := sp.ParseBytes(input, "test.tfstate")
		if err == nil {
			t.Fatalf("expected error on malformed state input: %s", string(input))
		}
		// Invariant: No panic occurred, and an informative error was returned
	}
}

// TestInvariant_MalformedHCL_SafeFailure verifies that corrupted HCL syntax
// is parsed gracefully with diagnostics rather than crashing.
func TestInvariant_MalformedHCL_SafeFailure(t *testing.T) {
	malformedHCL := []byte(`
		resource "aws_security_group" "unclosed {
			name = "broken"
	`)

	cp := terraform.NewConfigParser("us-east-1", "123456789012")
	_, _, err := cp.ParseBytes(malformedHCL, "broken.tf")
	if err == nil {
		t.Fatalf("expected syntax error on unclosed HCL block")
	}
}

// TestInvariant_ExitCodePrecedence verifies the strict hierarchy of CLI exit codes:
// InvalidConfig (5) > StateLocked (3) > DriftViolation (2) > PartialScan (4) > GenericError (1) > Success (0)
func TestInvariant_ExitCodePrecedence(t *testing.T) {
	reportWithDrift := &models.ScanReport{
		Status:            "PARTIAL_SCAN",
		AccessDeniedCount: 2,
		TotalDrift:        1,
		Items: []models.DriftItem{
			{
				Type:     models.DriftAttribute,
				Severity: models.SeverityCritical,
			},
		},
	}

	// Case 1: FailOnCritical with critical item beats PartialScan
	code := models.DetermineScanExitCode(reportWithDrift, false, true)
	if code != models.ExitDriftViolation {
		t.Fatalf("expected ExitDriftViolation (2) to beat PartialScan (4), got %d", code)
	}

	// Case 2: Without FailOnCritical/FailOnDrift, PartialScan takes precedence over success
	code = models.DetermineScanExitCode(reportWithDrift, false, false)
	if code != models.ExitPartialScan {
		t.Fatalf("expected ExitPartialScan (4), got %d", code)
	}
}
