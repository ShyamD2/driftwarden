package models

import (
	"errors"
	"testing"
)

func TestExitCodePrecedence(t *testing.T) {
	tests := []struct {
		name     string
		codes    []int
		expected int
	}{
		{
			name:     "InvalidConfig beats all",
			codes:    []int{ExitSuccess, ExitGenericError, ExitPartialScan, ExitDriftViolation, ExitStateLocked, ExitInvalidConfig},
			expected: ExitInvalidConfig,
		},
		{
			name:     "StateLocked beats DriftViolation",
			codes:    []int{ExitSuccess, ExitGenericError, ExitPartialScan, ExitDriftViolation, ExitStateLocked},
			expected: ExitStateLocked,
		},
		{
			name:     "DriftViolation beats PartialScan",
			codes:    []int{ExitSuccess, ExitGenericError, ExitPartialScan, ExitDriftViolation},
			expected: ExitDriftViolation,
		},
		{
			name:     "PartialScan beats GenericError",
			codes:    []int{ExitSuccess, ExitGenericError, ExitPartialScan},
			expected: ExitPartialScan,
		},
		{
			name:     "GenericError beats Success",
			codes:    []int{ExitSuccess, ExitGenericError},
			expected: ExitGenericError,
		},
		{
			name:     "Success when no other codes",
			codes:    []int{ExitSuccess},
			expected: ExitSuccess,
		},
		{
			name:     "Empty list yields Success",
			codes:    []int{},
			expected: ExitSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveExitCode(tt.codes...)
			if got != tt.expected {
				t.Errorf("ResolveExitCode(%v) = %d; want %d", tt.codes, got, tt.expected)
			}
		})
	}
}

func TestDetermineScanExitCode_PartialScan(t *testing.T) {
	report := &ScanReport{
		Status:            "PARTIAL_SCAN",
		AccessDeniedCount: 1,
		TotalDrift:        0,
	}

	code := DetermineScanExitCode(report, false, false)
	if code != ExitPartialScan {
		t.Fatalf("expected ExitPartialScan (5), got %d", code)
	}

	// But if config is invalid, ExitInvalidConfig (4) must take precedence
	configErr := errors.New("invalid configuration: missing region")
	codeWithErr := DetermineScanExitCode(report, false, false, configErr)
	if codeWithErr != ExitInvalidConfig {
		t.Fatalf("expected ExitInvalidConfig (4) to beat ExitPartialScan (5), got %d", codeWithErr)
	}
}
