package errors

import (
	"errors"
	"testing"
)

func TestAccessDeniedInvariant(t *testing.T) {
	// Attempting to wrap or create an AccessDenied error as ErrNotFound must fail safe to ErrAccessDenied
	accessDeniedErr := errors.New("api error: AccessDenied: User is not authorized to perform: ec2:DescribeInstances")
	classified := Classify(accessDeniedErr)

	if classified.Code != ErrAccessDenied {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: expected ErrAccessDenied, got %v", classified.Code)
	}
	if classified.Code == ErrNotFound {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: ErrAccessDenied was treated as ErrNotFound")
	}

	// Direct Wrap attempt trying to force ErrNotFound on an AccessDenied error message
	forcedWrap := Wrap(accessDeniedErr, ErrNotFound, "failed to read instance")
	if forcedWrap.Code != ErrAccessDenied {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: forced Wrap with ErrNotFound on AccessDenied must be corrected to ErrAccessDenied, got %v", forcedWrap.Code)
	}

	// Direct New attempt with AccessDenied string
	forcedNew := New(ErrNotFound, "AccessDenied: forbidden access to s3")
	if forcedNew.Code != ErrAccessDenied {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: forced New with ErrNotFound on AccessDenied text must be corrected to ErrAccessDenied, got %v", forcedNew.Code)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedCode  ErrorCode
		wantRetryable bool
	}{
		{
			name:          "NotFound - NoSuchBucket",
			err:           errors.New("NoSuchBucket: The specified bucket does not exist"),
			expectedCode:  ErrNotFound,
			wantRetryable: false,
		},
		{
			name:          "NotFound - ResourceNotFoundException",
			err:           errors.New("ResourceNotFoundException: subnet-123 does not exist"),
			expectedCode:  ErrNotFound,
			wantRetryable: false,
		},
		{
			name:          "AccessDenied - UnauthorizedOperation",
			err:           errors.New("UnauthorizedOperation: You are not authorized to perform this operation"),
			expectedCode:  ErrAccessDenied,
			wantRetryable: false,
		},
		{
			name:          "Throttling - RequestLimitExceeded",
			err:           errors.New("RequestLimitExceeded: Request limit exceeded"),
			expectedCode:  ErrThrottled,
			wantRetryable: true,
		},
		{
			name:          "Timeout - DeadlineExceeded",
			err:           errors.New("context deadline exceeded"),
			expectedCode:  ErrTimeout,
			wantRetryable: true,
		},
		{
			name:          "ServiceUnavailable - 503",
			err:           errors.New("status code: 503, request id: abc-123"),
			expectedCode:  ErrServiceUnavailable,
			wantRetryable: true,
		},
		{
			name:          "StateLocked - LockInfo",
			err:           errors.New("Error acquiring the state lock: ConditionalCheckFailedException"),
			expectedCode:  ErrStateLocked,
			wantRetryable: false,
		},
		{
			name:          "AuthFailure - InvalidClientTokenId",
			err:           errors.New("InvalidClientTokenId: The security token included in the request is invalid"),
			expectedCode:  ErrAuthFailure,
			wantRetryable: false,
		},
		{
			name:          "Unknown",
			err:           errors.New("arbitrary unclassified error occurred"),
			expectedCode:  ErrUnknown,
			wantRetryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classified := Classify(tt.err)
			if classified.Code != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, classified.Code)
			}
			if classified.IsRetryable() != tt.wantRetryable {
				t.Errorf("expected retryable %v, got %v", tt.wantRetryable, classified.IsRetryable())
			}
		})
	}
}
