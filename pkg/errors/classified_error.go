package errors

import (
	"errors"
	"fmt"
	"strings"
)

// ClassifiedError wraps an underlying error with rich contextual classification,
// including domain error code, affected service, target resource ARN, and retryability.
type ClassifiedError struct {
	Code        ErrorCode `json:"code"`
	Message     string    `json:"message"`
	Service     string    `json:"service,omitempty"`
	ResourceARN string    `json:"resource_arn,omitempty"`
	Retryable   bool      `json:"retryable"`
	Err         error     `json:"-"`
}

// Option configures optional parameters on a ClassifiedError.
type Option func(*ClassifiedError)

// WithService sets the affected AWS/cloud service.
func WithService(service string) Option {
	return func(ce *ClassifiedError) {
		ce.Service = service
	}
}

// WithResourceARN sets the affected resource ARN.
func WithResourceARN(arn string) Option {
	return func(ce *ClassifiedError) {
		ce.ResourceARN = arn
	}
}

// WithRetryable overrides the retryable flag.
func WithRetryable(retryable bool) Option {
	return func(ce *ClassifiedError) {
		ce.Retryable = retryable
	}
}

// WithUnderlying sets the underlying root cause error.
func WithUnderlying(err error) Option {
	return func(ce *ClassifiedError) {
		ce.Err = err
	}
}

// New creates a new ClassifiedError.
func New(code ErrorCode, message string, opts ...Option) *ClassifiedError {
	ce := &ClassifiedError{
		Code:      code,
		Message:   message,
		Retryable: DefaultRetryable(code),
	}
	for _, opt := range opts {
		opt(ce)
	}
	// CRITICAL INVARIANT ENFORCEMENT:
	// ErrAccessDenied must NEVER be converted to or treated as ErrNotFound.
	enforceAccessDeniedInvariant(ce)
	return ce
}

// Wrap wraps an existing error with a classified error code and message.
func Wrap(err error, code ErrorCode, message string, opts ...Option) *ClassifiedError {
	if err == nil {
		return nil
	}
	ce := &ClassifiedError{
		Code:      code,
		Message:   message,
		Err:       err,
		Retryable: DefaultRetryable(code),
	}
	for _, opt := range opts {
		opt(ce)
	}
	// CRITICAL INVARIANT ENFORCEMENT
	enforceAccessDeniedInvariant(ce)
	return ce
}

// Error implements the standard error interface.
func (ce *ClassifiedError) Error() string {
	if ce == nil {
		return "<nil>"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s]", ce.Code))
	if ce.Service != "" {
		sb.WriteString(fmt.Sprintf(" service=%s", ce.Service))
	}
	if ce.ResourceARN != "" {
		sb.WriteString(fmt.Sprintf(" arn=%s", ce.ResourceARN))
	}
	if ce.Message != "" {
		sb.WriteString(fmt.Sprintf(": %s", ce.Message))
	}
	if ce.Err != nil {
		sb.WriteString(fmt.Sprintf(" (caused by: %v)", ce.Err))
	}
	return sb.String()
}

// Unwrap returns the underlying error for standard errors.Is/As unwrapping.
func (ce *ClassifiedError) Unwrap() error {
	if ce == nil {
		return nil
	}
	return ce.Err
}

// IsRetryable reports whether the classified error can be retried.
func (ce *ClassifiedError) IsRetryable() bool {
	if ce == nil {
		return false
	}
	return ce.Retryable
}

// DefaultRetryable returns the standard retryability for a given ErrorCode.
func DefaultRetryable(code ErrorCode) bool {
	switch code {
	case ErrThrottled, ErrTimeout, ErrServiceUnavailable:
		return true
	case ErrAccessDenied, ErrNotFound, ErrUnsupported, ErrInvalidConfig, ErrAuthFailure, ErrStateLocked:
		return false
	default:
		return false
	}
}

// enforceAccessDeniedInvariant guarantees that if the underlying error or message indicates
// access denial, the error code cannot be downgraded to ErrNotFound or treated as absent.
func enforceAccessDeniedInvariant(ce *ClassifiedError) {
	if ce == nil {
		return
	}
	var fullText strings.Builder
	fullText.WriteString(ce.Message)
	if ce.Err != nil {
		fullText.WriteString(" ")
		fullText.WriteString(ce.Err.Error())
	}
	lower := strings.ToLower(fullText.String())

	isAccessDenied := strings.Contains(lower, "accessdenied") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "unauthorizedoperation") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "status code: 403") ||
		strings.Contains(lower, "not authorized")

	if isAccessDenied && ce.Code == ErrNotFound {
		// Strict invariant: Never allow AccessDenied to masquerade as ErrNotFound
		ce.Code = ErrAccessDenied
		ce.Retryable = false
	}
}

// Classify inspects an arbitrary error and classifies it into a structured ClassifiedError.
// CRITICAL INVARIANT: AccessDenied must NEVER be converted to or treated as ErrNotFound.
func Classify(err error) *ClassifiedError {
	if err == nil {
		return nil
	}

	var existing *ClassifiedError
	if errors.As(err, &existing) {
		enforceAccessDeniedInvariant(existing)
		return existing
	}

	errMsg := err.Error()
	lower := strings.ToLower(errMsg)

	// Step 1: Check Access Denied FIRST (Strict Priority)
	if strings.Contains(lower, "accessdenied") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "unauthorizedoperation") ||
		strings.Contains(lower, "authorizationerror") ||
		strings.Contains(lower, "status code: 403") ||
		strings.Contains(lower, "not authorized") ||
		strings.Contains(lower, "forbidden") {
		return &ClassifiedError{
			Code:      ErrAccessDenied,
			Message:   errMsg,
			Retryable: false,
			Err:       err,
		}
	}

	// Step 2: Check Authentication Failure
	if strings.Contains(lower, "authfailure") ||
		strings.Contains(lower, "invalidclienttokenid") ||
		strings.Contains(lower, "signaturedoesnotmatch") ||
		strings.Contains(lower, "expiredtoken") ||
		strings.Contains(lower, "token refresh required") ||
		strings.Contains(lower, "status code: 401") {
		return &ClassifiedError{
			Code:      ErrAuthFailure,
			Message:   errMsg,
			Retryable: false,
			Err:       err,
		}
	}

	// Step 3: Check Throttling
	if strings.Contains(lower, "throttling") ||
		strings.Contains(lower, "requestlimitexceeded") ||
		strings.Contains(lower, "toomanyrequestsexception") ||
		strings.Contains(lower, "slowdown") ||
		strings.Contains(lower, "status code: 429") ||
		strings.Contains(lower, "rate limit exceeded") {
		return &ClassifiedError{
			Code:      ErrThrottled,
			Message:   errMsg,
			Retryable: true,
			Err:       err,
		}
	}

	// Step 4: Check Timeout
	if strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "context deadline exceeded") ||
		strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "requesttimeout") {
		return &ClassifiedError{
			Code:      ErrTimeout,
			Message:   errMsg,
			Retryable: true,
			Err:       err,
		}
	}

	// Step 5: Check Service Unavailable
	if strings.Contains(lower, "serviceunavailable") ||
		strings.Contains(lower, "status code: 503") ||
		strings.Contains(lower, "endpointconnectionerror") ||
		strings.Contains(lower, "connection reset by peer") {
		return &ClassifiedError{
			Code:      ErrServiceUnavailable,
			Message:   errMsg,
			Retryable: true,
			Err:       err,
		}
	}

	// Step 6: Check State Locked
	if strings.Contains(lower, "state locked") ||
		strings.Contains(lower, "statelocked") ||
		strings.Contains(lower, "conditionalcheckfailedexception") ||
		strings.Contains(lower, "lock info:") {
		return &ClassifiedError{
			Code:      ErrStateLocked,
			Message:   errMsg,
			Retryable: false,
			Err:       err,
		}
	}

	// Step 7: Check Invalid Configuration
	if strings.Contains(lower, "invalid configuration") ||
		strings.Contains(lower, "invalidconfig") ||
		strings.Contains(lower, "invalid parameter") ||
		strings.Contains(lower, "missing required parameter") ||
		strings.Contains(lower, "validation error") {
		return &ClassifiedError{
			Code:      ErrInvalidConfig,
			Message:   errMsg,
			Retryable: false,
			Err:       err,
		}
	}

	// Step 8: Check Not Found (Only after confirming NOT AccessDenied)
	if strings.Contains(lower, "not found") ||
		strings.Contains(lower, "notfound") ||
		strings.Contains(lower, "nosuchbucket") ||
		strings.Contains(lower, "nosuchentity") ||
		strings.Contains(lower, "resourcenotfoundexception") ||
		strings.Contains(lower, "invalidinstanceid.notfound") ||
		strings.Contains(lower, "status code: 404") ||
		strings.Contains(lower, "does not exist") {
		return &ClassifiedError{
			Code:      ErrNotFound,
			Message:   errMsg,
			Retryable: false,
			Err:       err,
		}
	}

	// Default fallback: ErrUnknown
	return &ClassifiedError{
		Code:      ErrUnknown,
		Message:   errMsg,
		Retryable: false,
		Err:       err,
	}
}
