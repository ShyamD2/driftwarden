package errors

// ErrorCode represents a standardized error classification code across DriftWarden.
type ErrorCode string

const (
	ErrNotFound           ErrorCode = "NOT_FOUND"
	ErrAccessDenied       ErrorCode = "ACCESS_DENIED"
	ErrThrottled          ErrorCode = "THROTTLED"
	ErrTimeout            ErrorCode = "TIMEOUT"
	ErrServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrUnsupported        ErrorCode = "UNSUPPORTED"
	ErrInvalidConfig      ErrorCode = "INVALID_CONFIGURATION"
	ErrAuthFailure        ErrorCode = "AUTHENTICATION_FAILURE"
	ErrStateLocked        ErrorCode = "STATE_LOCKED"
	ErrUnknown            ErrorCode = "UNKNOWN"
)
