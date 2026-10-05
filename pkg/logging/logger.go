package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type contextKey string

const (
	scanIDContextKey contextKey = "driftwarden_scan_id"
	loggerContextKey contextKey = "driftwarden_logger"
)

// ParseLevel parses a string into a slog.Level.
func ParseLevel(lvl string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(lvl)) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	case "INFO":
		fallthrough
	default:
		return slog.LevelInfo
	}
}

// NewLogger creates a new slog.Logger configured with the specified level and format.
func NewLogger(levelStr string, formatStr string) *slog.Logger {
	return NewLoggerWithWriter(levelStr, formatStr, os.Stderr)
}

// NewLoggerWithWriter creates a new slog.Logger with a custom output writer.
func NewLoggerWithWriter(levelStr string, formatStr string, w io.Writer) *slog.Logger {
	level := ParseLevel(levelStr)
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(formatStr)) {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text":
		fallthrough
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}

// WithScanID attaches a scan ID to the context.
func WithScanID(ctx context.Context, scanID string) context.Context {
	return context.WithValue(ctx, scanIDContextKey, scanID)
}

// GetScanID extracts the scan ID from the context if present.
func GetScanID(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx.Value(scanIDContextKey).(string)
	return id, ok && id != ""
}

// WithLogger stores the logger in the context.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, logger)
}

// FromContext retrieves the logger from context, injecting the scan ID attribute if present.
func FromContext(ctx context.Context) *slog.Logger {
	var l *slog.Logger
	if ctx != nil {
		if ctxLogger, ok := ctx.Value(loggerContextKey).(*slog.Logger); ok && ctxLogger != nil {
			l = ctxLogger
		}
	}
	if l == nil {
		l = slog.Default()
	}

	if scanID, ok := GetScanID(ctx); ok {
		return l.With(slog.String("scan_id", scanID))
	}
	return l
}
