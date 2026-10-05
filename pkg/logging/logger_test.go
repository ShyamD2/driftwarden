package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"unknown", slog.LevelInfo},
	}

	for _, tt := range tests {
		got := ParseLevel(tt.input)
		if got != tt.expected {
			t.Errorf("ParseLevel(%q) = %v; want %v", tt.input, got, tt.expected)
		}
	}
}

func TestLoggerTextAndJSON(t *testing.T) {
	// Test JSON format and scan ID injection
	var buf bytes.Buffer
	logger := NewLoggerWithWriter("debug", "json", &buf)

	ctx := WithScanID(context.Background(), "scan-xyz-123")
	ctx = WithLogger(ctx, logger)

	l := FromContext(ctx)
	l.Info("testing json log", slog.String("component", "identity"))

	output := buf.String()
	if !strings.Contains(output, "scan-xyz-123") {
		t.Fatalf("expected log to contain scan_id, got: %s", output)
	}

	var jsonMap map[string]any
	if err := json.Unmarshal(buf.Bytes(), &jsonMap); err != nil {
		t.Fatalf("failed to parse JSON log output: %v", err)
	}
	if jsonMap["scan_id"] != "scan-xyz-123" {
		t.Errorf("expected scan_id in JSON map, got %v", jsonMap["scan_id"])
	}
	if jsonMap["msg"] != "testing json log" {
		t.Errorf("expected msg in JSON map, got %v", jsonMap["msg"])
	}

	// Test Text format
	buf.Reset()
	textLogger := NewLoggerWithWriter("info", "text", &buf)
	textCtx := WithLogger(context.Background(), textLogger)
	textL := FromContext(textCtx)
	textL.Info("hello text log")

	textOutput := buf.String()
	if !strings.Contains(textOutput, "hello text log") {
		t.Errorf("expected text log output, got: %s", textOutput)
	}
}
