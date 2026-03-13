package testutil

import (
	"testing"
)

func TestDiscardLogger(t *testing.T) {
	logger := DiscardLogger()
	if logger == nil {
		t.Fatal("DiscardLogger returned nil")
	}
	// Should not panic.
	logger.Info("test message")
}

func TestCaptureLogger(t *testing.T) {
	capture, logger := NewCaptureLogger()
	if capture == nil {
		t.Fatal("NewCaptureLogger returned nil CaptureLogger")
	}
	if logger == nil {
		t.Fatal("NewCaptureLogger returned nil logger")
	}

	// Initially empty.
	if capture.Output() != "" {
		t.Errorf("expected empty output, got %q", capture.Output())
	}
	if capture.Contains("anything") {
		t.Error("Contains should return false for empty output")
	}

	// Log a message and verify capture.
	logger.Warn("test warning message", "key", "value")

	output := capture.Output()
	if output == "" {
		t.Fatal("expected non-empty output after logging")
	}
	if !capture.Contains("test warning message") {
		t.Errorf("expected output to contain 'test warning message', got %q", output)
	}
	if !capture.Contains("key=value") {
		t.Errorf("expected output to contain 'key=value', got %q", output)
	}
	if !capture.Contains("WARN") {
		t.Errorf("expected output to contain 'WARN', got %q", output)
	}
}

func TestCaptureLogger_DebugLevel(t *testing.T) {
	capture, logger := NewCaptureLogger()

	logger.Debug("debug message")

	if !capture.Contains("debug message") {
		t.Errorf("expected debug message to be captured, got %q", capture.Output())
	}
}
