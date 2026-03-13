// Package testutil provides shared test helpers for the yorishiro-proxy project.
package testutil

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// DiscardLogger returns a *slog.Logger that discards all output.
// Use this in tests where a logger is required but output is not needed.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// CaptureLogger returns a *slog.Logger that writes all log output to a
// thread-safe buffer. Use Output() to retrieve the captured log text.
// This is useful for verifying that specific log messages (e.g. errors,
// warnings) are emitted during component initialization or request processing.
type CaptureLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewCaptureLogger creates a CaptureLogger and its associated *slog.Logger.
// All log levels are captured (including DEBUG).
func NewCaptureLogger() (*CaptureLogger, *slog.Logger) {
	cl := &CaptureLogger{}
	// Pass cl (which implements io.Writer) so writes are mutex-protected.
	logger := slog.New(slog.NewTextHandler(cl, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	return cl, logger
}

// Write implements io.Writer for thread-safe log capture.
func (cl *CaptureLogger) Write(p []byte) (int, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.buf.Write(p)
}

// Output returns all captured log text.
func (cl *CaptureLogger) Output() string {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.buf.String()
}

// Contains returns true if the captured log output contains the given substring.
func (cl *CaptureLogger) Contains(substr string) bool {
	return strings.Contains(cl.Output(), substr)
}
