// Package testutil provides shared test helpers for the yorishiro-proxy project.
package testutil

import (
	"io"
	"log/slog"
)

// DiscardLogger returns a *slog.Logger that discards all output.
// Use this in tests where a logger is required but output is not needed.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
