package connector

import (
	"io"
	"log/slog"
)

// newTestLogger returns a logger that swallows all output below Error so
// `go test -v` output stays focused on test failures.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
