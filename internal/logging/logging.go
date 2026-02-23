package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Config holds logging configuration.
type Config struct {
	// Level is the minimum log level: debug, info, warn, error. Default: info.
	Level string
	// Format is the log output format: text, json. Default: text.
	Format string
	// File is the log output file path. Empty means stderr.
	File string
}

// Setup creates a configured *slog.Logger and returns a cleanup function.
// The cleanup function must be called to release resources (e.g. close log file).
// Output is always stderr or a file — stdout is never used.
func Setup(cfg Config) (*slog.Logger, func(), error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}

	format := strings.ToLower(cfg.Format)
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return nil, nil, fmt.Errorf("unsupported log format: %q (must be text or json)", cfg.Format)
	}

	var w io.Writer
	cleanup := func() {}

	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", cfg.File, err)
		}
		w = f
		cleanup = func() { f.Close() }
	} else {
		w = os.Stderr
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	logger := slog.New(handler)
	return logger, cleanup, nil
}

// parseLevel converts a level string to slog.Level.
func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level: %q (must be debug, info, warn, or error)", s)
	}
}
