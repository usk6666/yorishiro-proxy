package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/usk6666/katashiro-proxy/internal/config"
	"github.com/usk6666/katashiro-proxy/internal/logging"
	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg := config.Default()
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "proxy listen address")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")
	flag.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "log format (text, json)")
	flag.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "log output file (default: stderr)")
	flag.Parse()

	// Initialize logger.
	logger, logCleanup, err := logging.Setup(logging.Config{
		Level:  cfg.LogLevel,
		Format: cfg.LogFormat,
		File:   cfg.LogFile,
	})
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logCleanup()
	slog.SetDefault(logger)

	// Initialize SQLite session store.
	store, err := session.NewSQLiteStore(ctx, cfg.DBPath, logger)
	if err != nil {
		return fmt.Errorf("init session store: %w", err)
	}
	defer store.Close()

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)

	// Start TCP listener.
	listener := proxy.NewListener(cfg.ListenAddr, detector, logger)
	logger.Info("proxy started", "listen_addr", cfg.ListenAddr, "db_path", cfg.DBPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		return nil
	}
}
