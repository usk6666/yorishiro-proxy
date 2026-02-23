package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/usk6666/katashiro-proxy/internal/cert"
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
	flag.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "CA certificate file path")
	flag.StringVar(&cfg.CAKeyPath, "ca-key", cfg.CAKeyPath, "CA private key file path")
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

	// Initialize CA and certificate issuer for HTTPS MITM.
	ca, err := initCA(cfg, logger)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	issuer := cert.NewIssuer(ca)

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager for MCP tool control.
	manager := proxy.NewManager(detector, logger)

	// Start proxy via manager.
	if err := manager.Start(ctx, cfg.ListenAddr); err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}

	<-ctx.Done()
	logger.Info("shutting down")

	if err := manager.Stop(context.Background()); err != nil {
		logger.Warn("proxy stop error", "error", err)
	}
	return nil
}

// initCA initializes the CA for TLS interception. If certificate and key paths
// are configured, it loads the CA from files. Otherwise, it generates an
// ephemeral CA that lasts for the lifetime of the process.
func initCA(cfg *config.Config, logger *slog.Logger) (*cert.CA, error) {
	hasCert := cfg.CACertPath != ""
	hasKey := cfg.CAKeyPath != ""
	if hasCert != hasKey {
		return nil, fmt.Errorf("both -ca-cert and -ca-key must be specified together")
	}

	ca := &cert.CA{}

	if hasCert && hasKey {
		if err := ca.Load(cfg.CACertPath, cfg.CAKeyPath); err != nil {
			return nil, fmt.Errorf("load CA from %s / %s: %w", cfg.CACertPath, cfg.CAKeyPath, err)
		}
		logger.Info("loaded CA certificate", "cert_path", cfg.CACertPath)
		return ca, nil
	}

	if err := ca.Generate(); err != nil {
		return nil, fmt.Errorf("generate ephemeral CA: %w", err)
	}
	logger.Info("generated ephemeral CA certificate")
	return ca, nil
}
