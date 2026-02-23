package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/config"
	"github.com/usk6666/katashiro-proxy/internal/logging"
	"github.com/usk6666/katashiro-proxy/internal/mcp"
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
	var stdio bool
	flag.BoolVar(&stdio, "stdio", false, "run as MCP server on stdin/stdout")
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "proxy listen address")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")
	flag.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "log format (text, json)")
	flag.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "log output file (default: stderr)")
	flag.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "CA certificate file path")
	flag.StringVar(&cfg.CAKeyPath, "ca-key", cfg.CAKeyPath, "CA private key file path")
	flag.DurationVar(&cfg.PeekTimeout, "peek-timeout", cfg.PeekTimeout, "protocol detection timeout")
	flag.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "HTTP request read timeout")
	flag.IntVar(&cfg.MaxConnections, "max-connections", cfg.MaxConnections, "max concurrent connections (default 1024)")
	flag.Parse()

	// Initialize logger.
	// In stdio mode, logs go to stderr by default (the logging package never
	// writes to stdout), keeping stdout clean for MCP JSON-RPC messages.
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
	httpHandler.SetRequestTimeout(cfg.RequestTimeout)
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager for MCP tool control.
	manager := proxy.NewManager(detector, logger)
	manager.SetPeekTimeout(cfg.PeekTimeout)
	manager.SetMaxConnections(cfg.MaxConnections)

	if stdio {
		return runStdio(ctx, ca, store, manager, logger)
	}

	return runProxy(ctx, cfg, manager, logger)
}

// runStdio starts the MCP server on stdin/stdout. The proxy is not started
// automatically; use the proxy_start tool to begin intercepting traffic.
func runStdio(ctx context.Context, ca *cert.CA, store session.Store, manager *proxy.Manager, logger *slog.Logger) error {
	logger.Info("starting MCP server on stdio")

	mcpServer := mcp.NewServer(ctx, ca, store, manager)
	transport := &gomcp.StdioTransport{}

	if err := mcpServer.Run(ctx, transport); err != nil {
		// Context cancellation is expected during graceful shutdown.
		if ctx.Err() != nil {
			logger.Info("MCP server stopped")
			return nil
		}
		return fmt.Errorf("MCP server: %w", err)
	}

	return nil
}

// runProxy starts the proxy directly without an MCP server.
func runProxy(ctx context.Context, cfg *config.Config, manager *proxy.Manager, logger *slog.Logger) error {
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
