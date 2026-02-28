package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/config"
	"github.com/usk6666/katashiro-proxy/internal/fuzzer"
	"github.com/usk6666/katashiro-proxy/internal/logging"
	"github.com/usk6666/katashiro-proxy/internal/mcp"
	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protogrpc "github.com/usk6666/katashiro-proxy/internal/protocol/grpc"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/katashiro-proxy/internal/protocol/http2"
	prototcp "github.com/usk6666/katashiro-proxy/internal/protocol/tcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/katashiro-proxy/internal/proxy/rules"
	"github.com/usk6666/katashiro-proxy/internal/session"
	"golang.org/x/sync/errgroup"
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
	flag.BoolVar(&cfg.InsecureSkipVerify, "insecure", cfg.InsecureSkipVerify, "skip TLS certificate verification for upstream connections")
	flag.IntVar(&cfg.RetentionMaxSessions, "retention-max-sessions", cfg.RetentionMaxSessions, "max sessions to retain (0 = unlimited)")
	flag.DurationVar(&cfg.RetentionMaxAge, "retention-max-age", cfg.RetentionMaxAge, "max session age (e.g. 720h for 30 days, 0 = unlimited)")
	flag.DurationVar(&cfg.CleanupInterval, "cleanup-interval", cfg.CleanupInterval, "interval between automatic cleanup runs (0 = disabled)")
	flag.BoolVar(&cfg.CAEphemeral, "ca-ephemeral", cfg.CAEphemeral, "use ephemeral in-memory CA (no file persistence)")
	flag.StringVar(&cfg.MCPHTTPAddr, "mcp-http-addr", cfg.MCPHTTPAddr, "MCP Streamable HTTP server listen address (e.g. :3000)")
	flag.Parse()

	// Allow KP_MCP_HTTP_ADDR environment variable as fallback when no flag is set.
	if cfg.MCPHTTPAddr == "" {
		cfg.MCPHTTPAddr = os.Getenv("KP_MCP_HTTP_ADDR")
	}

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

	// Start session cleaner if retention policy is configured.
	cleanerCfg := session.CleanerConfig{
		MaxSessions: cfg.RetentionMaxSessions,
		MaxAge:      cfg.RetentionMaxAge,
		Interval:    cfg.CleanupInterval,
	}
	if cleanerCfg.Enabled() {
		cleaner := session.NewCleaner(store, cleanerCfg, logger)
		cleaner.Start(ctx)
		defer cleaner.Stop()
		logger.Info("session cleaner started",
			"max_sessions", cleanerCfg.MaxSessions,
			"max_age", cleanerCfg.MaxAge,
			"interval", cleanerCfg.Interval)
	}

	// Initialize CA and certificate issuer for HTTPS MITM.
	ca, err := initCA(cfg, logger)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	issuer := cert.NewIssuer(ca)

	// Initialize TLS passthrough list and populate from config.
	passthrough := proxy.NewPassthroughList()
	for _, pattern := range cfg.TLSPassthrough {
		if !passthrough.Add(pattern) {
			logger.Warn("ignoring invalid TLS passthrough pattern", "pattern", pattern)
		}
	}
	if passthrough.Len() > 0 {
		logger.Info("TLS passthrough configured", "patterns", passthrough.Len())
	}

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	httpHandler.SetRequestTimeout(cfg.RequestTimeout)
	httpHandler.SetInsecureSkipVerify(cfg.InsecureSkipVerify)
	httpHandler.SetPassthroughList(passthrough)

	// Create shared capture scope for controlling session recording.
	scope := proxy.NewCaptureScope()
	httpHandler.SetCaptureScope(scope)

	// Initialize intercept engine and queue.
	interceptEngine := intercept.NewEngine()
	interceptQueue := intercept.NewQueue()
	httpHandler.SetInterceptEngine(interceptEngine)
	httpHandler.SetInterceptQueue(interceptQueue)

	// Initialize auto-transform pipeline for request/response modification.
	pipeline := rules.NewPipeline()
	httpHandler.SetTransformPipeline(pipeline)

	// Build HTTP/2 handler for h2c detection and h2 (TLS ALPN) delegation.
	http2Handler := protohttp2.NewHandler(store, logger)
	http2Handler.SetInsecureSkipVerify(cfg.InsecureSkipVerify)
	http2Handler.SetCaptureScope(scope)

	// Build gRPC handler and attach to the HTTP/2 handler for gRPC-specific recording.
	grpcHandler := protogrpc.NewHandler(store, logger)
	http2Handler.SetGRPCHandler(grpcHandler)

	// Link the HTTP/2 handler to the HTTP handler for h2 ALPN delegation.
	httpHandler.SetH2Handler(http2Handler)

	// Initialize fuzzer components for async fuzz job execution.
	// Use a hardened HTTP client with SSRF protection, explicit timeout,
	// and redirect suppression — never http.DefaultClient.
	fuzzEngine := fuzzer.NewEngine(store, store, store, mcp.NewHardenedHTTPClient(), "")
	fuzzRegistry := fuzzer.NewJobRegistry()
	fuzzRunner := fuzzer.NewRunner(fuzzEngine, fuzzRegistry)

	// Raw TCP fallback handler: must be last since Detect() always returns true.
	tcpHandler := prototcp.NewHandler(store, nil, logger)

	// Register handlers in priority order: h2c → HTTP/1.x → raw TCP fallback.
	detector := protocol.NewDetector(http2Handler, httpHandler, tcpHandler)

	// Create proxy manager for MCP tool control.
	manager := proxy.NewManager(detector, logger)
	manager.SetPeekTimeout(cfg.PeekTimeout)
	manager.SetMaxConnections(cfg.MaxConnections)

	if stdio {
		return runStdio(ctx, ca, issuer, store, store, manager, passthrough, scope, interceptEngine, interceptQueue, pipeline, fuzzRunner, cfg.DBPath, cfg.MCPHTTPAddr, logger)
	}

	return runProxy(ctx, cfg, manager, logger)
}

// runStdio starts the MCP server on stdin/stdout. When mcpHTTPAddr is non-empty,
// a Streamable HTTP transport is also started concurrently on that address.
// Both transports share the same MCP server instance, Manager, Store, and CA.
// The proxy is not started automatically; use the proxy_start tool to begin
// intercepting traffic.
func runStdio(ctx context.Context, ca *cert.CA, issuer *cert.Issuer, store session.Store, fuzzStore session.FuzzStore, manager *proxy.Manager, passthrough *proxy.PassthroughList, scope *proxy.CaptureScope, interceptEngine *intercept.Engine, interceptQueue *intercept.Queue, pipeline *rules.Pipeline, fuzzRunner *fuzzer.Runner, dbPath string, mcpHTTPAddr string, logger *slog.Logger) error {
	logger.Info("starting MCP server on stdio")

	mcpServer := mcp.NewServer(ctx, ca, store, manager,
		mcp.WithDBPath(dbPath),
		mcp.WithPassthroughList(passthrough),
		mcp.WithCaptureScope(scope),
		mcp.WithInterceptEngine(interceptEngine),
		mcp.WithInterceptQueue(interceptQueue),
		mcp.WithTransformPipeline(pipeline),
		mcp.WithFuzzRunner(fuzzRunner),
		mcp.WithFuzzStore(fuzzStore),
		mcp.WithIssuer(issuer),
	)

	g, gctx := errgroup.WithContext(ctx)

	// Always start stdio transport (single session via Server.Run).
	g.Go(func() error {
		transport := &gomcp.StdioTransport{}
		if err := mcpServer.Run(gctx, transport); err != nil {
			// Context cancellation is expected during graceful shutdown.
			if gctx.Err() != nil {
				logger.Info("MCP stdio server stopped")
				return nil
			}
			return fmt.Errorf("MCP stdio server: %w", err)
		}
		return nil
	})

	// Optionally start Streamable HTTP transport (multi-session via Server.Connect).
	if mcpHTTPAddr != "" {
		g.Go(func() error {
			if err := mcpServer.RunHTTP(gctx, mcpHTTPAddr); err != nil {
				// Context cancellation is expected during graceful shutdown.
				if gctx.Err() != nil {
					logger.Info("MCP HTTP server stopped")
					return nil
				}
				return err
			}
			return nil
		})
	}

	return g.Wait()
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

// initCA initializes the CA for TLS interception using one of three modes:
//
//  1. Explicit: -ca-cert and -ca-key flags specify paths (loaded from files).
//  2. Auto-persist (default): CA is stored in ~/.katashiro-proxy/ca/.
//     If files exist, the CA is loaded; otherwise a new CA is generated and saved.
//  3. Ephemeral: --ca-ephemeral generates an in-memory CA with no file persistence.
func initCA(cfg *config.Config, logger *slog.Logger) (*cert.CA, error) {
	hasCert := cfg.CACertPath != ""
	hasKey := cfg.CAKeyPath != ""
	if hasCert != hasKey {
		return nil, fmt.Errorf("both -ca-cert and -ca-key must be specified together")
	}

	// Explicit mode: user-specified paths.
	if hasCert && hasKey {
		if cfg.CAEphemeral {
			return nil, fmt.Errorf("--ca-ephemeral cannot be used with -ca-cert/-ca-key")
		}
		ca := &cert.CA{}
		if err := ca.Load(cfg.CACertPath, cfg.CAKeyPath); err != nil {
			return nil, fmt.Errorf("load CA from %s / %s: %w", cfg.CACertPath, cfg.CAKeyPath, err)
		}
		ca.SetSource(cert.CASource{
			Persisted: true,
			CertPath:  cfg.CACertPath,
			KeyPath:   cfg.CAKeyPath,
			Explicit:  true,
		})
		logger.Info("loaded CA certificate", "cert_path", cfg.CACertPath)
		return ca, nil
	}

	// Ephemeral mode: in-memory only.
	if cfg.CAEphemeral {
		ca := &cert.CA{}
		if err := ca.Generate(); err != nil {
			return nil, fmt.Errorf("generate ephemeral CA: %w", err)
		}
		logger.Info("generated ephemeral CA certificate (in-memory only)")
		return ca, nil
	}

	// Auto-persist mode (default).
	return initCAAutoPersist(cfg, logger)
}

// initCAAutoPersist implements the auto-persist CA mode.
// It loads an existing CA from the default path, or generates and saves a new one.
func initCAAutoPersist(cfg *config.Config, logger *slog.Logger) (*cert.CA, error) {
	caDir := cert.DefaultCADir()
	certPath := cert.DefaultCACertPath()
	keyPath := cert.DefaultCAKeyPath()

	// Allow test override of the data directory.
	if cfg.CADataDir != "" {
		caDir = cfg.CADataDir
		certPath = filepath.Join(caDir, "ca.crt")
		keyPath = filepath.Join(caDir, "ca.key")
	}

	ca := &cert.CA{}

	// Try loading existing CA files.
	if _, err := os.Stat(certPath); err == nil {
		if err := ca.Load(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("load persisted CA from %s: %w", certPath, err)
		}
		ca.SetSource(cert.CASource{
			Persisted: true,
			CertPath:  certPath,
			KeyPath:   keyPath,
		})
		logger.Info("loaded persisted CA certificate", "cert_path", certPath)
		return ca, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("check CA certificate file %s: %w", certPath, err)
	}

	// Generate a new CA.
	if err := ca.Generate(); err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	// Create CA directory with restrictive permissions.
	if err := os.MkdirAll(caDir, 0700); err != nil {
		logger.Warn("failed to create CA directory, continuing with ephemeral CA",
			"dir", caDir, "error", err)
		return ca, nil
	}

	// Save the CA files.
	if err := ca.Save(certPath, keyPath); err != nil {
		logger.Warn("failed to save CA certificate, continuing with ephemeral CA",
			"cert_path", certPath, "error", err)
		return ca, nil
	}

	ca.SetSource(cert.CASource{
		Persisted: true,
		CertPath:  certPath,
		KeyPath:   keyPath,
	})
	logger.Info("generated and saved CA certificate",
		"cert_path", certPath,
		"install_hint", "Install the CA certificate from the path above into your OS/browser trust store for HTTPS interception")
	return ca, nil
}
