package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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

// envVarMap maps flag names to their corresponding KP_ environment variable names.
var envVarMap = map[string]string{
	"config":         "KP_CONFIG",
	"db":             "KP_DB",
	"ca-cert":        "KP_CA_CERT",
	"ca-key":         "KP_CA_KEY",
	"ca-ephemeral":   "KP_CA_EPHEMERAL",
	"insecure":       "KP_INSECURE",
	"log-level":      "KP_LOG_LEVEL",
	"log-format":     "KP_LOG_FORMAT",
	"log-file":       "KP_LOG_FILE",
	"mcp-http-addr":  "KP_MCP_HTTP_ADDR",
	"mcp-http-token": "KP_MCP_HTTP_TOKEN",
	"ui-dir":         "KP_UI_DIR",
}

func run(ctx context.Context) error {
	return runWithFlags(ctx, flag.CommandLine, os.Args[1:])
}

// runWithFlags implements the main logic using the provided FlagSet.
// This separation allows testing flag parsing and env var fallback
// without affecting the global flag.CommandLine state.
func runWithFlags(ctx context.Context, fs *flag.FlagSet, args []string) error {
	cfg := config.Default()

	// Config file path — loaded early to provide defaults for proxy_start.
	var configFile string
	fs.StringVar(&configFile, "config", "", "JSON config file path for proxy defaults (env: KP_CONFIG)")

	// Define flags — only those requiring startup-time decisions.
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath,
		"SQLite database path or project name (env: KP_DB)\n"+
			"    project name (no ext, no path sep) -> ~/.katashiro-proxy/<name>.db\n"+
			"    absolute path                      -> used as-is\n"+
			"    relative path with extension        -> CWD-relative")
	fs.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "CA certificate file path (env: KP_CA_CERT)")
	fs.StringVar(&cfg.CAKeyPath, "ca-key", cfg.CAKeyPath, "CA private key file path (env: KP_CA_KEY)")
	fs.BoolVar(&cfg.CAEphemeral, "ca-ephemeral", cfg.CAEphemeral, "use ephemeral in-memory CA (env: KP_CA_EPHEMERAL)")
	fs.BoolVar(&cfg.InsecureSkipVerify, "insecure", cfg.InsecureSkipVerify, "skip upstream TLS verification (env: KP_INSECURE)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, error (env: KP_LOG_LEVEL)")
	fs.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "log format: text, json (env: KP_LOG_FORMAT)")
	fs.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "log output file, default stderr (env: KP_LOG_FILE)")
	fs.StringVar(&cfg.MCPHTTPAddr, "mcp-http-addr", cfg.MCPHTTPAddr, "Streamable HTTP listen address (env: KP_MCP_HTTP_ADDR)")
	fs.StringVar(&cfg.MCPHTTPToken, "mcp-http-token", cfg.MCPHTTPToken, "HTTP Bearer auth token, auto-generated if empty (env: KP_MCP_HTTP_TOKEN)")
	fs.StringVar(&cfg.UIDir, "ui-dir", cfg.UIDir, "directory for WebUI static files, overrides embedded assets (env: KP_UI_DIR)")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: katashiro-proxy [flags]\n\n")
		fmt.Fprintf(fs.Output(), "katashiro-proxy is an AI agent network proxy (MCP server).\n")
		fmt.Fprintf(fs.Output(), "It runs as an MCP server on stdin/stdout by default.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment variables:\n")
		fmt.Fprintf(fs.Output(), "  All flags accept a KP_ prefixed environment variable as fallback.\n")
		fmt.Fprintf(fs.Output(), "  Priority: CLI flag > environment variable > config file > default value.\n")
		fmt.Fprintf(fs.Output(), "  Naming: replace hyphens with underscores, uppercase (e.g. -log-level -> KP_LOG_LEVEL).\n")
		fmt.Fprintf(fs.Output(), "\nExamples:\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy                                  # MCP stdio mode (default)\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy -db pentest-2026                 # project DB: ~/.katashiro-proxy/pentest-2026.db\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy -db /data/project.db             # absolute path: used as-is\n")
		fmt.Fprintf(fs.Output(), "  KP_DB=client-audit katashiro-proxy               # project name via env var\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy -config proxy.json               # load proxy config from file\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy -mcp-http-addr 127.0.0.1:3000    # stdio + Streamable HTTP\n")
		fmt.Fprintf(fs.Output(), "  KP_INSECURE=true katashiro-proxy                  # skip TLS verification\n")
	}
	// Allow KP_MCP_HTTP_TOKEN environment variable as fallback when no flag is set.
	if cfg.MCPHTTPToken == "" {
		cfg.MCPHTTPToken = os.Getenv("KP_MCP_HTTP_TOKEN")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply environment variable fallback for flags not explicitly set.
	applyEnvFallback(fs, cfg, &configFile)

	// Load proxy config file if specified.
	var proxyCfg *config.ProxyConfig
	if configFile != "" {
		var err error
		proxyCfg, err = config.LoadFile(configFile)
		if err != nil {
			return fmt.Errorf("load config file: %w", err)
		}
	}

	// Apply smart DB path resolution: project name -> ~/.katashiro-proxy/<name>.db.
	resolvedDBPath, err := config.ResolveDBPath(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	cfg.DBPath = resolvedDBPath

	// Initialize logger.
	// Logs go to stderr by default (the logging package never writes to stdout),
	// keeping stdout clean for MCP JSON-RPC messages.
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

	// Ensure the database directory exists (e.g. ~/.katashiro-proxy/).
	if err := config.EnsureDBDir(cfg.DBPath); err != nil {
		return fmt.Errorf("ensure db directory: %w", err)
	}

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
	http2Handler.SetInterceptEngine(interceptEngine)
	http2Handler.SetInterceptQueue(interceptQueue)

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

	// Register handlers in priority order: h2c -> HTTP/1.x -> raw TCP fallback.
	detector := protocol.NewDetector(http2Handler, httpHandler, tcpHandler)

	// Create proxy manager for MCP tool control.
	manager := proxy.NewManager(detector, logger)
	manager.SetPeekTimeout(cfg.PeekTimeout)
	manager.SetMaxConnections(cfg.MaxConnections)

	return runMCP(ctx, ca, issuer, store, store, manager, passthrough, scope, interceptEngine, interceptQueue, pipeline, fuzzRunner, tcpHandler, httpHandler, http2Handler, proxyCfg, cfg.DBPath, cfg.MCPHTTPAddr, cfg.MCPHTTPToken, cfg.UIDir, logger)
}

// applyEnvFallback checks each flag in envVarMap; if the flag was not explicitly
// set on the command line, it falls back to the corresponding KP_ environment
// variable. Priority: CLI flag > environment variable > config file > default value.
func applyEnvFallback(fs *flag.FlagSet, cfg *config.Config, configFile *string) {
	// Collect flags that were explicitly set on the command line.
	flagSet := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		flagSet[f.Name] = true
	})

	for flagName, envVar := range envVarMap {
		if flagSet[flagName] {
			continue
		}
		v := os.Getenv(envVar)
		if v == "" {
			continue
		}
		switch flagName {
		case "config":
			if configFile != nil && *configFile == "" {
				*configFile = v
			}
		case "db":
			cfg.DBPath = v
		case "ca-cert":
			cfg.CACertPath = v
		case "ca-key":
			cfg.CAKeyPath = v
		case "ca-ephemeral":
			cfg.CAEphemeral = parseBool(v)
		case "insecure":
			cfg.InsecureSkipVerify = parseBool(v)
		case "log-level":
			cfg.LogLevel = v
		case "log-format":
			cfg.LogFormat = v
		case "log-file":
			cfg.LogFile = v
		case "mcp-http-addr":
			cfg.MCPHTTPAddr = v
		case "mcp-http-token":
			cfg.MCPHTTPToken = v
		case "ui-dir":
			cfg.UIDir = v
		}
	}
}

// parseBool parses a boolean string, accepting "true", "false", "1", "0".
// Returns false for unrecognized values.
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "1":
		return true
	case "false", "0":
		return false
	default:
		// Fallback to strconv for broader coverage (e.g. "t", "f", "yes", "no").
		v, err := strconv.ParseBool(s)
		if err != nil {
			return false
		}
		return v
	}
}

// runMCP starts the MCP server on stdin/stdout. When mcpHTTPAddr is non-empty,
// a Streamable HTTP transport is also started concurrently on that address.
// Both transports share the same MCP server instance, Manager, Store, and CA.
// The proxy is not started automatically; use the proxy_start tool to begin
// intercepting traffic.
func runMCP(ctx context.Context, ca *cert.CA, issuer *cert.Issuer, store session.Store, fuzzStore session.FuzzStore, manager *proxy.Manager, passthrough *proxy.PassthroughList, scope *proxy.CaptureScope, interceptEngine *intercept.Engine, interceptQueue *intercept.Queue, pipeline *rules.Pipeline, fuzzRunner *fuzzer.Runner, tcpHandler *prototcp.Handler, httpHandler *protohttp.Handler, http2Handler *protohttp2.Handler, proxyCfg *config.ProxyConfig, dbPath string, mcpHTTPAddr string, mcpHTTPToken string, uiDir string, logger *slog.Logger) error {
	logger.Info("starting MCP server on stdio")

	// Build MCP server options.
	opts := []mcp.ServerOption{
		mcp.WithDBPath(dbPath),
		mcp.WithPassthroughList(passthrough),
		mcp.WithCaptureScope(scope),
		mcp.WithInterceptEngine(interceptEngine),
		mcp.WithInterceptQueue(interceptQueue),
		mcp.WithTransformPipeline(pipeline),
		mcp.WithFuzzRunner(fuzzRunner),
		mcp.WithFuzzStore(fuzzStore),
		mcp.WithIssuer(issuer),
		mcp.WithTCPHandler(tcpHandler),
		mcp.WithUpstreamProxySetter(httpHandler),
		mcp.WithUpstreamProxySetter(http2Handler),
	}

	// Pass proxy config file defaults to the MCP server.
	if proxyCfg != nil {
		opts = append(opts, mcp.WithProxyDefaults(proxyCfg))
		logger.Info("loaded proxy config file defaults")
	}

	// Set up WebUI override directory if specified.
	if uiDir != "" {
		opts = append(opts, mcp.WithUIDir(uiDir))
	}

	// Set up Bearer token authentication middleware for HTTP transport.
	if mcpHTTPAddr != "" {
		token, err := resolveHTTPToken(mcpHTTPToken, logger)
		if err != nil {
			return fmt.Errorf("MCP HTTP token: %w", err)
		}
		opts = append(opts, mcp.WithMiddleware(func(next http.Handler) http.Handler {
			return mcp.BearerAuthMiddleware(next, token)
		}))
	}

	mcpServer := mcp.NewServer(ctx, ca, store, manager, opts...)

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

// resolveHTTPToken returns the Bearer token to use for MCP HTTP authentication.
// If token is non-empty it is returned as-is. Otherwise a random token is
// generated and logged to stderr so the operator can retrieve it.
func resolveHTTPToken(token string, logger *slog.Logger) (string, error) {
	if token != "" {
		return token, nil
	}
	generated, err := mcp.GenerateToken()
	if err != nil {
		return "", err
	}
	// Log the auto-generated token to stderr so the operator can use it.
	// This is the only time the token value appears in logs.
	logger.Info("generated MCP HTTP Bearer token (use this to authenticate)",
		"token", generated)
	return generated, nil
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
