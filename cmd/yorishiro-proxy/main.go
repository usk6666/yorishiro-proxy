package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/logging"
	"github.com/usk6666/yorishiro-proxy/internal/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	protosocks5 "github.com/usk6666/yorishiro-proxy/internal/protocol/socks5"
	prototcp "github.com/usk6666/yorishiro-proxy/internal/protocol/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
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

// envVarMap maps flag names to their corresponding YP_ environment variable names.
var envVarMap = map[string]string{
	"config":             "YP_CONFIG",
	"db":                 "YP_DB",
	"ca-cert":            "YP_CA_CERT",
	"ca-key":             "YP_CA_KEY",
	"ca-ephemeral":       "YP_CA_EPHEMERAL",
	"insecure":           "YP_INSECURE",
	"log-level":          "YP_LOG_LEVEL",
	"log-format":         "YP_LOG_FORMAT",
	"log-file":           "YP_LOG_FILE",
	"mcp-http-addr":      "YP_MCP_HTTP_ADDR",
	"mcp-http-token":     "YP_MCP_HTTP_TOKEN",
	"ui-dir":             "YP_UI_DIR",
	"target-policy-file": "YP_TARGET_POLICY_FILE",
	"no-open-browser":    "YP_NO_OPEN_BROWSER",
	"tls-fingerprint":    "YP_TLS_FINGERPRINT",
	"safety-filter":      "YP_SAFETY_FILTER_ENABLED",
}

func run(ctx context.Context) error {
	// Check for subcommands before parsing flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			return runInstall(ctx, os.Args[2:])
		case "upgrade":
			return runUpgrade(ctx, os.Args[2:])
		case "version":
			fmt.Println(buildVersion())
			return nil
		}
	}
	return runWithFlags(ctx, flag.CommandLine, os.Args[1:])
}

// runWithFlags implements the main logic using the provided FlagSet.
// This separation allows testing flag parsing and env var fallback
// without affecting the global flag.CommandLine state.
func runWithFlags(ctx context.Context, fs *flag.FlagSet, args []string) error {
	cfg := config.Default()

	// Config file path — loaded early to provide defaults for proxy_start.
	var configFile string
	fs.StringVar(&configFile, "config", "", "JSON config file path for proxy defaults (env: YP_CONFIG)")

	// Target scope policy file path.
	var targetPolicyFile string
	fs.StringVar(&targetPolicyFile, "target-policy-file", "", "target scope policy JSON file path (env: YP_TARGET_POLICY_FILE)")

	// TLS fingerprint profile override. Applied as a proxy default when set.
	var tlsFingerprint string
	fs.StringVar(&tlsFingerprint, "tls-fingerprint", "", "TLS fingerprint profile: chrome, firefox, safari, edge, random, none (env: YP_TLS_FINGERPRINT)")

	// Define flags — only those requiring startup-time decisions.
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath,
		"SQLite database path or project name (env: YP_DB)\n"+
			"    project name (no ext, no path sep) -> ~/.yorishiro-proxy/<name>.db\n"+
			"    absolute path                      -> used as-is\n"+
			"    relative path with extension        -> CWD-relative")
	fs.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "CA certificate file path (env: YP_CA_CERT)")
	fs.StringVar(&cfg.CAKeyPath, "ca-key", cfg.CAKeyPath, "CA private key file path (env: YP_CA_KEY)")
	fs.BoolVar(&cfg.CAEphemeral, "ca-ephemeral", cfg.CAEphemeral, "use ephemeral in-memory CA (env: YP_CA_EPHEMERAL)")
	fs.BoolVar(&cfg.InsecureSkipVerify, "insecure", cfg.InsecureSkipVerify, "skip upstream TLS verification (env: YP_INSECURE)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, error (env: YP_LOG_LEVEL)")
	fs.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "log format: text, json (env: YP_LOG_FORMAT)")
	fs.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "log output file, default stderr (env: YP_LOG_FILE)")
	fs.StringVar(&cfg.MCPHTTPAddr, "mcp-http-addr", cfg.MCPHTTPAddr, "Streamable HTTP listen address (env: YP_MCP_HTTP_ADDR)")
	fs.StringVar(&cfg.MCPHTTPToken, "mcp-http-token", cfg.MCPHTTPToken, "HTTP Bearer auth token, auto-generated if empty (env: YP_MCP_HTTP_TOKEN)")
	fs.StringVar(&cfg.UIDir, "ui-dir", cfg.UIDir, "directory for WebUI static files, overrides embedded assets (env: YP_UI_DIR)")
	fs.BoolVar(&cfg.NoOpenBrowser, "no-open-browser", cfg.NoOpenBrowser, "disable auto-opening WebUI in browser (env: YP_NO_OPEN_BROWSER)")

	// SafetyFilter enable/disable override. When set via flag or env var,
	// it overrides the config file's safety_filter.enabled value.
	var safetyFilterEnabled bool
	fs.BoolVar(&safetyFilterEnabled, "safety-filter", false, "enable SafetyFilter engine (env: YP_SAFETY_FILTER_ENABLED)")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "yorishiro-proxy %s\n\n", buildVersion())
		fmt.Fprintf(fs.Output(), "Usage: yorishiro-proxy [flags]\n")
		fmt.Fprintf(fs.Output(), "       yorishiro-proxy install [target] [flags]\n")
		fmt.Fprintf(fs.Output(), "       yorishiro-proxy upgrade [--check]\n\n")
		fmt.Fprintf(fs.Output(), "yorishiro-proxy is an AI agent network proxy (MCP server).\n")
		fmt.Fprintf(fs.Output(), "It runs as an MCP server on stdin/stdout by default.\n\n")
		fmt.Fprintf(fs.Output(), "Subcommands:\n")
		fmt.Fprintf(fs.Output(), "  install  Install and configure components (MCP, CA, Skills, Playwright)\n")
		fmt.Fprintf(fs.Output(), "  upgrade  Check for and install updates from GitHub Releases\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment variables:\n")
		fmt.Fprintf(fs.Output(), "  All flags accept a YP_ prefixed environment variable as fallback.\n")
		fmt.Fprintf(fs.Output(), "  Priority: CLI flag > environment variable > config file > default value.\n")
		fmt.Fprintf(fs.Output(), "  Naming: replace hyphens with underscores, uppercase (e.g. -log-level -> YP_LOG_LEVEL).\n")
		fmt.Fprintf(fs.Output(), "\nExamples:\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy                                  # MCP stdio mode (default)\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install                          # install all components\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install mcp                      # register MCP config only\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install ca --trust               # generate CA + register in OS\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install skills                   # install skills only\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy -db pentest-2026                 # project DB: ~/.yorishiro-proxy/pentest-2026.db\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy -db /data/project.db             # absolute path: used as-is\n")
		fmt.Fprintf(fs.Output(), "  YP_DB=client-audit yorishiro-proxy               # project name via env var\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy -config proxy.json               # load proxy config from file\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy -mcp-http-addr 127.0.0.1:3000    # stdio + Streamable HTTP\n")
		fmt.Fprintf(fs.Output(), "  YP_INSECURE=true yorishiro-proxy                  # skip TLS verification\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply environment variable fallback for flags not explicitly set.
	applyEnvFallback(fs)

	// Track whether safety-filter was explicitly set (flag or env var).
	safetyFilterExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "safety-filter" {
			safetyFilterExplicit = true
		}
	})
	if safetyFilterExplicit {
		cfg.SafetyFilterEnabled = &safetyFilterEnabled
	}

	// Validate configuration values before proceeding with initialization.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Load proxy config and target scope policy.
	configs, err := loadConfigs(configFile, targetPolicyFile)
	if err != nil {
		return err
	}
	proxyCfg := configs.proxyCfg
	targetScopePolicy := configs.targetScopePolicy
	targetScopePolicySource := configs.targetScopePolicySource

	// Apply CLI TLS fingerprint flag. CLI flag takes precedence over config file.
	proxyCfg, err = applyTLSFingerprintFlag(tlsFingerprint, proxyCfg)
	if err != nil {
		return err
	}

	infra, err := initInfra(ctx, cfg)
	if err != nil {
		return err
	}
	defer infra.cleanup()
	logger := infra.logger
	store := infra.store

	// Initialize CA and certificate issuer for HTTPS MITM.
	ca, err := initCA(cfg, logger)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	issuer := cert.NewIssuer(ca)

	// Initialize TLS passthrough list and populate from config.
	passthrough := initPassthroughList(cfg, logger)

	// Create shared capture scope for controlling flow recording.
	scope := proxy.NewCaptureScope()

	// Initialize intercept engine and queue.
	interceptEngine := intercept.NewEngine()
	interceptQueue := intercept.NewQueue()

	// Initialize auto-transform pipeline for request/response modification.
	pipeline := rules.NewPipeline()

	proto, err := initProtocolHandlers(ctx, protocolDeps{
		cfg:             cfg,
		proxyCfg:        proxyCfg,
		store:           store,
		issuer:          issuer,
		passthrough:     passthrough,
		scope:           scope,
		interceptEngine: interceptEngine,
		interceptQueue:  interceptQueue,
		pipeline:        pipeline,
		logger:          logger,
	})
	if err != nil {
		return err
	}
	if proto.pluginEngine != nil {
		defer proto.pluginEngine.Close()
	}

	// Create proxy manager for MCP tool control.
	manager := proxy.NewManager(proto.detector, logger)
	manager.SetPeekTimeout(cfg.PeekTimeout)
	manager.SetMaxConnections(cfg.MaxConnections)

	// Build target scope with policy rules if configured.
	targetScope := initTargetScope(targetScopePolicy, proto.socks5Handler)

	rateLimiter := initRateLimiter(targetScopePolicy, logger)

	// Initialize SafetyFilter engine from config.
	safetyEngine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		return err
	}

	opts, err := buildMCPOptions(cfg, proxyCfg, store, issuer, passthrough, scope,
		interceptEngine, interceptQueue, pipeline, proto, targetScope, rateLimiter,
		safetyEngine, targetScopePolicySource, logger)
	if err != nil {
		return err
	}

	mcpServer := mcp.NewServer(ctx, ca, store, manager, opts...)
	logger.Info("starting MCP server on stdio")

	return startServers(ctx, cfg, mcpServer, proto.webUIToken, logger)
}

// applyEnvFallback checks each flag in envVarMap; if the flag was not explicitly
// set on the command line, it falls back to the corresponding YP_ environment
// variable. Priority: CLI flag > environment variable > config file > default value.
//
// Because all flags are registered with fs.StringVar/fs.BoolVar pointing to the
// target struct fields, fs.Set() updates those fields directly.
func applyEnvFallback(fs *flag.FlagSet) {
	flagSet := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { flagSet[f.Name] = true })

	for flagName, envVar := range envVarMap {
		if flagSet[flagName] {
			continue
		}
		if v := os.Getenv(envVar); v != "" {
			_ = fs.Set(flagName, v)
		}
	}
}

// configsResult holds loaded configuration files.
type configsResult struct {
	proxyCfg                *config.ProxyConfig
	targetScopePolicy       *config.TargetScopePolicyConfig
	targetScopePolicySource string
}

// applyTLSFingerprintFlag validates and applies the CLI -tls-fingerprint flag value.
// Returns the (possibly initialized) ProxyConfig with the fingerprint set.
func applyTLSFingerprintFlag(tlsFingerprint string, proxyCfg *config.ProxyConfig) (*config.ProxyConfig, error) {
	if tlsFingerprint == "" {
		return proxyCfg, nil
	}
	tlsFingerprint = strings.ToLower(tlsFingerprint)
	validProfiles := map[string]bool{
		"chrome": true, "firefox": true, "safari": true,
		"edge": true, "random": true, "none": true,
	}
	if !validProfiles[tlsFingerprint] {
		return nil, fmt.Errorf("invalid -tls-fingerprint value %q: valid values are chrome, firefox, safari, edge, random, none", tlsFingerprint)
	}
	if proxyCfg == nil {
		proxyCfg = &config.ProxyConfig{}
	}
	proxyCfg.TLSFingerprint = tlsFingerprint
	return proxyCfg, nil
}

// loadConfigs loads the proxy config file and target scope policy.
// Priority for target scope: -target-policy-file > config file target_scope_policy section.
func loadConfigs(configFile, targetPolicyFile string) (*configsResult, error) {
	var proxyCfg *config.ProxyConfig
	if configFile != "" {
		var err error
		proxyCfg, err = config.LoadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("load config file: %w", err)
		}
	}

	var targetScopePolicy *config.TargetScopePolicyConfig
	var targetScopePolicySource string
	if targetPolicyFile != "" {
		var err error
		targetScopePolicy, err = config.LoadPolicyFile(targetPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("load target policy file: %w", err)
		}
		targetScopePolicySource = "policy file"
	} else if proxyCfg != nil && proxyCfg.TargetScopePolicy != nil {
		targetScopePolicy = proxyCfg.TargetScopePolicy
		targetScopePolicySource = "config file"
	}

	return &configsResult{
		proxyCfg:                proxyCfg,
		targetScopePolicy:       targetScopePolicy,
		targetScopePolicySource: targetScopePolicySource,
	}, nil
}

// infraResult holds infrastructure components initialized by initInfra.
type infraResult struct {
	logger  *slog.Logger
	store   *flow.SQLiteStore
	cleanup func()
}

// initInfra resolves the DB path, sets up the logger, opens the SQLite store,
// and starts the flow cleaner. The returned cleanup function closes all resources.
func initInfra(ctx context.Context, cfg *config.Config) (*infraResult, error) {
	// Apply smart DB path resolution: project name -> ~/.yorishiro-proxy/<name>.db.
	resolvedDBPath, err := config.ResolveDBPath(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("resolve db path: %w", err)
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
		return nil, fmt.Errorf("init logger: %w", err)
	}
	slog.SetDefault(logger)

	// Ensure the database directory exists (e.g. ~/.yorishiro-proxy/).
	if err := config.EnsureDBDir(cfg.DBPath); err != nil {
		logCleanup()
		return nil, fmt.Errorf("ensure db directory: %w", err)
	}

	// Initialize SQLite flow store.
	store, err := flow.NewSQLiteStore(ctx, cfg.DBPath, logger)
	if err != nil {
		logCleanup()
		return nil, fmt.Errorf("init flow store: %w", err)
	}

	// Build composite cleanup function.
	var cleanerStop func()
	cleanup := func() {
		if cleanerStop != nil {
			cleanerStop()
		}
		store.Close()
		logCleanup()
	}

	// Start flow cleaner if retention policy is configured.
	cleanerCfg := flow.CleanerConfig{
		MaxFlows: cfg.RetentionMaxFlows,
		MaxAge:   cfg.RetentionMaxAge,
		Interval: cfg.CleanupInterval,
	}
	if cleanerCfg.Enabled() {
		cleaner := flow.NewCleaner(store, cleanerCfg, logger)
		cleaner.Start(ctx)
		cleanerStop = cleaner.Stop
		logger.Info("flow cleaner started",
			"max_flows", cleanerCfg.MaxFlows,
			"max_age", cleanerCfg.MaxAge,
			"interval", cleanerCfg.Interval)
	}

	return &infraResult{logger: logger, store: store, cleanup: cleanup}, nil
}

// protocolDeps holds dependencies needed by initProtocolHandlers.
type protocolDeps struct {
	cfg             *config.Config
	proxyCfg        *config.ProxyConfig
	store           *flow.SQLiteStore
	issuer          *cert.Issuer
	passthrough     *proxy.PassthroughList
	scope           *proxy.CaptureScope
	interceptEngine *intercept.Engine
	interceptQueue  *intercept.Queue
	pipeline        *rules.Pipeline
	logger          *slog.Logger
}

// protocolResult holds all protocol handlers and related components.
type protocolResult struct {
	detector        *protocol.Detector
	httpHandler     *protohttp.Handler
	http2Handler    *protohttp2.Handler
	tcpHandler      *prototcp.Handler
	socks5Handler   *protosocks5.Handler
	socks5Adapter   *socks5AuthAdapter
	pluginEngine    *plugin.Engine
	fuzzRunner      *fuzzer.Runner
	tlsTransport    httputil.TLSTransport
	hostTLSRegistry *httputil.HostTLSRegistry
	webUIToken      string
}

// initProtocolHandlers builds all protocol handlers, the plugin engine, and the
// fuzzer. It returns a protocolResult containing all initialized components.
func initProtocolHandlers(ctx context.Context, deps protocolDeps) (*protocolResult, error) {
	cfg := deps.cfg
	logger := deps.logger
	store := deps.store

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store, deps.issuer, logger)
	httpHandler.SetRequestTimeout(cfg.RequestTimeout)
	httpHandler.SetInsecureSkipVerify(cfg.InsecureSkipVerify)
	httpHandler.SetPassthroughList(deps.passthrough)
	httpHandler.SetCaptureScope(deps.scope)
	httpHandler.SetInterceptEngine(deps.interceptEngine)
	httpHandler.SetInterceptQueue(deps.interceptQueue)
	httpHandler.SetTransformPipeline(deps.pipeline)

	// Build the host TLS registry and TLS transport.
	hostTLSRegistry, err := initHostTLSRegistry(cfg, deps.proxyCfg, logger)
	if err != nil {
		return nil, err
	}
	tlsTransport := initTLSTransport(cfg, hostTLSRegistry, httpHandler, logger)

	// Configure technology stack fingerprint detector for response analysis.
	fpDetector := fingerprint.NewDetector()
	httpHandler.SetDetector(fpDetector)

	// Build HTTP/2 handler for h2c detection and h2 (TLS ALPN) delegation.
	http2Handler := protohttp2.NewHandler(store, logger)
	http2Handler.SetInsecureSkipVerify(cfg.InsecureSkipVerify)
	http2Handler.SetCaptureScope(deps.scope)
	http2Handler.SetInterceptEngine(deps.interceptEngine)
	http2Handler.SetInterceptQueue(deps.interceptQueue)
	http2Handler.SetDetector(fpDetector)
	http2Handler.SetTransformPipeline(deps.pipeline)

	// Build gRPC handler and attach to the HTTP/2 handler for gRPC-specific recording.
	grpcHandler := protogrpc.NewHandler(store, logger)
	http2Handler.SetGRPCHandler(grpcHandler)

	// Link the HTTP/2 handler to the HTTP handler for h2 ALPN delegation.
	httpHandler.SetH2Handler(http2Handler)

	// Initialize fuzzer components for async fuzz job execution.
	fuzzEngine := fuzzer.NewEngine(store, store, store, mcp.NewDefaultHTTPClient(), "")
	fuzzRegistry := fuzzer.NewJobRegistry()
	fuzzRunner := fuzzer.NewRunner(fuzzEngine, fuzzRegistry)

	// Raw TCP fallback handler: must be last since Detect() always returns true.
	tcpHandler := prototcp.NewHandler(store, nil, logger)

	// Build SOCKS5 handler. Post-handshake dispatch is set after plugin
	// engine initialization so that the dispatch closure can capture the
	// plugin engine (which may be nil until then).
	socks5Handler := protosocks5.NewHandler(logger)

	// Build SOCKS5 auth adapter for MCP tool control.
	socks5Adapter := newSOCKS5AuthAdapter(socks5Handler)

	// Apply SOCKS5 auth from config file if specified.
	if deps.proxyCfg != nil && deps.proxyCfg.SOCKS5Auth == "password" {
		if deps.proxyCfg.SOCKS5Username != "" && deps.proxyCfg.SOCKS5Password != "" {
			socks5Adapter.SetPasswordAuth(deps.proxyCfg.SOCKS5Username, deps.proxyCfg.SOCKS5Password)
			logger.Info("SOCKS5 password authentication configured from config file")
		} else {
			logger.Warn("SOCKS5 password auth requested but username/password missing in config file")
		}
	}

	// Load codec plugins from config if configured.
	if err := loadCodecPlugins(deps.proxyCfg, logger); err != nil {
		return nil, err
	}

	// Initialize plugin engine from config if plugins are configured.
	var pluginEngine *plugin.Engine
	if deps.proxyCfg != nil && len(deps.proxyCfg.Plugins) > 0 {
		var pluginConfigs []plugin.PluginConfig
		if err := json.Unmarshal(deps.proxyCfg.Plugins, &pluginConfigs); err != nil {
			return nil, fmt.Errorf("parse plugin configs: %w", err)
		}
		pluginEngine = plugin.NewEngine(logger)
		if err := pluginEngine.SetDB(ctx, store.DB()); err != nil {
			return nil, fmt.Errorf("init plugin store: %w", err)
		}
		if err := pluginEngine.LoadPlugins(ctx, pluginConfigs); err != nil {
			return nil, fmt.Errorf("load plugins: %w", err)
		}
		httpHandler.SetPluginEngine(pluginEngine)
		http2Handler.SetPluginEngine(pluginEngine)
		grpcHandler.SetPluginEngine(pluginEngine)
		tcpHandler.SetPluginEngine(pluginEngine)
		socks5Handler.SetPluginEngine(pluginEngine)
		logger.Info("plugins loaded", "count", pluginEngine.PluginCount())
	}

	// Build SOCKS5 post-handshake dispatch after plugin engine initialization
	// so the raw TCP relay path can use flow recording and plugin hooks.
	socks5Dispatch := protosocks5.NewPostHandshakeDispatch(protosocks5.DispatchConfig{
		TunnelHandler: httpHandler,
		HTTPDetector:  httpHandler,
		Logger:        logger,
		FlowWriter:    store,
		PluginEngine:  pluginEngine,
	})
	socks5Handler.SetPostHandshake(socks5Dispatch)

	// Register handlers in priority order: h2c -> HTTP/1.x -> SOCKS5 -> raw TCP fallback.
	detector := protocol.NewDetector(http2Handler, httpHandler, socks5Handler, tcpHandler)

	return &protocolResult{
		detector:        detector,
		httpHandler:     httpHandler,
		http2Handler:    http2Handler,
		tcpHandler:      tcpHandler,
		socks5Handler:   socks5Handler,
		socks5Adapter:   socks5Adapter,
		pluginEngine:    pluginEngine,
		fuzzRunner:      fuzzRunner,
		tlsTransport:    tlsTransport,
		hostTLSRegistry: hostTLSRegistry,
	}, nil
}

// initHostTLSRegistry builds a HostTLSRegistry from the CLI config and proxy config file.
// CLI config settings take precedence; proxy config file settings are applied as fallbacks.
func initHostTLSRegistry(cfg *config.Config, proxyCfg *config.ProxyConfig, logger *slog.Logger) (*httputil.HostTLSRegistry, error) {
	reg := httputil.NewHostTLSRegistry()

	// Apply global mTLS client certificate from CLI config.
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		globalTLS := &httputil.HostTLSConfig{
			ClientCertPath: cfg.ClientCertPath,
			ClientKeyPath:  cfg.ClientKeyPath,
		}
		if err := globalTLS.Validate(); err != nil {
			return nil, fmt.Errorf("global client cert: %w", err)
		}
		reg.SetGlobal(globalTLS)
		logger.Info("global mTLS client certificate configured",
			"cert", cfg.ClientCertPath, "key", cfg.ClientKeyPath)
	}

	// Apply per-host TLS configs from CLI config.
	if err := applyHostTLSEntries(reg, cfg.HostTLS, "", logger); err != nil {
		return nil, err
	}

	// Apply from proxy config file as fallback.
	if proxyCfg != nil {
		if proxyCfg.ClientCertPath != "" && proxyCfg.ClientKeyPath != "" && reg.Global() == nil {
			globalTLS := &httputil.HostTLSConfig{
				ClientCertPath: proxyCfg.ClientCertPath,
				ClientKeyPath:  proxyCfg.ClientKeyPath,
			}
			if err := globalTLS.Validate(); err != nil {
				return nil, fmt.Errorf("proxy config global client cert: %w", err)
			}
			reg.SetGlobal(globalTLS)
			logger.Info("global mTLS client certificate configured from proxy config",
				"cert", proxyCfg.ClientCertPath, "key", proxyCfg.ClientKeyPath)
		}
		if err := applyHostTLSEntries(reg, proxyCfg.HostTLS, "proxy config ", logger); err != nil {
			return nil, err
		}
	}

	return reg, nil
}

// applyHostTLSEntries adds per-host TLS configurations from a map to the registry.
func applyHostTLSEntries(reg *httputil.HostTLSRegistry, entries map[string]*config.HostTLSEntry, prefix string, logger *slog.Logger) error {
	for hostname, entry := range entries {
		hostCfg := &httputil.HostTLSConfig{
			ClientCertPath: entry.ClientCertPath,
			ClientKeyPath:  entry.ClientKeyPath,
			TLSVerify:      entry.TLSVerify,
			CABundlePath:   entry.CABundlePath,
		}
		if err := hostCfg.Validate(); err != nil {
			return fmt.Errorf("%shost_tls[%s]: %w", prefix, hostname, err)
		}
		reg.Set(hostname, hostCfg)
		logger.Info("per-host TLS configured", "source", prefix+"config", "host", hostname)
	}
	return nil
}

// initTLSTransport creates the TLS transport with HostTLS support and attaches
// it to the HTTP handler. If a TLS fingerprint profile is configured, uTLS is used;
// otherwise StandardTransport is used.
func initTLSTransport(cfg *config.Config, reg *httputil.HostTLSRegistry, httpHandler *protohttp.Handler, logger *slog.Logger) httputil.TLSTransport {
	if cfg.TLSFingerprint != "" {
		profile, err := httputil.ParseBrowserProfile(cfg.TLSFingerprint)
		if err != nil {
			// This was already validated earlier; log and use standard transport.
			logger.Warn("invalid TLS fingerprint profile, using standard transport", "error", err)
			return initStandardTransport(cfg, reg, httpHandler)
		}
		t := &httputil.UTLSTransport{
			Profile:            profile,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			HostTLS:            reg,
		}
		httpHandler.SetTLSTransport(t)
		logger.Info("uTLS fingerprint enabled", "profile", profile.String())
		return t
	}
	return initStandardTransport(cfg, reg, httpHandler)
}

// initStandardTransport creates a StandardTransport with HostTLS and sets it on the handler.
func initStandardTransport(cfg *config.Config, reg *httputil.HostTLSRegistry, httpHandler *protohttp.Handler) httputil.TLSTransport {
	t := &httputil.StandardTransport{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		HostTLS:            reg,
	}
	httpHandler.SetTLSTransport(t)
	return t
}

// loadCodecPlugins loads Starlark codec plugins from the proxy config.
// Codec plugins are registered with the default codec registry.
func loadCodecPlugins(proxyCfg *config.ProxyConfig, logger *slog.Logger) error {
	if proxyCfg == nil || len(proxyCfg.CodecPlugins) == 0 {
		return nil
	}
	var codecConfigs []codec.CodecPluginConfig
	if err := json.Unmarshal(proxyCfg.CodecPlugins, &codecConfigs); err != nil {
		return fmt.Errorf("parse codec plugin configs: %w", err)
	}
	logWarn := func(msg string, args ...any) {
		logger.Warn(msg, args...)
	}
	n, err := codec.LoadCodecPlugins(codec.DefaultRegistry(), codecConfigs, logWarn)
	if err != nil {
		return fmt.Errorf("load codec plugins: %w", err)
	}
	if n > 0 {
		logger.Info("codec plugins loaded", "count", n)
	}
	return nil
}

// buildMCPOptions assembles the MCP server option slice from all components.
func buildMCPOptions(
	cfg *config.Config,
	proxyCfg *config.ProxyConfig,
	store *flow.SQLiteStore,
	issuer *cert.Issuer,
	passthrough *proxy.PassthroughList,
	scope *proxy.CaptureScope,
	interceptEngine *intercept.Engine,
	interceptQueue *intercept.Queue,
	pipeline *rules.Pipeline,
	proto *protocolResult,
	targetScope *proxy.TargetScope,
	rateLimiter *proxy.RateLimiter,
	safetyEngine *safety.Engine,
	targetScopePolicySource string,
	logger *slog.Logger,
) ([]mcp.ServerOption, error) {
	opts := []mcp.ServerOption{
		mcp.WithVersion(version),
		mcp.WithDBPath(cfg.DBPath),
		mcp.WithPassthroughList(passthrough),
		mcp.WithCaptureScope(scope),
		mcp.WithInterceptEngine(interceptEngine),
		mcp.WithInterceptQueue(interceptQueue),
		mcp.WithTransformPipeline(pipeline),
		mcp.WithFuzzRunner(proto.fuzzRunner),
		mcp.WithFuzzStore(store),
		mcp.WithIssuer(issuer),
		mcp.WithTCPHandler(proto.tcpHandler),
		mcp.WithUpstreamProxySetter(proto.httpHandler),
		mcp.WithUpstreamProxySetter(proto.http2Handler),
		mcp.WithTargetScopeSetter(proto.httpHandler),
		mcp.WithTargetScopeSetter(proto.http2Handler),
		mcp.WithTLSFingerprintSetter(proto.httpHandler),
		mcp.WithTLSFingerprintSetter(proto.http2Handler),
		mcp.WithSOCKS5Handler(proto.socks5Adapter),
		mcp.WithRateLimiter(rateLimiter),
		mcp.WithRateLimiterSetter(proto.httpHandler),
		mcp.WithRateLimiterSetter(proto.http2Handler),
		mcp.WithRateLimiterSetter(proto.socks5Handler),
		mcp.WithSafetyEngineSetter(proto.httpHandler),
		mcp.WithSafetyEngineSetter(proto.http2Handler),
	}

	if proto.tlsTransport != nil {
		opts = append(opts, mcp.WithTLSTransport(proto.tlsTransport))
	}
	if proto.hostTLSRegistry != nil {
		opts = append(opts, mcp.WithHostTLSRegistry(proto.hostTLSRegistry))
	}

	if proxyCfg != nil {
		opts = append(opts, mcp.WithProxyDefaults(proxyCfg))
		logger.Info("loaded proxy config file defaults")
	}
	if proto.pluginEngine != nil {
		opts = append(opts, mcp.WithPluginEngine(proto.pluginEngine))
	}
	if targetScope != nil {
		opts = append(opts, mcp.WithTargetScope(targetScope))
		allows, denies := targetScope.PolicyRules()
		logger.Info("target scope policy loaded",
			"allows", len(allows),
			"denies", len(denies),
			"source", targetScopePolicySource)
	}
	if safetyEngine != nil {
		opts = append(opts, mcp.WithSafetyEngine(safetyEngine))
	}
	if cfg.UIDir != "" {
		opts = append(opts, mcp.WithUIDir(cfg.UIDir))
	}

	// Set up Bearer token authentication middleware for HTTP transport.
	if cfg.MCPHTTPAddr != "" {
		token, err := resolveHTTPToken(cfg.MCPHTTPToken, logger)
		if err != nil {
			return nil, fmt.Errorf("MCP HTTP token: %w", err)
		}
		proto.webUIToken = token
		opts = append(opts, mcp.WithMiddleware(func(next http.Handler) http.Handler {
			return mcp.BearerAuthMiddleware(next, token)
		}))
		logger.Info("WebUI available",
			"url", fmt.Sprintf("http://%s/?token=%s", cfg.MCPHTTPAddr, url.QueryEscape(token)))
	}

	return opts, nil
}

// startServers launches the MCP stdio and optional HTTP servers using an errgroup.
func startServers(ctx context.Context, cfg *config.Config, mcpServer *mcp.Server, webUIToken string, logger *slog.Logger) error {
	g, gctx := errgroup.WithContext(ctx)

	// Always start stdio transport (single flow via Server.Run).
	g.Go(func() error {
		transport := &gomcp.StdioTransport{}
		if err := mcpServer.Run(gctx, transport); err != nil {
			if gctx.Err() != nil {
				logger.Info("MCP stdio server stopped")
				return nil
			}
			return fmt.Errorf("MCP stdio server: %w", err)
		}
		return nil
	})

	// Optionally start Streamable HTTP transport (multi-flow via Server.Connect).
	if cfg.MCPHTTPAddr != "" {
		var onListening func(addr string)
		if !cfg.NoOpenBrowser {
			capturedToken := webUIToken
			onListening = func(addr string) {
				u := fmt.Sprintf("http://%s/?token=%s", addr, url.QueryEscape(capturedToken))
				if err := openBrowser(u); err != nil {
					logger.Warn("failed to open browser", "url", u, "error", err)
				}
			}
		}

		g.Go(func() error {
			if err := mcpServer.RunHTTP(gctx, cfg.MCPHTTPAddr, onListening); err != nil {
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

// initSafetyFilter creates a SafetyFilter engine from config file settings and
// CLI/env overrides. Returns nil if SafetyFilter is not enabled or not configured.
func initSafetyFilter(cfg *config.Config, proxyCfg *config.ProxyConfig, logger *slog.Logger) (*safety.Engine, error) {
	var sfCfg *config.SafetyFilterConfig
	if proxyCfg != nil {
		sfCfg = proxyCfg.SafetyFilter
	}

	// Determine if SafetyFilter is enabled.
	// Priority: CLI flag/env var > config file > default (disabled).
	enabled := false
	if sfCfg != nil {
		enabled = sfCfg.Enabled
	}
	if cfg.SafetyFilterEnabled != nil {
		enabled = *cfg.SafetyFilterEnabled
	}

	if !enabled {
		return nil, nil
	}

	// Build safety.Config from the config file settings.
	engineCfg := safety.Config{}
	if sfCfg != nil {
		// Validate before building.
		if err := config.ValidateSafetyFilterConfig(sfCfg); err != nil {
			return nil, fmt.Errorf("safety filter config: %w", err)
		}

		if sfCfg.Input != nil {
			for _, rule := range sfCfg.Input.Rules {
				rc := safety.RuleConfig{
					Preset:  rule.Preset,
					ID:      rule.ID,
					Name:    rule.Name,
					Pattern: rule.Pattern,
					Targets: rule.Targets,
				}

				// Set action: use section-level action if set, otherwise default to "block".
				action := "block"
				if sfCfg.Input.Action != "" {
					action = sfCfg.Input.Action
				}
				rc.Action = action

				engineCfg.InputRules = append(engineCfg.InputRules, rc)
			}
		}

		if sfCfg.Output != nil {
			for _, rule := range sfCfg.Output.Rules {
				rc := safety.RuleConfig{
					Preset:      rule.Preset,
					ID:          rule.ID,
					Name:        rule.Name,
					Pattern:     rule.Pattern,
					Targets:     rule.Targets,
					Replacement: rule.Replacement,
				}

				// Set action: use section-level action if set, otherwise default to "mask".
				action := "mask"
				if sfCfg.Output.Action != "" {
					action = sfCfg.Output.Action
				}
				rc.Action = action

				engineCfg.OutputRules = append(engineCfg.OutputRules, rc)
			}
		}
	}

	engine, err := safety.NewEngine(engineCfg)
	if err != nil {
		return nil, fmt.Errorf("init safety filter: %w", err)
	}

	logger.Info("safety filter enabled",
		"input_rules", len(engine.InputRules()),
		"output_rules", len(engine.OutputRules()))

	return engine, nil
}

// initRateLimiter creates a RateLimiter and applies policy limits from the config.
func initRateLimiter(policy *config.TargetScopePolicyConfig, logger *slog.Logger) *proxy.RateLimiter {
	rl := proxy.NewRateLimiter()
	if policy != nil && policy.RateLimits != nil {
		rl.SetPolicyLimits(proxy.RateLimitConfig{
			MaxRequestsPerSecond:        policy.RateLimits.MaxRequestsPerSecond,
			MaxRequestsPerHostPerSecond: policy.RateLimits.MaxRequestsPerHostPerSecond,
		})
		logger.Info("rate limits policy loaded",
			"max_rps", policy.RateLimits.MaxRequestsPerSecond,
			"max_rps_per_host", policy.RateLimits.MaxRequestsPerHostPerSecond)
	}
	return rl
}

// initPassthroughList creates and populates the TLS passthrough list from config.
func initPassthroughList(cfg *config.Config, logger *slog.Logger) *proxy.PassthroughList {
	passthrough := proxy.NewPassthroughList()
	for _, pattern := range cfg.TLSPassthrough {
		if !passthrough.Add(pattern) {
			logger.Warn("ignoring invalid TLS passthrough pattern", "pattern", pattern)
		}
	}
	if passthrough.Len() > 0 {
		logger.Info("TLS passthrough configured", "patterns", passthrough.Len())
	}
	return passthrough
}

// initTargetScope builds a TargetScope from the policy config and attaches it
// to the SOCKS5 handler. Returns nil if no policy is configured.
func initTargetScope(policy *config.TargetScopePolicyConfig, socks5Handler *protosocks5.Handler) *proxy.TargetScope {
	if policy == nil {
		return nil
	}
	targetScope := proxy.NewTargetScope()
	allows := convertTargetRules(policy.Allows)
	denies := convertTargetRules(policy.Denies)
	targetScope.SetPolicyRules(allows, denies)
	socks5Handler.SetTargetScope(targetScope)
	return targetScope
}

// convertTargetRules converts config TargetRuleConfig values to proxy TargetRule values.
func convertTargetRules(cfgRules []config.TargetRuleConfig) []proxy.TargetRule {
	if len(cfgRules) == 0 {
		return nil
	}
	rules := make([]proxy.TargetRule, len(cfgRules))
	for i, r := range cfgRules {
		rules[i] = proxy.TargetRule{
			Hostname:   r.Hostname,
			Ports:      r.Ports,
			PathPrefix: r.PathPrefix,
			Schemes:    r.Schemes,
		}
	}
	return rules
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
//  2. Auto-persist (default): CA is stored in ~/.yorishiro-proxy/ca/.
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

// socks5AuthAdapter bridges the MCP server's socks5AuthSetter interface to the
// SOCKS5 handler's SetAuthenticator method. It avoids importing the socks5
// package from the mcp package by keeping the adapter in main.
type socks5AuthAdapter struct {
	handler *protosocks5.Handler
}

// newSOCKS5AuthAdapter creates a new adapter around a SOCKS5 handler.
func newSOCKS5AuthAdapter(h *protosocks5.Handler) *socks5AuthAdapter {
	return &socks5AuthAdapter{handler: h}
}

// SetPasswordAuth enables username/password authentication on the SOCKS5 handler.
func (a *socks5AuthAdapter) SetPasswordAuth(username, password string) {
	a.handler.SetAuthenticator(&staticSOCKS5Auth{
		username: username,
		password: password,
	})
}

// ClearAuth resets the SOCKS5 handler to no-authentication mode (default/global).
func (a *socks5AuthAdapter) ClearAuth() {
	a.handler.SetAuthenticator(nil)
}

// SetPasswordAuthForListener enables username/password authentication for a specific listener.
func (a *socks5AuthAdapter) SetPasswordAuthForListener(listenerName, username, password string) {
	a.handler.SetListenerAuthenticator(listenerName, &staticSOCKS5Auth{
		username: username,
		password: password,
	})
}

// ClearAuthForListener resets a specific listener to no-authentication mode,
// falling back to the default authenticator.
func (a *socks5AuthAdapter) ClearAuthForListener(listenerName string) {
	a.handler.SetListenerAuthenticator(listenerName, nil)
}

// staticSOCKS5Auth is a simple authenticator that validates against a single
// username/password pair.
type staticSOCKS5Auth struct {
	username string
	password string
}

// Authenticate returns true if the credentials match.
// Uses constant-time comparison to prevent timing side-channel attacks.
func (a *staticSOCKS5Auth) Authenticate(username, password string) bool {
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.password))
	return usernameMatch == 1 && passwordMatch == 1
}
