package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/logging"
	"github.com/usk6666/yorishiro-proxy/internal/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/pushrecorder"
	rulescommon "github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// InfraResult holds infrastructure components initialized by InitInfra.
type InfraResult struct {
	Logger  *slog.Logger
	Store   *flow.SQLiteStore
	Cleanup func()
}

// InitInfra resolves the DB path, sets up the logger, opens the SQLite
// store, and starts the flow cleaner. The returned cleanup function closes
// all resources.
func InitInfra(ctx context.Context, cfg *config.Config) (*InfraResult, error) {
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

	// Sweep orphaned yorishiro-body-* temp files from prior crashed or killed
	// runs before initializing any further state. Failures are logged but
	// never block startup.
	config.SweepOrphanBodyFiles(config.ResolveBodySpillDir(cfg), logger)

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
		MaxStreams: cfg.RetentionMaxFlows,
		MaxAge:     cfg.RetentionMaxAge,
		Interval:   cfg.CleanupInterval,
	}
	if cleanerCfg.Enabled() {
		cleaner := flow.NewCleaner(store, cleanerCfg, logger)
		cleaner.Start(ctx)
		cleanerStop = cleaner.Stop
		logger.Info("flow cleaner started",
			"max_flows", cleanerCfg.MaxStreams,
			"max_age", cleanerCfg.MaxAge,
			"interval", cleanerCfg.Interval)
	}

	return &InfraResult{Logger: logger, Store: store, Cleanup: cleanup}, nil
}

// InitSafetyFilter creates a SafetyFilter engine from config file settings
// and CLI/env overrides. Returns nil if SafetyFilter is not enabled or not
// configured.
func InitSafetyFilter(cfg *config.Config, proxyCfg *config.ProxyConfig, logger *slog.Logger) (*safety.Engine, error) {
	sfCfg := proxyCfg.SafetyFilter

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

// InitRateLimiter creates a RateLimiter and applies policy limits from the
// config.
func InitRateLimiter(policy *config.TargetScopePolicyConfig, logger *slog.Logger) *connector.RateLimiter {
	rl := connector.NewRateLimiter()
	if policy != nil && policy.RateLimits != nil {
		rl.SetPolicyLimits(connector.RateLimitConfig{
			MaxRequestsPerSecond:        policy.RateLimits.MaxRequestsPerSecond,
			MaxRequestsPerHostPerSecond: policy.RateLimits.MaxRequestsPerHostPerSecond,
		})
		logger.Info("rate limits policy loaded",
			"max_rps", policy.RateLimits.MaxRequestsPerSecond,
			"max_rps_per_host", policy.RateLimits.MaxRequestsPerHostPerSecond)
	}
	return rl
}

// InitPassthroughList creates and populates the TLS passthrough list from
// config.
func InitPassthroughList(cfg *config.Config, logger *slog.Logger) *connector.PassthroughList {
	passthrough := connector.NewPassthroughList()
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

// InitTargetScope builds a TargetScope from the policy config. Returns nil
// if no policy is configured. The SOCKS5 negotiator picks up the scope
// via connector wiring (USK-690), not via a per-handler setter.
func InitTargetScope(policy *config.TargetScopePolicyConfig) *connector.TargetScope {
	if policy == nil {
		return nil
	}
	targetScope := connector.NewTargetScope()
	allows := ConvertTargetRules(policy.Allows)
	denies := ConvertTargetRules(policy.Denies)
	targetScope.SetPolicyRules(allows, denies)
	return targetScope
}

// ConvertTargetRules converts config.TargetRuleConfig entries into
// connector.TargetRule values. Returns nil for an empty input.
func ConvertTargetRules(cfgRules []config.TargetRuleConfig) []connector.TargetRule {
	if len(cfgRules) == 0 {
		return nil
	}
	rules := make([]connector.TargetRule, len(cfgRules))
	for i, r := range cfgRules {
		rules[i] = connector.TargetRule{
			Hostname:   r.Hostname,
			Ports:      r.Ports,
			PathPrefix: r.PathPrefix,
			Schemes:    r.Schemes,
		}
	}
	return rules
}

// ResolveHTTPToken returns the Bearer token to use for MCP HTTP
// authentication. If token is non-empty it is returned as-is. Otherwise
// a random token is generated and logged to stderr so the operator can
// retrieve it.
func ResolveHTTPToken(token string, logger *slog.Logger) (string, error) {
	if token != "" {
		return token, nil
	}
	generated, err := mcp.GenerateToken()
	if err != nil {
		return "", err
	}
	// Log the auto-generated token at Info (summary) and Debug (full value).
	// The token appears at Debug level only to avoid forwarding the credential
	// to centralized log aggregation systems.
	logger.Info("generated MCP HTTP Bearer token (check server.json or use -mcp-http-token to set explicitly)")
	logger.Debug("generated MCP HTTP Bearer token", "token", generated)
	return generated, nil
}

// InitCA initializes the CA for TLS interception using one of three modes:
//
//  1. Explicit: -ca-cert and -ca-key flags specify paths (loaded from files).
//  2. Auto-persist (default): CA is stored in ~/.yorishiro-proxy/ca/.
//     If files exist, the CA is loaded; otherwise a new CA is generated and saved.
//  3. Ephemeral: --ca-ephemeral generates an in-memory CA with no file persistence.
func InitCA(cfg *config.Config, logger *slog.Logger) (*cert.CA, error) {
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

// initCAAutoPersist implements the auto-persist CA mode. It loads an
// existing CA from the default path, or generates and saves a new one.
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

// InitPluginV2Engine constructs the pluginv2.Engine, ensures the
// pluginv2_kv table exists, and loads the typed pluginv2 plugin list from
// proxyCfg.Plugins. Errors propagate so misconfigured plugins fail boot
// (per-plugin OnError defaults to "skip" so individual broken plugins are
// tolerated without aborting the proxy).
func InitPluginV2Engine(ctx context.Context, store *flow.SQLiteStore, proxyCfg *config.ProxyConfig, logger *slog.Logger) (*pluginv2.Engine, error) {
	eng := pluginv2.NewEngine(logger)
	if err := eng.SetDB(ctx, store.DB()); err != nil {
		eng.Close()
		return nil, fmt.Errorf("init pluginv2 store: %w", err)
	}
	if len(proxyCfg.Plugins) > 0 {
		if err := eng.LoadPlugins(ctx, proxyCfg.Plugins); err != nil {
			eng.Close()
			return nil, fmt.Errorf("load pluginv2 plugins: %w", err)
		}
		logger.Info("pluginv2 plugins loaded", "count", len(proxyCfg.Plugins))
	}
	return eng, nil
}

// assembleLiveManager assembles the connector.BuildConfig and constructs
// the live RFC-001 proxybuild.Manager in one step. Extracted so the caller
// stays under the gocyclo budget.
//
// appCtx is the application lifecycle context — propagated into goroutines
// (currently only the upstream push recorder) so a SIGINT-triggered
// cancellation reaches them without waiting for the upstream Layer's
// channel-close drain path.
func assembleLiveManager(
	appCtx context.Context,
	cfg *config.Config,
	proxyCfg *config.ProxyConfig,
	store *flow.SQLiteStore,
	issuer *cert.Issuer,
	pluginv2Engine *pluginv2.Engine,
	holdQueue *rulescommon.HoldQueue,
	httpInterceptEngine *httprules.InterceptEngine,
	wsInterceptEngine *wsrules.InterceptEngine,
	grpcInterceptEngine *grpcrules.InterceptEngine,
	httpTransformEngine *httprules.TransformEngine,
	passthrough *connector.PassthroughList,
	targetScope *connector.TargetScope,
	rateLimiter *connector.RateLimiter,
	safetyEngine *safety.Engine,
	perProtoSafety PerProtocolSafetyEngines,
	hostTLSRegistry *transport.HostTLSRegistry,
	socks5Negotiator *connector.SOCKS5Negotiator,
	recordScope *flow.RecordScope,
	logger *slog.Logger,
) (*proxybuild.Manager, error) {
	buildCfg := NewLiveBuildConfig(appCtx, cfg, proxyCfg, issuer, pluginv2Engine, store, hostTLSRegistry, logger)
	return NewLiveManager(cfg, proxyCfg, store, issuer, pluginv2Engine,
		holdQueue, httpInterceptEngine, wsInterceptEngine, grpcInterceptEngine,
		httpTransformEngine, passthrough, targetScope, rateLimiter, safetyEngine, perProtoSafety, buildCfg,
		socks5Negotiator, recordScope, logger)
}

// NewLiveBuildConfig assembles the connector.BuildConfig consumed by every
// per-listener stack. PluginV2Engine reaches every Layer construction site
// + the tls.on_handshake hook. OnHTTP2UpstreamDialed installs the upstream
// push recorder so pushed streams are recorded (USK-623). Per-protocol
// caps (body spill, gRPC LPM, WS frame, SSE event) are resolved from
// proxyCfg via the config-package helpers.
//
// appCtx is the application lifecycle context — passed to
// pushrecorder.RunUpstream so a SIGINT-triggered cancellation reaches the
// per-Layer drainer goroutines without waiting for the upstream Layer's
// own channel-close path.
func NewLiveBuildConfig(
	appCtx context.Context,
	cfg *config.Config,
	proxyCfg *config.ProxyConfig,
	issuer *cert.Issuer,
	pluginv2Engine *pluginv2.Engine,
	store *flow.SQLiteStore,
	hostTLSRegistry *transport.HostTLSRegistry,
	logger *slog.Logger,
) *connector.BuildConfig {
	bc := &connector.BuildConfig{
		ProxyConfig:        proxyCfg,
		Issuer:             issuer,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		PluginV2Engine:     pluginv2Engine,
		ALPNCache:          connector.NewALPNCache(connector.DefaultALPNCacheSize, connector.DefaultALPNCacheTTL),
		HTTP2Pool:          h2pool.New(h2pool.PoolOptions{}),
		BodySpillDir:       config.ResolveBodySpillDir(cfg),
		BodySpillThreshold: config.ResolveBodySpillThreshold(cfg),
		MaxRawCaptureSize:  config.ResolveMaxRawCaptureSize(cfg),
		// USK-733: thread the runtime-mutable HostTLSRegistry into the live
		// dial path so `proxy_start(client_cert=..., client_key=...)`
		// updates reach the next outbound TLS handshake. The startup-time
		// HostTLSResolver and ClientCert snapshot below are kept as
		// fallbacks for hosts the registry has no entry for.
		HostTLSRegistry: hostTLSRegistry,
	}
	bc.HostTLSResolver = connector.NewHostTLSResolver(proxyCfg.HostTLS)
	bc.WSMaxFrameSize = config.ResolveWSMaxFrameSize(proxyCfg.WebSocket)
	bc.WSDeflateEnabled = config.ResolveWSDeflateEnabled(proxyCfg.WebSocket)
	bc.GRPCMaxMessageSize = uint32(config.ResolveGRPCMaxMessageSize(proxyCfg.GRPC))
	bc.SSEMaxEventSize = config.ResolveSSEMaxEventSize(proxyCfg.SSE)
	// USK-802: per-Stream record caps for streaming protocols. Resolved into
	// BuildConfig so proxybuild's RecordStep construction picks up the
	// operator-configured value (or the package default when unset).
	bc.GRPCMaxMessagesPerStream = config.ResolveGRPCMaxMessagesPerStream(proxyCfg.GRPC)
	bc.SSEMaxEventsPerStream = config.ResolveSSEMaxEventsPerStream(proxyCfg.SSE)
	bc.MaxBodySize = config.ResolveMaxBodySize(proxyCfg)
	if proxyCfg.TLSFingerprint != "" {
		bc.TLSFingerprint = proxyCfg.TLSFingerprint
	}

	// Install the upstream push recorder (USK-623). The callback fires
	// once per freshly-dialed *http2.Layer; pool hits skip it (the
	// drainer is already running for the cached Layer's lifetime).
	// appCtx is captured so SIGINT-triggered cancellation propagates to
	// every push drainer in addition to the Layer.Channels-close path.
	bc.OnHTTP2UpstreamDialed = func(l *http2.Layer) {
		go pushrecorder.RunUpstream(appCtx, l, store, logger)
	}

	return bc
}

// NewLiveManager constructs the live RFC-001 proxybuild.Manager. The
// StackFactory closure captures the per-process singletons (logger,
// store, build config, plugin engine, hold queue, rate limiter,
// passthrough list) so each StartNamed call assembles a Stack pointing
// at the same dependencies.
//
// SetMaxConnections / SetPeekTimeout are seeded from cfg so listener
// defaults match the legacy behavior; the Manager re-applies them to
// every newly-started listener via its stored values.
func NewLiveManager(
	cfg *config.Config,
	proxyCfg *config.ProxyConfig,
	store *flow.SQLiteStore,
	issuer *cert.Issuer,
	pluginv2Engine *pluginv2.Engine,
	holdQueue *rulescommon.HoldQueue,
	httpInterceptEngine *httprules.InterceptEngine,
	wsInterceptEngine *wsrules.InterceptEngine,
	grpcInterceptEngine *grpcrules.InterceptEngine,
	httpTransformEngine *httprules.TransformEngine,
	passthrough *connector.PassthroughList,
	targetScope *connector.TargetScope,
	rateLimiter *connector.RateLimiter,
	safetyEngine *safety.Engine,
	perProtoSafety PerProtocolSafetyEngines,
	buildCfg *connector.BuildConfig,
	socks5Negotiator *connector.SOCKS5Negotiator,
	recordScope *flow.RecordScope,
	logger *slog.Logger,
) (*proxybuild.Manager, error) {
	// PassthroughList, RateLimiter, and TargetScope come straight from
	// connector.* and are threaded directly into proxybuild.Deps so the
	// per-listener Pipeline's HostScopeStep / HTTPScopeStep enforces the
	// configured policy (USK-782 wiring fix surfacing as part of the
	// blocked-recording AC). socks5Negotiator is the process-singleton
	// owned by the caller (USK-770) so MCP socks5_auth runtime mutations
	// reach every listener built from this factory.
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:              logger,
			ListenerName:        name,
			ListenAddr:          addr,
			FlowStore:           store,
			PluginV2Engine:      pluginv2Engine,
			BuildConfig:         buildCfg,
			HoldQueue:           holdQueue,
			HTTPInterceptEngine: httpInterceptEngine,
			WSInterceptEngine:   wsInterceptEngine,
			GRPCInterceptEngine: grpcInterceptEngine,
			HTTPTransformEngine: httpTransformEngine,
			HTTPSafetyEngine:    perProtoSafety.HTTP,
			WSSafetyEngine:      perProtoSafety.WS,
			GRPCSafetyEngine:    perProtoSafety.GRPC,
			PeekTimeout:         cfg.PeekTimeout,
			MaxConnections:      cfg.MaxConnections,
			PassthroughList:     passthrough,
			Scope:               targetScope,
			RateLimiter:         rateLimiter,
			SOCKS5Negotiator:    socks5Negotiator,
			RecordScope:         recordScope,
			// USK-802: per-Stream record caps surface via BuildConfig so a
			// single resolved value drives RecordStep construction across
			// every listener built by this factory.
			RecordGRPCMaxMessagesPerStream: buildCfg.GRPCMaxMessagesPerStream,
			RecordSSEMaxEventsPerStream:    buildCfg.SSEMaxEventsPerStream,
		})
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
		// BuildConfig is the process-singleton handed to every Stack via
		// the factory closure. Sharing the same pointer with the Manager
		// lets Manager.SetUpstreamProxy mutate the live dial-path's
		// dynamic upstream-proxy slot at runtime (USK-734).
		BuildConfig: buildCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("init proxybuild manager: %w", err)
	}
	mgr.SetPeekTimeout(cfg.PeekTimeout)
	mgr.SetMaxConnections(cfg.MaxConnections)

	// proxyCfg + issuer are reachable via buildCfg; kept on the parameter
	// list for future cleanup work (USK-697 connector-adapter migration).
	// safetyEngine is the read-only Policy Layer view consumed by the
	// `security` MCP tool — wired via mcp.NewPipeline in
	// buildMCPComponents, not via proxybuild.Deps.
	_ = proxyCfg
	_ = issuer
	_ = safetyEngine
	return mgr, nil
}

// InitHostTLSRegistry builds a transport.HostTLSRegistry from the CLI
// config and proxy config file. CLI config settings take precedence;
// proxy config file settings are applied as fallbacks.
func InitHostTLSRegistry(cfg *config.Config, proxyCfg *config.ProxyConfig, logger *slog.Logger) (*transport.HostTLSRegistry, error) {
	reg := transport.NewHostTLSRegistry()

	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		globalTLS := &transport.HostTLSConfig{
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

	if err := applyHostTLSEntries(reg, cfg.HostTLS, "", logger); err != nil {
		return nil, err
	}

	if proxyCfg.ClientCertPath != "" && proxyCfg.ClientKeyPath != "" && reg.Global() == nil {
		globalTLS := &transport.HostTLSConfig{
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

	return reg, nil
}

// applyHostTLSEntries adds per-host TLS configurations from a map to the
// registry.
func applyHostTLSEntries(reg *transport.HostTLSRegistry, entries map[string]*config.HostTLSEntry, prefix string, logger *slog.Logger) error {
	for hostname, entry := range entries {
		hostCfg := &transport.HostTLSConfig{
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

// InitTLSTransport builds the transport.TLSTransport implementation used
// by the typed-resend MCP tools (and exposed via configure_tool). uTLS
// transport is selected when a TLS fingerprint profile is set; the
// standard transport is used otherwise. The HostTLSRegistry threaded in
// here applies per-host mTLS / verify overrides.
//
// TLSFingerprint resolution order (USK-719):
//
//  1. proxyCfg.TLSFingerprint — populated by `-tls-fingerprint` CLI flag
//     and by the proxy-config file's `tls_fingerprint`. This is the
//     surface most users discover first.
//  2. cfg.TLSFingerprint — populated by the top-level config file's
//     `tls_fingerprint`. Kept for backward compatibility.
//  3. empty — falls back to StandardTransport.
func InitTLSTransport(cfg *config.Config, proxyCfg *config.ProxyConfig, reg *transport.HostTLSRegistry, logger *slog.Logger) transport.TLSTransport {
	fingerprint := ""
	if proxyCfg.TLSFingerprint != "" {
		fingerprint = proxyCfg.TLSFingerprint
	} else if cfg.TLSFingerprint != "" {
		fingerprint = cfg.TLSFingerprint
	}

	if fingerprint != "" {
		profile, err := transport.ParseBrowserProfile(fingerprint)
		if err != nil {
			logger.Warn("invalid TLS fingerprint profile, using standard transport", "error", err)
			return &transport.StandardTransport{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
				HostTLS:            reg,
			}
		}
		logger.Info("uTLS fingerprint enabled", "profile", profile.String())
		return &transport.UTLSTransport{
			Profile:            profile,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			HostTLS:            reg,
		}
	}
	return &transport.StandardTransport{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		HostTLS:            reg,
	}
}
