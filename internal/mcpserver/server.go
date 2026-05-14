// Package mcpserver hosts the production MCP server assembly extracted from
// cmd/yorishiro-proxy/. It exposes the same wiring path the binary entry
// point uses so that out-of-process tests (notably the upcoming JSON-RPC
// e2e harness in internal/mcptest/, USK-724) can drive the production stack
// instead of stubbing transports in-memory.
//
// The production-wiring contract is: callers MUST treat Run as the single
// entry point. Re-implementing the body of Run elsewhere would defeat the
// purpose of this package (USK-717/718/719 RCA: harness diverged from
// production wiring). If a test needs to inject a single dependency, prefer
// adding a named hook to RunOptions over duplicating Run.
package mcpserver

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	rulescommon "github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"golang.org/x/sync/errgroup"
)

// EnvVarMap maps flag names to their corresponding YP_ environment variable
// names. It is exported so tests can assert that every CLI flag has a
// matching env var.
var EnvVarMap = map[string]string{
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
	"open-browser":       "YP_OPEN_BROWSER",
	"tls-fingerprint":    "YP_TLS_FINGERPRINT",
	"safety-filter":      "YP_SAFETY_FILTER_ENABLED",
	"stdio-mcp":          "YP_STDIO_MCP",
	"no-http-mcp":        "YP_NO_HTTP_MCP",
	// USK-862: HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS override; 0 = H2
	// layer default.
	"max-concurrent-streams": "YP_MAX_CONCURRENT_STREAMS",
}

// RunOptions controls the runtime behavior of Run. The zero value is valid
// and matches the production binary's defaults; tests typically populate
// only the fields they need to override.
type RunOptions struct {
	// Version is the build-time version string used as mcp.WithVersion(...)
	// when constructing the MCP server. Defaults to "dev" when empty.
	Version string

	// UsageBanner is the program identifier shown in fs.Usage. Defaults to
	// "yorishiro-proxy" when empty.
	UsageBanner string

	// OnHTTPListening, when non-nil, is invoked once the HTTP MCP listener
	// has bound to its address and is ready to accept connections. The
	// resolved address is passed in (important when -mcp-http-addr uses a
	// :0 port). The hook fires in addition to the production behavior
	// (server.json write, WebUI URL log, optional browser open) — it does
	// not replace it. Intended for the JSON-RPC e2e harness in
	// internal/mcptest/ (USK-724) which needs to learn the OS-assigned
	// port before issuing tools/call requests.
	OnHTTPListening func(addr string)
}

// Run parses CLI flags from args using fs, then performs the full server
// assembly and blocks on the MCP server until ctx is cancelled. It is the
// production entry point relocated from cmd/yorishiro-proxy/main.go's
// runWithFlags so the same wiring is reachable from tests.
//
// Run owns the registration of every CLI flag on fs; callers must pass a
// fresh *flag.FlagSet that has not had any other flags registered.
func Run(ctx context.Context, fs *flag.FlagSet, args []string, opts RunOptions) error {
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
	// HTTP MCP transport: defaults to 127.0.0.1:0 (OS-assigned port).
	// Use -mcp-http-addr to specify an explicit address.
	// Use -no-http-mcp to disable HTTP MCP entirely.
	defaultMCPHTTPAddr := "127.0.0.1:0"
	if cfg.MCPHTTPAddr != "" {
		defaultMCPHTTPAddr = cfg.MCPHTTPAddr
	}
	fs.StringVar(&cfg.MCPHTTPAddr, "mcp-http-addr", defaultMCPHTTPAddr, "Streamable HTTP MCP listen address; use 0 for OS-assigned port (env: YP_MCP_HTTP_ADDR)")
	fs.StringVar(&cfg.MCPHTTPToken, "mcp-http-token", cfg.MCPHTTPToken, "HTTP Bearer auth token, auto-generated if empty (env: YP_MCP_HTTP_TOKEN)")
	fs.StringVar(&cfg.UIDir, "ui-dir", cfg.UIDir, "directory for WebUI static files, overrides embedded assets (env: YP_UI_DIR)")

	// -open-browser enables auto-opening the WebUI; default is disabled.
	var openBrowser bool
	fs.BoolVar(&openBrowser, "open-browser", false, "open WebUI in browser when HTTP MCP starts (env: YP_OPEN_BROWSER)")

	// -stdio-mcp enables stdio MCP transport (opt-in).
	var stdioMCP bool
	fs.BoolVar(&stdioMCP, "stdio-mcp", false, "start stdio MCP transport in addition to HTTP MCP (env: YP_STDIO_MCP)")

	// -no-http-mcp disables HTTP MCP transport (opt-out).
	var noHTTPMCP bool
	fs.BoolVar(&noHTTPMCP, "no-http-mcp", false, "disable HTTP MCP transport (env: YP_NO_HTTP_MCP)")

	// SafetyFilter enable/disable override. When set via flag or env var,
	// it overrides the config file's safety_filter.enabled value.
	var safetyFilterEnabled bool
	fs.BoolVar(&safetyFilterEnabled, "safety-filter", false, "enable SafetyFilter engine (env: YP_SAFETY_FILTER_ENABLED)")

	// USK-862: HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS advertised to clients
	// on the inbound (client-facing) Layer. Zero means "use the H2 layer's
	// compile-time default" (currently 500). Stored as uint via flag.UintVar
	// because flag has no UintVar32, then narrowed to uint32 below.
	var maxConcurrentStreams uint
	fs.UintVar(&maxConcurrentStreams, "max-concurrent-streams", 0,
		"HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS advertised to clients; 0 = use H2 default (500) (env: YP_MAX_CONCURRENT_STREAMS)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply environment variable fallback for flags not explicitly set.
	ApplyEnvFallback(fs)

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

	// USK-862: thread the parsed -max-concurrent-streams value into the
	// Config struct. Reject values that exceed uint32 (the H2 SETTINGS wire
	// type is u32; SETTINGS_MAX_CONCURRENT_STREAMS is unsigned 32-bit per
	// RFC 9113 §6.5.2). Zero is the documented "use H2 default" sentinel.
	if maxConcurrentStreams > 0xFFFFFFFF {
		return fmt.Errorf("invalid configuration: max_concurrent_streams %d exceeds uint32 max (4294967295)", maxConcurrentStreams)
	}
	cfg.MaxConcurrentStreams = uint32(maxConcurrentStreams)

	// Validate configuration values before proceeding with initialization.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Load proxy config and target scope policy.
	configs, err := LoadConfigs(configFile, targetPolicyFile)
	if err != nil {
		return err
	}
	proxyCfg := configs.ProxyCfg
	targetScopePolicy := configs.TargetScopePolicy
	targetScopePolicySource := configs.TargetScopePolicySource

	// Apply CLI TLS fingerprint flag. CLI flag takes precedence over config file.
	proxyCfg, err = ApplyTLSFingerprintFlag(tlsFingerprint, proxyCfg)
	if err != nil {
		return err
	}

	// Cross-struct invariant: the resolved BodySpillThreshold (RAM cap on
	// Config) must not exceed the resolved MaxBodySize (wire cap on
	// ProxyConfig). Config.Validate enforces the raw BodySpillThreshold
	// against the package constant; this re-check uses the resolved values
	// so the default-spill-threshold case (zero → 10 MiB) is also caught
	// when the operator overrides max_body_size to a smaller value.
	resolvedThreshold := config.ResolveBodySpillThreshold(cfg)
	resolvedMaxBody := config.ResolveMaxBodySize(proxyCfg)
	if resolvedThreshold > resolvedMaxBody {
		return fmt.Errorf("invalid configuration: body_spill_threshold (%d) must be <= max_body_size (%d)", resolvedThreshold, resolvedMaxBody)
	}

	infra, err := InitInfra(ctx, cfg)
	if err != nil {
		return err
	}
	defer infra.Cleanup()
	logger := infra.Logger
	store := infra.Store

	// Initialize CA and certificate issuer for HTTPS MITM.
	ca, err := InitCA(cfg, logger)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	issuer := cert.NewIssuer(ca)

	// Initialize TLS passthrough list and populate from config.
	passthrough := InitPassthroughList(cfg, logger)

	// Initialize the RFC-001 HoldQueue + per-protocol intercept engines
	// shared between pipeline.InterceptStep (live data path via
	// proxybuild) and the MCP intercept / configure tools.
	holdQueue := rulescommon.NewHoldQueue()
	// USK-855: apply per-protocol intercept-queue overrides from the
	// loaded file-config (proxyCfg.InterceptQueue). A nil substruct is a
	// no-op; the built-in NewHoldQueue defaults (WS=8s, SSE=8s, gRPC=60s,
	// global 5min/auto_release) stay in place.
	applyInterceptQueueConfig(holdQueue, proxyCfg.InterceptQueue, logger)
	// USK-851: process-singleton ReleaseTracker shared between the MCP
	// intercept tool (Release stamps it) and the live data path (relay
	// goroutines query it on EOF). Threading the same pointer through
	// both halves ensures the operator-facing Stream tag fires regardless
	// of which listener the affected Stream belongs to.
	releaseTracker := rulescommon.NewReleaseTracker()
	// USK-854: process-singleton HoldTracker stamped by every live
	// InterceptStep on hold-enter and queried by the session keepalive
	// goroutine on each tick. Sibling of ReleaseTracker — independent
	// state (in-flight hold vs. recently released).
	holdTracker := rulescommon.NewHoldTracker()
	httpInterceptEngine := httprules.NewInterceptEngine()
	wsInterceptEngine := wsrules.NewInterceptEngine()
	grpcInterceptEngine := grpcrules.NewInterceptEngine()

	pluginv2Engine, err := InitPluginV2Engine(ctx, store, proxyCfg, logger)
	if err != nil {
		return err
	}
	defer pluginv2Engine.Close()

	// Initialize the per-protocol HTTP transform engine. Threaded into
	// both proxybuild.Deps (live data path TransformStep) and mcp.Pipeline
	// so MCP-driven configure auto_transform changes reach the wire.
	// WS/gRPC transform engines are not yet exposed by the auto_transform
	// MCP schema (deferred per RFC-001 N9 design review 2026-05-04).
	httpTransformEngine := httprules.NewTransformEngine()

	// Apply transport flags before building options so MCPHTTPAddr is correct.
	if noHTTPMCP {
		cfg.MCPHTTPAddr = ""
	}

	versionStr := opts.Version
	if versionStr == "" {
		versionStr = "dev"
	}

	return assembleAndRunMCPServer(ctx, cfg, proxyCfg, ca, issuer, store, pluginv2Engine,
		holdQueue, releaseTracker, holdTracker, httpInterceptEngine, wsInterceptEngine, grpcInterceptEngine,
		httpTransformEngine, passthrough,
		targetScopePolicy, targetScopePolicySource, openBrowser, stdioMCP, versionStr, opts.OnHTTPListening, logger)
}

// assembleAndRunMCPServer is the hot final phase of Run: build the live
// manager + Safety/TargetScope + MCP components, then hand off to
// startServers. Extracted as a helper so Run stays under the gocyclo
// budget after USK-690 added pluginv2 + proxybuild plumbing.
func assembleAndRunMCPServer(
	ctx context.Context,
	cfg *config.Config,
	proxyCfg *config.ProxyConfig,
	ca *cert.CA,
	issuer *cert.Issuer,
	store *flow.SQLiteStore,
	pluginv2Engine *pluginv2.Engine,
	holdQueue *rulescommon.HoldQueue,
	releaseTracker *rulescommon.ReleaseTracker,
	holdTracker *rulescommon.HoldTracker,
	httpInterceptEngine *httprules.InterceptEngine,
	wsInterceptEngine *wsrules.InterceptEngine,
	grpcInterceptEngine *grpcrules.InterceptEngine,
	httpTransformEngine *httprules.TransformEngine,
	passthrough *connector.PassthroughList,
	targetScopePolicy *config.TargetScopePolicyConfig,
	targetScopePolicySource string,
	openBrowserFlag, stdioMCP bool,
	version string,
	onHTTPListening func(addr string),
	logger *slog.Logger,
) error {
	targetScope := InitTargetScope(targetScopePolicy)
	rateLimiter := InitRateLimiter(targetScopePolicy, logger)
	// USK-818: process-singleton BudgetManager owned here so the live
	// data path's BudgetStep, the resend/fuzz dispatch helpers, and the
	// MCP `security` tool all observe the same counters and the same
	// MaxTotalRequests / MaxDuration policy. Start() arms the duration
	// timer and shutdown callback after assembleLiveManager returns
	// (the manager is required for the StopAll closure).
	// USK-819: feed the policy-layer ceiling from
	// TargetScopePolicy.Budget so set_budget rejects values exceeding it.
	budgetManager := InitBudgetManager(targetScopePolicy, logger)
	safetyEngine, err := InitSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		return err
	}
	// Build the per-protocol live SafetyEngines from the same source-of-truth
	// (cfg.SafetyFilter) so the live pipeline.SafetyStep enforces the
	// configured rules. The read-only `safetyEngine` above feeds the
	// `security` MCP tool's Policy Layer view; this trio drives the data
	// path. (USK-760)
	perProtoSafety, err := InitPerProtocolSafetyEngines(cfg, proxyCfg)
	if err != nil {
		return err
	}

	// HostTLS registry + TLS transport for the typed-resend MCP tools.
	// Also reachable via configure_tool surfaces.
	hostTLSRegistry, err := InitHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		return err
	}
	tlsTransport := InitTLSTransport(cfg, proxyCfg, hostTLSRegistry, logger)

	// USK-770: process-singleton SOCKS5Negotiator owned here so the MCP
	// control plane (mcp.socks5AuthSetter wired below) and the live data
	// path (proxybuild.Deps.SOCKS5Negotiator) reference the same instance.
	// Runtime auth mutations from `proxy_start socks5_auth=...` /
	// `configure socks5_auth=...` therefore reach in-flight listeners
	// without restart.
	socks5Negotiator := connector.NewSOCKS5Negotiator(logger)

	// USK-776: build the recording-only observability filter once and
	// share the pointer between the live data path (via
	// proxybuild.Deps.RecordScope inside assembleLiveManager) and the
	// MCP control plane (via mcp.NewFlowStore inside buildMCPComponents)
	// so configure / proxy_start / query mutate the same instance the
	// live RecordStep reads.
	recordScope := flow.NewRecordScope()

	manager, err := assembleLiveManager(cfg, proxyCfg, store, issuer, pluginv2Engine,
		holdQueue, releaseTracker, holdTracker, httpInterceptEngine, wsInterceptEngine, grpcInterceptEngine,
		httpTransformEngine, passthrough, targetScope, rateLimiter, budgetManager, safetyEngine, perProtoSafety, hostTLSRegistry,
		socks5Negotiator, recordScope, logger)
	if err != nil {
		return err
	}
	// Order shutdown so all in-flight Pipeline scopes finish releasing
	// before pluginv2Engine.Close() (deferred in the caller, Run) zeroes
	// plugin state. Without this, listener goroutines that hold a
	// *PluginState pointer can race the engine shutdown's nil-map writes.
	// 5s bound matches proxybuild.shutdownTimeout for graceful drain.
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.StopAll(sctx)
	}()

	// USK-818: arm the BudgetManager AFTER assembleLiveManager so the
	// onShutdown callback can capture the live manager. When the budget
	// is exhausted (request count exceeded or MaxDuration timer fires)
	// the callback stops every listener — symmetric with how
	// `proxy_stop` halts the proxy on operator action. budgetManager.Stop()
	// is deferred so the duration timer goroutine cleans up before the
	// process exits.
	budgetManager.Start(func(reason string) {
		logger.Info("budget exhausted; stopping proxy", "reason", reason)
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if stopErr := manager.StopAll(sctx); stopErr != nil {
			logger.Error("budget shutdown: StopAll failed", "error", stopErr)
		}
	})
	defer budgetManager.Stop()

	socks5AuthSetter := newSOCKS5AuthAdapter(socks5Negotiator, logger)
	mcpComps, webUIToken, opts, err := buildMCPComponents(ctx, cfg, proxyCfg, ca, issuer, store, manager,
		passthrough, holdQueue, releaseTracker, httpInterceptEngine, wsInterceptEngine, grpcInterceptEngine,
		pluginv2Engine, httpTransformEngine, hostTLSRegistry, tlsTransport, targetScope, rateLimiter, budgetManager, safetyEngine,
		socks5AuthSetter, recordScope, targetScopePolicySource, version, logger)
	if err != nil {
		return err
	}

	mcpServer := mcp.NewServer(
		mcpComps.misc,
		mcpComps.pipeline,
		mcpComps.connector,
		mcpComps.jobRunner,
		mcpComps.flowStore,
		mcpComps.macroEngine,
		mcpComps.pluginEngine,
		opts...,
	)

	logger.Info("starting MCP server", "http_mcp_addr", cfg.MCPHTTPAddr, "stdio_mcp", stdioMCP)
	return startServers(ctx, cfg, mcpServer, webUIToken, openBrowserFlag, stdioMCP, onHTTPListening, logger)
}

// ApplyEnvFallback checks each flag in EnvVarMap; if the flag was not
// explicitly set on the command line, it falls back to the corresponding
// YP_ environment variable. Priority: CLI flag > environment variable >
// config file > default value.
//
// Because all flags are registered with fs.StringVar/fs.BoolVar pointing
// to the target struct fields, fs.Set() updates those fields directly.
func ApplyEnvFallback(fs *flag.FlagSet) {
	flagSet := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { flagSet[f.Name] = true })

	for flagName, envVar := range EnvVarMap {
		if flagSet[flagName] {
			continue
		}
		if v := os.Getenv(envVar); v != "" {
			_ = fs.Set(flagName, v)
		}
	}
}

// ConfigsResult holds loaded configuration files.
type ConfigsResult struct {
	ProxyCfg                *config.ProxyConfig
	TargetScopePolicy       *config.TargetScopePolicyConfig
	TargetScopePolicySource string
}

// ApplyTLSFingerprintFlag validates and applies the CLI -tls-fingerprint
// flag value. Returns the (possibly initialized) ProxyConfig with the
// fingerprint set.
func ApplyTLSFingerprintFlag(tlsFingerprint string, proxyCfg *config.ProxyConfig) (*config.ProxyConfig, error) {
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
	proxyCfg.TLSFingerprint = tlsFingerprint
	return proxyCfg, nil
}

// LoadConfigs loads the proxy config file and target scope policy.
// Priority for target scope: -target-policy-file > config file
// target_scope_policy section.
//
// LoadConfigs also runs the per-protocol limit validation
// (config.ValidateProtocolLimits) on the loaded ProxyConfig — sibling of
// ValidateSafetyFilterConfig. Validation rejects negative numbers and
// accepts zero (= "use default" per project convention; see
// config.ResolveBodySpillThreshold).
func LoadConfigs(configFile, targetPolicyFile string) (*ConfigsResult, error) {
	var proxyCfg *config.ProxyConfig
	if configFile != "" {
		var err error
		proxyCfg, err = config.LoadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("load config file: %w", err)
		}
		if err := config.ValidateProtocolLimits(proxyCfg); err != nil {
			return nil, fmt.Errorf("invalid protocol limits: %w", err)
		}
		if err := proxyCfg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid proxy config: %w", err)
		}
	}

	if proxyCfg == nil {
		// proxybuild.BuildLiveStack requires a non-nil ProxyConfig.
		// When no -config file is provided, supply a zero-valued config so
		// downstream consumers can rely on the non-nil contract.
		proxyCfg = &config.ProxyConfig{}
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
	} else if proxyCfg.TargetScopePolicy != nil {
		targetScopePolicy = proxyCfg.TargetScopePolicy
		targetScopePolicySource = "config file"
	}

	return &ConfigsResult{
		ProxyCfg:                proxyCfg,
		TargetScopePolicy:       targetScopePolicy,
		TargetScopePolicySource: targetScopePolicySource,
	}, nil
}

// mcpComponents groups the seven MCP component pointers built by
// buildMCPComponents so the call site can pass them to mcp.NewServer in
// one go without a long argument list at the assembly point.
type mcpComponents struct {
	misc         *mcp.Misc
	pipeline     *mcp.Pipeline
	connector    *mcp.Connector
	jobRunner    *mcp.JobRunner
	flowStore    *mcp.FlowStore
	macroEngine  *mcp.MacroEngine
	pluginEngine *mcp.PluginEngine
}

// buildMCPComponents assembles the seven MCP server components plus the
// remaining ServerOption slice (middleware / UI dir / version) from the
// initialized infrastructure. The legacy per-protocol-handler setter slices
// are gone — the live data path runs through proxybuild + connector +
// pluginv2 wiring (USK-690), so per-handler runtime config propagation
// happens inside the proxybuild Stack instead of via mcp.NewConnector
// setter slices. webUIToken is returned so startServers can write
// server.json without back-channel mutation.
func buildMCPComponents(
	ctx context.Context,
	cfg *config.Config,
	proxyCfg *config.ProxyConfig,
	ca *cert.CA,
	issuer *cert.Issuer,
	store *flow.SQLiteStore,
	manager *proxybuild.Manager,
	passthrough *connector.PassthroughList,
	holdQueue *rulescommon.HoldQueue,
	releaseTracker *rulescommon.ReleaseTracker,
	httpInterceptEngine *httprules.InterceptEngine,
	wsInterceptEngine *wsrules.InterceptEngine,
	grpcInterceptEngine *grpcrules.InterceptEngine,
	pluginv2Engine *pluginv2.Engine,
	httpTransformEngine *httprules.TransformEngine,
	hostTLSRegistry *transport.HostTLSRegistry,
	tlsTransport transport.TLSTransport,
	targetScope *connector.TargetScope,
	rateLimiter *connector.RateLimiter,
	budgetManager *connector.BudgetManager,
	safetyEngine *safety.Engine,
	socks5AuthSetter *socks5AuthAdapter,
	recordScope *flow.RecordScope,
	targetScopePolicySource string,
	version string,
	logger *slog.Logger,
) (*mcpComponents, string, []mcp.ServerOption, error) {
	mc := &mcpComponents{
		misc: mcp.NewMisc(
			ctx,
			ca,
			issuer,
			cfg.DBPath,
			rateLimiter,
			budgetManager,
		),
		pipeline: mcp.NewPipeline(
			httpInterceptEngine,
			wsInterceptEngine,
			grpcInterceptEngine,
			holdQueue,
			httpTransformEngine,
			safetyEngine,
			nil, // safetyEngineSetters — legacy per-handler propagation gone with USK-706.
		).WithReleaseTracker(releaseTracker),
		connector: mcp.NewConnector(
			manager,
			passthrough,
			targetScope,
			hostTLSRegistry,
			tlsTransport,
			socks5AuthSetter, // USK-770: bridge MCP socks5_auth -> live connector.SOCKS5Negotiator
			nil,              // tcpHandler — TCP forward orchestration owned by USK-697 follow-up.
			nil,              // detector — protocol detection runs inside proxybuild Stack via connector.DetectKind.
			proxyCfg,
			nil, // targetScopeSetters — propagation handled by connector wiring.
			nil, // tlsFingerprintSetters — proxybuild rebuilds Stacks on configure.
			nil, // upstreamProxySetters — proxybuild Manager.SetUpstreamProxy is canonical.
			// USK-844: proxybuild.Manager implements requestTimeoutSetter
			// (SetRequestTimeout / RequestTimeout). Registering it here
			// connects MCP `configure { request_timeout_ms }` and
			// `proxy_start { request_timeout_ms }` to the live data path's
			// plain-HTTP and CONNECT/SOCKS5 inner read deadlines.
			mcp.RequestTimeoutSetters(manager),
			nil, // rateLimiterSetters — connector.SOCKS5Negotiator.RateLimiter is canonical.
		),
		jobRunner: mcp.NewJobRunner(
			store,
			nil, // legacy replayDoer, not pre-populated (set in tests).
			nil, // raw replay dialer, not pre-populated.
		),
		flowStore:    mcp.NewFlowStore(store, recordScope),
		macroEngine:  mcp.NewMacroEngine(),
		pluginEngine: mcp.NewPluginEngine(pluginv2Engine),
	}

	logger.Info("loaded proxy config file defaults")
	if targetScope != nil && targetScope.HasPolicyRules() {
		// USK-879: InitTargetScope now always returns a non-nil scope so the
		// MCP-side and data-path share one pointer. Only log "policy loaded"
		// when an actual policy file (or config-embedded policy) populated
		// rules; an empty boot-default scope is not a policy decision worth
		// logging.
		allows, denies := targetScope.PolicyRules()
		logger.Info("target scope policy loaded",
			"allows", len(allows),
			"denies", len(denies),
			"source", targetScopePolicySource)
	}

	opts := []mcp.ServerOption{
		mcp.WithVersion(version),
	}
	if cfg.UIDir != "" {
		opts = append(opts, mcp.WithUIDir(cfg.UIDir))
	}
	// Set up Bearer token authentication middleware for HTTP transport.
	// This is always configured when HTTP MCP is enabled (MCPHTTPAddr != "").
	// The WebUI URL is logged from startServers once the actual port is known.
	var webUIToken string
	if cfg.MCPHTTPAddr != "" {
		token, err := ResolveHTTPToken(cfg.MCPHTTPToken, logger)
		if err != nil {
			return nil, "", nil, fmt.Errorf("MCP HTTP token: %w", err)
		}
		webUIToken = token
		opts = append(opts, mcp.WithMiddleware(func(next http.Handler) http.Handler {
			return mcp.BearerAuthMiddleware(next, token)
		}))
	}

	return mc, webUIToken, opts, nil
}

// startServers launches the MCP HTTP and optional stdio servers using an
// errgroup. When cfg.MCPHTTPAddr is non-empty, the HTTP MCP server is
// started (default). When stdioMCP is true, the stdio MCP transport is
// also started. server.json is written once the HTTP server starts
// listening and removed on exit.
func startServers(ctx context.Context, cfg *config.Config, mcpServer *mcp.Server, webUIToken string, openBrowserFlag bool, stdioMCP bool, onHTTPListening func(addr string), logger *slog.Logger) error {
	g, gctx := errgroup.WithContext(ctx)

	// Optionally start stdio MCP transport (opt-in via -stdio-mcp).
	if stdioMCP {
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
	}

	// Start HTTP MCP transport (default; disabled by -no-http-mcp).
	if cfg.MCPHTTPAddr != "" {
		capturedToken := webUIToken
		g.Go(func() error {
			wrote := false
			onListening := func(addr string) {
				// Log the WebUI URL with the actual (resolved) address.
				// Log only the base URL at Info to avoid emitting the credential in default logs.
				// The full URL (with token) is logged at Debug for diagnostics.
				baseURL := fmt.Sprintf("http://%s/", addr)
				webURL := fmt.Sprintf("http://%s/?token=%s", addr, url.QueryEscape(capturedToken))
				logger.Info("WebUI available", "url", baseURL)
				logger.Debug("WebUI available (with token)", "url", webURL)

				// Write server.json for the CLI client to discover this server.
				sj := &ServerJSON{
					Addr:      addr,
					Token:     capturedToken,
					PID:       os.Getpid(),
					StartedAt: timeNow(),
				}
				if err := writeServerJSON(sj); err != nil {
					logger.Error("failed to write server.json", "error", err)
				} else {
					wrote = true
					logger.Info("server.json written", "path", mustServerJSONPath())
				}

				// Optionally open the browser.
				if openBrowserFlag {
					if err := openBrowser(webURL); err != nil {
						logger.Warn("failed to open browser", "url", baseURL, "error", err)
						logger.Debug("failed to open browser (full url)", "url", webURL, "error", err)
					}
				}

				// Fire the test hook last so harnesses observe the same
				// post-bind state production sees (server.json written,
				// WebUI URL logged). The hook is intentionally invoked
				// even on server.json write failure — the harness still
				// needs the address to issue tool calls.
				if onHTTPListening != nil {
					onHTTPListening(addr)
				}
			}
			defer func() {
				if wrote {
					removeServerJSON()
				}
			}()
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

	// If neither transport is enabled, return an error.
	if !stdioMCP && cfg.MCPHTTPAddr == "" {
		return fmt.Errorf("no MCP transport enabled: use -stdio-mcp or remove -no-http-mcp")
	}

	return g.Wait()
}

// timeNow returns the current UTC time. It is a variable to allow test
// overrides.
var timeNow = func() time.Time {
	return time.Now().UTC()
}

// mustServerJSONPath returns the server.json path, falling back to a
// placeholder on error.
func mustServerJSONPath() string {
	p, err := ServerJSONPath()
	if err != nil {
		return "~/.yorishiro-proxy/server.json"
	}
	return p
}
