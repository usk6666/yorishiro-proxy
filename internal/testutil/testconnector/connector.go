package testconnector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// PluginObserver records every plugin hook invocation it sees. It is attached
// to the harness Pipeline so tests can confirm that the expected hooks fire
// without having to inject a real Starlark script.
type PluginObserver struct {
	mu    sync.Mutex
	calls map[plugin.Hook]int
}

func newPluginObserver() *PluginObserver {
	return &PluginObserver{calls: make(map[plugin.Hook]int)}
}

func (o *PluginObserver) record(hook plugin.Hook) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls[hook]++
}

// Count returns the number of times the named hook has been dispatched.
func (o *PluginObserver) Count(hook plugin.Hook) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls[hook]
}

// Harness bundles every resource a testconnector-backed integration test
// needs: the listen address for drivers, a CA pool for TLS client
// verification, the Store for flow assertions, the ALPN cache for eviction
// tests, a blocking channel for OnBlock callbacks, and a plugin observer for
// hook assertions.
type Harness struct {
	t *testing.T

	// ClientAddr is the connector listener's bound "host:port" — drivers
	// connect here with an HTTP CONNECT or SOCKS5 client.
	ClientAddr string

	// CAPool is the x509 pool that trusts the MITM CA used by the harness.
	// Test clients must set this as RootCAs so TLS handshakes against the
	// connector's mint-on-demand certificates succeed.
	CAPool *x509.CertPool

	// CA is the underlying cert.CA, exposed for tests that need to inspect
	// the CA certificate directly (e.g. for wire fidelity checks).
	CA *cert.CA

	// UpstreamAddr is the address of the test TLS upstream. Tests reach it
	// via CONNECT/SOCKS5 tunnels.
	UpstreamAddr string

	// UpstreamCAPool trusts the upstream's ephemeral test cert so the
	// connector (and test clients in passthrough mode) can complete TLS.
	UpstreamCAPool *x509.CertPool

	// UpstreamServer is the http.Handler-driven TLS server. May be nil if
	// the test opted for a custom upstream via WithRawUpstream.
	UpstreamServer *httptest.Server

	// Store is the in-memory SQLite flow store used by RecordStep.
	Store *flow.SQLiteStore

	// ALPNCache is the cache installed on the TunnelHandler. Tests assert
	// against its Len() and Get()/Delete() to verify miss/hit/stale paths.
	ALPNCache *connector.ALPNCache

	// BlockCh receives every BlockInfo delivered by the TunnelHandler's
	// OnBlock callback. The buffer is large enough for typical tests; tests
	// that generate many blocks should drain it promptly.
	BlockCh chan connector.BlockInfo

	// Plugins records plugin hook invocations.
	Plugins *PluginObserver

	// TunnelHandler is the installed TunnelHandler. Tests may inspect it to
	// prove that CONNECT and SOCKS5 share the same instance (Q3 proof).
	TunnelHandler *connector.TunnelHandler

	// Interrogate the captured logs for failure diagnostics.
	CapturedLogs *testutil.CaptureLogger

	// Pipeline is the live Pipeline installed on the tunnel's SessionRunner.
	Pipeline *pipeline.Pipeline

	// Scope and RateLimiter are exposed so tests can tighten rules at
	// runtime (e.g. to test per-URL scope blocks).
	Scope       *connector.TargetScope
	RateLimiter *connector.RateLimiter
	Passthrough *connector.PassthroughList

	// InterceptEngine / InterceptQueue are the intercept wiring. Tests use
	// these to inject rules and release requests.
	InterceptEngine *intercept.Engine
	InterceptQueue  *intercept.Queue

	// TransformPipeline is the rules.Pipeline installed in TransformStep.
	TransformPipeline *rules.Pipeline

	// SafetyEngine is the safety engine installed in SafetyStep. May be nil
	// if the test did not configure safety rules.
	SafetyEngine *safety.Engine

	// PluginEngine is the plugin.Engine used by the harness.
	PluginEngine *plugin.Engine

	// Internal lifecycle state.
	connCtx    context.Context
	connCancel context.CancelFunc
	wg         sync.WaitGroup
	stopped    atomic.Bool
}

// Option configures a harness at Start time.
type Option func(*options)

type options struct {
	upstreamHandler http.Handler
	upstreamServer  *httptest.Server

	// Raw upstream injection (for wire-fidelity tests). If set, the harness
	// does not spin up an httptest.Server and uses upstreamAddr +
	// upstreamCert directly.
	upstreamAddr net.Addr
	upstreamCert *x509.Certificate

	scopePolicyAllows []connector.TargetRule
	scopePolicyDenies []connector.TargetRule
	rateLimitCfg      connector.RateLimitConfig

	passthroughHosts []string

	authenticator connector.Authenticator

	alpnCacheSize int
	alpnCacheTTL  time.Duration

	safetyConfig  *safety.Config
	extraSteps    []pipeline.Step
	dialTimeout   time.Duration
	hookObservers map[plugin.Hook]struct{}
}

func defaultOptions() *options {
	return &options{
		alpnCacheSize: 32,
		alpnCacheTTL:  time.Minute,
		dialTimeout:   5 * time.Second,
		hookObservers: map[plugin.Hook]struct{}{
			plugin.HookOnReceiveFromClient:  {},
			plugin.HookOnBeforeSendToServer: {},
			plugin.HookOnReceiveFromServer:  {},
			plugin.HookOnBeforeSendToClient: {},
			plugin.HookOnTLSHandshake:       {},
			plugin.HookOnSOCKS5Connect:      {},
		},
	}
}

// WithUpstreamHandler overrides the default upstream HTTPS handler.
func WithUpstreamHandler(h http.Handler) Option {
	return func(o *options) { o.upstreamHandler = h }
}

// WithUpstreamServer injects an externally-constructed httptest.Server. When
// set, the harness does not own the server's lifecycle (tests must Close it).
func WithUpstreamServer(s *httptest.Server) Option {
	return func(o *options) { o.upstreamServer = s }
}

// WithRawUpstream injects a raw TLS upstream address + certificate. The
// harness will trust cert and publish UpstreamAddr but will not start an
// httptest.Server. Used by wire fidelity tests that need a bufio-driven
// handler to observe exact bytes.
func WithRawUpstream(addr net.Addr, cert *x509.Certificate) Option {
	return func(o *options) {
		o.upstreamAddr = addr
		o.upstreamCert = cert
	}
}

// WithScopePolicy installs policy-level allow/deny target rules.
func WithScopePolicy(allows, denies []connector.TargetRule) Option {
	return func(o *options) {
		o.scopePolicyAllows = allows
		o.scopePolicyDenies = denies
	}
}

// WithRateLimit installs a policy-level rate-limit config.
func WithRateLimit(cfg connector.RateLimitConfig) Option {
	return func(o *options) { o.rateLimitCfg = cfg }
}

// WithPassthroughHosts marks the given host patterns as TLS passthrough.
func WithPassthroughHosts(hosts []string) Option {
	return func(o *options) { o.passthroughHosts = append([]string(nil), hosts...) }
}

// WithAuthenticator installs an Authenticator for the SOCKS5 negotiator.
func WithAuthenticator(a connector.Authenticator) Option {
	return func(o *options) { o.authenticator = a }
}

// WithALPNCacheSize sets the LRU capacity of the ALPN cache.
func WithALPNCacheSize(n int) Option {
	return func(o *options) { o.alpnCacheSize = n }
}

// WithALPNCacheTTL sets the per-entry TTL of the ALPN cache.
func WithALPNCacheTTL(d time.Duration) Option {
	return func(o *options) { o.alpnCacheTTL = d }
}

// WithSafetyConfig installs safety engine rules.
func WithSafetyConfig(cfg safety.Config) Option {
	return func(o *options) {
		c := cfg
		o.safetyConfig = &c
	}
}

// WithExtraPipelineStep appends a custom Step to the Pipeline in front of
// RecordStep. Useful for assertion probes that just observe Exchanges.
func WithExtraPipelineStep(s pipeline.Step) Option {
	return func(o *options) { o.extraSteps = append(o.extraSteps, s) }
}

// WithDialTimeout bounds the upstream dial timeout.
func WithDialTimeout(d time.Duration) Option {
	return func(o *options) { o.dialTimeout = d }
}

// Start spins up the harness. The test's Cleanup registers Stop automatically
// so tests can omit the deferred call.
func Start(t *testing.T, opts ...Option) *Harness {
	t.Helper()

	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	capture, logger := testutil.NewCaptureLogger()

	upstreamServer, upstreamAddr, upstreamCert := resolveUpstream(t, o)
	upstreamCAPool := x509.NewCertPool()
	upstreamCAPool.AddCert(upstreamCert)

	ca, caPool, issuer := buildCA(t)
	store := newFlowStore(t, logger)
	scope, rateLimiter, passthrough := buildPolicies(o)
	alpnCache := connector.NewALPNCache(o.alpnCacheSize, o.alpnCacheTTL)
	pluginEngine, observer := buildPluginEngine(o, logger)
	safetyEngine := buildSafetyEngine(t, o)
	interceptEngine := intercept.NewEngine()
	interceptQueue := intercept.NewQueue()
	transformPipeline := rules.NewPipeline()

	pl := buildPipeline(o, store, logger, pluginEngine, safetyEngine,
		scope, rateLimiter, interceptEngine, interceptQueue, transformPipeline)

	blockCh := make(chan connector.BlockInfo, 64)
	tunnel := buildTunnel(o, issuer, alpnCache, passthrough, scope, rateLimiter,
		pluginEngine, logger, upstreamCAPool, store, pl, blockCh)

	listener := startListener(t, o, scope, rateLimiter, pluginEngine, tunnel, logger)

	h := &Harness{
		t:                 t,
		CAPool:            caPool,
		CA:                ca,
		UpstreamCAPool:    upstreamCAPool,
		UpstreamAddr:      upstreamAddr,
		UpstreamServer:    upstreamServer,
		Store:             store,
		ALPNCache:         alpnCache,
		BlockCh:           blockCh,
		Plugins:           observer,
		TunnelHandler:     tunnel,
		CapturedLogs:      capture,
		Pipeline:          pl,
		Scope:             scope,
		RateLimiter:       rateLimiter,
		Passthrough:       passthrough,
		InterceptEngine:   interceptEngine,
		InterceptQueue:    interceptQueue,
		TransformPipeline: transformPipeline,
		SafetyEngine:      safetyEngine,
		PluginEngine:      pluginEngine,
	}

	// Start the listener goroutine and wire lifecycle cleanup.
	h.connCtx, h.connCancel = context.WithCancel(context.Background())
	h.runListener(t, listener)
	h.ClientAddr = listener.Addr()
	t.Cleanup(h.Stop)
	return h
}

// resolveUpstream picks between a caller-provided raw upstream, a caller-
// provided httptest.Server, or a newly-spun-up default server.
func resolveUpstream(t *testing.T, o *options) (*httptest.Server, string, *x509.Certificate) {
	t.Helper()
	switch {
	case o.upstreamAddr != nil && o.upstreamCert != nil:
		return nil, o.upstreamAddr.String(), o.upstreamCert
	case o.upstreamServer != nil:
		srv := o.upstreamServer
		return srv, srv.Listener.Addr().String(), srv.Certificate()
	default:
		handler := o.upstreamHandler
		if handler == nil {
			handler = http.HandlerFunc(defaultUpstreamHandler)
		}
		srv := httptest.NewTLSServer(handler)
		t.Cleanup(srv.Close)
		return srv, srv.Listener.Addr().String(), srv.Certificate()
	}
}

func buildCA(t *testing.T) (*cert.CA, *x509.CertPool, *cert.Issuer) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("testconnector: generate CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return ca, pool, cert.NewIssuer(ca)
}

func newFlowStore(t *testing.T, logger *slog.Logger) *flow.SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := flow.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("testconnector: new sqlite store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func buildPolicies(o *options) (*connector.TargetScope, *connector.RateLimiter, *connector.PassthroughList) {
	scope := connector.NewTargetScope()
	if len(o.scopePolicyAllows) > 0 || len(o.scopePolicyDenies) > 0 {
		scope.SetPolicyRules(o.scopePolicyAllows, o.scopePolicyDenies)
	}
	rl := connector.NewRateLimiter()
	if !o.rateLimitCfg.IsZero() {
		rl.SetPolicyLimits(o.rateLimitCfg)
	}
	pt := connector.NewPassthroughList()
	for _, host := range o.passthroughHosts {
		pt.Add(host)
	}
	return scope, rl, pt
}

func buildPluginEngine(o *options, logger *slog.Logger) (*plugin.Engine, *PluginObserver) {
	engine := plugin.NewEngine(logger)
	observer := newPluginObserver()
	for hook := range o.hookObservers {
		hook := hook
		engine.Registry().Register(
			"testconnector-observer",
			hook,
			func(_ context.Context, _ map[string]any) (*plugin.HookResult, error) {
				observer.record(hook)
				return nil, nil
			},
			plugin.OnErrorSkip,
		)
	}
	return engine, observer
}

func buildSafetyEngine(t *testing.T, o *options) *safety.Engine {
	t.Helper()
	if o.safetyConfig == nil {
		return nil
	}
	engine, err := safety.NewEngine(*o.safetyConfig)
	if err != nil {
		t.Fatalf("testconnector: safety engine: %v", err)
	}
	return engine
}

func buildPipeline(
	o *options,
	store *flow.SQLiteStore,
	logger *slog.Logger,
	pluginEngine *plugin.Engine,
	safetyEngine *safety.Engine,
	scope *connector.TargetScope,
	rateLimiter *connector.RateLimiter,
	interceptEngine *intercept.Engine,
	interceptQueue *intercept.Queue,
	transformPipeline *rules.Pipeline,
) *pipeline.Pipeline {
	// ScopeStep/RateLimitStep take *proxy.TargetScope / *proxy.RateLimiter
	// which are Go type aliases for the corresponding connector types, so
	// we pass our connector values directly.
	recordStep := pipeline.NewRecordStep(store, logger)
	steps := []pipeline.Step{
		pipeline.NewScopeStep(scope),
		pipeline.NewRateLimitStep(rateLimiter),
		pipeline.NewSafetyStep(safetyEngine),
		pipeline.NewPluginStep(pluginEngine, pipeline.PhaseRecv, logger),
		pipeline.NewInterceptStep(interceptEngine, interceptQueue),
		pipeline.NewTransformStep(transformPipeline),
		pipeline.NewPluginStep(pluginEngine, pipeline.PhaseSend, logger),
	}
	steps = append(steps, o.extraSteps...)
	steps = append(steps, recordStep)
	return pipeline.New(steps...)
}

func buildTunnel(
	o *options,
	issuer *cert.Issuer,
	alpnCache *connector.ALPNCache,
	passthrough *connector.PassthroughList,
	scope *connector.TargetScope,
	rateLimiter *connector.RateLimiter,
	pluginEngine *plugin.Engine,
	logger *slog.Logger,
	upstreamCAPool *x509.CertPool,
	store *flow.SQLiteStore,
	pl *pipeline.Pipeline,
	blockCh chan connector.BlockInfo,
) *connector.TunnelHandler {
	dialOpts := connector.DialOpts{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    upstreamCAPool,
		},
		DialTimeout: o.dialTimeout,
	}

	tunnel := &connector.TunnelHandler{
		Issuer:       issuer,
		DialOpts:     dialOpts,
		ALPNCache:    alpnCache,
		Passthrough:  passthrough,
		Scope:        scope,
		RateLimiter:  rateLimiter,
		PluginEngine: pluginEngine,
		Logger:       logger,
		OnBlock: func(_ context.Context, info connector.BlockInfo) {
			select {
			case blockCh <- info:
			default:
			}
		},
	}

	// Wire RunSession after construction so it closes over the pipeline.
	tunnel.RunSession = func(ctx context.Context, client codec.Codec, dial connector.DialFunc) error {
		onComplete := func(ctx context.Context, streamID string, sessionErr error) {
			if streamID == "" {
				return
			}
			state := "complete"
			if sessionErr != nil {
				state = "error"
			}
			_ = store.UpdateStream(ctx, streamID, flow.StreamUpdate{State: state})
		}
		return session.RunSession(ctx, client, session.DialFunc(dial), pl, session.SessionOptions{
			OnComplete: onComplete,
		})
	}
	return tunnel
}

func startListener(
	t *testing.T,
	o *options,
	scope *connector.TargetScope,
	rateLimiter *connector.RateLimiter,
	pluginEngine *plugin.Engine,
	tunnel *connector.TunnelHandler,
	logger *slog.Logger,
) *connector.Listener {
	t.Helper()

	socks5Neg := connector.NewSOCKS5Negotiator(logger)
	socks5Neg.Scope = scope
	socks5Neg.RateLimiter = rateLimiter
	socks5Neg.PluginEngine = pluginEngine
	if o.authenticator != nil {
		socks5Neg.Authenticator = o.authenticator
	}

	dispatcher := connector.NewKindDispatcher().
		WithCONNECT(connector.CONNECTHandler(connector.NewCONNECTNegotiator(logger), tunnel)).
		WithSOCKS5(connector.SOCKS5Handler(socks5Neg, tunnel))

	ln := connector.NewListener(connector.ListenerConfig{
		Name:     "testconnector",
		Addr:     "127.0.0.1:0",
		Detector: connector.NewDetector(),
		Dispatch: dispatcher,
		Logger:   logger,
	})
	ln.SetPluginEngine(pluginEngine)
	return ln
}

// runListener starts the listener goroutine and waits for Ready.
func (h *Harness) runListener(t *testing.T, listener *connector.Listener) {
	t.Helper()
	errCh := make(chan error, 1)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		errCh <- listener.Start(h.connCtx)
	}()

	select {
	case <-listener.Ready():
	case err := <-errCh:
		h.connCancel()
		t.Fatalf("testconnector: listener did not start: %v", err)
	case <-time.After(2 * time.Second):
		h.connCancel()
		t.Fatal("testconnector: listener did not become ready within 2s")
	}
}

// Stop shuts the harness down. It is safe to call multiple times.
func (h *Harness) Stop() {
	if !h.stopped.CompareAndSwap(false, true) {
		return
	}
	if h.connCancel != nil {
		h.connCancel()
	}
	// Wait for the listener goroutine to exit. Bound the wait so a stuck
	// listener cannot deadlock test cleanup.
	//
	// Note: we deliberately do not fail the test on a timeout here. In
	// practice, an HTTPS MITM tunnel goroutine can outlive its parent
	// context by a few seconds (client keep-alive connections sit in the
	// transport's idle pool until IdleConnTimeout, and the tunnel's
	// handleConn loop only terminates once the underlying socket is fully
	// drained). Treating that as a per-test failure would mask real
	// assertion errors with goroutine-lifecycle noise; tunnel goroutine
	// lifecycle is tracked separately at the connector level.
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// defaultUpstreamHandler is the default http.Handler mounted on the TLS
// upstream. Tests that want to observe requests can override via
// WithUpstreamHandler.
func defaultUpstreamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Testconnector", "upstream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
