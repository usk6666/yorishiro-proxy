package proxybuild

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// shutdownTimeout bounds the wait for a listener goroutine to exit during
// graceful shutdown. Mirrors proxy.Manager.shutdownTimeout.
const shutdownTimeout = 30 * time.Second

// DefaultListenerName is the implicit listener name when callers omit one.
// Mirrors proxy.DefaultListenerName.
const DefaultListenerName = "default"

// defaultListenAddr is the bind address used when StartNamed is called
// with an empty addr. Mirrors proxy.Manager's hard-coded default.
const defaultListenAddr = "127.0.0.1:8080"

// listenerEntry tracks a single named listener plus its lifecycle state.
type listenerEntry struct {
	stack      *Stack
	cancel     context.CancelFunc
	done       chan struct{}
	listenAddr string
	startedAt  time.Time

	// listenerCtx is the per-listener context derived from the StartNamed
	// caller's ctx. It is cancelled by entry.cancel; TCP forward listeners
	// derive their own per-port contexts from this so a forward outlives
	// the caller's (shorter-lived) MCP request ctx but is torn down with
	// the parent listener.
	listenerCtx context.Context

	// tcpForwards tracks the per-port forward listeners associated with this
	// parent listener. nil until the first StartTCPForwardsNamed call.
	// Mutations protected by Manager.mu.
	tcpForwards map[string]*tcpForwardEntry
}

// ManagerConfig configures a Manager. The factory is invoked per StartNamed
// call to produce the per-listener Stack — making engine, store, build
// config, and policy a process-singleton view passed into every listener.
//
// The factory pattern keeps Manager a thin orchestrator (it does not own
// the lifetime of the engine, store, etc.) while letting callers decide
// per-listener variation (different scopes, different listen addresses).
type ManagerConfig struct {
	// Logger is used for manager-level Info/Debug logs.
	Logger *slog.Logger

	// StackFactory builds a per-listener Stack. The factory receives the
	// listener name and addr resolved by StartNamed (defaults applied).
	// All other Deps fields the factory must source from its closure.
	StackFactory func(ctx context.Context, name, addr string) (*Stack, error)

	// BuildConfig, when non-nil, is the connector.BuildConfig instance
	// shared by every Stack produced by StackFactory. The Manager mutates
	// its dynamic upstream-proxy slot when SetUpstreamProxy is called so
	// the URL change reaches the live dial path (USK-734). nil disables
	// the wire-up — SetUpstreamProxy still records the URL for status
	// reporting via UpstreamProxy() but no dial-path mutation occurs (the
	// historical pre-USK-734 behaviour, retained for tests and adapters
	// that do not own the live BuildConfig).
	BuildConfig *connector.BuildConfig

	// H1UpstreamMetrics is the Manager-level USK-1000 counter set.
	// When non-nil, [Manager.H1UpstreamMetrics] returns a snapshot of
	// these counters; production wiring threads the SAME pointer into
	// every [Deps.H1UpstreamMetrics] so all per-CONNECT chains emit
	// into the same struct. nil constructs a fresh empty counter set
	// inside NewManager — callers that omit the field still get a
	// working snapshot accessor; they just won't see counters from any
	// listener built via a Deps that omitted the matching field.
	H1UpstreamMetrics *H1UpstreamMetrics

	// H2UpstreamMetrics is the Manager-level USK-1001 counter set —
	// h1 parity for the HTTP/2 upstream redial / refused-retry surface.
	// When non-nil, [Manager.H2UpstreamMetrics] returns a snapshot of
	// these counters; production wiring threads the SAME pointer into
	// every [Deps.H2UpstreamMetrics] so all per-CONNECT chains emit
	// into the same struct. nil constructs a fresh empty counter set
	// inside NewManager — callers that omit the field still get a
	// working snapshot accessor; they just won't see counters from any
	// listener built via a Deps that omitted the matching field.
	H2UpstreamMetrics *H2UpstreamMetrics
}

// Manager orchestrates one or more named live Stacks. It exposes
// Start/Stop/Status/SetMaxConnections/SetPeekTimeout/SetUpstreamProxy and
// the related methods consumed by the MCP proxy_start / proxy_stop tools.
//
// Caveats:
//
//   - SetMaxConnections / SetPeekTimeout fan-out applies to the wrapped
//     Listener.SetMaxConnections / SetPeekTimeout (which mutate the
//     underlying connector.FullListener).
//   - StartTCPForwardsNamed binds an extra net.Listener per port and
//     reuses the parent listener's Pipeline + FlowStore for recording.
//     First-iteration scope (USK-711) supports the "raw" / "auto" / ""
//     protocol modes; L7-mode dispatch (http, http2, grpc, websocket)
//     and tls=true are deferred to a follow-up issue and rejected at
//     start time.
type Manager struct {
	logger         *slog.Logger
	factory        func(ctx context.Context, name, addr string) (*Stack, error)
	buildCfg       *connector.BuildConfig
	peekTimeout    time.Duration
	requestTimeout time.Duration
	maxConns       int
	upstreamProxy  string

	// upstreamProxyPerListener tracks the upstream-proxy URL string for
	// each listener (USK-826). The string form is preserved alongside the
	// BuildConfig per-listener entry so status surfaces (query_tool) can
	// report the original URL (after redaction) without re-stringifying a
	// parsed *url.URL. Mutations guarded by m.mu.
	upstreamProxyPerListener map[string]string

	// upstreamProxyRotationPerListener tracks the per-listener rotation
	// state for the URL-template form (USK-959). Stored alongside the
	// legacy string map so status surfaces can report the active
	// template (redacted) and policy without re-stringifying the
	// resolver's internal state. Mutations guarded by m.mu.
	upstreamProxyRotationPerListener map[string]*upstreamProxyRotationEntry

	mu        sync.Mutex
	listeners map[string]*listenerEntry

	// h1Upstream collects USK-998 Phase 1 + USK-999 Phase 2 + USK-1000
	// observability counters for the HTTP/1.x upstream redial / replay
	// surface. One struct per Manager (each Manager has its own;
	// multi-listener isolation is provided by Manager-per-listener).
	// The pointer is threaded through every per-CONNECT h1Chain and
	// per-exchange retryingUpstreamChannel via the Deps that
	// BuildLiveStack consumes, so counter updates aggregate across
	// every CONNECT under this Manager. See
	// [Manager.H1UpstreamMetrics] for the snapshot accessor and
	// internal/proxybuild/h1_metrics.go for the schema.
	h1Upstream *H1UpstreamMetrics

	// h2Upstream collects USK-991 + USK-992 + USK-993 + USK-1001
	// observability counters for the HTTP/2 upstream redial /
	// refused-retry surface. Same scoping rules as h1Upstream — one
	// per Manager, threaded through every per-CONNECT redialChain via
	// Deps. See [Manager.H2UpstreamMetrics] for the snapshot accessor
	// and internal/proxybuild/h2_metrics.go for the schema.
	h2Upstream *H2UpstreamMetrics
}

// upstreamProxyRotationEntry pairs the operator-supplied template
// (verbatim, so the status surface can redact via
// connector.RedactProxyURL) with the resolved RotationPolicy. The
// BuildConfig holds the live RotationResolver; this struct is purely
// for status reporting.
type upstreamProxyRotationEntry struct {
	Template string
	Policy   string
}

// NewManager constructs a Manager. cfg.StackFactory is required; nil
// returns an error so the bug surfaces at construction rather than at
// the first StartNamed call.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.StackFactory == nil {
		return nil, fmt.Errorf("proxybuild: NewManager: StackFactory is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// USK-1000: prefer the operator-supplied counter pointer so it can
	// be shared with Deps.H1UpstreamMetrics; fall back to a fresh
	// empty set when omitted (tests that don't care about counters
	// still get a working snapshot accessor).
	h1Metrics := cfg.H1UpstreamMetrics
	if h1Metrics == nil {
		h1Metrics = NewH1UpstreamMetrics()
	}
	// USK-1001: same singleton/fallback pattern for the h2 counter set.
	h2Metrics := cfg.H2UpstreamMetrics
	if h2Metrics == nil {
		h2Metrics = NewH2UpstreamMetrics()
	}
	return &Manager{
		logger:     logger,
		factory:    cfg.StackFactory,
		buildCfg:   cfg.BuildConfig,
		listeners:  make(map[string]*listenerEntry),
		h1Upstream: h1Metrics,
		h2Upstream: h2Metrics,
	}, nil
}

// H1UpstreamMetrics returns a snapshot of the USK-998 / USK-999 /
// USK-1000 HTTP/1.x upstream redial counters maintained under this
// Manager. The snapshot is a value type so callers may retain it
// safely; subsequent increments do not back-mutate the returned
// struct.
//
// The MCP query(resource:"status") tool surfaces these counters to
// AI agents under the `h1_upstream` field. The counter set matches
// the design review schema (5 counters + 6th redial_failed counter
// from scope-adjustment #1 + replay outcome split from
// scope-adjustment #3 + chain_generation gauge family).
//
// h2-parity counters are tracked in a follow-up Issue per memory
// `feedback_shared_seam_hardcoded_flag` — once both protocols have
// counters in this shape, both can move to a shared file.
func (m *Manager) H1UpstreamMetrics() H1UpstreamMetricsSnapshot {
	// h1Upstream is set at construction by NewManager and never
	// reassigned, so a lock is unnecessary for the pointer read. The
	// snapshot itself uses atomic Loads inside.
	return m.h1Upstream.Snapshot()
}

// H2UpstreamMetrics returns a snapshot of the USK-991 / USK-992 /
// USK-993 / USK-1001 HTTP/2 upstream redial counters maintained under
// this Manager. The snapshot is a value type so callers may retain it
// safely; subsequent increments do not back-mutate the returned
// struct.
//
// The MCP query(resource:"status") tool surfaces these counters to
// AI agents under the `h2_upstream` field. The counter set matches
// the design review schema (3 stale-detect counters + 3 redial
// triggers + 3 redial-failed triggers + 3 retry outcomes +
// chain_generation gauge family — 12 counters + 2 gauges, mirroring
// the h1 14-field shape).
//
// Shared-seam extraction with H1UpstreamMetrics is deferred to a
// follow-up Issue per memory `feedback_shared_seam_hardcoded_flag` —
// once both protocols have counters of identical shape we can lift
// them into a shared file without baking h1-only assumptions into
// the seam.
func (m *Manager) H2UpstreamMetrics() H2UpstreamMetricsSnapshot {
	// h2Upstream is set at construction by NewManager and never
	// reassigned, so a lock is unnecessary for the pointer read. The
	// snapshot itself uses atomic Loads inside.
	return m.h2Upstream.Snapshot()
}

// Start is shorthand for StartNamed(ctx, DefaultListenerName, listenAddr).
// Returns ErrAlreadyRunning when the default listener is already running
// (mirrors proxy.Manager.Start).
func (m *Manager) Start(ctx context.Context, listenAddr string) error {
	return m.StartNamed(ctx, DefaultListenerName, listenAddr)
}

// StartNamed builds a Stack via the configured factory, starts the
// listener, and waits for Ready (or an early Start error) before returning.
//
// Returns ErrAlreadyRunning when name is the default listener name and a
// default listener is already running. Returns ErrListenerExists for
// non-default names that already exist.
//
// listenAddr defaults to "127.0.0.1:8080" when empty.
func (m *Manager) StartNamed(ctx context.Context, name string, listenAddr string) error {
	if name == "" {
		name = DefaultListenerName
	}
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[name]; exists {
		if name == DefaultListenerName {
			return ErrAlreadyRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerExists)
	}

	stack, err := m.factory(ctx, name, listenAddr)
	if err != nil {
		return fmt.Errorf("proxybuild: build live stack %q: %w", name, err)
	}

	// Apply manager-level tunables to the new Listener so a runtime
	// SetMaxConnections / SetPeekTimeout / SetRequestTimeout call before
	// any listener existed is honored when the listener comes up.
	if m.maxConns > 0 {
		stack.Listener.SetMaxConnections(m.maxConns)
	}
	if m.peekTimeout > 0 {
		stack.Listener.SetPeekTimeout(m.peekTimeout)
	}
	if m.requestTimeout > 0 {
		stack.Listener.SetRequestTimeout(m.requestTimeout)
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		errCh <- stack.Listener.Start(listenerCtx)
	}()

	// Wait for Ready (success) or an early error from Start.
	select {
	case <-stack.Listener.Ready():
	case err := <-errCh:
		cancel()
		if err != nil {
			return fmt.Errorf("start proxy %q: %w", name, err)
		}
		return fmt.Errorf("start proxy %q: listener exited unexpectedly", name)
	}

	m.listeners[name] = &listenerEntry{
		stack:       stack,
		cancel:      cancel,
		done:        done,
		listenAddr:  stack.Listener.Addr(),
		startedAt:   time.Now(),
		listenerCtx: listenerCtx,
	}

	m.logger.Info("proxy started", "name", name, "listen_addr", stack.Listener.Addr())
	return nil
}

// Stop is shorthand for StopNamed(ctx, DefaultListenerName).
func (m *Manager) Stop(ctx context.Context) error {
	return m.StopNamed(ctx, DefaultListenerName)
}

// StopNamed gracefully shuts down the named listener. Returns ErrNotRunning
// for the default listener and ErrListenerNotFound for other names.
func (m *Manager) StopNamed(ctx context.Context, name string) error {
	if name == "" {
		name = DefaultListenerName
	}

	m.mu.Lock()
	entry, exists := m.listeners[name]
	if !exists {
		m.mu.Unlock()
		if name == DefaultListenerName {
			return ErrNotRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}
	delete(m.listeners, name)
	m.mu.Unlock()

	return m.shutdownEntry(ctx, name, entry)
}

// StopAll gracefully shuts down every running listener. Returns the first
// error encountered; remaining listeners are still shut down.
func (m *Manager) StopAll(ctx context.Context) error {
	m.mu.Lock()
	if len(m.listeners) == 0 {
		m.mu.Unlock()
		return nil
	}
	entries := m.listeners
	m.listeners = make(map[string]*listenerEntry)
	m.mu.Unlock()

	var firstErr error
	for name, entry := range entries {
		if err := m.shutdownEntry(ctx, name, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// shutdownEntry cancels the listener's context, drains any associated TCP
// forward listeners, and waits for the parent listener goroutine to exit
// (bounded by shutdownTimeout or ctx). TCP forwards are torn down BEFORE
// the parent so plugin lifecycle hooks running in forward sessions can
// observe a still-live parent Stack on their way out.
func (m *Manager) shutdownEntry(ctx context.Context, name string, entry *listenerEntry) error {
	// Snapshot + clear entry.tcpForwards under m.mu so a concurrent
	// StartTCPForwardsNamed (which captured this entry pointer before
	// StopNamed/StopAll removed it from m.listeners) cannot race with our
	// iteration and cannot write to a nil map after we clear it. After this
	// critical section the post-bind re-check in StartTCPForwardsNamed
	// observes tcpForwards==nil and discards the freshly-bound forward
	// instead of panicking on a nil-map assignment.
	m.mu.Lock()
	forwards := entry.tcpForwards
	entry.tcpForwards = nil
	m.mu.Unlock()

	// Cancel TCP forwards first so accept goroutines stop returning new
	// conns. Each stopTCPForwardEntry call blocks on the forward goroutine
	// (bounded by shutdownTimeout) so handlers complete before we close the
	// parent — matching legacy proxy.Manager.shutdownEntry semantics.
	for port, fwd := range forwards {
		m.stopTCPForwardEntry(name, port, fwd)
	}

	entry.cancel()

	select {
	case <-entry.done:
		m.logger.Info("proxy stopped", "name", name, "listen_addr", entry.listenAddr)
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("stop proxy %q: shutdown timed out after %v", name, shutdownTimeout)
	case <-ctx.Done():
		return fmt.Errorf("stop proxy %q: %w", name, ctx.Err())
	}
}

// Status returns whether the default listener is running and its listen
// address. Mirrors proxy.Manager.Status's "default-only" semantics.
func (m *Manager) Status() (running bool, listenAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists {
		return false, ""
	}
	return true, entry.listenAddr
}

// ListenerStatus describes a single running listener. Mirrors
// proxy.ListenerStatus.
//
// UpstreamProxy (USK-826) carries the per-listener upstream-proxy URL
// string as stored via SetUpstreamProxyForListener, empty when no
// per-listener override is set. The MCP status surface is responsible
// for redaction via connector.RedactProxyURL before serialising.
//
// UpstreamProxyTemplate / UpstreamProxyRotationPolicy (USK-959) carry
// the rotating-template form. Both fields are empty when the listener
// is not using rotation (UpstreamProxy carries the literal URL or the
// listener has no upstream proxy configured). When rotation IS active,
// UpstreamProxy is empty (the literal URL doesn't exist — only a
// template). The MCP status surface MUST redact UpstreamProxyTemplate
// via connector.RedactProxyURL before serialising; the template may
// resolve to credentials.
type ListenerStatus struct {
	Name                        string `json:"name"`
	ListenAddr                  string `json:"listen_addr"`
	ActiveConnections           int    `json:"active_connections"`
	UptimeSeconds               int64  `json:"uptime_seconds"`
	UpstreamProxy               string `json:"upstream_proxy,omitempty"`
	UpstreamProxyTemplate       string `json:"upstream_proxy_template,omitempty"`
	UpstreamProxyRotationPolicy string `json:"upstream_proxy_rotation_policy,omitempty"`
}

// ListenerStatuses returns a snapshot of every running listener. Returns
// nil when no listeners are running.
func (m *Manager) ListenerStatuses() []ListenerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.listeners) == 0 {
		return nil
	}

	out := make([]ListenerStatus, 0, len(m.listeners))
	for name, entry := range m.listeners {
		var uptime int64
		if !entry.startedAt.IsZero() {
			uptime = int64(time.Since(entry.startedAt).Seconds())
		}
		status := ListenerStatus{
			Name:              name,
			ListenAddr:        entry.listenAddr,
			ActiveConnections: entry.stack.Listener.ActiveConnections(),
			UptimeSeconds:     uptime,
			UpstreamProxy:     m.upstreamProxyPerListener[name],
		}
		if rot := m.upstreamProxyRotationPerListener[name]; rot != nil {
			status.UpstreamProxyTemplate = rot.Template
			status.UpstreamProxyRotationPolicy = rot.Policy
		}
		out = append(out, status)
	}
	return out
}

// ListenerCount returns the number of currently running listeners.
func (m *Manager) ListenerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.listeners)
}

// ActiveConnections sums the active-connection counts across all running
// listeners.
func (m *Manager) ActiveConnections() int {
	m.mu.Lock()
	entries := make([]*listenerEntry, 0, len(m.listeners))
	for _, entry := range m.listeners {
		entries = append(entries, entry)
	}
	m.mu.Unlock()

	total := 0
	for _, entry := range entries {
		total += entry.stack.Listener.ActiveConnections()
	}
	return total
}

// Uptime reports how long the default listener has been running. Returns
// 0 when the default listener is not running. Mirrors proxy.Manager.Uptime.
func (m *Manager) Uptime() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists || entry.startedAt.IsZero() {
		return 0
	}
	return time.Since(entry.startedAt)
}

// SetMaxConnections updates the concurrent-connection cap for new accepts.
// The change applies immediately to all running listeners (including TCP
// forward listeners attached to each entry); in-flight connections drain
// naturally.
func (m *Manager) SetMaxConnections(n int) {
	m.mu.Lock()
	m.maxConns = n
	listeners := make([]*Listener, 0, len(m.listeners))
	forwards := make([]*tcpForwardEntry, 0)
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.stack.Listener)
		for _, fwd := range entry.tcpForwards {
			forwards = append(forwards, fwd)
		}
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetMaxConnections(n)
	}
	// Fan out to TCP forward listeners. Storing 0 disables the per-forward
	// cap (matches FullListener semantics where SetMaxConnections(0) means
	// unlimited). The accept loop reads maxConns atomically.
	for _, fwd := range forwards {
		fwd.maxConns.Store(int64(n))
	}
}

// MaxConnections returns the configured cap. When any listener is running,
// returns the first listener's current value (matches proxy.Manager
// semantics including the "first-running-wins" detail).
func (m *Manager) MaxConnections() int {
	m.mu.Lock()
	stored := m.maxConns
	var first *Listener
	for _, entry := range m.listeners {
		first = entry.stack.Listener
		break
	}
	m.mu.Unlock()
	if first != nil {
		return first.MaxConnections()
	}
	return stored
}

// SetPeekTimeout updates the protocol-detection timeout. Applies
// immediately to all running listeners.
func (m *Manager) SetPeekTimeout(d time.Duration) {
	m.mu.Lock()
	m.peekTimeout = d
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.stack.Listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetPeekTimeout(d)
	}
}

// PeekTimeout returns the configured peek timeout. When any listener is
// running, returns the first listener's current value.
func (m *Manager) PeekTimeout() time.Duration {
	m.mu.Lock()
	stored := m.peekTimeout
	var first *Listener
	for _, entry := range m.listeners {
		first = entry.stack.Listener
		break
	}
	m.mu.Unlock()
	if first != nil {
		return first.PeekTimeout()
	}
	return stored
}

// SetRequestTimeout updates the HTTP request header read timeout enforced
// by the plain-HTTP forward handler and the CONNECT / SOCKS5 inner-byte
// peek (USK-844). Applies immediately to every running listener via the
// per-listener atomic-Int64 slot wired in BuildLiveStack; the value is
// also remembered so listeners started later inherit it. Non-positive
// values are stored verbatim — Listener.SetRequestTimeout normalises any
// negative to zero, and zero means "fall back to handler defaults"
// downstream.
//
// Mirrors SetPeekTimeout to keep the operator surface symmetric.
func (m *Manager) SetRequestTimeout(d time.Duration) {
	m.mu.Lock()
	m.requestTimeout = d
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.stack.Listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetRequestTimeout(d)
	}
}

// RequestTimeout returns the configured HTTP request header read timeout
// (USK-844). When any listener is running, returns the first listener's
// current value — matching the "first-running-wins" detail of
// MaxConnections / PeekTimeout. Zero means handlers will fall back to
// their per-package defaults (connector.forwardPeekTimeout for plain HTTP,
// connector.DefaultInnerPeekTimeout for CONNECT/SOCKS5 inner peek).
func (m *Manager) RequestTimeout() time.Duration {
	m.mu.Lock()
	stored := m.requestTimeout
	var first *Listener
	for _, entry := range m.listeners {
		first = entry.stack.Listener
		break
	}
	m.mu.Unlock()
	if first != nil {
		return first.RequestTimeout()
	}
	return stored
}

// SetUpstreamProxy stores an upstream proxy URL and, when ManagerConfig
// supplied a BuildConfig, applies it to the default listener's per-listener
// slot so the next live data-path dial under that listener transits the
// configured proxy (USK-826).
//
// Historical behaviour: pre-USK-826 this method mutated the process-global
// dynamic slot, which propagated to ALL listeners in a multi-listener setup
// and caused listener B chained through listener A to silently recurse
// through itself. The method now defaults to scoping the URL to the
// "default" listener; callers wiring multi-listener configurations should
// use SetUpstreamProxyForListener with an explicit name.
//
// The string form is reflected back via UpstreamProxy() for status
// reporting; an empty string clears both the status state and the
// default-listener's per-listener dial-path override.
//
// Parsing failures fall back to the historical "store-only" behaviour
// (status surfaces the raw string but the dial path stays direct). The
// MCP layer (proxy_start_tool / configure_tool) validates the URL via
// connector.ParseUpstreamProxy before reaching here, so a parse failure
// at this layer means an internal mis-call rather than a malformed
// user input — logging at Warn matches that severity.
func (m *Manager) SetUpstreamProxy(proxyURL string) {
	m.SetUpstreamProxyForListener(DefaultListenerName, proxyURL)
}

// SetUpstreamProxyForListener stores an upstream proxy URL scoped to the
// named listener and, when ManagerConfig supplied a BuildConfig, mutates
// the BuildConfig's per-listener upstream-proxy entry for `name` so the
// next live data-path dial for connections accepted on that listener
// transits the configured proxy (USK-826).
//
// This is the canonical setter for the multi-listener case: a chained
// MITM where listener B sends its traffic through listener A must scope
// the "send through A" decision to listener B — otherwise listener A
// would itself recurse through its own upstream URL.
//
// Empty proxyURL clears both the manager status state for the listener
// and the BuildConfig per-listener entry, so the global / boot-time
// fallback re-emerges for that listener. An empty name is treated as
// DefaultListenerName.
func (m *Manager) SetUpstreamProxyForListener(name, proxyURL string) {
	if name == "" {
		name = DefaultListenerName
	}
	// Parse outside the lock so a malformed URL does not deadlock under
	// m.mu — the result is consumed inside the critical section below.
	var parsed *url.URL
	var parseErr error
	if proxyURL != "" {
		parsed, parseErr = connector.ParseUpstreamProxy(proxyURL)
	}

	m.mu.Lock()
	if proxyURL == "" {
		delete(m.upstreamProxyPerListener, name)
		// USK-959 (F-4): an empty proxyURL means "no upstream proxy of
		// any flavour for this listener" — clear the rotation slot too
		// so the setter is symmetric with the non-empty branch (which
		// already clears rotation). Without this, calling the setter
		// with "" would leave an orphan resolver active.
		delete(m.upstreamProxyRotationPerListener, name)
	} else {
		if m.upstreamProxyPerListener == nil {
			m.upstreamProxyPerListener = make(map[string]string)
		}
		m.upstreamProxyPerListener[name] = proxyURL
		// USK-959: setting a literal URL clears any active rotation
		// for the listener — they are mutually exclusive at the wire
		// level (cf. UpstreamProxyConfig.Validate).
		delete(m.upstreamProxyRotationPerListener, name)
	}
	// Maintain the legacy default-listener mirror on m.upstreamProxy so
	// UpstreamProxy() / status surfaces keep working for callers that have
	// not adopted the per-listener API.
	if name == DefaultListenerName {
		m.upstreamProxy = proxyURL
	}
	bc := m.buildCfg
	// USK-959 (S-2 / CWE-362): perform BuildConfig writes under m.mu so
	// the manager-status mutations above and the BuildConfig mutations
	// below form one atomic critical section. Without this, two
	// configure_tool calls racing on the same listener could observe
	// (status says rotation X, bc has rotation Y) for a brief window.
	// Lock ordering is m.mu → bc.upstreamProxyPerListenerMu /
	// bc.rotationByListenerMu; no reader of those bc muxes acquires
	// m.mu, so this is safe.
	if bc != nil {
		if proxyURL == "" {
			bc.SetUpstreamProxyForListener(name, nil)
			bc.SetRotationForListener(name, nil)
		} else {
			// Clear any stale rotation first so the new literal URL is
			// the only thing the dial path consults.
			bc.SetRotationForListener(name, nil)
			if parseErr == nil {
				bc.SetUpstreamProxyForListener(name, parsed)
			}
		}
	}
	m.mu.Unlock()

	// Logging happens after releasing m.mu so a slow log sink cannot
	// stall other manager callers. parseErr captures the malformed-URL
	// case where status was still updated but the live dial path stays
	// on the previous URL (the per-listener slot is not overwritten).
	if proxyURL != "" && parseErr != nil {
		m.logger.Warn("upstream proxy URL not applied to live dial path",
			"listener", name, "url", connector.RedactProxyURL(proxyURL), "error", parseErr)
	}
}

// ClearUpstreamProxyForListener removes the named listener's per-listener
// upstream-proxy entry (USK-826) AND any rotation resolver installed via
// SetUpstreamProxyRotationForListener (USK-959). Equivalent to
// SetUpstreamProxyForListener(name, "") + SetUpstreamProxyRotationForListener(name, nil).
// Provided as a named accessor so the proxy_start reset path expresses
// intent clearly.
func (m *Manager) ClearUpstreamProxyForListener(name string) {
	m.SetUpstreamProxyForListener(name, "")
	m.SetUpstreamProxyRotationForListener(name, nil)
}

// SetUpstreamProxyRotationForListener installs (or clears) a rotating
// upstream-proxy resolver for the named listener (USK-959). cfg.URLTemplate
// must be non-empty, cfg.Rotation.Policy must be one of the four
// supported policies. Passing nil clears the resolver — the listener
// then falls back to its static per-listener URL (USK-826) or the
// process-global / boot-time slot.
//
// The Manager stores the template + policy for status reporting AND
// hands a fresh RotationResolver to the bound BuildConfig so the live
// dial path consults it inside EffectiveUpstreamProxyForCtxErr. An
// empty name is treated as DefaultListenerName.
//
// configure_tool dynamic tuning: re-calling this method with a fresh
// cfg replaces the resolver entirely so per-conn / per-host / sticky
// caches are dropped on the same call. In-flight connections keep the
// URL they already captured (the previous resolver still exists in
// goroutine-local state until GC).
//
// Returns an error when cfg is malformed (template fails probe
// expansion, policy not recognised). Callers must ensure the listener
// is running before invoking (the MCP layer enforces this).
func (m *Manager) SetUpstreamProxyRotationForListener(name string, cfg *connector.RotationConfig) error {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	if cfg == nil {
		delete(m.upstreamProxyRotationPerListener, name)
		bc := m.buildCfg
		m.mu.Unlock()
		if bc != nil {
			bc.SetRotationForListener(name, nil)
		}
		return nil
	}
	// Defensive policy validation (the MCP layer already validated, but
	// programmatic callers may bypass).
	if !cfg.Policy.IsValid() {
		m.mu.Unlock()
		return fmt.Errorf("rotation policy %q is not supported", cfg.Policy)
	}
	if cfg.Template == "" {
		m.mu.Unlock()
		return fmt.Errorf("rotation template is empty")
	}
	// Record for status surfaces.
	if m.upstreamProxyRotationPerListener == nil {
		m.upstreamProxyRotationPerListener = make(map[string]*upstreamProxyRotationEntry)
	}
	m.upstreamProxyRotationPerListener[name] = &upstreamProxyRotationEntry{
		Template: cfg.Template,
		Policy:   string(cfg.Policy),
	}
	// When rotation is active, the legacy literal slot must be empty —
	// they are mutually exclusive at the wire level.
	delete(m.upstreamProxyPerListener, name)
	if name == DefaultListenerName {
		m.upstreamProxy = ""
	}
	bc := m.buildCfg
	m.mu.Unlock()

	if bc == nil {
		return nil
	}
	// Clear any literal per-listener URL so the resolver path is the
	// only one consulted for this listener.
	bc.SetUpstreamProxyForListener(name, nil)
	resolver := connector.NewRotationResolver(*cfg, 0, 0)
	bc.SetRotationForListener(name, resolver)
	return nil
}

// UpstreamProxyRotationForListener returns the operator-supplied
// template and policy for the named listener (USK-959), or empty
// strings when no rotation is configured. An empty name is treated as
// DefaultListenerName.
func (m *Manager) UpstreamProxyRotationForListener(name string) (template, policy string) {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if rot := m.upstreamProxyRotationPerListener[name]; rot != nil {
		return rot.Template, rot.Policy
	}
	return "", ""
}

// UpstreamProxy returns the stored upstream proxy URL for the default
// listener, or empty string when none is set. This mirrors the
// pre-USK-826 status accessor; per-listener inspection is available via
// UpstreamProxyForListener.
func (m *Manager) UpstreamProxy() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProxy
}

// UpstreamProxyForListener returns the stored upstream proxy URL for the
// named listener (USK-826), or empty string when none is set. An empty
// name is treated as DefaultListenerName.
func (m *Manager) UpstreamProxyForListener(name string) string {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProxyPerListener[name]
}

// SetTLSFingerprint installs a runtime override for the uTLS browser
// fingerprint profile on the bound BuildConfig so the next live
// data-path upstream dial uses the new profile (USK-809). Mirrors the
// SetUpstreamProxy precedent: parsing / validation is the MCP layer's
// responsibility (proxy_start_tool / configure_tool validate the
// profile name before reaching here), so this method is a thin
// passthrough. An empty profile clears the override and falls back to
// the boot-time BuildConfig.TLSFingerprint value. No-op when no
// BuildConfig is bound (test-only Manager constructions).
func (m *Manager) SetTLSFingerprint(profile string) {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()

	if bc == nil {
		return
	}
	bc.SetTLSFingerprint(profile)
}

// SetMaxConcurrentStreams installs a runtime override for the HTTP/2
// SETTINGS_MAX_CONCURRENT_STREAMS value advertised to clients on the
// inbound (ServerRole) Layer (USK-862). Mirrors the SetTLSFingerprint
// precedent: validation is the MCP layer's responsibility, so this is a
// thin passthrough to BuildConfig.SetMaxConcurrentStreams.
//
// Next-connection semantics: already-accepted H2 connections retain the
// cap captured at their stack-assembly time; the new value takes effect
// at the next listener-stack assembly. No-op when no BuildConfig is
// bound (test-only Manager constructions).
//
// Passing 0 clears the override so subsequent stack assemblies fall back
// to the boot-time BuildConfig.MaxConcurrentStreams field (and ultimately
// the H2 Layer default).
func (m *Manager) SetMaxConcurrentStreams(v uint32) {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()

	if bc == nil {
		return
	}
	bc.SetMaxConcurrentStreams(v)
}

// MaxConcurrentStreams returns the effective HTTP/2
// SETTINGS_MAX_CONCURRENT_STREAMS value from the bound BuildConfig
// (USK-862). Reflects any runtime override installed via
// SetMaxConcurrentStreams and falls back to the boot-time
// BuildConfig.MaxConcurrentStreams when no override is in effect.
// Returns 0 (the "use H2 default" sentinel) when no BuildConfig is
// bound — callers MUST treat 0 as "fall through to the H2 Layer
// default" (defaultMaxConcurrentStreams in
// internal/layer/http2/connstate.go).
func (m *Manager) MaxConcurrentStreams() uint32 {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()

	if bc == nil {
		return 0
	}
	return bc.EffectiveMaxConcurrentStreams()
}

// TLSFingerprint returns the effective uTLS browser fingerprint profile
// from the bound BuildConfig (USK-809). The returned value reflects any
// runtime override installed via SetTLSFingerprint and falls back to
// the boot-time BuildConfig.TLSFingerprint when no override is in
// effect. Returns the empty string when no BuildConfig is bound — the
// caller is responsible for translating empty into a user-facing
// representation if desired (this accessor does NOT substitute a
// "chrome" default).
func (m *Manager) TLSFingerprint() string {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()

	if bc == nil {
		return ""
	}
	return bc.EffectiveTLSFingerprint()
}

// MaxRawCaptureSize returns the per-message HTTP/1.x raw-bytes capture cap
// from the bound BuildConfig (USK-800).
//
// On the production wiring path (NewLiveBuildConfig) the field is always
// set via config.ResolveMaxRawCaptureSize, which substitutes
// config.DefaultMaxRawCaptureSize (2 MiB) when the operator left the knob
// unset. Callers therefore do NOT need to apply their own zero-fallback —
// the value returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) MaxRawCaptureSize() int64 {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.MaxRawCaptureSize
}

// MaxBodySize returns the absolute body-size cap from the bound BuildConfig
// (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveMaxBodySize, which substitutes the package default
// (config.MaxBodySize, 254 MiB) when the operator left the knob unset.
// Callers therefore do NOT need to apply their own zero-fallback — the value
// returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) MaxBodySize() int64 {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.MaxBodySize
}

// BodySpillThreshold returns the body memory→disk spill threshold from the
// bound BuildConfig (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveBodySpillThreshold, which substitutes
// config.DefaultBodySpillThreshold (10 MiB) when the operator left the knob
// unset. Callers therefore do NOT need to apply their own zero-fallback —
// the value returned here is the resolved threshold.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) BodySpillThreshold() int64 {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.BodySpillThreshold
}

// BodySpillDir returns the directory used for body-spill temp files from the
// bound BuildConfig (USK-807).
//
// On the production Live wiring path the field is set via
// config.ResolveBodySpillDir. The empty-string sentinel means the bodybuf
// package falls back to os.TempDir() at spill time — that is the resolver
// default and a normal operating mode, not a missing value.
//
// Empty is also returned when no BuildConfig was bound to the Manager. Both
// cases serialise to "default = os.TempDir()"; callers that need to
// distinguish "operator unset" from "no manager" must inspect the Manager
// state out-of-band.
func (m *Manager) BodySpillDir() string {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return ""
	}
	return bc.BodySpillDir
}

// WSMaxFrameSize returns the per-frame WebSocket payload cap from the bound
// BuildConfig (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveWSMaxFrameSize, which substitutes the Layer default
// (config.MaxWebSocketFrameSize, 16 MiB) when the operator left the knob
// unset. Callers therefore do NOT need to apply their own zero-fallback —
// the value returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) WSMaxFrameSize() int64 {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.WSMaxFrameSize
}

// GRPCMaxMessageSize returns the per-LPM gRPC / gRPC-Web payload cap from
// the bound BuildConfig (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveGRPCMaxMessageSize, which substitutes the Layer default
// (config.MaxGRPCMessageSize, 254 MiB) when the operator left the knob
// unset. Callers therefore do NOT need to apply their own zero-fallback —
// the value returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) GRPCMaxMessageSize() uint32 {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.GRPCMaxMessageSize
}

// SSEMaxEventSize returns the per-event SSE raw-byte cap from the bound
// BuildConfig (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveSSEMaxEventSize, which substitutes the Layer default when
// the operator left the knob unset. Callers therefore do NOT need to apply
// their own zero-fallback — the value returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) SSEMaxEventSize() int {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.SSEMaxEventSize
}

// GRPCMaxMessagesPerStream returns the per-stream RecordStep cap on
// GRPCDataMessage envelopes from the bound BuildConfig (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveGRPCMaxMessagesPerStream, which substitutes the RecordStep
// default (config.MaxGRPCMessagesPerStream, 10000) when the operator left
// the knob unset. Callers therefore do NOT need to apply their own
// zero-fallback — the value returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) GRPCMaxMessagesPerStream() int {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.GRPCMaxMessagesPerStream
}

// SSEMaxEventsPerStream returns the per-stream RecordStep cap on SSEMessage
// envelopes from the bound BuildConfig (USK-807).
//
// On the production Live wiring path the field is always set via
// config.ResolveSSEMaxEventsPerStream, which substitutes the RecordStep
// default (config.MaxSSEEventsPerStream, 100000) when the operator left the
// knob unset. Callers therefore do NOT need to apply their own
// zero-fallback — the value returned here is the resolved cap.
//
// Zero is still possible from two paths and must be handled by callers
// only if they construct the Manager outside the Live wiring:
//   - No BuildConfig was bound to the Manager (returned as 0 below).
//   - A non-Live BuildConfig was assembled directly without running the
//     resolver (e.g., tests).
func (m *Manager) SSEMaxEventsPerStream() int {
	m.mu.Lock()
	bc := m.buildCfg
	m.mu.Unlock()
	if bc == nil {
		return 0
	}
	return bc.SSEMaxEventsPerStream
}

// Listener returns the Stack's Listener wrapper for the named listener,
// or nil if no such listener is running. Useful for tests and for callers
// that need to reach the bound pluginv2.Engine via Listener.PluginV2Engine().
func (m *Manager) Listener(name string) *Listener {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[name]
	if !exists {
		return nil
	}
	return entry.stack.Listener
}

// Stack returns the named listener's full Stack, or nil if no such
// listener is running.
func (m *Manager) Stack(name string) *Stack {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[name]
	if !exists {
		return nil
	}
	return entry.stack
}

// StartTCPForwardsNamed binds a per-port net.Listener for each entry in
// params.Forwards and dispatches accepted connections through the parent
// listener's Pipeline so raw bytes flow recording captures the forwarded
// stream end-to-end.
//
// Semantics:
//   - params must be (or unwrap to) TCPForwardParams. Other types are
//     rejected with a typed error so MCP callers see a clear failure.
//   - Ports already bound on this entry are skipped (idempotent re-call).
//   - On any per-port bind failure, ports added by THIS call are torn
//     down in reverse order; ports established by earlier calls survive.
//   - Returns ErrNotRunning when the parent listener is not running
//     (mirrors legacy proxy.Manager.StartTCPForwardsNamed semantics).
func (m *Manager) StartTCPForwardsNamed(ctx context.Context, name string, params any) error {
	if name == "" {
		name = DefaultListenerName
	}
	// Fast-fail if the caller's ctx is already cancelled — avoids the
	// per-port bind syscall when the caller has lost interest.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("start tcp forwards on %q: %w", name, err)
	}

	tp, err := coerceTCPForwardParams(params)
	if err != nil {
		return err
	}
	if len(tp.Forwards) == 0 {
		return nil
	}
	// Defensive port-key validation at the package boundary. The MCP layer
	// already validates these via validatePortNumber, but a programmatic
	// caller passing a malformed key (empty / non-numeric / out-of-range)
	// would otherwise reach net.Listen with a confusing bind-address error.
	for port := range tp.Forwards {
		if err := validateForwardPortKey(port); err != nil {
			return fmt.Errorf("start tcp forwards on %q: %w", name, err)
		}
	}

	m.mu.Lock()
	entry, exists := m.listeners[name]
	if !exists {
		m.mu.Unlock()
		if name == DefaultListenerName {
			return ErrNotRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}
	if entry.tcpForwards == nil {
		entry.tcpForwards = make(map[string]*tcpForwardEntry)
	}
	m.mu.Unlock()

	// Track ports started by THIS call so a mid-loop bind error rolls back
	// only the new ones (legacy semantics: previously-running forwards
	// survive a partial failure).
	//
	// Forward listeners derive their lifetime context from the parent
	// listener's listenerCtx — NOT from the caller's ctx. The MCP
	// proxy_start handler calls this with the per-request ctx which is
	// cancelled when the response is sent, so deriving from `ctx` would
	// tear down forwards immediately. Using parent.listenerCtx keeps
	// forwards alive until StopNamed cancels the parent.
	parentCtx := entry.listenerCtx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	var started []string
	for port, fc := range tp.Forwards {
		m.mu.Lock()
		if _, dup := entry.tcpForwards[port]; dup {
			m.mu.Unlock()
			continue
		}
		m.mu.Unlock()

		fwd, startErr := m.startTCPForwardListener(parentCtx, name, port, fc)
		if startErr != nil {
			m.rollbackTCPForwards(name, entry, started)
			return fmt.Errorf("start tcp forward on port %s: %w", port, startErr)
		}

		// Re-check the parent listener has not been stopped between our
		// previous Unlock and this Lock. shutdownEntry nils
		// entry.tcpForwards under m.mu; without this check we would either
		// panic on a nil-map assignment or leak the freshly-bound listener.
		m.mu.Lock()
		if entry.tcpForwards == nil {
			m.mu.Unlock()
			m.stopTCPForwardEntry(name, port, fwd)
			m.rollbackTCPForwards(name, entry, started)
			return fmt.Errorf("start tcp forward on port %s: %w", port, ErrNotRunning)
		}
		entry.tcpForwards[port] = fwd
		m.mu.Unlock()
		started = append(started, port)

		m.logger.Info("tcp forward listener started",
			"name", name,
			"port", port,
			"upstream", fc.Target,
			"protocol", fc.Protocol,
			"listen_addr", fwd.addr,
		)
	}
	return nil
}

// rollbackTCPForwards tears down forwards added by an in-progress
// StartTCPForwardsNamed call after a per-port failure. Caller must NOT hold
// m.mu (stopTCPForwardEntry blocks on the listener goroutine).
func (m *Manager) rollbackTCPForwards(name string, entry *listenerEntry, started []string) {
	for _, port := range started {
		m.mu.Lock()
		fwd, ok := entry.tcpForwards[port]
		if ok {
			delete(entry.tcpForwards, port)
		}
		m.mu.Unlock()
		if !ok {
			continue
		}
		m.stopTCPForwardEntry(name, port, fwd)
	}
}

// StartTCPForwardsNamedAny is the any-typed adapter; identical signature to
// StartTCPForwardsNamed (kept for parity with the legacy *proxy.Manager
// surface that the MCP proxyManager interface speaks).
func (m *Manager) StartTCPForwardsNamedAny(ctx context.Context, name string, params any) error {
	return m.StartTCPForwardsNamed(ctx, name, params)
}

// StartTCPForwards is shorthand for StartTCPForwardsNamed on the default
// listener.
func (m *Manager) StartTCPForwards(ctx context.Context, params any) error {
	return m.StartTCPForwardsNamed(ctx, DefaultListenerName, params)
}

// TCPForwardAddrs returns a snapshot of port -> bound listen address for the
// default listener's TCP forwards. Returns nil when the default listener is
// not running or has no forwards (mirrors legacy semantics — the MCP
// proxy_start tool publishes only the default listener's forward map).
func (m *Manager) TCPForwardAddrs() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists || len(entry.tcpForwards) == 0 {
		return nil
	}
	out := make(map[string]string, len(entry.tcpForwards))
	for port, fwd := range entry.tcpForwards {
		out[port] = fwd.addr
	}
	return out
}

// coerceTCPForwardParams accepts either TCPForwardParams (production form)
// or *TCPForwardParams (in case a caller threads a pointer) and returns a
// concrete value. Other types — including nil and the zero-value `any` —
// produce a typed error. nil-empty Forwards is accepted (the caller
// short-circuits before bind).
func coerceTCPForwardParams(params any) (TCPForwardParams, error) {
	switch v := params.(type) {
	case TCPForwardParams:
		return v, nil
	case *TCPForwardParams:
		if v == nil {
			return TCPForwardParams{}, nil
		}
		return *v, nil
	case nil:
		return TCPForwardParams{}, nil
	default:
		return TCPForwardParams{}, fmt.Errorf("proxybuild: StartTCPForwardsNamed: params must be TCPForwardParams, got %T", params)
	}
}
