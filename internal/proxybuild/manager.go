package proxybuild

import (
	"context"
	"fmt"
	"log/slog"
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
	logger           *slog.Logger
	factory          func(ctx context.Context, name, addr string) (*Stack, error)
	buildCfg         *connector.BuildConfig
	peekTimeout      time.Duration
	maxConns         int
	upstreamProxy    string
	enabledProtocols []string

	mu        sync.Mutex
	listeners map[string]*listenerEntry
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
	return &Manager{
		logger:    logger,
		factory:   cfg.StackFactory,
		buildCfg:  cfg.BuildConfig,
		listeners: make(map[string]*listenerEntry),
	}, nil
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
	// SetMaxConnections / SetPeekTimeout / SetEnabledProtocols call
	// before any listener existed is honored when the listener comes up.
	if m.maxConns > 0 {
		stack.Listener.SetMaxConnections(m.maxConns)
	}
	if m.peekTimeout > 0 {
		stack.Listener.SetPeekTimeout(m.peekTimeout)
	}
	if len(m.enabledProtocols) > 0 {
		stack.Listener.SetEnabledProtocols(m.enabledProtocols)
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
type ListenerStatus struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
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
		out = append(out, ListenerStatus{
			Name:              name,
			ListenAddr:        entry.listenAddr,
			ActiveConnections: entry.stack.Listener.ActiveConnections(),
			UptimeSeconds:     uptime,
		})
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

// SetEnabledProtocols updates the runtime protocol allow-list applied
// at peek-based detection. Empty (nil or zero-length) restores "accept
// all detected kinds". The change applies immediately to all running
// listeners and is remembered so listeners started later inherit it.
// USK-732 wiring: pairs with proxybuild.Listener.SetEnabledProtocols.
//
// USK-808: the snapshot is also propagated to the bound BuildConfig so
// the per-connection MITM TLS handshake filters its advertised ALPN
// list to only the protocols the operator enabled. Without this fan-out
// the listener-level peek filter would let a CONNECT through and the
// MITM handshake would still advertise h2 even if "HTTP/2" is not in
// protocols. Mirrors the SetUpstreamProxy → BuildConfig propagation
// added in USK-734. nil BuildConfig (Managers constructed without one,
// e.g. tests/adapters) is tolerated as a no-op for that fan-out leg.
func (m *Manager) SetEnabledProtocols(protocols []string) {
	var stored []string
	if len(protocols) > 0 {
		stored = make([]string, len(protocols))
		copy(stored, protocols)
	}
	m.mu.Lock()
	m.enabledProtocols = stored
	bc := m.buildCfg
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.stack.Listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetEnabledProtocols(stored)
	}
	if bc != nil {
		bc.SetEnabledProtocols(stored)
	}
}

// EnabledProtocols returns a snapshot of the configured allow-list, or
// nil when no filter is active. Reads the manager-level stored value so
// the answer is correct even when no listener is currently running.
func (m *Manager) EnabledProtocols() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.enabledProtocols) == 0 {
		return nil
	}
	out := make([]string, len(m.enabledProtocols))
	copy(out, m.enabledProtocols)
	return out
}

// SetUpstreamProxy stores an upstream proxy URL and, when ManagerConfig
// supplied a BuildConfig, mutates that BuildConfig's dynamic
// upstream-proxy slot so the next live data-path dial transits the
// configured proxy (USK-734). The string form is reflected back via
// UpstreamProxy() for status reporting; an empty string clears both the
// status state and the dynamic dial-path override.
//
// Parsing failures fall back to the historical "store-only" behaviour
// (status surfaces the raw string but the dial path stays direct). The
// MCP layer (proxy_start_tool / configure_tool) validates the URL via
// connector.ParseUpstreamProxy before reaching here, so a parse failure
// at this layer means an internal mis-call rather than a malformed
// user input — logging at Warn matches that severity.
func (m *Manager) SetUpstreamProxy(proxyURL string) {
	m.mu.Lock()
	m.upstreamProxy = proxyURL
	bc := m.buildCfg
	m.mu.Unlock()

	if bc == nil {
		return
	}
	if proxyURL == "" {
		bc.SetUpstreamProxy(nil)
		return
	}
	parsed, err := connector.ParseUpstreamProxy(proxyURL)
	if err != nil {
		m.logger.Warn("upstream proxy URL not applied to live dial path",
			"url", connector.RedactProxyURL(proxyURL), "error", err)
		return
	}
	bc.SetUpstreamProxy(parsed)
}

// UpstreamProxy returns the stored upstream proxy URL, or empty string.
func (m *Manager) UpstreamProxy() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProxy
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
