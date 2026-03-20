package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// TCPForwardListenerConfig holds configuration for creating a TCPForwardListener.
type TCPForwardListenerConfig struct {
	Addr           string
	Handler        ProtocolHandler  // fallback handler (raw TCP)
	Detector       ProtocolDetector // optional: for "auto" protocol detection
	Config         *config.ForwardConfig
	Issuer         *cert.Issuer // optional: for TLS MITM termination
	Logger         *slog.Logger
	MaxConnections int           // 0 = defaultMaxConnections (128)
	PeekTimeout    time.Duration // 0 = defaultPeekTimeout (30s)
}

// TCPForwardListener accepts TCP connections on a local port and dispatches
// them to a ProtocolHandler based on the ForwardConfig.Protocol setting.
//
// Protocol dispatch modes:
//   - "raw": direct dispatch to the fallback handler (no protocol detection)
//   - "auto" (or ""): peek-based protocol detection using the Detector
//   - "http", "http2", "grpc", "websocket": fixed handler selection by name
//
// Each connection is annotated with a forwarding target in the context
// so that L7 handlers can resolve the upstream address.
type TCPForwardListener struct {
	addr           string
	handler        ProtocolHandler  // fallback (raw TCP) handler
	detector       ProtocolDetector // for "auto" mode protocol detection
	config         *config.ForwardConfig
	issuer         *cert.Issuer // for TLS MITM termination (nil = no TLS)
	logger         *slog.Logger
	maxConnections int
	activeConns    atomic.Int64
	peekTimeoutNs  atomic.Int64 // nanoseconds

	pluginEngine *plugin.Engine

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup
	semMu    sync.RWMutex // protects maxConnections during dynamic resize
}

// NewTCPForwardListener creates a new TCP forward listener.
// addr is the local address to listen on (e.g. "127.0.0.1:9998").
// handler is the fallback protocol handler for raw TCP dispatch.
func NewTCPForwardListener(cfg TCPForwardListenerConfig) *TCPForwardListener {
	maxConns := cfg.MaxConnections
	if maxConns == 0 {
		maxConns = defaultMaxConnections
	}
	peekTimeout := cfg.PeekTimeout
	if peekTimeout == 0 {
		peekTimeout = defaultPeekTimeout
	}
	l := &TCPForwardListener{
		addr:           cfg.Addr,
		handler:        cfg.Handler,
		detector:       cfg.Detector,
		config:         cfg.Config,
		issuer:         cfg.Issuer,
		logger:         cfg.Logger,
		maxConnections: maxConns,
		ready:          make(chan struct{}),
	}
	l.peekTimeoutNs.Store(int64(peekTimeout))
	return l
}

// SetPluginEngine sets the plugin engine used to dispatch lifecycle hook events
// (on_connect, on_disconnect). If engine is nil, hooks are silently skipped.
// Must be called before Start.
func (l *TCPForwardListener) SetPluginEngine(engine *plugin.Engine) {
	l.pluginEngine = engine
}

// Start begins accepting connections. It blocks until the context is cancelled.
func (l *TCPForwardListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("tcp forward listen on %s: %w", l.addr, err)
	}

	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()
	close(l.ready)

	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				l.wg.Wait()
				return nil
			default:
				l.wg.Wait()
				return fmt.Errorf("tcp forward accept: %w", err)
			}
		}

		// Capacity check: reject if at capacity.
		l.semMu.RLock()
		maxConns := l.maxConnections
		rejected := false
		if maxConns > 0 {
			if current := l.activeConns.Add(1); current > int64(maxConns) {
				l.activeConns.Add(-1)
				rejected = true
			}
		}
		l.semMu.RUnlock()

		if rejected {
			l.logger.Warn("tcp forward connection rejected: at capacity",
				"remote_addr", conn.RemoteAddr().String(),
				"max_connections", maxConns)
			conn.Close()
			continue
		}

		if l.logger.Enabled(ctx, slog.LevelDebug) {
			l.logger.Debug("tcp forward connection accepted",
				"remote_addr", conn.RemoteAddr().String(),
				"active_connections", l.activeConns.Load(),
				"max_connections", maxConns,
			)
		}

		l.wg.Go(func() {
			if maxConns > 0 {
				defer l.activeConns.Add(-1)
			}
			l.handleConn(ctx, conn)
		})
	}
}

// handleConn dispatches a single connection based on the protocol configuration.
func (l *TCPForwardListener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	connStart := time.Now()
	connID := GenerateConnID()
	connLogger := l.logger.With("conn_id", connID, "remote_addr", remoteAddr)

	// Store connection metadata in context.
	ctx = ContextWithConnID(ctx, connID)
	ctx = ContextWithClientAddr(ctx, remoteAddr)
	ctx = ContextWithLogger(ctx, connLogger)

	// Inject forwarding target into context for L7 handler target resolution.
	if l.config != nil && l.config.Target != "" {
		ctx = ContextWithForwardTarget(ctx, l.config.Target)
	}

	// Dispatch on_connect lifecycle hook (fail-open).
	l.dispatchOnConnect(ctx, remoteAddr, connLogger)

	// Dispatch on_disconnect lifecycle hook when this connection closes.
	defer l.dispatchOnDisconnect(ctx, remoteAddr, connStart, connLogger)

	// TLS MITM termination: when config.TLS is true, terminate TLS and
	// dispatch the cleartext connection to protocol handlers.
	dispatchConn := conn
	if l.config != nil && l.config.TLS {
		tlsConn, err := l.terminateTLS(ctx, conn, connLogger)
		if err != nil {
			connLogger.Debug("tcp forward TLS termination failed", "error", err)
			return
		}
		dispatchConn = tlsConn
	}

	// If TLS termination produced a different conn, ensure it is closed
	// so that a proper close_notify is sent to the client.
	if dispatchConn != conn {
		defer dispatchConn.Close()
	}

	// Determine the protocol mode.
	proto := ""
	if l.config != nil {
		proto = l.config.Protocol
	}

	switch proto {
	case "raw":
		// Direct dispatch to fallback handler (existing behavior).
		l.handleRaw(ctx, dispatchConn, connLogger, connStart)
	case "auto", "":
		// Peek-based protocol detection (same as Listener).
		l.handleAuto(ctx, dispatchConn, connLogger, connStart)
	default:
		// Fixed handler selection by protocol name.
		l.handleFixed(ctx, dispatchConn, proto, connLogger, connStart)
	}
}

// handleRaw dispatches directly to the fallback handler without detection.
func (l *TCPForwardListener) handleRaw(ctx context.Context, conn net.Conn, logger *slog.Logger, connStart time.Time) {
	logger.Debug("tcp forward dispatched", "protocol", l.handler.Name(), "mode", "raw")
	if err := l.handler.Handle(ctx, conn); err != nil {
		logger.Error("tcp forward handler error", "protocol", l.handler.Name(), "error", err)
		return
	}
	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.Debug("tcp forward connection closed",
			"protocol", l.handler.Name(),
			"status", "complete",
			"duration_ms", time.Since(connStart).Milliseconds(),
		)
	}
}

// handleAuto performs peek-based protocol detection and dispatches to the matched handler.
func (l *TCPForwardListener) handleAuto(ctx context.Context, conn net.Conn, logger *slog.Logger, connStart time.Time) {
	if l.detector == nil {
		// No detector configured; fall back to raw handler.
		logger.Debug("tcp forward no detector, falling back to raw handler")
		l.handleRaw(ctx, conn, logger, connStart)
		return
	}

	pc := NewPeekConn(conn)

	// Set read deadline for protocol detection (Slowloris protection).
	peekTimeout := time.Duration(l.peekTimeoutNs.Load())
	if peekTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(peekTimeout))
	}

	// Two-stage protocol detection (same as Listener.detectProtocol).
	handler, peek, ok := l.detectProtocol(pc, logger)

	// Reset deadline before passing to handler.
	conn.SetReadDeadline(time.Time{})

	if !ok {
		// No match: fall back to raw handler.
		logger.Debug("tcp forward no protocol matched, using fallback handler",
			"peek_bytes", fmt.Sprintf("%x", peek))
		handler = l.handler
	}

	logger.Debug("tcp forward dispatched", "protocol", handler.Name(), "mode", "auto")

	if err := handler.Handle(ctx, pc); err != nil {
		logger.Error("tcp forward handler error", "protocol", handler.Name(), "error", err)
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("tcp forward connection closed",
				"protocol", handler.Name(),
				"status", "error",
				"duration_ms", time.Since(connStart).Milliseconds(),
			)
		}
		return
	}

	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.Debug("tcp forward connection closed",
			"protocol", handler.Name(),
			"status", "complete",
			"duration_ms", time.Since(connStart).Milliseconds(),
		)
	}
}

// handleFixed selects a handler by protocol name and dispatches to it.
func (l *TCPForwardListener) handleFixed(ctx context.Context, conn net.Conn, proto string, logger *slog.Logger, connStart time.Time) {
	if l.detector == nil {
		logger.Warn("tcp forward fixed protocol requested but no detector available, falling back to raw handler",
			"protocol", proto)
		l.handleRaw(ctx, conn, logger, connStart)
		return
	}

	// Use the detector to find a handler matching the protocol name.
	handler := l.findHandlerByName(proto)
	if handler == nil {
		logger.Warn("tcp forward no handler found for protocol, falling back to raw handler",
			"protocol", proto)
		l.handleRaw(ctx, conn, logger, connStart)
		return
	}

	logger.Debug("tcp forward dispatched", "protocol", handler.Name(), "mode", "fixed")

	if err := handler.Handle(ctx, conn); err != nil {
		logger.Error("tcp forward handler error", "protocol", handler.Name(), "error", err)
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("tcp forward connection closed",
				"protocol", handler.Name(),
				"status", "error",
				"duration_ms", time.Since(connStart).Milliseconds(),
			)
		}
		return
	}

	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.Debug("tcp forward connection closed",
			"protocol", handler.Name(),
			"status", "complete",
			"duration_ms", time.Since(connStart).Milliseconds(),
		)
	}
}

// protocolNameMap maps ForwardConfig.Protocol values to handler Name() values.
var protocolNameMap = map[string]string{
	"http":      "HTTP/1.x",
	"http2":     "HTTP/2 (h2c)",
	"grpc":      "gRPC",
	"websocket": "WebSocket",
}

// findHandlerByName searches the detector for a handler matching the given
// protocol config value. Returns nil if no match is found.
func (l *TCPForwardListener) findHandlerByName(proto string) ProtocolHandler {
	handlerName, ok := protocolNameMap[proto]
	if !ok {
		return nil
	}
	if hl, ok := l.detector.(HandlerLister); ok {
		for _, h := range hl.Handlers() {
			if h.Name() == handlerName {
				return h
			}
		}
	}
	return nil
}

// detectProtocol performs two-stage protocol detection (mirrors Listener.detectProtocol).
func (l *TCPForwardListener) detectProtocol(pc *PeekConn, logger *slog.Logger) (ProtocolHandler, []byte, bool) {
	peek, err := pc.Peek(quickPeekSize)
	if err != nil && len(peek) == 0 {
		logger.Debug("tcp forward peek failed", "error", err)
		return nil, nil, false
	}

	quickHandler := l.detector.Detect(peek)
	handler, peek := l.refineDetection(pc, quickHandler, peek, logger)
	return handler, peek, handler != nil
}

// refineDetection performs stage 2 of protocol detection (mirrors Listener.refineDetection).
func (l *TCPForwardListener) refineDetection(pc *PeekConn, quickHandler ProtocolHandler, peek []byte, logger *slog.Logger) (ProtocolHandler, []byte) {
	handler := quickHandler
	buffered := pc.Buffered()
	switch {
	case quickHandler != nil && buffered > quickPeekSize:
		n := buffered
		if n > peekSize {
			n = peekSize
		}
		if fullPeek, err := pc.Peek(n); err == nil || len(fullPeek) > 0 {
			if fullHandler := l.detector.Detect(fullPeek); fullHandler != nil {
				handler = fullHandler
				peek = fullPeek
			}
		}
	case quickHandler == nil:
		fullPeek, fullErr := pc.Peek(peekSize)
		if fullErr != nil && len(fullPeek) == 0 {
			logger.Debug("tcp forward peek failed", "error", fullErr)
			return nil, peek
		}
		if fullHandler := l.detector.Detect(fullPeek); fullHandler != nil {
			handler = fullHandler
			peek = fullPeek
		}
	}
	return handler, peek
}

// terminateTLS performs TLS MITM termination on an incoming connection.
// It peeks for a TLS ClientHello, resolves the hostname for certificate
// generation from ForwardConfig.Target (falling back to SNI), and completes
// the server-side TLS handshake using the configured certificate issuer.
//
// When the client sends non-TLS data despite config.TLS=true, a warning is
// logged and the cleartext connection is returned as-is (graceful fallback).
func (l *TCPForwardListener) terminateTLS(ctx context.Context, conn net.Conn, logger *slog.Logger) (net.Conn, error) {
	if l.issuer == nil {
		return nil, fmt.Errorf("TLS MITM requested but no certificate issuer configured")
	}

	// Peek to confirm TLS ClientHello.
	pc := NewPeekConn(conn)

	// Set a short deadline for the peek to avoid blocking on non-TLS clients.
	peekTimeout := time.Duration(l.peekTimeoutNs.Load())
	if peekTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(peekTimeout))
	}

	peek, _ := pc.Peek(6)

	// Reset deadline.
	conn.SetReadDeadline(time.Time{})

	if !isTLSClientHello(peek) {
		logger.Warn("tcp forward tls: true but no TLS ClientHello detected, proceeding as cleartext",
			"peek_hex", fmt.Sprintf("%x", peek))
		return pc, nil
	}

	// Resolve hostname for certificate generation.
	hostname := l.targetHostname()

	logger.Debug("tcp forward TLS termination starting", "hostname", hostname)

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				// SNI not sent (e.g., IP address connection per RFC 6066).
				logger.Debug("TLS ClientHello without SNI, using target hostname", "hostname", hostname)
				name = hostname
			} else if name != hostname {
				logger.Debug("TLS SNI differs from target hostname",
					"sni", name, "target_hostname", hostname)
				// Use SNI for cert generation so the client sees the expected name.
				// The forwarding target remains the configured target.
			}
			return l.issuer.GetCertificate(name)
		},
		MinVersion: tls.VersionTLS12,
		// Advertise both h2 and http/1.1 to allow HTTP/2 negotiation
		// when the cleartext is dispatched to an L7 handler.
		NextProtos: []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Server(pc, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake for %s: %w", hostname, err)
	}

	state := tlsConn.ConnectionState()
	logger.Debug("tcp forward TLS termination complete",
		"hostname", hostname,
		"alpn", state.NegotiatedProtocol,
		"tls_version", tlsVersionName(state.Version),
	)

	return tlsConn, nil
}

// targetHostname extracts the hostname from the ForwardConfig.Target for use
// as the CN/SAN in MITM certificate generation. It strips the port if present.
// Returns "localhost" as a last resort fallback.
func (l *TCPForwardListener) targetHostname() string {
	if l.config == nil || l.config.Target == "" {
		return "localhost"
	}
	host, _, err := net.SplitHostPort(l.config.Target)
	if err != nil {
		// Target might be a bare hostname without port.
		return l.config.Target
	}
	if host == "" {
		return "localhost"
	}
	return host
}

// isTLSClientHello checks if the peeked bytes begin with a TLS ClientHello.
// isTLSClientHello checks whether peek bytes look like a TLS ClientHello.
// TLS record header: ContentType(1) + Version(2) + Length(2), followed by
// HandshakeType(1). We require ContentType = 0x16 (Handshake), major version
// 0x03 (SSL 3.x / TLS 1.x), and HandshakeType = 0x01 (ClientHello).
func isTLSClientHello(peek []byte) bool {
	if len(peek) < 6 {
		return false
	}
	return peek[0] == 0x16 && peek[1] == 0x03 && peek[5] == 0x01
}

// tlsVersionName returns a human-readable name for a TLS version constant.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// dispatchOnConnect dispatches the on_connect lifecycle hook.
// Errors are logged but do not block connection processing (fail-open).
func (l *TCPForwardListener) dispatchOnConnect(ctx context.Context, clientAddr string, logger *slog.Logger) {
	if l.pluginEngine == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()

	connInfo := &plugin.ConnInfo{
		ClientAddr: clientAddr,
	}
	data := map[string]any{
		"event":     "connect",
		"conn_info": connInfo.ToMap(),
	}

	_, err := l.pluginEngine.Dispatch(ctx, plugin.HookOnConnect, data)
	if err != nil {
		logger.Warn("plugin on_connect hook error", "error", err)
	}
}

// dispatchOnDisconnect dispatches the on_disconnect lifecycle hook.
// Uses context.Background() so disconnect hooks run even during shutdown.
func (l *TCPForwardListener) dispatchOnDisconnect(_ context.Context, clientAddr string, connStart time.Time, logger *slog.Logger) {
	if l.pluginEngine == nil {
		return
	}

	dispatchCtx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()

	durationMs := time.Since(connStart).Milliseconds()
	connInfo := &plugin.ConnInfo{
		ClientAddr: clientAddr,
	}
	data := map[string]any{
		"event":       "disconnect",
		"conn_info":   connInfo.ToMap(),
		"duration_ms": durationMs,
	}

	_, err := l.pluginEngine.Dispatch(dispatchCtx, plugin.HookOnDisconnect, data)
	if err != nil {
		logger.Warn("plugin on_disconnect hook error", "error", err)
	}
}

// Ready returns a channel that is closed when the listener is ready to accept connections.
func (l *TCPForwardListener) Ready() <-chan struct{} {
	return l.ready
}

// Addr returns the listener's network address, or empty string if not started.
func (l *TCPForwardListener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return ""
}

// ActiveConnections returns the number of connections currently being handled.
func (l *TCPForwardListener) ActiveConnections() int {
	return int(l.activeConns.Load())
}

// SetMaxConnections dynamically changes the maximum number of concurrent connections.
func (l *TCPForwardListener) SetMaxConnections(n int) {
	if n <= 0 {
		return
	}
	l.semMu.Lock()
	defer l.semMu.Unlock()
	l.maxConnections = n
}
