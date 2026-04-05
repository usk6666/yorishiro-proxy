package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	prototcp "github.com/usk6666/yorishiro-proxy/internal/protocol/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// TunnelHandler defines the interface for performing TLS MITM on a tunneled
// connection. This is implemented by the HTTP handler and allows the SOCKS5
// post-handshake dispatch to delegate TLS interception without importing the
// HTTP package directly.
type TunnelHandler interface {
	// HandleTunnelMITM performs TLS MITM on a tunneled connection.
	// It performs a TLS handshake, then dispatches to the appropriate
	// protocol handler based on ALPN negotiation.
	HandleTunnelMITM(ctx context.Context, conn net.Conn, authority string) error

	// IsPassthrough checks if the hostname should bypass TLS interception.
	IsPassthrough(hostname string) bool
}

// HTTPDetector detects plaintext HTTP traffic by checking for HTTP method
// prefixes in the peeked bytes and handles HTTP connections.
type HTTPDetector interface {
	// Detect checks if the peeked bytes look like an HTTP request.
	Detect(peek []byte) bool

	// Handle processes an HTTP connection.
	Handle(ctx context.Context, conn net.Conn) error
}

// DispatchConfig holds the dependencies for post-handshake protocol dispatch.
type DispatchConfig struct {
	// TunnelHandler performs TLS MITM (implemented by the HTTP handler).
	TunnelHandler TunnelHandler

	// HTTPDetector detects and handles plaintext HTTP traffic.
	HTTPDetector HTTPDetector

	// Logger is the structured logger for dispatch operations.
	Logger *slog.Logger

	// FlowWriter records raw TCP flows. If nil, flow recording is skipped
	// for the raw TCP relay path.
	FlowWriter flow.Writer

	// PluginEngine dispatches per-chunk plugin hooks for the raw TCP relay
	// path. If nil, plugin hooks are skipped.
	PluginEngine *plugin.Engine
}

// isTLSClientHello checks if the peeked bytes begin with a TLS ClientHello.
// TLS records start with ContentType (0x16) followed by the protocol version
// (0x03, 0x0N where N is the minor version).
func isTLSClientHello(peek []byte) bool {
	if len(peek) < 2 {
		return false
	}
	return peek[0] == 0x16 && peek[1] == 0x03
}

// NewPostHandshakeDispatch creates a PostHandshakeFunc that performs protocol
// detection on the tunneled connection after a successful SOCKS5 handshake.
//
// The dispatch logic:
//  1. TLS ClientHello detected → check passthrough, then delegate to TunnelHandler
//     for TLS MITM (dynamic cert, ALPN negotiation, HTTP/2 or HTTP/1.x).
//  2. Plaintext HTTP detected → delegate to HTTPDetector.
//  3. Other traffic → bidirectional relay between client and upstream (raw TCP).
func NewPostHandshakeDispatch(cfg DispatchConfig) PostHandshakeFunc {
	return func(ctx context.Context, clientConn, upstreamConn net.Conn, target string) error {
		logger := proxy.LoggerFromContext(ctx, cfg.Logger)

		// Peek at the first bytes from the client to detect the inner protocol.
		peekConn := proxy.NewPeekConn(clientConn)
		peek, err := peekConn.Peek(2)
		if err != nil {
			// Client closed or errored before sending data; relay whatever
			// we got and let the upstream handle it.
			logger.Debug("socks5 post-handshake peek failed, falling back to relay",
				"target", target, "error", err)
			return relayConns(ctx, peekConn, upstreamConn)
		}

		// 1. TLS ClientHello → TLS MITM path.
		if isTLSClientHello(peek) {
			return handleTLSPath(ctx, peekConn, upstreamConn, target, cfg, logger)
		}

		// 2. Plaintext HTTP → delegate to HTTP handler.
		if cfg.HTTPDetector != nil {
			// Peek more bytes for HTTP method detection.
			httpPeek, peekErr := peekConn.Peek(8)
			if peekErr == nil && cfg.HTTPDetector.Detect(httpPeek) {
				return handleHTTPPath(ctx, peekConn, upstreamConn, target, cfg, logger)
			}
		}

		// 3. Other → raw TCP relay with flow recording + plugin hooks.
		logger.Info("socks5 raw TCP relay", "target", target)
		return relayRawTCP(ctx, peekConn, upstreamConn, target, cfg, logger)
	}
}

// handleTLSPath handles the TLS MITM path for SOCKS5 tunnels.
func handleTLSPath(ctx context.Context, clientConn net.Conn, upstreamConn net.Conn, target string, cfg DispatchConfig, logger *slog.Logger) error {
	hostname, _, err := parseHostPort(target)
	if err != nil {
		logger.Error("socks5 invalid target for TLS", "target", target, "error", err)
		return fmt.Errorf("socks5 TLS invalid target %q: %w", target, err)
	}

	// Check TLS passthrough before MITM.
	if cfg.TunnelHandler != nil && cfg.TunnelHandler.IsPassthrough(hostname) {
		logger.Info("socks5 TLS passthrough", "target", target)
		return relayConns(ctx, clientConn, upstreamConn)
	}

	if cfg.TunnelHandler == nil {
		logger.Warn("socks5 TLS detected but no tunnel handler configured", "target", target)
		return relayConns(ctx, clientConn, upstreamConn)
	}

	// Close the upstream connection — the HTTP handler's MITM path will
	// establish its own upstream connections per-request.
	upstreamConn.Close()

	logger.Info("socks5 TLS MITM", "target", target)
	return cfg.TunnelHandler.HandleTunnelMITM(ctx, clientConn, target)
}

// handleHTTPPath handles plaintext HTTP traffic through SOCKS5 tunnels.
// It injects the target host into the context and delegates to the HTTP handler.
func handleHTTPPath(ctx context.Context, clientConn net.Conn, upstreamConn net.Conn, target string, cfg DispatchConfig, logger *slog.Logger) error {
	// Close the pre-established upstream — the HTTP handler manages its own
	// upstream connections per-request.
	upstreamConn.Close()

	logger.Info("socks5 plaintext HTTP", "target", target)

	// Store the SOCKS5 target in context so the HTTP handler can reconstruct
	// absolute URLs for non-proxy-form requests (which lack a host in the
	// request line).
	ctx = withSOCKS5Target(ctx, target)
	return cfg.HTTPDetector.Handle(ctx, clientConn)
}

// relayRawTCP performs a bidirectional relay for non-TLS, non-HTTP traffic
// through a SOCKS5 tunnel. It creates a flow record, runs the relay with
// per-chunk recording and plugin hook dispatch, then updates the flow state.
func relayRawTCP(ctx context.Context, clientConn, upstreamConn net.Conn, target string, cfg DispatchConfig, logger *slog.Logger) error {
	// If no FlowWriter is configured, fall back to the simple relay.
	if cfg.FlowWriter == nil {
		return relayConns(ctx, clientConn, upstreamConn)
	}

	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Build SOCKS5 metadata tags from context.
	tags := make(map[string]string)
	if authMethod := proxy.SOCKS5AuthMethodFromContext(ctx); authMethod != "" {
		tags["socks5_auth_method"] = authMethod
	}
	if authUser := proxy.SOCKS5AuthUserFromContext(ctx); authUser != "" {
		tags["socks5_auth_user"] = authUser
	}
	if socks5Target := proxy.SOCKS5TargetFromContext(ctx); socks5Target != "" {
		tags["socks5_target"] = socks5Target
	}

	// Create flow record.
	start := time.Now()
	fl := &flow.Stream{
		ConnID:    connID,
		Protocol:  "SOCKS5+TCP",
		Scheme:    "tcp",
		State:     "active",
		Timestamp: start,
		Tags:      tags,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			ServerAddr: target,
		},
	}

	if err := cfg.FlowWriter.SaveStream(ctx, fl); err != nil {
		logger.Error("socks5 raw TCP flow save failed", "error", err)
		// Continue relaying even if recording fails.
	}

	// Build plugin ConnInfo.
	var pluginConnInfo *plugin.ConnInfo
	if fl.ConnInfo != nil {
		pluginConnInfo = &plugin.ConnInfo{
			ClientAddr: fl.ConnInfo.ClientAddr,
			ServerAddr: fl.ConnInfo.ServerAddr,
		}
	}

	// Run the recording relay.
	relayErr := prototcp.RunRelay(ctx, clientConn, upstreamConn, prototcp.RelayConfig{
		Store:        cfg.FlowWriter,
		StreamID:     fl.ID,
		Logger:       logger,
		PluginEngine: cfg.PluginEngine,
		ConnInfo:     pluginConnInfo,
		Target:       target,
	})

	// Update flow state.
	duration := time.Since(start)
	state := "complete"
	if relayErr != nil && ctx.Err() == nil {
		state = "error"
	}
	if err := cfg.FlowWriter.UpdateStream(ctx, fl.ID, flow.StreamUpdate{
		State:    state,
		Duration: duration,
	}); err != nil {
		logger.Error("socks5 raw TCP flow update failed", "error", err)
	}

	logger.Info("socks5 raw TCP relay closed", "target", target, "duration_ms", duration.Milliseconds())

	if relayErr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return relayErr
}

// relayConns performs a bidirectional data relay between two connections.
// Used for TLS passthrough and fallback paths where flow recording is not needed.
func relayConns(ctx context.Context, client, upstream net.Conn) error {
	return standaloneRelay(ctx, client, upstream)
}

// standaloneRelay copies data bidirectionally between two connections until
// one side closes, an error occurs, or the context is cancelled.
func standaloneRelay(ctx context.Context, a, b net.Conn) error {
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	go func() {
		<-relayCtx.Done()
		a.SetReadDeadline(time.Now())
		b.SetReadDeadline(time.Now())
	}()

	errCh := make(chan error, 2)

	go func() {
		err := copyConn(b, a)
		errCh <- err
		b.SetReadDeadline(time.Now())
	}()

	go func() {
		err := copyConn(a, b)
		errCh <- err
		a.SetReadDeadline(time.Now())
	}()

	err := <-errCh
	<-errCh

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// withSOCKS5Target stores the SOCKS5 target address in the context.
// This is a convenience wrapper around proxy.ContextWithSOCKS5Target.
func withSOCKS5Target(ctx context.Context, target string) context.Context {
	return proxy.ContextWithSOCKS5Target(ctx, target)
}

// SOCKS5TargetFromContext retrieves the SOCKS5 target address from the context.
// Returns empty string if not present.
func SOCKS5TargetFromContext(ctx context.Context) string {
	return proxy.SOCKS5TargetFromContext(ctx)
}
