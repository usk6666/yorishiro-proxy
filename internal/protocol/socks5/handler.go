// Package socks5 implements a SOCKS5 protocol handler (RFC 1928) for the proxy.
// It supports NO AUTH and USERNAME/PASSWORD (RFC 1929) authentication methods,
// and the CONNECT command for establishing TCP tunnels through the proxy.
package socks5

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

const (
	// socks5Version is the SOCKS protocol version byte.
	socks5Version = 0x05

	// dialTimeout is the default timeout for connecting to the upstream target.
	dialTimeout = 30 * time.Second

	// relayBufSize is the buffer size for bidirectional data relay.
	relayBufSize = 32 * 1024
)

// Authenticator validates username/password credentials for SOCKS5 authentication.
type Authenticator interface {
	// Authenticate returns true if the given credentials are valid.
	Authenticate(username, password string) bool
}

// PostHandshakeFunc is called after a successful SOCKS5 handshake with the
// established upstream connection and the target address. It allows the caller
// to take over the relay or inject additional protocol handling (e.g., TLS MITM).
// If nil, the handler performs a simple bidirectional TCP relay.
type PostHandshakeFunc func(ctx context.Context, clientConn, upstreamConn net.Conn, target string) error

// Handler implements proxy.ProtocolHandler for SOCKS5 connections.
type Handler struct {
	logger        *slog.Logger
	auth          Authenticator
	targetScope   *proxy.TargetScope
	postHandshake PostHandshakeFunc
	dialer        func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewHandler creates a new SOCKS5 handler.
func NewHandler(logger *slog.Logger) *Handler {
	return &Handler{
		logger: logger,
	}
}

// SetAuthenticator sets the authenticator for USERNAME/PASSWORD authentication.
// If nil, only NO AUTH is offered to clients.
func (h *Handler) SetAuthenticator(auth Authenticator) {
	h.auth = auth
}

// SetTargetScope sets the target scope used to enforce which destinations are
// allowed. When set, CONNECT requests to targets outside the scope receive a
// SOCKS5 error reply (connection not allowed by ruleset).
func (h *Handler) SetTargetScope(scope *proxy.TargetScope) {
	h.targetScope = scope
}

// SetPostHandshake sets the post-handshake function called after successful
// SOCKS5 CONNECT. This allows the caller to inject protocol-specific handling
// (e.g., TLS MITM, protocol detection) on the tunneled connection.
func (h *Handler) SetPostHandshake(fn PostHandshakeFunc) {
	h.postHandshake = fn
}

// SetDialer sets a custom dialer for upstream connections.
// If nil, net.Dialer with dialTimeout is used.
func (h *Handler) SetDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	h.dialer = dialer
}

// Name returns the protocol name.
func (h *Handler) Name() string {
	return "SOCKS5"
}

// Detect checks if the peeked bytes indicate a SOCKS5 handshake.
// The first byte of a SOCKS5 client greeting is always 0x05 (version).
func (h *Handler) Detect(peek []byte) bool {
	if len(peek) < 1 {
		return false
	}
	return peek[0] == socks5Version
}

// Handle processes a SOCKS5 connection: handshake, authentication, CONNECT,
// then bidirectional relay (or delegation to PostHandshakeFunc).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	logger := proxy.LoggerFromContext(ctx, h.logger)

	// 1. Method negotiation.
	method, err := h.negotiateMethod(conn)
	if err != nil {
		return fmt.Errorf("socks5 method negotiation: %w", err)
	}

	// 2. Authentication (if required).
	if method == methodUsernamePassword {
		if err := h.authenticateUserPass(conn); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
	}

	// 3. Read request.
	target, err := h.handleRequest(conn)
	if err != nil {
		return fmt.Errorf("socks5 request: %w", err)
	}

	// 4. Target scope check.
	if blocked, reason := h.checkTargetScope(target); blocked {
		logger.Info("socks5 target blocked by scope", "target", target, "reason", reason)
		_ = writeReply(conn, replyConnectionNotAllowed, nil)
		return nil
	}

	// 5. Dial upstream.
	upstream, err := h.dialUpstream(ctx, target)
	if err != nil {
		logger.Error("socks5 dial upstream failed", "target", target, "error", err)
		_ = writeReply(conn, replyHostUnreachable, nil)
		return fmt.Errorf("socks5 dial %s: %w", target, err)
	}
	defer upstream.Close()

	// 6. Send success reply with bound address.
	if err := writeReply(conn, replySuccess, upstream.LocalAddr()); err != nil {
		return fmt.Errorf("socks5 write success reply: %w", err)
	}

	logger.Info("socks5 tunnel established", "target", target)

	// 7. Post-handshake delegation or direct relay.
	if h.postHandshake != nil {
		return h.postHandshake(ctx, conn, upstream, target)
	}

	return h.relay(ctx, conn, upstream)
}

// dialUpstream connects to the target address.
func (h *Handler) dialUpstream(ctx context.Context, target string) (net.Conn, error) {
	if h.dialer != nil {
		return h.dialer(ctx, "tcp", target)
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", target)
}

// checkTargetScope checks if the target host:port is allowed.
func (h *Handler) checkTargetScope(target string) (blocked bool, reason string) {
	if h.targetScope == nil || !h.targetScope.HasRules() {
		return false, ""
	}
	host, port, err := parseHostPort(target)
	if err != nil {
		return true, "invalid target address"
	}
	allowed, reason := h.targetScope.CheckTarget("", host, port, "")
	if !allowed {
		return true, reason
	}
	return false, ""
}

// relay performs a bidirectional data relay between client and upstream.
func (h *Handler) relay(ctx context.Context, client, upstream net.Conn) error {
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	// Watch for context cancellation and interrupt blocking reads.
	go func() {
		<-relayCtx.Done()
		client.SetReadDeadline(time.Now())
		upstream.SetReadDeadline(time.Now())
	}()

	var (
		once     sync.Once
		firstErr error
	)

	errCh := make(chan error, 2)

	// client -> upstream
	go func() {
		err := copyConn(upstream, client)
		once.Do(func() { firstErr = err })
		errCh <- err
		upstream.SetReadDeadline(time.Now())
	}()

	// upstream -> client
	go func() {
		err := copyConn(client, upstream)
		once.Do(func() { firstErr = err })
		errCh <- err
		client.SetReadDeadline(time.Now())
	}()

	<-errCh
	<-errCh

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return firstErr
}

// copyConn copies data from src to dst until EOF or error.
func copyConn(dst, src net.Conn) error {
	buf := make([]byte, relayBufSize)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}
