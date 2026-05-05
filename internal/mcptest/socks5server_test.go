//go:build e2e

package mcptest_test

import (
	"net"
	"sync/atomic"
	"testing"
)

// placeholderSOCKS5Listener wraps a plain loopback TCP listener used by
// USK-725's SOCKS5 wiring tests as a stand-in for a real SOCKS5 server.
// It performs no RFC 1928 / RFC 1929 handshake, accepts no
// authentication, and never reads bytes off the accepted sockets — its
// sole purpose is to expose a reachable Addr() so the URL the test hands
// to proxy_start is syntactically valid and points at a real loopback
// port. The full SOCKS5 fixture lives behind USK-734 (the live-transit
// follow-up); when that lands the placeholder is replaced with a
// handshake-capable server and any auth-credential plumbing is
// reintroduced at the same time.
type placeholderSOCKS5Listener struct {
	listener net.Listener
	closed   atomic.Bool
}

// startPlaceholderSOCKS5Listener returns the address of a TCP listener
// used as a placeholder until USK-734 lands the live transit assertion.
// It registers a t.Cleanup hook to close the listener. The placeholder
// intentionally takes no auth parameters; SOCKS5 user/pass plumbing
// returns when USK-734 grows the fixture into a real handshake-capable
// server.
func startPlaceholderSOCKS5Listener(t *testing.T) *placeholderSOCKS5Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5 placeholder: %v", err)
	}

	s := &placeholderSOCKS5Listener{listener: ln}
	t.Cleanup(s.Close)
	return s
}

// Addr returns the host:port the listener is bound to.
func (s *placeholderSOCKS5Listener) Addr() string {
	return s.listener.Addr().String()
}

// Close stops the listener. Idempotent.
func (s *placeholderSOCKS5Listener) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	_ = s.listener.Close()
}
