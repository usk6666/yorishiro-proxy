package proxybuild

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// newRawRelayTestStack builds a pre-dialed [bytechunk → bytechunk] stack
// over two net.Pipes stamped with target, the shape every raw relay entry
// point hands runSingleChannelSession: tcp_forwards raw and the auto → Raw
// fallback, CONNECT / SOCKS5 inner bytechunk, and TLS MITM with an ALPN
// that is neither h2 nor http/1.1.
func newRawRelayTestStack(t *testing.T, target string) (stack *connector.ConnectionStack, clientPeer, upstreamPeer net.Conn) {
	t.Helper()
	clientPeer, clientConn := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	t.Cleanup(func() {
		_ = clientPeer.Close()
		_ = upstreamPeer.Close()
	})
	const connID = "c1"
	stack = connector.NewConnectionStack(connID)
	stack.PushClient(bytechunk.New(clientConn, connID+"/client", envelope.Send,
		bytechunk.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: connID, TargetHost: target}),
	))
	stack.PushUpstream(bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive,
		bytechunk.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: connID, TargetHost: target}),
	))
	t.Cleanup(func() { _ = stack.Close() })
	return stack, clientPeer, upstreamPeer
}

// readUpstreamBytes counts what clientPeer receives until it is closed or
// d elapses.
func readUpstreamBytes(clientPeer net.Conn, d time.Duration) int {
	_ = clientPeer.SetReadDeadline(time.Now().Add(d))
	total := 0
	buf := make([]byte, 4096)
	for {
		n, err := clientPeer.Read(buf)
		total += n
		if err != nil {
			return total
		}
	}
}

// runRawRelayAsync runs runSingleChannelSession in the background and
// returns a stop function that tears the session down and waits for it.
func runRawRelayAsync(t *testing.T, ctx context.Context, stack *connector.ConnectionStack, p *pipeline.Pipeline) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runSingleChannelSession(ctx, stack, nil, p, session.SessionOptions{})
	}()
	return func() {
		cancel()
		_ = stack.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runSingleChannelSession did not return")
		}
	}
}

// pathOnlyScope allows 127.0.0.1 only under path_prefix "/api/".
func pathOnlyScope() *connector.TargetScope {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/api/"}}, nil)
	return scope
}

// streamBanner writes a server-first stream on upstreamPeer.
func streamBanner(upstreamPeer net.Conn) {
	for i := 0; i < 20; i++ {
		if _, err := upstreamPeer.Write([]byte("220 banner chunk\r\n")); err != nil {
			return
		}
	}
}

// USK-1130 review S-1: a raw relay to a host that only a path-scoped allow
// admits must relay no upstream byte. The connection gates admit such a
// host provisionally on routes that may still turn out to carry HTTP
// (tcp_forwards auto, CONNECT / SOCKS5 inner peek, TLS MITM); once the
// route resolves to a raw relay no request path will ever be checked, so
// the relay must be refused before it starts. HostScopeStep only sees
// Send envelopes, so with a silent client and a server-first upstream the
// per-envelope check never fires on its own.
func TestRunSingleChannelSession_PathScopedAllowRawRelayRefused(t *testing.T) {
	stack, clientPeer, upstreamPeer := newRawRelayTestStack(t, "127.0.0.1:2525")
	go streamBanner(upstreamPeer) // server speaks first; the client never writes

	stop := runRawRelayAsync(t, context.Background(), stack, pipeline.New(pipeline.NewHostScopeStep(pathOnlyScope())))
	defer stop()

	if got := readUpstreamBytes(clientPeer, 2*time.Second); got != 0 {
		t.Errorf("client received %d upstream bytes over a raw relay admitted only by a path-scoped allow, want 0", got)
	}
}

// Control: an unconditional allow keeps the server-first raw relay working
// (USK-1216) — the refusal is specific to path-scoped allows.
func TestRunSingleChannelSession_UnconditionalAllowRawRelayRelays(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	stack, clientPeer, upstreamPeer := newRawRelayTestStack(t, "127.0.0.1:2525")
	banner := []byte("220 ready\r\n")
	go func() { _, _ = upstreamPeer.Write(banner) }()

	stop := runRawRelayAsync(t, context.Background(), stack, pipeline.New(pipeline.NewHostScopeStep(scope)))
	defer stop()

	_ = clientPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(banner))
	n, err := clientPeer.Read(got)
	if err != nil || string(got[:n]) != string(banner) {
		t.Errorf("client read %q, %v; want the banner %q", got[:n], err, banner)
	}
}
