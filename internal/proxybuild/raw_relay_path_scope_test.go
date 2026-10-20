package proxybuild

import (
	"context"
	"errors"
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

// S-1, gate leg: the admitting gate's strict check (LiveConn.AdmitOpaque,
// with the gate's own scheme) refuses the relay even where HostScopeStep —
// which reads the client leg's scheme — would admit it, and the refusal is
// handed to OnPipelineDrop as a payload-free target_scope audit envelope.
func TestRunRawRelaySession_GateStrictCheckRefuses(t *testing.T) {
	stack, clientPeer, upstreamPeer := newRawRelayTestStack(t, "127.0.0.1:2525")
	go streamBanner(upstreamPeer)

	reg := connector.NewLiveConns(nil)
	ctx, release, err := reg.Register(context.Background(), connector.LiveConn{
		Via:         "tcp-forward",
		Target:      "127.0.0.1:2525",
		Admit:       func() (bool, string) { return true, "" },
		AdmitOpaque: func() (bool, string) { return false, connector.ReasonPathRequired },
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer release()

	type drop struct {
		env       *envelope.Envelope
		blockedBy string
	}
	drops := make(chan drop, 4)
	opts := session.SessionOptions{OnPipelineDrop: func(_ context.Context, env *envelope.Envelope, blockedBy string) {
		drops <- drop{env, blockedBy}
	}}

	done := make(chan error, 1)
	go func() { done <- runRawRelaySession(ctx, stack, pipeline.New(), opts) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runRawRelaySession = %v, want nil on a refusal", err)
		}
	case <-time.After(5 * time.Second):
		_ = stack.Close()
		t.Fatal("runRawRelaySession relayed instead of refusing")
	}
	if got := readUpstreamBytes(clientPeer, 200*time.Millisecond); got != 0 {
		t.Errorf("client received %d upstream bytes, want 0", got)
	}
	select {
	case d := <-drops:
		if d.blockedBy != pipeline.BlockedByTargetScope || d.env.Protocol != envelope.ProtocolRaw ||
			d.env.Context.TargetHost != "127.0.0.1:2525" {
			t.Errorf("audit drop = (%q, protocol %q, target %q), want (target_scope, raw, 127.0.0.1:2525)",
				d.blockedBy, d.env.Protocol, d.env.Context.TargetHost)
		}
		if m, _ := d.env.Message.(*envelope.RawMessage); m == nil || len(m.Bytes) != 0 || len(d.env.Raw) != 0 {
			t.Errorf("audit envelope carries payload: %+v", d.env)
		}
	default:
		t.Error("refusal was not handed to OnPipelineDrop")
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

// USK-1283: a raw relay that started under a host-only allow must be cut by
// the live-connection registry when the scope is narrowed to a path-scoped
// allow only — an identical new relay would be refused (refuseRawRelay), so
// the live one must not survive. Before the fix Reconcile kept re-running
// the gate's provisional check, which a path-scoped allow passes, and a
// server-first upstream kept relaying to the client.
func TestRunRawRelaySession_NarrowedToPathOnlyCutByReconcile(t *testing.T) {
	const target = "127.0.0.1:2525"
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	stack, clientPeer, upstreamPeer := newRawRelayTestStack(t, target)

	// The tcp_forwards gate's predicates (tcp_forward_scope.go): the auto
	// arm is admitted provisionally, the raw fallback strictly.
	reg := connector.NewLiveConns(nil)
	ctx, release, err := reg.Register(context.Background(), connector.LiveConn{
		Via: "tcp-forward", Target: target,
		Admit: func() (bool, string) {
			allowed, _, reason := scope.CheckHost("", "127.0.0.1", 2525)
			return allowed, reason
		},
		AdmitOpaque: func() (bool, string) { return scope.CheckOpaqueTarget("", "127.0.0.1", 2525) },
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer release()

	// Server-first upstream that keeps writing until the leg closes.
	chunk := []byte("220 stream chunk\r\n")
	go func() {
		for {
			if _, err := upstreamPeer.Write(chunk); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Mirror the production callers (buildOnStack, tcp_forward.go): a
	// watcher closes the stack when the Register ctx is cancelled, which
	// is how a revocation reaches both legs.
	stopWatch := context.AfterFunc(ctx, func() { _ = stack.Close() })
	defer stopWatch()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runRawRelaySession(ctx, stack, pipeline.New(pipeline.NewHostScopeStep(scope)), session.SessionOptions{})
	}()
	defer func() {
		_ = stack.Close()
		<-done
	}()

	// The relay runs under the host-only allow.
	_ = clientPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	if n, err := clientPeer.Read(buf); err != nil || n == 0 {
		t.Fatalf("client read before narrowing = %d, %v; want upstream bytes", n, err)
	}

	scope.ReplacePolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/api/"}}, nil,
		connector.PolicyOrigin{Source: "test"})
	if got := reg.Reconcile("test"); got != 1 {
		t.Errorf("Reconcile after narrowing to a path-only allow = %d revoked, want 1", got)
	}

	// At most the chunk already in flight on the synchronous pipe may
	// arrive; then the client leg must close.
	_ = clientPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	after := 0
	for {
		n, err := clientPeer.Read(buf)
		after += n
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Errorf("client leg still open 2s after Reconcile (%d upstream bytes relayed after narrowing)", after)
			}
			break
		}
	}
	if after > len(chunk) {
		t.Errorf("client received %d upstream bytes after narrowing, want at most the %d-byte chunk in flight", after, len(chunk))
	}
}
