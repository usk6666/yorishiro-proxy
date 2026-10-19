package connector

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1130: a path-scoped allow ({hostname: X, path_prefix: "/api/"}) at the
// connection-level gates. The gates never know a request path, so
// CheckTarget(..., "") never matches such a rule. Routes on which the
// Pipeline's HTTPScopeStep will see every request path admit the host
// provisionally (TargetScope.CheckHost); routes that never yield a path
// (TLS passthrough relay, raw_passthrough_hosts, tcp_forwards raw / grpc)
// stay strict.

func pathAllow(host, prefix string) []TargetRule {
	return []TargetRule{{Hostname: host, PathPrefix: prefix}}
}

func TestTargetScope_CheckHost(t *testing.T) {
	tests := []struct {
		name            string
		policyAllows    []TargetRule
		policyDenies    []TargetRule
		agentAllows     []TargetRule
		agentDenies     []TargetRule
		scheme          string
		host            string
		port            int
		wantAllowed     bool
		wantPathPending bool
		wantReason      string
	}{
		{
			name: "no rules: open",
			host: "a.test", port: 443, scheme: "https",
			wantAllowed: true,
		},
		{
			name:         "host-only policy allow: full admission",
			policyAllows: []TargetRule{{Hostname: "a.test"}},
			host:         "a.test", port: 443, scheme: "https",
			wantAllowed: true,
		},
		{
			name:         "path-only policy allow: conditional admission",
			policyAllows: pathAllow("a.test", "/api/"),
			host:         "a.test", port: 443, scheme: "https",
			wantAllowed:     true,
			wantPathPending: true,
		},
		{
			name:         "path_prefix \"/\" is still conditional (a path is required)",
			policyAllows: pathAllow("a.test", "/"),
			host:         "a.test", port: 80, scheme: "http",
			wantAllowed:     true,
			wantPathPending: true,
		},
		{
			name:         "path-scoped allow for another host does not admit",
			policyAllows: pathAllow("b.test", "/api/"),
			host:         "a.test", port: 443, scheme: "https",
			wantReason: "not in policy allow list",
		},
		{
			name:         "path-scoped allow still honours ports",
			policyAllows: []TargetRule{{Hostname: "a.test", Ports: []int{8443}, PathPrefix: "/api/"}},
			host:         "a.test", port: 443, scheme: "https",
			wantReason: "not in policy allow list",
		},
		{
			name:         "path-scoped allow still honours schemes",
			policyAllows: []TargetRule{{Hostname: "a.test", Schemes: []string{"http"}, PathPrefix: "/api/"}},
			host:         "a.test", port: 443, scheme: "https",
			wantReason: "not in policy allow list",
		},
		{
			name:         "mixed layer: a full match beats a conditional one",
			policyAllows: []TargetRule{{Hostname: "a.test", PathPrefix: "/api/"}, {Hostname: "a.test"}},
			host:         "a.test", port: 443, scheme: "https",
			wantAllowed: true,
		},
		{
			name:         "agent conditional under a policy full match is conditional",
			policyAllows: []TargetRule{{Hostname: "a.test"}},
			agentAllows:  pathAllow("a.test", "/api/"),
			host:         "a.test", port: 443, scheme: "https",
			wantAllowed:     true,
			wantPathPending: true,
		},
		{
			name:         "agent allow miss blocks with the agent reason",
			policyAllows: []TargetRule{{Hostname: "a.test", PathPrefix: "/api/"}, {Hostname: "other.test"}},
			agentAllows:  []TargetRule{{Hostname: "other.test"}},
			host:         "a.test", port: 443, scheme: "https",
			wantReason: "not in agent allow list",
		},
		{
			name:         "host deny beats a path-scoped allow",
			policyAllows: pathAllow("a.test", "/api/"),
			policyDenies: []TargetRule{{Hostname: "a.test"}},
			host:         "a.test", port: 443, scheme: "https",
			wantReason: "blocked by policy deny rule",
		},
		{
			name:        "agent host deny blocks",
			agentDenies: []TargetRule{{Hostname: "a.test"}},
			host:        "a.test", port: 443, scheme: "https",
			wantReason: "blocked by agent deny rule",
		},
		{
			// R3: a path-scoped deny does not close the connection; it is
			// enforced per request by HTTPScopeStep.
			name:         "path-scoped deny does not block a path-unknown check",
			policyDenies: []TargetRule{{Hostname: "a.test", PathPrefix: "/admin"}},
			host:         "a.test", port: 443, scheme: "https",
			wantAllowed: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tc.policyAllows, tc.policyDenies)
			if err := s.SetAgentRules(tc.agentAllows, tc.agentDenies); err != nil {
				t.Fatalf("SetAgentRules: %v", err)
			}
			allowed, pending, reason := s.CheckHost(tc.scheme, tc.host, tc.port)
			if allowed != tc.wantAllowed || pending != tc.wantPathPending || reason != tc.wantReason {
				t.Errorf("CheckHost(%q, %q, %d) = (%v, %v, %q), want (%v, %v, %q)",
					tc.scheme, tc.host, tc.port, allowed, pending, reason,
					tc.wantAllowed, tc.wantPathPending, tc.wantReason)
			}
		})
	}
}

// CheckTarget with an empty path keeps its strict verdict: a path-scoped
// allow never matches it (R2). Only the gate-level CheckHost is lenient.
func TestCheckTarget_PathScopedAllow_EmptyPathStaysStrict(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(pathAllow("a.test", "/api/"), nil)
	if allowed, reason := s.CheckTarget("https", "a.test", 443, ""); allowed || reason != "not in policy allow list" {
		t.Errorf("CheckTarget(path \"\") = (%v, %q), want (false, \"not in policy allow list\")", allowed, reason)
	}
	if allowed, _ := s.CheckTarget("https", "a.test", 443, "/api/x"); !allowed {
		t.Errorf("CheckTarget(path /api/x) = false, want true")
	}
}

// echoCountingListener is a TCP upstream that counts accepted connections and
// received bytes, echoing what it reads.
type echoCountingListener struct {
	ln       net.Listener
	accepts  atomic.Int64
	received atomic.Int64
}

func startCountingListener(t *testing.T) *echoCountingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &echoCountingListener{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						c.received.Add(int64(n))
						_, _ = conn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *echoCountingListener) addr() string { return c.ln.Addr().String() }

// writeCONNECT sends a CONNECT for target and returns the status line, or
// "" when the proxy closed the connection without answering.
func writeCONNECT(t *testing.T, client net.Conn, target string) string {
	t.Helper()
	if _, err := io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	var sb strings.Builder
	buf := make([]byte, 1)
	for !strings.HasSuffix(sb.String(), "\r\n\r\n") {
		if _, err := client.Read(buf); err != nil {
			break
		}
		sb.WriteByte(buf[0])
	}
	line, _, _ := strings.Cut(sb.String(), "\r\n")
	return line
}

// onStackProbe is an OnStackFunc that reports when a stack reached it.
func onStackProbe(reached chan<- struct{}) OnStackFunc {
	return func(_ context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer stack.Close()
		select {
		case reached <- struct{}{}:
		default:
		}
	}
}

func waitReached(t *testing.T, reached <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the connection never reached OnStack — refused at the gate", what)
	}
}

// T-gate (R8): a CONNECT whose inner route is MITM'd (here: bytechunk, the
// same gate path as TLS MITM / plaintext HTTP) is admitted by a
// path-scoped allow; the Pipeline is authoritative for the path.
func TestCONNECTHandler_PathScopedAllow_MITMRouteAdmitted(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	reached := make(chan struct{}, 1)

	client, _ := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:       NewCONNECTNegotiator(newTestLogger()),
		BuildCfg:         &BuildConfig{},
		Scope:            scope,
		InnerPeekTimeout: 2 * time.Second,
		OnStack:          onStackProbe(reached),
		Logger:           newTestLogger(),
	}))
	if line := writeCONNECT(t, client, up.addr()); !strings.Contains(line, "200") {
		t.Fatalf("CONNECT status = %q, want 200", line)
	}
	if _, err := client.Write([]byte{0x00, 0x01, 'r', 'a', 'w'}); err != nil {
		t.Fatalf("write inner bytes: %v", err)
	}
	waitReached(t, reached, "CONNECT under a path-scoped allow")
}

// T-gate (R8): the plain-HTTP forward gate admits a path-scoped allow.
func TestHTTP1ForwardHandler_PathScopedAllow_Admitted(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	reached := make(chan struct{}, 1)

	client, _ := serveOneConn(t, NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		BuildCfg: &BuildConfig{},
		Scope:    scope,
		OnStack:  onStackProbe(reached),
		Logger:   newTestLogger(),
	}))
	if _, err := io.WriteString(client, "GET http://"+up.addr()+"/api/x HTTP/1.1\r\nHost: "+up.addr()+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	waitReached(t, reached, "plain-HTTP forward under a path-scoped allow")
}

// T-gate (R8): a SOCKS5 tunnel that is not a passthrough target is admitted
// by a path-scoped allow (production wiring sets OpaqueRoute).
func TestSOCKS5Handler_PathScopedAllow_NonPassthroughAdmitted(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	pl := NewPassthroughList()
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Scope = scope
	neg.OpaqueRoute = func(target string) bool { return TunnelRouteOpaque(pl, nil, target) }
	reached := make(chan struct{}, 1)

	client, _ := serveOneConn(t, NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:       neg,
		BuildCfg:         &BuildConfig{},
		PassthroughList:  pl,
		InnerPeekTimeout: 2 * time.Second,
		OnStack:          onStackProbe(reached),
		Logger:           newTestLogger(),
	}))
	socks5Through(t, client, up.addr())
	if _, err := client.Write([]byte{0x00, 0x01, 'r', 'a', 'w'}); err != nil {
		t.Fatalf("write inner bytes: %v", err)
	}
	waitReached(t, reached, "SOCKS5 under a path-scoped allow")
}

// T4 (R7): a CONNECT to a TLS passthrough target never yields a path, so a
// path-scoped allow does not admit it: the relay never dials the target.
func TestCONNECTHandler_PathScopedAllow_PassthroughRefused(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")

	client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:      NewCONNECTNegotiator(newTestLogger()),
		Scope:           scope,
		PassthroughList: pl,
		Logger:          newTestLogger(),
	}))
	_ = writeCONNECT(t, client, up.addr())
	_, _ = client.Write([]byte("\x16\x03\x01 not really a ClientHello"))
	assertClosedWithin(t, client, 5*time.Second)
	<-done
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("passthrough target accepted %d connections under a path-scoped allow, want 0", n)
	}
}

// T4 (R7), SOCKS5: the negotiator refuses with REP=0x02 when OpaqueRoute
// classifies the target as passthrough, and the relay never dials.
func TestSOCKS5Handler_PathScopedAllow_PassthroughRefused(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Scope = scope
	neg.OpaqueRoute = func(target string) bool { return TunnelRouteOpaque(pl, nil, target) }

	client, done := serveOneConn(t, NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:      neg,
		PassthroughList: pl,
		Logger:          newTestLogger(),
	}))
	rep := socks5Request(t, client, up.addr())
	if rep != socks5ReplyConnectionNotAllowed {
		t.Errorf("SOCKS5 REP = 0x%02x, want 0x%02x (connection not allowed)", rep, socks5ReplyConnectionNotAllowed)
	}
	<-done
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("passthrough target accepted %d connections under a path-scoped allow, want 0", n)
	}
}

// T4 backstop: a negotiator without OpaqueRoute (it is a singleton other
// callers may build bare) admits provisionally, and the handler — which
// knows the route — still refuses the passthrough relay.
func TestSOCKS5Handler_PathScopedAllow_PassthroughRefusedWithoutOpaqueRoute(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Scope = scope

	client, done := serveOneConn(t, NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:      neg,
		PassthroughList: pl,
		Logger:          newTestLogger(),
	}))
	_ = socks5Request(t, client, up.addr())
	_, _ = client.Write([]byte("\x16\x03\x01 not really a ClientHello"))
	assertClosedWithin(t, client, 5*time.Second)
	<-done
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("passthrough target accepted %d connections under a path-scoped allow, want 0", n)
	}
}

// socks5Request runs a NO_AUTH SOCKS5 CONNECT for target and returns REP.
func socks5Request(t *testing.T, client net.Conn, target string) byte {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host).To4()
	var port int
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	sel := make([]byte, 2)
	if _, err := io.ReadFull(client, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(client, rep); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return rep[1]
}

// T9 (R5/R7): narrowing a policy from {X} to {X, /api/} keeps a MITM'd
// tunnel (the Pipeline still checks each request path) and closes a TLS
// passthrough relay (which would carry X traffic with no path check) — the
// live-connection predicate encodes the same strict / provisional choice
// as admission.
func TestLiveConns_PathScopedReload_MITMKeptPassthroughCut(t *testing.T) {
	t.Run("MITM tunnel kept", func(t *testing.T) {
		up := startCountingListener(t)
		scope := NewTargetScope()
		scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
		reg := NewLiveConns(newTestLogger())
		causeCh := make(chan error, 1)
		started := make(chan struct{})
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		client, _ := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
			Negotiator:       NewCONNECTNegotiator(newTestLogger()),
			BuildCfg:         &BuildConfig{},
			Scope:            scope,
			LiveConns:        reg,
			InnerPeekTimeout: 2 * time.Second,
			OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
				defer stack.Close()
				close(started)
				select {
				case <-ctx.Done():
					causeCh <- context.Cause(ctx)
				case <-release:
				}
			},
			Logger: newTestLogger(),
		}))
		connectThrough(t, client, up.addr())
		if _, err := client.Write([]byte{0x00, 0x01, 'r', 'a', 'w'}); err != nil {
			t.Fatalf("write raw bytes: %v", err)
		}
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("tunnel never reached OnStack")
		}

		scope.ReplacePolicyRules(pathAllow("127.0.0.1", "/api/"), nil, PolicyOrigin{Source: "test"})
		if n := reg.Reconcile("test"); n != 0 {
			t.Errorf("Reconcile closed %d MITM tunnels after narrowing to a path-scoped allow, want 0", n)
		}
		select {
		case cause := <-causeCh:
			t.Errorf("MITM tunnel ctx cancelled (%v), want it kept open", cause)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("passthrough relay cut", func(t *testing.T) {
		up := startCountingListener(t)
		scope := NewTargetScope()
		scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
		reg := NewLiveConns(newTestLogger())
		pl := NewPassthroughList()
		pl.Add("127.0.0.1")

		client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
			Negotiator:      NewCONNECTNegotiator(newTestLogger()),
			Scope:           scope,
			LiveConns:       reg,
			PassthroughList: pl,
			Logger:          newTestLogger(),
		}))
		connectThrough(t, client, up.addr())
		roundTrip(t, client, "before")

		scope.ReplacePolicyRules(pathAllow("127.0.0.1", "/api/"), nil, PolicyOrigin{Source: "test"})
		if n := reg.Reconcile("test"); n != 1 {
			t.Errorf("Reconcile closed %d passthrough relays, want 1", n)
		}
		assertClosedWithin(t, client, 5*time.Second)
		<-done
		if got := reg.Len(); got != 0 {
			t.Errorf("registry Len after cut = %d, want 0", got)
		}
	})
}
