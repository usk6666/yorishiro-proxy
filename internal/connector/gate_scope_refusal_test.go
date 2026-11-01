package connector

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// USK-1403: a scope refusal on the CONNECT, plain-HTTP forward and SOCKS5
// gates — at the gate, in the admission race (Register's re-check) and,
// for SOCKS5, in the handler's opaque-route re-check — fires OnGateRefusal
// once with BlockedBy target_scope, after the refusal bytes the client saw
// before (which stay unchanged).

// raceReasonPrefix marks a refusal decided by LiveConns.Register's re-check
// rather than by the gate itself.
const raceReasonPrefix = "policy changed during admission: "

// assertScopeRefusal requires exactly one target_scope refusal call for
// via / target / host whose reason tag is reason.
func assertScopeRefusal(t *testing.T, calls []GateRefusal, via, target, host, reason string) {
	t.Helper()
	if len(calls) != 1 {
		t.Fatalf("OnGateRefusal called %d times, want 1: %+v", len(calls), calls)
	}
	r := calls[0]
	if r.Via != via || r.Target != target || r.Host != host || r.BlockedBy != GateRefusalBlockedByTargetScope {
		t.Errorf("refusal = %+v, want via %q target %q host %q blocked_by target_scope", r, via, target, host)
	}
	if r.ClientAddr == "" {
		t.Error("refusal ClientAddr is empty")
	}
	want := map[string]string{"via": via, "target": target, "reason": reason}
	for k, v := range want {
		if r.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, r.Tags[k], v, r.Tags)
		}
	}
	for k := range r.Tags {
		if strings.HasPrefix(k, "rate_limit_") {
			t.Errorf("scope refusal carries rate-limit tag %s (tags %v)", k, r.Tags)
		}
	}
}

// serveOneConnCtx is serveOneConn with a caller-built handler context.
func serveOneConnCtx(t *testing.T, handler HandlerFunc, mkCtx func() context.Context) (net.Conn, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = handler(mkCtx(), NewPeekConn(c))
	}()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

// raceCtx returns a context builder whose scope flips to a deny of host
// in the admission window (see flipOnConnIDCtx), and a flag reporting
// that the flip ran.
func raceCtx(scope *TargetScope, host string) (func() context.Context, *atomic.Bool) {
	var flipped atomic.Bool
	return func() context.Context {
		return &flipOnConnIDCtx{
			Context: ContextWithConnID(context.Background(), "race-conn"),
			flip: func() {
				denyHost(scope, host)
				flipped.Store(true)
			},
		}
	}, &flipped
}

// TestCONNECTHandler_ScopeRefusal_AdmissionRaceFiresTargetScope is T4: a
// CONNECT the gate admitted but Register's re-check refused is answered
// with the unchanged 403 and fires one target_scope refusal whose reason
// marks the race.
func TestCONNECTHandler_ScopeRefusal_AdmissionRaceFiresTargetScope(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
	var capt gateRefusalCapture
	mk, flipped := raceCtx(scope, "127.0.0.1")
	client, done := serveOneConnCtx(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:    NewCONNECTNegotiator(newTestLogger()),
		Scope:         scope,
		LiveConns:     NewLiveConns(newTestLogger()),
		Logger:        newTestLogger(),
		OnGateRefusal: capt.fn,
	}), mk)

	target := up.addr()
	if _, err := io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(client)
	waitHandlerDone(t, done)
	if !flipped.Load() {
		t.Fatal("scope flip never ran; fix the test seam")
	}
	assertCONNECTReject(t, string(got), 403, "Forbidden", connectScopeDenyDetail)
	assertScopeRefusal(t, capt.calls(), "connect", target, "127.0.0.1", raceReasonPrefix+"blocked by policy deny rule")
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}
}

// TestHTTP1ForwardHandler_ScopeRefusal_AdmissionRaceFiresTargetScope is T3.
func TestHTTP1ForwardHandler_ScopeRefusal_AdmissionRaceFiresTargetScope(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
	var capt gateRefusalCapture
	mk, flipped := raceCtx(scope, "127.0.0.1")
	client, done := serveOneConnCtx(t, NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		BuildCfg:      &BuildConfig{},
		Scope:         scope,
		LiveConns:     NewLiveConns(newTestLogger()),
		Logger:        newTestLogger(),
		OnGateRefusal: capt.fn,
	}), mk)

	target := up.addr()
	if _, err := io.WriteString(client, "GET http://"+target+"/x HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(client)
	waitHandlerDone(t, done)
	if !flipped.Load() {
		t.Fatal("scope flip never ran; fix the test seam")
	}
	if want := string(forwardErrorResponse(403, "Forbidden", "yorishiro-proxy: target blocked by scope")); string(got) != want {
		t.Errorf("client read %q, want %q", got, want)
	}
	assertScopeRefusal(t, capt.calls(), "http1-forward", target, "127.0.0.1", raceReasonPrefix+"blocked by policy deny rule")
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}
}

// TestSOCKS5Negotiator_ScopeErrorCarriesReason is T5: the negotiator's
// scope refusal returns a *SOCKS5ScopeError carrying the scope reason,
// still errors.Is ErrSOCKS5BlockedByScope, after the unchanged REP=0x02.
func TestSOCKS5Negotiator_ScopeErrorCarriesReason(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "example.com"}})
	neg.Scope = scope
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()
	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildConnectDomain("example.com", 443))
	}()
	_ = rig.readClient(2)
	if reply := rig.readClient(10); reply[1] != socks5ReplyConnectionNotAllowed {
		t.Errorf("reply REP = 0x%02x, want 0x02", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5BlockedByScope) {
		t.Errorf("errors.Is(err, ErrSOCKS5BlockedByScope) = false for %v", rig.retErr)
	}
	var scErr *SOCKS5ScopeError
	if !errors.As(rig.retErr, &scErr) || scErr.Reason != "blocked by policy deny rule" {
		t.Errorf("errors.As(err, *SOCKS5ScopeError) = %+v (err %v), want reason %q", scErr, rig.retErr, "blocked by policy deny rule")
	}
	if rig.retTarget != "example.com:443" {
		t.Errorf("returned target = %q, want example.com:443", rig.retTarget)
	}
}

// readSOCKS5ReplyThenEOF reads the 10-byte SOCKS5 reply and requires the
// proxy to close the connection with no further byte.
func readSOCKS5ReplyThenEOF(t *testing.T, client net.Conn, target string) {
	t.Helper()
	if rep := socks5Request(t, client, target); rep != socks5ReplySuccess {
		t.Errorf("SOCKS5 REP = 0x%02x, want 0x00", rep)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, err := io.ReadAll(client)
	if len(rest) != 0 {
		t.Errorf("read %q after the reply, want EOF", rest)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Error("connection still open after the refusal")
	}
}

// TestSOCKS5Handler_ScopeRefusal_OpaqueRecheckFiresTargetScope is T7: a
// negotiator without OpaqueRoute admits a passthrough target under a
// path-scoped allow; the handler's strict re-check refuses it. The client
// still sees REP=0x00 then EOF, and one target_scope refusal is fired with
// ReasonPathRequired.
func TestSOCKS5Handler_ScopeRefusal_OpaqueRecheckFiresTargetScope(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(pathAllow("127.0.0.1", "/api/"), nil)
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Scope = scope
	var capt gateRefusalCapture

	client, done := serveOneConn(t, NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:      neg,
		PassthroughList: pl,
		Logger:          newTestLogger(),
		OnGateRefusal:   capt.fn,
	}))
	target := up.addr()
	readSOCKS5ReplyThenEOF(t, client, target)
	waitHandlerDone(t, done)
	assertScopeRefusal(t, capt.calls(), "socks5", target, "127.0.0.1", ReasonPathRequired)
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}
}

// TestSOCKS5Handler_ScopeRefusal_AdmissionRaceFiresTargetScope is T8.
func TestSOCKS5Handler_ScopeRefusal_AdmissionRaceFiresTargetScope(t *testing.T) {
	up := startCountingListener(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Scope = scope
	var capt gateRefusalCapture
	mk, flipped := raceCtx(scope, "127.0.0.1")

	client, done := serveOneConnCtx(t, NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:    neg,
		LiveConns:     NewLiveConns(newTestLogger()),
		Logger:        newTestLogger(),
		OnGateRefusal: capt.fn,
	}), mk)
	target := up.addr()
	readSOCKS5ReplyThenEOF(t, client, target)
	waitHandlerDone(t, done)
	if !flipped.Load() {
		t.Fatal("scope flip never ran; fix the test seam")
	}
	assertScopeRefusal(t, capt.calls(), "socks5", target, "127.0.0.1", raceReasonPrefix+"blocked by policy deny rule")
	if n := up.accepts.Load(); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}
}

func TestReportScopeRefusal_NilCallback(t *testing.T) {
	reportScopeRefusal(context.Background(), nil, "connect", "a.example:443", nil, "r")
	var capt gateRefusalCapture
	// A target without a port keys on the literal target; the remote
	// address is the ClientAddr fallback.
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 1234}
	reportScopeRefusal(context.Background(), capt.fn, "socks5", "noport", remote, "why")
	calls := capt.calls()
	if len(calls) != 1 || calls[0].Host != "noport" || calls[0].ClientAddr != "192.0.2.9:1234" || calls[0].Tags["reason"] != "why" || calls[0].BlockedBy != GateRefusalBlockedByTargetScope {
		t.Errorf("calls = %+v, want one target_scope call with Host noport, ClientAddr 192.0.2.9:1234, reason why", calls)
	}
}
