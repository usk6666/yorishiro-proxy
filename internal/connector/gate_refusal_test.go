package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// gateRefusalCapture records every OnGateRefusal call.
type gateRefusalCapture struct {
	mu   sync.Mutex
	got  []GateRefusal
	ctxs []context.Context
}

func (c *gateRefusalCapture) fn(ctx context.Context, r GateRefusal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, r)
	c.ctxs = append(c.ctxs, ctx)
}

func (c *gateRefusalCapture) calls() []GateRefusal {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]GateRefusal(nil), c.got...)
}

// spentLimiter returns a burst-1 global limiter whose token is spent.
func spentLimiter() *RateLimiter {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerSecond: 0.001})
	_ = rl.Check("spend.example")
	return rl
}

// assertRateLimitRefusal requires exactly one rate_limit refusal call for
// via / target.
func assertRateLimitRefusal(t *testing.T, calls []GateRefusal, via, target, host string) {
	t.Helper()
	if len(calls) != 1 {
		t.Fatalf("OnGateRefusal called %d times, want 1: %+v", len(calls), calls)
	}
	r := calls[0]
	if r.Via != via || r.Target != target || r.Host != host || r.BlockedBy != GateRefusalBlockedByRateLimit {
		t.Errorf("refusal = %+v, want via %q target %q host %q blocked_by rate_limit", r, via, target, host)
	}
	if r.ClientAddr == "" {
		t.Error("refusal ClientAddr is empty")
	}
	want := map[string]string{
		"via":                      via,
		"target":                   target,
		"reason":                   "global limit 0.001 rps",
		"rate_limit_type":          "global",
		"rate_limit_effective_rps": "0.001",
	}
	for k, v := range want {
		if r.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, r.Tags[k], v, r.Tags)
		}
	}
}

func TestNewCONNECTHandler_OnGateRefusal(t *testing.T) {
	t.Run("rate limit refusal fires once after the 429", func(t *testing.T) {
		var capt gateRefusalCapture
		handler := NewCONNECTHandler(CONNECTHandlerConfig{
			Negotiator:       NewCONNECTNegotiator(nil),
			RateLimiter:      spentLimiter(),
			InnerPeekTimeout: connectDenialInnerPeek,
			Logger:           discardLogger(),
			OnGateRefusal:    capt.fn,
		})
		got := runDeniedCONNECT(t, handler, "limited.example:443")
		if want := string(RateLimitRefusalResponse()); got != want {
			t.Errorf("client read %q, want %q", got, want)
		}
		assertRateLimitRefusal(t, capt.calls(), "connect", "limited.example:443", "limited.example")
	})
	t.Run("scope refusal does not fire", func(t *testing.T) {
		var capt gateRefusalCapture
		scope := NewTargetScope()
		scope.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.example"}})
		handler := NewCONNECTHandler(CONNECTHandlerConfig{
			Negotiator:       NewCONNECTNegotiator(nil),
			Scope:            scope,
			RateLimiter:      spentLimiter(),
			InnerPeekTimeout: connectDenialInnerPeek,
			Logger:           discardLogger(),
			OnGateRefusal:    capt.fn,
		})
		got := runDeniedCONNECT(t, handler, "blocked.example:443")
		assertCONNECTReject(t, got, 403, "Forbidden", connectScopeDenyDetail)
		if n := len(capt.calls()); n != 0 {
			t.Errorf("OnGateRefusal called %d times on a scope refusal, want 0", n)
		}
	})
}

// runForwardRefusal drives a forward handler with req and returns what the
// client read.
func runForwardRefusal(t *testing.T, handler HandlerFunc, req string) []byte {
	t.Helper()
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	read := make(chan []byte, 1)
	go func() {
		_, _ = clientA.Write([]byte(req))
		_ = clientA.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, _ := io.ReadAll(clientA)
		read <- got
	}()
	if err := handler(ContextWithClientAddr(context.Background(), "192.0.2.7:4242"), NewPeekConn(clientB)); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	_ = clientB.Close()
	return <-read
}

func TestNewHTTP1ForwardHandler_OnGateRefusal(t *testing.T) {
	t.Run("rate limit refusal fires once after the 429", func(t *testing.T) {
		var capt gateRefusalCapture
		handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
			RateLimiter:   spentLimiter(),
			Logger:        discardLogger(),
			OnGateRefusal: capt.fn,
		})
		got := runForwardRefusal(t, handler, "GET http://rl.example:8080/ HTTP/1.1\r\nHost: rl.example:8080\r\n\r\n")
		if want := RateLimitRefusalResponse(); !bytes.Equal(got, want) {
			t.Errorf("client read %q, want %q", got, want)
		}
		calls := capt.calls()
		assertRateLimitRefusal(t, calls, "http1-forward", "rl.example:8080", "rl.example")
		if len(calls) == 1 && calls[0].ClientAddr != "192.0.2.7:4242" {
			t.Errorf("ClientAddr = %q, want the ctx client address", calls[0].ClientAddr)
		}
	})
	t.Run("scope refusal does not fire", func(t *testing.T) {
		var capt gateRefusalCapture
		scope := NewTargetScope()
		scope.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.example"}})
		handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
			Scope:         scope,
			RateLimiter:   spentLimiter(),
			Logger:        discardLogger(),
			OnGateRefusal: capt.fn,
		})
		got := runForwardRefusal(t, handler, "GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
		if !bytes.HasPrefix(got, []byte("HTTP/1.1 403")) {
			t.Errorf("client read %q, want 403", got)
		}
		if n := len(capt.calls()); n != 0 {
			t.Errorf("OnGateRefusal called %d times on a scope refusal, want 0", n)
		}
	})
}

func TestSOCKS5Negotiator_RateLimitErrorCarriesDenial(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.RateLimiter = spentLimiter()
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
	if !errors.Is(rig.retErr, ErrSOCKS5BlockedByRateLimit) {
		t.Errorf("errors.Is(err, ErrSOCKS5BlockedByRateLimit) = false for %v", rig.retErr)
	}
	var rlErr *SOCKS5RateLimitError
	if !errors.As(rig.retErr, &rlErr) || rlErr.Denial == nil || rlErr.Denial.LimitType != "global" {
		t.Errorf("errors.As(err, *SOCKS5RateLimitError) = %+v, want the global denial", rlErr)
	}
	if rig.retTarget != "example.com:443" {
		t.Errorf("returned target = %q, want example.com:443", rig.retTarget)
	}
}

// runSOCKS5Refusal drives a SOCKS5 handler through a NO_AUTH CONNECT to
// domain:443 and returns the REP byte.
func runSOCKS5Refusal(t *testing.T, handler HandlerFunc, domain string) byte {
	t.Helper()
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	rep := make(chan byte, 1)
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = clientA.Write(buildMethodGreeting(socks5MethodNoAuth))
		_, _ = io.ReadFull(clientA, make([]byte, 2))
		_, _ = clientA.Write(buildConnectDomain(domain, 443))
		reply := make([]byte, 10)
		if _, err := io.ReadFull(clientA, reply); err != nil {
			rep <- 0xff
			return
		}
		rep <- reply[1]
	}()
	if err := handler(context.Background(), NewPeekConn(clientB)); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	_ = clientB.Close()
	return <-rep
}

func TestNewSOCKS5Handler_OnGateRefusal(t *testing.T) {
	t.Run("rate limit refusal fires once after REP 0x02", func(t *testing.T) {
		var capt gateRefusalCapture
		neg := NewSOCKS5Negotiator(newTestLogger())
		neg.RateLimiter = spentLimiter()
		handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
			Negotiator:    neg,
			Logger:        discardLogger(),
			OnGateRefusal: capt.fn,
		})
		if rep := runSOCKS5Refusal(t, handler, "limited.example"); rep != socks5ReplyConnectionNotAllowed {
			t.Errorf("REP = 0x%02x, want 0x02", rep)
		}
		assertRateLimitRefusal(t, capt.calls(), "socks5", "limited.example:443", "limited.example")
	})
	t.Run("scope refusal does not fire", func(t *testing.T) {
		var capt gateRefusalCapture
		neg := NewSOCKS5Negotiator(newTestLogger())
		scope := NewTargetScope()
		scope.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.example"}})
		neg.Scope = scope
		neg.RateLimiter = spentLimiter()
		handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
			Negotiator:    neg,
			Logger:        discardLogger(),
			OnGateRefusal: capt.fn,
		})
		if rep := runSOCKS5Refusal(t, handler, "blocked.example"); rep != socks5ReplyConnectionNotAllowed {
			t.Errorf("REP = 0x%02x, want 0x02", rep)
		}
		if n := len(capt.calls()); n != 0 {
			t.Errorf("OnGateRefusal called %d times on a scope refusal, want 0", n)
		}
	})
	t.Run("nil callback", func(t *testing.T) {
		neg := NewSOCKS5Negotiator(newTestLogger())
		neg.RateLimiter = spentLimiter()
		handler := NewSOCKS5Handler(SOCKS5HandlerConfig{Negotiator: neg, Logger: discardLogger()})
		if rep := runSOCKS5Refusal(t, handler, "limited.example"); rep != socks5ReplyConnectionNotAllowed {
			t.Errorf("REP = 0x%02x, want 0x02", rep)
		}
	})
}

func TestReportRateLimitRefusal_NilDenialOrCallback(t *testing.T) {
	var capt gateRefusalCapture
	reportRateLimitRefusal(context.Background(), capt.fn, "connect", "a.example:443", nil, nil)
	reportRateLimitRefusal(context.Background(), nil, "connect", "a.example:443", nil, &RateLimitDenial{LimitType: "global"})
	if n := len(capt.calls()); n != 0 {
		t.Errorf("OnGateRefusal called %d times, want 0", n)
	}
	// A target without a port keys on the literal target.
	reportRateLimitRefusal(context.Background(), capt.fn, "socks5", "noport", nil, &RateLimitDenial{LimitType: "per_host", EffectiveRPS: 2})
	calls := capt.calls()
	if len(calls) != 1 || calls[0].Host != "noport" || calls[0].Tags["reason"] != "per_host limit 2 rps" {
		t.Errorf("calls = %+v, want one with Host noport and reason %q", calls, "per_host limit 2 rps")
	}
}
