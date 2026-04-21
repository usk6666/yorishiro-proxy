package connector

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestNewCONNECTHandler_SuccessfulPipeline(t *testing.T) {
	var stackReceived atomic.Bool

	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(nil),
		BuildCfg:   nil, // Will cause stack build to fail — that's OK for this test
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackReceived.Store(true)
			defer stack.Close()
			if target != "example.com:443" {
				t.Errorf("target = %q, want %q", target, "example.com:443")
			}
		},
	})

	// We can't test the full pipeline without a real TLS setup,
	// but we can test that the negotiation and scope check flow works.
	// BuildConnectionStack will fail with nil config, which is expected.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		// Send CONNECT request
		_, _ = clientConn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		// Read 200 OK response
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test-conn")
	ctx = ContextWithClientAddr(ctx, "127.0.0.1:12345")

	// Handler should negotiate CONNECT then fail at stack build (nil config)
	// and return nil (not propagate error)
	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	// Stack not received because build fails with nil config
}

func TestNewCONNECTHandler_ScopeDenial(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{
		{Hostname: "blocked.com"},
	})

	var stackCalled atomic.Bool
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(nil),
		Scope:      scope,
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackCalled.Store(true)
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("CONNECT blocked.com:443 HTTP/1.1\r\nHost: blocked.com:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test-conn")

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if stackCalled.Load() {
		t.Error("OnStack should not be called when target is blocked by scope")
	}
}

func TestNewCONNECTHandler_RateLimitDenial(t *testing.T) {
	rl := NewRateLimiter()
	// Set an extremely low rate limit so the second request is denied.
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 0.001, // effectively blocks everything
	})
	// Pre-consume the tiny bucket.
	_ = rl.Check("limited.com")

	var stackCalled atomic.Bool
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:  NewCONNECTNegotiator(nil),
		RateLimiter: rl,
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackCalled.Store(true)
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("CONNECT limited.com:443 HTTP/1.1\r\nHost: limited.com:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test-conn")

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if stackCalled.Load() {
		t.Error("OnStack should not be called when target is rate limited")
	}
}

func TestNewCONNECTHandler_NotCONNECT(t *testing.T) {
	var stackCalled atomic.Bool
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(nil),
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackCalled.Store(true)
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		// Send a GET request, not CONNECT
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	pc := NewPeekConn(serverConn)
	ctx := context.Background()

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error on non-CONNECT: %v", err)
	}
	if stackCalled.Load() {
		t.Error("OnStack should not be called for non-CONNECT request")
	}
}

func TestNewCONNECTHandler_NilOnStack(t *testing.T) {
	// When OnStack is nil, stack should be closed (not leaked)
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(nil),
		BuildCfg:   nil, // stack build will fail
		OnStack:    nil,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
	}()

	pc := NewPeekConn(serverConn)
	ctx := context.Background()

	// Should not panic
	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}
}

func TestNewCONNECTHandler_NilScope_NilRateLimiter(t *testing.T) {
	// Nil Scope and RateLimiter should not panic — just skip the checks
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:  NewCONNECTNegotiator(nil),
		BuildCfg:    nil, // stack build will fail
		Scope:       nil,
		RateLimiter: nil,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
	}()

	pc := NewPeekConn(serverConn)
	ctx := context.Background()

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}
}

func TestNewCONNECTHandler_NegotiationError(t *testing.T) {
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(nil),
	})

	clientConn, serverConn := net.Pipe()

	go func() {
		// Send garbage and close immediately
		_, _ = clientConn.Write([]byte("garbage"))
		clientConn.Close()
	}()

	pc := NewPeekConn(serverConn)
	ctx := context.Background()

	// Should handle negotiation error gracefully
	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler should return nil on negotiation error, got: %v", err)
	}
}

func TestNewCONNECTHandler_ScopeAllowed(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules([]TargetRule{
		{Hostname: "allowed.com"},
	}, nil)

	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(nil),
		BuildCfg:   nil, // stack build fails — OK, just testing scope passes
		Scope:      scope,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("CONNECT allowed.com:443 HTTP/1.1\r\nHost: allowed.com:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test")

	// Should pass scope (allowed) then fail at stack build (nil config) — not an error
	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}
}
