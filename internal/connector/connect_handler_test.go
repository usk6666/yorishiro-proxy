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
		// Short inner-peek so the test does not wait the production default
		// (5s) for a client that sends no inner bytes.
		InnerPeekTimeout: 50 * time.Millisecond,
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
		Negotiator:       NewCONNECTNegotiator(nil),
		BuildCfg:         nil, // stack build will fail
		InnerPeekTimeout: 50 * time.Millisecond,
		OnStack:          nil,
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
		Negotiator:       NewCONNECTNegotiator(nil),
		BuildCfg:         nil, // stack build will fail
		Scope:            nil,
		RateLimiter:      nil,
		InnerPeekTimeout: 50 * time.Millisecond,
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

// TestNewCONNECTHandler_UpstreamTLSError_FiresCallback proves the USK-784
// wiring: when CONNECT was accepted but BuildConnectionStack fails, the
// OnUpstreamTLSError callback is invoked with the original CONNECT
// authority and the underlying error so the recorder in proxybuild can
// persist a state="error" Stream.
//
// We trigger the failure via BuildCfg=nil (BuildConnectionStack rejects
// nil cfg with a synthetic "nil config" error). The exact error class
// does not matter for this contract test — we only assert that the
// callback fires AND receives the authority verbatim.
func TestNewCONNECTHandler_UpstreamTLSError_FiresCallback(t *testing.T) {
	var (
		callbackFired atomic.Bool
		gotTarget     atomic.Value // string
		gotErrText    atomic.Value // string
	)

	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:       NewCONNECTNegotiator(nil),
		BuildCfg:         nil, // forces BuildConnectionStack failure
		InnerPeekTimeout: 50 * time.Millisecond,
		OnUpstreamTLSError: func(_ context.Context, target string, err error) {
			callbackFired.Store(true)
			gotTarget.Store(target)
			if err != nil {
				gotErrText.Store(err.Error())
			}
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		// Send CONNECT and the TLS Handshake first byte (0x16) so the
		// inner-byte peek classifies the tunnel as InnerTLS and the
		// handler invokes runTLSMITM (the path that invokes
		// OnUpstreamTLSError on failure). Without this byte the peek
		// would classify the connection as InnerUnknown / fall back to
		// bytechunk and the recorder path is skipped.
		_, _ = clientConn.Write([]byte("CONNECT badssl.example.test:443 HTTP/1.1\r\nHost: badssl.example.test:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
		// Send a TLS ClientHello first byte to trigger the TLS path.
		_, _ = clientConn.Write([]byte{0x16, 0x03, 0x01})
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "usk-784-conn")
	ctx = ContextWithClientAddr(ctx, "127.0.0.1:54321")

	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	// Allow the synchronous OnUpstreamTLSError callback to land.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && !callbackFired.Load() {
		time.Sleep(10 * time.Millisecond)
	}

	if !callbackFired.Load() {
		t.Fatal("OnUpstreamTLSError was not invoked")
	}
	if got, _ := gotTarget.Load().(string); got != "badssl.example.test:443" {
		t.Errorf("OnUpstreamTLSError target = %q, want %q",
			got, "badssl.example.test:443")
	}
	if got, _ := gotErrText.Load().(string); got == "" {
		t.Error("OnUpstreamTLSError error message is empty")
	}
}

// TestNewCONNECTHandler_UpstreamTLSError_NilCallback verifies the legacy
// silent-drop behaviour holds when no callback is wired — proxy
// configurations that opt out of recording must continue to work.
func TestNewCONNECTHandler_UpstreamTLSError_NilCallback(t *testing.T) {
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:         NewCONNECTNegotiator(nil),
		BuildCfg:           nil, // forces BuildConnectionStack failure
		InnerPeekTimeout:   50 * time.Millisecond,
		OnUpstreamTLSError: nil, // explicit
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("CONNECT badssl.example.test:443 HTTP/1.1\r\nHost: badssl.example.test:443\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = clientConn.Read(buf)
		_, _ = clientConn.Write([]byte{0x16, 0x03, 0x01})
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "usk-784-conn-nil")

	// Must not panic and must return nil — silent drop is the legacy
	// behaviour.
	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error with nil callback: %v", err)
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
		Negotiator:       NewCONNECTNegotiator(nil),
		BuildCfg:         nil, // stack build fails — OK, just testing scope passes
		Scope:            scope,
		InnerPeekTimeout: 50 * time.Millisecond,
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
