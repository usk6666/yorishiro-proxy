package connector

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

func TestClassifyInnerByte(t *testing.T) {
	tests := []struct {
		name string
		peek []byte
		want InnerProtocolKind
	}{
		{"empty", nil, InnerBytechunk},
		{"tls handshake", []byte{0x16}, InnerTLS},
		{"tls handshake with extra bytes", []byte{0x16, 0x03, 0x01, 0x00, 0x01}, InnerTLS},
		{"http get", []byte("GET / HTTP/1.1\r\n"), InnerHTTP1},
		{"http post", []byte("POST / "), InnerHTTP1},
		{"http options", []byte("OPTIONS "), InnerHTTP1},
		{"h2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), InnerH2C},
		{"h2 preface short prefix", []byte("PRI * HT"), InnerH2C},
		{"raw bytes", []byte{0xff, 0xff, 0xff, 0xff}, InnerBytechunk},
		{"smtp banner-ish", []byte("220 mail.example.com"), InnerBytechunk},
		// SOCKS5 / CONNECT prefixes are not legal inner protocols — they
		// fold into bytechunk because we already negotiated the tunnel.
		{"socks5 byte (not inner)", []byte{0x05, 0x01}, InnerBytechunk},
		{"connect prefix (not inner)", []byte("CONNECT foo:443"), InnerBytechunk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyInnerByte(tt.peek)
			if got != tt.want {
				t.Errorf("classifyInnerByte(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

func TestPeekInnerProtocol_Timeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	pc := NewPeekConn(serverConn)
	start := time.Now()
	kind, peek := peekInnerProtocol(pc, 50*time.Millisecond)
	elapsed := time.Since(start)

	if kind != InnerUnknown {
		t.Errorf("kind = %v, want InnerUnknown", kind)
	}
	if peek != nil {
		t.Errorf("peek = %x, want nil", peek)
	}
	// Allow generous slack for slow CI; the deadline is the upper bound.
	if elapsed > 2*time.Second {
		t.Errorf("peek took %v, expected to honour 50ms deadline", elapsed)
	}
}

func TestPeekInnerProtocol_DetectsTLS(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x01})
	}()

	pc := NewPeekConn(serverConn)
	kind, peek := peekInnerProtocol(pc, time.Second)

	if kind != InnerTLS {
		t.Errorf("kind = %v, want InnerTLS", kind)
	}
	if len(peek) == 0 || peek[0] != 0x16 {
		t.Errorf("peek = %x, want first byte 0x16", peek)
	}
}

func TestPeekInnerProtocol_DetectsHTTP1(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\n"))
	}()

	pc := NewPeekConn(serverConn)
	kind, _ := peekInnerProtocol(pc, time.Second)

	if kind != InnerHTTP1 {
		t.Errorf("kind = %v, want InnerHTTP1", kind)
	}
}

func TestPeekInnerProtocol_DetectsH2C(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	}()

	pc := NewPeekConn(serverConn)
	kind, _ := peekInnerProtocol(pc, time.Second)

	if kind != InnerH2C {
		t.Errorf("kind = %v, want InnerH2C", kind)
	}
}

func TestPeekInnerProtocol_FallbackBytechunk(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{0xde, 0xad, 0xbe, 0xef})
	}()

	pc := NewPeekConn(serverConn)
	kind, _ := peekInnerProtocol(pc, time.Second)

	if kind != InnerBytechunk {
		t.Errorf("kind = %v, want InnerBytechunk", kind)
	}
}

// TestDispatchInnerProtocol_TLSPath asserts the TLS branch returns
// handleAsTLS=true so the caller can drive the existing BuildConnectionStack
// path (which the inner-dispatch helper deliberately does not own).
func TestDispatchInnerProtocol_TLSPath(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x01})
	}()

	pc := NewPeekConn(serverConn)
	var onStackCalled atomic.Bool
	var onH2StackCalled atomic.Bool

	got := dispatchInnerProtocol(context.Background(), pc, "example.com:443", innerDispatchConfig{
		PeekTimeout: time.Second,
		BuildCfg:    nil, // unused on TLS path
		OnStack: func(_ context.Context, _ *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			onStackCalled.Store(true)
		},
		OnHTTP2Stack: func(_ context.Context, _ *ConnectionStack, _ *http2.Layer, _, _ *envelope.TLSSnapshot, _ string) {
			onH2StackCalled.Store(true)
		},
	})

	if !got {
		t.Errorf("handleAsTLS = false, want true on 0x16 inner byte")
	}
	if onStackCalled.Load() {
		t.Errorf("OnStack was called on TLS branch (expected caller-owned dispatch)")
	}
	if onH2StackCalled.Load() {
		t.Errorf("OnHTTP2Stack was called on TLS branch")
	}
}

// TestDispatchInnerProtocol_PeekTimeoutClosesQuietly asserts that when the
// client sends nothing after CONNECT 200, dispatchInnerProtocol returns
// quickly with handleAsTLS=false and does NOT invoke any stack callback.
func TestDispatchInnerProtocol_PeekTimeoutClosesQuietly(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	pc := NewPeekConn(serverConn)
	var onStackCalled atomic.Bool

	start := time.Now()
	got := dispatchInnerProtocol(context.Background(), pc, "example.com:443", innerDispatchConfig{
		PeekTimeout: 50 * time.Millisecond,
		OnStack: func(_ context.Context, _ *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			onStackCalled.Store(true)
		},
	})
	elapsed := time.Since(start)

	if got {
		t.Errorf("handleAsTLS = true on peek timeout, want false")
	}
	if onStackCalled.Load() {
		t.Errorf("OnStack invoked despite peek timeout")
	}
	if elapsed > 2*time.Second {
		t.Errorf("dispatchInnerProtocol took %v, expected to honour 50ms deadline", elapsed)
	}
}

// TestBuildBytechunkStack verifies the helper produces a stack with one
// bytechunk Layer per side and TargetHost is informational (no panic on
// empty target).
func TestBuildBytechunkStack(t *testing.T) {
	cfg := &BuildConfig{}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()

	stack, err := BuildBytechunkStack(a, c, "example.com:443", cfg)
	if err != nil {
		t.Fatalf("BuildBytechunkStack: %v", err)
	}
	defer stack.Close()
	if stack.ClientTopmost() == nil {
		t.Fatal("ClientTopmost is nil")
	}
	if stack.UpstreamTopmost() == nil {
		t.Fatal("UpstreamTopmost is nil")
	}
}

// TestBuildBytechunkStack_NilConn ensures the constructor surfaces a clear
// error on nil conns rather than panicking inside bytechunk.New.
func TestBuildBytechunkStack_NilConn(t *testing.T) {
	cfg := &BuildConfig{}
	_, err := BuildBytechunkStack(nil, nil, "example.com:443", cfg)
	if err == nil {
		t.Fatal("expected error on nil conns, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("nil conn")) {
		t.Errorf("error %q does not mention nil conn", err)
	}
}

// TestBuildPlainH2CStack_NilCfg asserts the validation guard.
func TestBuildPlainH2CStack_NilCfg(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()

	_, err := BuildPlainH2CStack(a, c, "example.com:80", nil)
	if err == nil {
		t.Fatal("expected error on nil config, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("nil config")) {
		t.Errorf("error %q does not mention nil config", err)
	}
}
