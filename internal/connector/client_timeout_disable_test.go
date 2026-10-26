package connector

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1185: with request_timeout_ms disabled the CONNECT / SOCKS5 inner
// peek and the plain-HTTP forward peek arm no deadline — neither the
// static value nor the package default applies.

func TestDispatchInnerProtocol_RequestTimeoutDisabledNoDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	pc := NewPeekConn(serverConn)
	done := make(chan bool, 1)
	go func() {
		done <- dispatchInnerProtocol(context.Background(), pc, "example.com:443", innerDispatchConfig{
			PeekTimeout:         200 * time.Millisecond,
			PeekTimeoutProvider: func() time.Duration { return 200 * time.Millisecond },
			PeekTimeoutDisabled: func() bool { return true },
		})
	}()

	select {
	case <-done:
		t.Fatal("inner peek gave up within 1s although request_timeout_ms is disabled")
	case <-time.After(1 * time.Second):
	}
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchInnerProtocol did not return after the client closed")
	}
}

func TestNewHTTP1ForwardHandler_RequestTimeoutDisabledNoDeadline(t *testing.T) {
	handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		OnStack: func(context.Context, *ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, string) {
		},
		RequestTimeout:         200 * time.Millisecond,
		RequestTimeoutProvider: func() time.Duration { return 200 * time.Millisecond },
		RequestTimeoutDisabled: func() bool { return true },
	})

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handler(ContextWithConnID(context.Background(), "test-conn"), NewPeekConn(clientB))
	}()
	if _, err := clientA.Write([]byte("GET / HT")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := clientA.Read(buf)
		got <- buf[:n]
	}()
	select {
	case b := <-got:
		t.Fatalf("forward handler answered %q within 1s although request_timeout_ms is disabled", b)
	case <-done:
		t.Fatal("forward handler returned within 1s although request_timeout_ms is disabled")
	case <-time.After(1 * time.Second):
	}
	_ = clientA.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forward handler did not return after the client closed")
	}
}
