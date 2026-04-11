package connector

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestKindDispatcher_CONNECT(t *testing.T) {
	d := NewKindDispatcher()

	called := false
	d.WithCONNECT(func(_ context.Context, _ *PeekConn, _ CodecFactory) error {
		called = true
		return nil
	})

	_, server := net.Pipe()
	defer server.Close()
	pc := NewPeekConn(server)

	if err := d.Dispatch(context.Background(), pc, ProtocolHTTPConnect, nil); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !called {
		t.Error("CONNECT handler was not invoked")
	}
}

func TestKindDispatcher_NoHandler(t *testing.T) {
	d := NewKindDispatcher()

	_, server := net.Pipe()
	defer server.Close()
	pc := NewPeekConn(server)

	err := d.Dispatch(context.Background(), pc, ProtocolHTTPConnect, nil)
	if !errors.Is(err, ErrNoHandler) {
		t.Errorf("err = %v, want ErrNoHandler wrapping", err)
	}
}

func TestKindDispatcher_Plain(t *testing.T) {
	d := NewKindDispatcher()
	var gotKind ProtocolKind
	d.WithPlain(func(_ context.Context, _ *PeekConn, kind ProtocolKind, _ CodecFactory) error {
		gotKind = kind
		return nil
	})

	_, server := net.Pipe()
	defer server.Close()
	pc := NewPeekConn(server)

	if err := d.Dispatch(context.Background(), pc, ProtocolHTTP1, nil); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if gotKind != ProtocolHTTP1 {
		t.Errorf("gotKind = %v", gotKind)
	}
}

func TestCONNECTHandler_NilGuards(t *testing.T) {
	_, server := net.Pipe()
	defer server.Close()
	pc := NewPeekConn(server)

	// Nil negotiator.
	h := CONNECTHandler(nil, nil)
	if err := h(context.Background(), pc, nil); err == nil {
		t.Error("expected error for nil negotiator")
	}

	// Nil tunnel.
	neg := NewCONNECTNegotiator(newTestLogger())
	h = CONNECTHandler(neg, nil)
	if err := h(context.Background(), pc, nil); err == nil {
		t.Error("expected error for nil tunnel")
	}
}
