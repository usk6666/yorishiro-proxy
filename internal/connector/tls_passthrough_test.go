package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestRelayBidirectional(t *testing.T) {
	// Create two pipe pairs to simulate client↔proxy↔upstream
	clientConn, proxyClientSide := net.Pipe()
	proxyUpstreamSide, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer upstreamConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relayBidirectional(ctx, proxyClientSide, proxyUpstreamSide)
	}()

	// Client sends data → should arrive at upstream
	testData := []byte("hello from client")
	go func() {
		_, _ = clientConn.Write(testData)
	}()

	buf := make([]byte, 256)
	n, err := upstreamConn.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("upstream got %q, want %q", buf[:n], testData)
	}

	// Upstream sends data → should arrive at client
	responseData := []byte("hello from upstream")
	go func() {
		_, _ = upstreamConn.Write(responseData)
	}()

	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != string(responseData) {
		t.Errorf("client got %q, want %q", buf[:n], responseData)
	}

	// Close one side → relay should complete
	clientConn.Close()
	upstreamConn.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not complete")
	}
}

func TestRelayBidirectional_ContextCancel(t *testing.T) {
	a, b := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- relayBidirectional(ctx, a, b)
	}()

	// Give the relay time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context → relay should stop
	cancel()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after context cancel")
	}
}

func TestRelayBidirectional_OneDirectionClose(t *testing.T) {
	clientConn, proxyClientSide := net.Pipe()
	proxyUpstreamSide, upstreamConn := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relayBidirectional(ctx, proxyClientSide, proxyUpstreamSide)
	}()

	// Send data one direction then close
	go func() {
		_, _ = clientConn.Write([]byte("data"))
		clientConn.Close()
	}()

	// Upstream should receive data
	buf := make([]byte, 256)
	n, _ := upstreamConn.Read(buf)
	if string(buf[:n]) != "data" {
		t.Errorf("got %q, want %q", buf[:n], "data")
	}

	// Close upstream to unblock the relay
	upstreamConn.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not complete")
	}
}

func TestIsTunneledOutcome(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"io.EOF", io.EOF, true},
		{"wrapped EOF", fmt.Errorf("readfrom: %w", io.EOF), true},
		{"io.ErrClosedPipe", io.ErrClosedPipe, true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"wrapped net.ErrClosed", fmt.Errorf("write tcp: %w", net.ErrClosed), true},
		// USK-952: ECONNRESET on a passthrough relay is dominated by
		// ungraceful peer close after bytes have flowed (TLS close_notify
		// in flight, mobile-handover, browser tab close). Classify as
		// tunneled per the function's tolerance policy.
		{"syscall.ECONNRESET", syscall.ECONNRESET, true},
		{"wrapped ECONNRESET", fmt.Errorf("read tcp: %w", syscall.ECONNRESET), true},
		{"unrelated error", errors.New("i/o timeout mid-relay"), false},
		{"DNS error", errors.New("no such host"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTunneledOutcome(tc.err); got != tc.want {
				t.Errorf("isTunneledOutcome(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
