package proxy_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// echoHandler is defined in manager_test.go

func TestTCPForwardListener_StartStop(t *testing.T) {
	logger := newTestLogger()
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener("127.0.0.1:0", handler, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	// Wait for the listener to be ready.
	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	addr := fl.Addr()
	if addr == "" {
		t.Fatal("expected non-empty address after Start")
	}

	// Verify we can connect.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	// Write data and verify echo.
	testData := []byte("hello tcp forward")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	conn.Close()

	// Stop the listener.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Start to return")
	}
}

func TestTCPForwardListener_InvalidAddr(t *testing.T) {
	logger := newTestLogger()
	handler := &echoHandler{}

	// Use an invalid address that will fail to bind.
	fl := proxy.NewTCPForwardListener("192.0.2.1:0", handler, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := fl.Start(ctx)
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestTCPForwardListener_AddrBeforeStart(t *testing.T) {
	logger := newTestLogger()
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener("127.0.0.1:0", handler, logger)

	// Addr should be empty before Start.
	if addr := fl.Addr(); addr != "" {
		t.Errorf("Addr before Start = %q, want empty", addr)
	}
}

func TestTCPForwardListener_MultipleConnections(t *testing.T) {
	logger := newTestLogger()
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener("127.0.0.1:0", handler, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	addr := fl.Addr()

	// Open multiple concurrent connections, verify echo, and close each.
	const numConns = 5
	for i := range numConns {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}

		testData := []byte("test data")
		if _, err := conn.Write(testData); err != nil {
			conn.Close()
			t.Fatalf("write %d: %v", i, err)
		}

		buf := make([]byte, len(testData))
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			t.Fatalf("read %d: %v", i, err)
		}

		if string(buf) != string(testData) {
			t.Errorf("conn %d echo mismatch: got %q, want %q", i, buf, testData)
		}

		conn.Close()
	}

	cancel()
	<-errCh
}
