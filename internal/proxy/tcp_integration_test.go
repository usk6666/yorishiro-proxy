//go:build e2e

package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	prototcp "github.com/usk6666/yorishiro-proxy/internal/protocol/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startTCPEchoServer creates a simple TCP echo server.
func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		cancel()
		ln.Close()
	}
}

func TestIntegration_TCP_Relay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start TCP echo upstream.
	upstreamAddr, closeUpstream := startTCPEchoServer(t)
	defer closeUpstream()

	// Create SQLite store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// We need a proxy with a TCP handler that has forwarding configured.
	// The TCP handler needs to know which port maps to which upstream.
	// We'll set up a dedicated listener with TCP forwarding.
	httpHandler := protohttp.NewHandler(store, nil, logger)

	// TCP handler is a fallback — it must be registered last.
	// We'll configure forwarding after we know the listener port.
	tcpHandler := prototcp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler, tcpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      logger,
		PeekTimeout: 2 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// Configure TCP forwarding: proxy port -> upstream echo server.
	_, proxyPort, _ := net.SplitHostPort(listener.Addr())
	tcpHandler.SetForwards(map[string]string{
		proxyPort: upstreamAddr,
	})

	// Connect to the proxy with non-HTTP data (triggers TCP fallback).
	conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send 16+ bytes of binary data (not HTTP, not TLS, not SOCKS5)
	// to satisfy the 16-byte peek requirement.
	testData := []byte{
		0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10,
	}
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read echo response.
	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read: %v (got %d bytes)", err, n)
	}

	for i, b := range testData {
		if buf[i] != b {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, buf[i], b)
		}
	}

	// Verify flow recording.
	conn.Close()
	var flows []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Protocol: "TCP", Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) > 0 {
			break
		}
	}
	if len(flows) == 0 {
		t.Fatal("no TCP flows recorded")
	}
	if flows[0].FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want bidirectional", flows[0].FlowType)
	}
}

func TestIntegration_TCP_ConcurrentRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startTCPEchoServer(t)
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	httpHandler := protohttp.NewHandler(store, nil, logger)
	tcpHandler := prototcp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler, tcpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      logger,
		PeekTimeout: 2 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	_, proxyPort, _ := net.SplitHostPort(listener.Addr())
	tcpHandler.SetForwards(map[string]string{
		proxyPort: upstreamAddr,
	})

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
			if err != nil {
				errs <- fmt.Errorf("client %d dial: %w", n, err)
				return
			}
			defer conn.Close()

			// Pad to 16+ bytes to satisfy peek requirement.
			msg := fmt.Sprintf("client-%02d-data!", n)
			conn.Write([]byte(msg))

			buf := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- fmt.Errorf("client %d read: %w", n, err)
				return
			}

			if string(buf) != msg {
				errs <- fmt.Errorf("client %d: got %q, want %q", n, buf, msg)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
