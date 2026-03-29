//go:build e2e

package proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// Performance Benchmarks: independent engine vs net/http baseline
// =============================================================================

// BenchmarkH1Engine_ForwardProxy measures the independent engine's throughput
// using raw TCP connections (Connection: close per request).
func BenchmarkH1Engine_ForwardProxy(b *testing.B) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbPath := filepath.Join(b.TempDir(), "bench.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	go listener.Start(ctx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		b.Fatal("proxy did not become ready")
	}

	reqLine := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
		if err != nil {
			b.Fatalf("dial proxy: %v", err)
		}

		if _, err := io.WriteString(conn, reqLine); err != nil {
			conn.Close()
			b.Fatalf("write: %v", err)
		}

		resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			b.Fatalf("read response: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		conn.Close()

		if resp.StatusCode != gohttp.StatusOK {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
}

// BenchmarkH1Engine_ForwardProxy_KeepAlive measures throughput with keep-alive
// connections (single connection, multiple requests).
func BenchmarkH1Engine_ForwardProxy_KeepAlive(b *testing.B) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbPath := filepath.Join(b.TempDir(), "bench.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	go listener.Start(ctx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		b.Fatal("proxy did not become ready")
	}

	reqLine := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		b.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := io.WriteString(conn, reqLine); err != nil {
			b.Fatalf("write: %v", err)
		}

		resp, err := gohttp.ReadResponse(reader, nil)
		if err != nil {
			b.Fatalf("read response (iter %d): %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
}

// BenchmarkH1Engine_GoHTTPClient measures throughput using Go's standard
// http.Client (validates compatibility and measures overhead).
func BenchmarkH1Engine_GoHTTPClient(b *testing.B) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbPath := filepath.Join(b.TempDir(), "bench.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	go listener.Start(ctx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		b.Fatal("proxy did not become ready")
	}

	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Timeout: 5 * time.Second,
		Transport: &gohttp.Transport{
			Proxy:                 gohttp.ProxyURL(proxyURL),
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(upstream.URL + "/bench")
		if err != nil {
			b.Fatalf("GET: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
}
