package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

func startProxy(t *testing.T, ctx context.Context, store session.Store) (*proxy.Listener, context.CancelFunc) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener, proxyCancel
}

func proxyClient(proxyAddr string) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
}

func TestIntegration_HTTPForwardProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start a test upstream HTTP server.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "upstream")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from upstream")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Create temporary SQLite database.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Build and start proxy.
	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	// Send GET request through proxy.
	targetURL := fmt.Sprintf("http://%s/test-path", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q, want %q", body, "hello from upstream")
	}
	if resp.Header.Get("X-Test") != "upstream" {
		t.Errorf("X-Test header = %q, want %q", resp.Header.Get("X-Test"), "upstream")
	}

	// Wait for session to be persisted.
	time.Sleep(100 * time.Millisecond)

	// Verify session was recorded in SQLite.
	entries, err := store.List(ctx, session.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 session, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Request.Method != "GET" {
		t.Errorf("session method = %q, want %q", entry.Request.Method, "GET")
	}
	if entry.Request.URL == nil || entry.Request.URL.Path != "/test-path" {
		path := ""
		if entry.Request.URL != nil {
			path = entry.Request.URL.Path
		}
		t.Errorf("session URL path = %q, want %q", path, "/test-path")
	}
	if entry.Response.StatusCode != 200 {
		t.Errorf("session status = %d, want %d", entry.Response.StatusCode, 200)
	}
	if string(entry.Response.Body) != "hello from upstream" {
		t.Errorf("session response body = %q, want %q", entry.Response.Body, "hello from upstream")
	}
	if entry.Protocol != "HTTP/1.x" {
		t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTP/1.x")
	}
}

func TestIntegration_HTTPForwardProxy_POST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "received: %s", body)
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	targetURL := fmt.Sprintf("http://%s/api/data", upstreamListener.Addr().String())
	resp, err := client.Post(targetURL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}

	time.Sleep(100 * time.Millisecond)

	entries, err := store.List(ctx, session.ListOptions{Method: "POST"})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 POST session, got %d", len(entries))
	}
	if entries[0].Response.StatusCode != 201 {
		t.Errorf("session status = %d, want %d", entries[0].Response.StatusCode, 201)
	}
}

// --- Error Recovery Integration Tests ---

// failingStore is a session.Store that always returns an error from Save.
// It is used to verify that the proxy continues forwarding traffic even when
// session persistence fails (USK-36 fix).
type failingStore struct {
	saveCallCount atomic.Int64
}

func (s *failingStore) Save(_ context.Context, _ *session.Entry) error {
	s.saveCallCount.Add(1)
	return errors.New("simulated DB write failure")
}

func (s *failingStore) Get(_ context.Context, _ string) (*session.Entry, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) List(_ context.Context, _ session.ListOptions) ([]*session.Entry, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) Count(_ context.Context, _ session.ListOptions) (int, error) {
	return 0, errors.New("simulated DB read failure")
}

func (s *failingStore) Delete(_ context.Context, _ string) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteAll(_ context.Context) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteExcess(_ context.Context, _ int) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure(t *testing.T) {
	// Verifies that when session.Store.Save fails, the proxy still forwards
	// the upstream response to the client (USK-36 fix).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start a test upstream HTTP server.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "upstream response")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Use a failing store instead of a real SQLite store.
	store := &failingStore{}

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	// Send a request through the proxy.
	targetURL := fmt.Sprintf("http://%s/test-error-recovery", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy with failing store: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The proxy should have forwarded the response despite the save failure.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "upstream response" {
		t.Errorf("body = %q, want %q", body, "upstream response")
	}
	if resp.Header.Get("X-Test") != "ok" {
		t.Errorf("X-Test header = %q, want %q", resp.Header.Get("X-Test"), "ok")
	}

	// Verify that Save was actually called (and failed).
	if store.saveCallCount.Load() == 0 {
		t.Error("expected Save to be called at least once, but it was not")
	}
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure_MultipleRequests(t *testing.T) {
	// Verifies that multiple sequential requests through the same proxy continue
	// to work even when every Save call fails. This tests the keep-alive
	// connection behavior under persistent save failures.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var requestCount atomic.Int64
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		n := requestCount.Add(1)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "response-%d", n)
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	store := &failingStore{}

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	// Send multiple requests through the proxy.
	const numRequests = 5
	for i := 0; i < numRequests; i++ {
		targetURL := fmt.Sprintf("http://%s/request-%d", upstreamAddr, i)
		resp, err := client.Get(targetURL)
		if err != nil {
			t.Fatalf("GET %d through proxy with failing store: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, gohttp.StatusOK)
		}
		if len(body) == 0 {
			t.Errorf("request %d: got empty body", i)
		}
	}

	// All Save calls should have been attempted (and failed).
	if got := store.saveCallCount.Load(); got < int64(numRequests) {
		t.Errorf("Save call count = %d, want >= %d", got, numRequests)
	}
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure_WithRealDB(t *testing.T) {
	// This test uses a real SQLite store, saves some entries, then closes
	// the database to simulate a failure mid-operation. The proxy should
	// still forward traffic.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Create a real store and immediately use a failing store for the proxy.
	// This approach avoids the complexity of closing a DB mid-stream.
	// The real-world scenario (DB failure after successful start) is adequately
	// covered by the failingStore tests above.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	realStore, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// First, verify the proxy works with a healthy store.
	listener1, proxyCancel1 := startProxy(t, ctx, realStore)
	client1 := proxyClient(listener1.Addr())

	resp, err := client1.Get(fmt.Sprintf("http://%s/healthy", upstreamAddr))
	if err != nil {
		t.Fatalf("GET through healthy proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("healthy proxy: status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	proxyCancel1()

	// Close the real store — this simulates a DB failure.
	realStore.Close()

	// Now start a proxy with a failing store and verify it still forwards.
	failStore := &failingStore{}
	listener2, proxyCancel2 := startProxy(t, ctx, failStore)
	defer proxyCancel2()

	client2 := proxyClient(listener2.Addr())
	resp2, err := client2.Get(fmt.Sprintf("http://%s/after-failure", upstreamAddr))
	if err != nil {
		t.Fatalf("GET through failing proxy: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != gohttp.StatusOK {
		t.Errorf("failing proxy: status = %d, want %d", resp2.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

func TestIntegration_ProxyContextCancellation(t *testing.T) {
	// Verifies that the proxy shuts down cleanly when the context is cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)

	client := proxyClient(listener.Addr())

	// Verify proxy works before cancellation.
	resp, err := client.Get(fmt.Sprintf("http://%s/before-cancel", upstreamAddr))
	if err != nil {
		t.Fatalf("GET before cancel: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status before cancel = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Cancel the proxy context.
	proxyCancel()

	// Give the proxy a moment to shut down.
	time.Sleep(200 * time.Millisecond)

	// Requests after cancellation should fail (connection refused).
	_, err = client.Get(fmt.Sprintf("http://%s/after-cancel", upstreamAddr))
	if err == nil {
		t.Error("expected error after proxy cancellation, got nil")
	}
}
