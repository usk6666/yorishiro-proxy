package proxy_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
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

func TestIntegration_ConcurrentClients_HTTP(t *testing.T) {
	const numClients = 15

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream HTTP server that echoes a unique identifier back.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "echo:%s:%s", r.URL.Path, string(body))
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

	// Launch concurrent clients, each sending a unique request.
	var wg sync.WaitGroup
	wg.Add(numClients)

	for i := 0; i < numClients; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine creates its own HTTP client (separate connection).
			client := proxyClient(listener.Addr())

			path := fmt.Sprintf("/concurrent/%d", id)
			reqBody := fmt.Sprintf(`{"client":%d}`, id)
			targetURL := fmt.Sprintf("http://%s%s", upstreamAddr, path)

			resp, err := client.Post(targetURL, "application/json", strings.NewReader(reqBody))
			if err != nil {
				t.Errorf("client %d: POST through proxy: %v", id, err)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("client %d: status = %d, want %d", id, resp.StatusCode, gohttp.StatusOK)
			}

			expectedBody := fmt.Sprintf("echo:%s:%s", path, reqBody)
			if string(body) != expectedBody {
				t.Errorf("client %d: body = %q, want %q", id, body, expectedBody)
			}
		}(i)
	}

	wg.Wait()

	// Wait for all sessions to be persisted.
	time.Sleep(500 * time.Millisecond)

	// Verify all sessions were recorded.
	entries, err := store.List(ctx, session.ListOptions{Limit: numClients + 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != numClients {
		t.Fatalf("expected %d sessions, got %d", numClients, len(entries))
	}

	// Verify each client's session is distinct and data is not mixed.
	seenPaths := make(map[string]bool)
	seenBodies := make(map[string]bool)
	for _, entry := range entries {
		if entry.Protocol != "HTTP/1.x" {
			t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTP/1.x")
		}
		if entry.Request.Method != "POST" {
			t.Errorf("session method = %q, want %q", entry.Request.Method, "POST")
		}
		if entry.Request.URL == nil {
			t.Error("request URL is nil")
			continue
		}

		path := entry.Request.URL.Path
		seenPaths[path] = true

		// Verify request body matches the path (no cross-contamination).
		// Path is /concurrent/<id>, body is {"client":<id>}.
		// Extract the ID from the path and verify it matches the body.
		var pathID int
		if _, err := fmt.Sscanf(path, "/concurrent/%d", &pathID); err != nil {
			t.Errorf("unexpected path format: %q", path)
			continue
		}
		expectedReqBody := fmt.Sprintf(`{"client":%d}`, pathID)
		if string(entry.Request.Body) != expectedReqBody {
			t.Errorf("session path %s: request body = %q, want %q (data mixed between sessions)",
				path, entry.Request.Body, expectedReqBody)
		}

		// Verify response body matches.
		expectedRespBody := fmt.Sprintf("echo:%s:%s", path, expectedReqBody)
		if string(entry.Response.Body) != expectedRespBody {
			t.Errorf("session path %s: response body = %q, want %q (data mixed between sessions)",
				path, entry.Response.Body, expectedRespBody)
		}

		seenBodies[string(entry.Request.Body)] = true

		if entry.Response.StatusCode != 200 {
			t.Errorf("session path %s: status = %d, want %d", path, entry.Response.StatusCode, 200)
		}
		if entry.ID == "" {
			t.Errorf("session path %s: ID is empty", path)
		}
		if entry.Duration < 0 {
			t.Errorf("session path %s: duration = %v, want non-negative", path, entry.Duration)
		}
	}

	// Verify all unique paths were recorded (no duplicates, no missing).
	if len(seenPaths) != numClients {
		t.Errorf("expected %d unique paths, got %d", numClients, len(seenPaths))
	}
	for i := 0; i < numClients; i++ {
		expectedPath := fmt.Sprintf("/concurrent/%d", i)
		if !seenPaths[expectedPath] {
			t.Errorf("missing session for path %q", expectedPath)
		}
	}
}
