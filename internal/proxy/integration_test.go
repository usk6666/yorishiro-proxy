package proxy_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
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

// maxBodyRecordSize mirrors the constant from the HTTP handler (1MB).
const maxBodyRecordSize = 1 << 20

func TestIntegration_LargeBodyBoundary_HTTP(t *testing.T) {
	tests := []struct {
		name string
		// bodySize is the size of the request body to send.
		bodySize int
		// wantReqTruncated is whether the recorded request body should be truncated.
		wantReqTruncated bool
		// wantRespTruncated is whether the recorded response body should be truncated.
		wantRespTruncated bool
		// wantRecordedReqLen is the expected length of the recorded request body.
		wantRecordedReqLen int
		// wantRecordedRespLen is the expected length of the recorded response body.
		wantRecordedRespLen int
		// timeout is the context timeout for this test case.
		timeout time.Duration
	}{
		{
			name:                "empty body",
			bodySize:            0,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  0,
			wantRecordedRespLen: 0,
			timeout:             15 * time.Second,
		},
		{
			name:                "body exactly 1MB",
			bodySize:            maxBodyRecordSize,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             30 * time.Second,
		},
		{
			name:                "body 1MB plus 1 byte",
			bodySize:            maxBodyRecordSize + 1,
			wantReqTruncated:    true,
			wantRespTruncated:   true,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             30 * time.Second,
		},
		{
			name:                "very large body 2MB",
			bodySize:            2 * maxBodyRecordSize,
			wantReqTruncated:    true,
			wantRespTruncated:   true,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             60 * time.Second,
		},
		{
			name:                "very large body 10MB",
			bodySize:            10 * maxBodyRecordSize,
			wantReqTruncated:    true,
			wantRespTruncated:   true,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             120 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			// Start upstream echo server: responds with the same body it received.
			upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(gohttp.StatusOK)
				io.Copy(w, r.Body)
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
			defer proxyCancel()

			client := proxyClient(listener.Addr())
			client.Timeout = tt.timeout

			// Generate deterministic test data using a repeating pattern.
			var reqBody []byte
			if tt.bodySize > 0 {
				reqBody = bytes.Repeat([]byte("A"), tt.bodySize)
			}

			// Send POST request through the proxy.
			targetURL := fmt.Sprintf("http://%s/large-body-test", upstreamAddr)
			resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("POST through proxy: %v", err)
			}
			defer resp.Body.Close()

			// Verify the full response body was transferred correctly (not truncated in transit).
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
			}
			if len(respBody) != tt.bodySize {
				t.Errorf("response body length = %d, want %d (transfer should not truncate)", len(respBody), tt.bodySize)
			}
			if tt.bodySize > 0 && !bytes.Equal(respBody, reqBody) {
				t.Error("response body content differs from request body (transfer corruption)")
			}

			// Poll for session to be persisted (large bodies may take longer to save).
			var entries []*session.Entry
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				entries, err = store.List(ctx, session.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("List sessions: %v", err)
				}
				if len(entries) == 1 {
					break
				}
			}
			if len(entries) != 1 {
				t.Fatalf("expected 1 session, got %d", len(entries))
			}

			entry := entries[0]

			// Verify request body recording.
			if len(entry.Request.Body) != tt.wantRecordedReqLen {
				t.Errorf("recorded request body length = %d, want %d", len(entry.Request.Body), tt.wantRecordedReqLen)
			}
			if entry.Request.BodyTruncated != tt.wantReqTruncated {
				t.Errorf("request BodyTruncated = %v, want %v", entry.Request.BodyTruncated, tt.wantReqTruncated)
			}

			// Verify response body recording.
			if len(entry.Response.Body) != tt.wantRecordedRespLen {
				t.Errorf("recorded response body length = %d, want %d", len(entry.Response.Body), tt.wantRecordedRespLen)
			}
			if entry.Response.BodyTruncated != tt.wantRespTruncated {
				t.Errorf("response BodyTruncated = %v, want %v", entry.Response.BodyTruncated, tt.wantRespTruncated)
			}

			// When truncated, verify the recorded body is the prefix of the original.
			if tt.wantReqTruncated && tt.bodySize > 0 {
				if !bytes.Equal(entry.Request.Body, reqBody[:maxBodyRecordSize]) {
					t.Error("truncated request body is not a prefix of the original body")
				}
			}
			if tt.wantRespTruncated && tt.bodySize > 0 {
				if !bytes.Equal(entry.Response.Body, reqBody[:maxBodyRecordSize]) {
					t.Error("truncated response body is not a prefix of the original body")
				}
			}

			// Verify metadata.
			if entry.Protocol != "HTTP/1.x" {
				t.Errorf("protocol = %q, want %q", entry.Protocol, "HTTP/1.x")
			}
			if entry.Request.Method != "POST" {
				t.Errorf("method = %q, want %q", entry.Request.Method, "POST")
			}
			if entry.Response.StatusCode != 200 {
				t.Errorf("status code = %d, want %d", entry.Response.StatusCode, 200)
			}
		})
	}
}
