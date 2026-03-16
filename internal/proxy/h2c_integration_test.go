//go:build e2e

package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startH2CProxy creates and starts a proxy that supports both HTTP/1.x and h2c.
func startH2CProxy(t *testing.T, ctx context.Context, store flow.Store) (*proxy.Listener, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	h2Handler := protohttp2.NewHandler(store, logger)
	detector := protocol.NewDetector(h2Handler, httpHandler)
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

// startH2CUpstream creates a test HTTP/2 cleartext (h2c) server.
func startH2CUpstream(t *testing.T, handler gohttp.Handler) (string, func()) {
	t.Helper()

	protos := &gohttp.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &gohttp.Server{
		Handler:   handler,
		Protocols: protos,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go server.Serve(ln)

	return ln.Addr().String(), func() {
		server.Close()
	}
}

func TestIntegration_H2C_GET(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start h2c upstream.
	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from h2c upstream")
	}))
	defer closeUpstream()

	// Create SQLite store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Start proxy.
	listener, proxyCancel := startH2CProxy(t, ctx, store)
	defer proxyCancel()

	// Create h2c client that connects through the proxy.
	// For h2c, the client sends the HTTP/2 preface directly.
	proxyAddr := listener.Addr()
	h2cProtos := &gohttp.Protocols{}
	h2cProtos.SetUnencryptedHTTP2(true)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: h2cProtos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Connect to the proxy instead of the upstream.
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/test-h2c", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from h2c upstream" {
		t.Errorf("body = %q, want %q", body, "hello from h2c upstream")
	}

	// Verify flow recording.
	var flows []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) > 0 {
			break
		}
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded for h2c request")
	}

	found := false
	for _, f := range flows {
		if strings.Contains(f.Protocol, "HTTP/2") || strings.Contains(f.Protocol, "h2c") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected HTTP/2 flow, got protocols: %v", func() []string {
			var ps []string
			for _, f := range flows {
				ps = append(ps, f.Protocol)
			}
			return ps
		}())
	}
}

func TestIntegration_H2C_POST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "echo: %s", body)
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startH2CProxy(t, ctx, store)
	defer proxyCancel()

	proxyAddr := listener.Addr()
	client := &gohttp.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/test-post", upstreamAddr)
	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("h2c body"))
	if err != nil {
		t.Fatalf("h2c POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "echo: h2c body" {
		t.Errorf("body = %q, want %q", body, "echo: h2c body")
	}

	// Verify flow recording.
	var flows []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) > 0 {
			break
		}
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded for h2c POST request")
	}
}

func TestIntegration_H2C_ConcurrentStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startH2CProxy(t, ctx, store)
	defer proxyCancel()

	proxyAddr := listener.Addr()
	client := &gohttp.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 10 * time.Second,
	}

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			targetURL := fmt.Sprintf("http://%s/stream/%d", upstreamAddr, n)
			resp, err := client.Get(targetURL)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", n, err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			expected := fmt.Sprintf("path=/stream/%d", n)
			if string(body) != expected {
				errs <- fmt.Errorf("stream %d: body = %q, want %q", n, body, expected)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Wait for flows to be recorded.
	var flows []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= concurrency {
			break
		}
	}
	if len(flows) < concurrency {
		t.Errorf("expected at least %d flows, got %d", concurrency, len(flows))
	}
}
