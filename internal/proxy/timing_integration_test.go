//go:build e2e

package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ============================================================================
// Flow timing recording tests
// ============================================================================

func TestFlowTiming_HTTPSTimingRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream that introduces a small delay.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		time.Sleep(10 * time.Millisecond) // Small server-side delay.
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "timing-test-body")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/timing-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to be persisted.
	flows := pollFlows(t, ctx, store, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]

	// Verify timing fields are populated.
	if fl.SendMs == nil {
		t.Error("SendMs is nil, expected non-nil")
	}
	if fl.WaitMs == nil {
		t.Error("WaitMs is nil, expected non-nil")
	}
	if fl.ReceiveMs == nil {
		t.Error("ReceiveMs is nil, expected non-nil")
	}

	// All timing values should be non-negative.
	if fl.SendMs != nil && *fl.SendMs < 0 {
		t.Errorf("SendMs = %d, want >= 0", *fl.SendMs)
	}
	if fl.WaitMs != nil && *fl.WaitMs < 0 {
		t.Errorf("WaitMs = %d, want >= 0", *fl.WaitMs)
	}
	if fl.ReceiveMs != nil && *fl.ReceiveMs < 0 {
		t.Errorf("ReceiveMs = %d, want >= 0", *fl.ReceiveMs)
	}
}

func TestFlowTiming_ConsistencyCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream with a measurable delay.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		// Write a larger body to have non-zero receive time.
		fmt.Fprint(w, strings.Repeat("x", 1024))
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/consistency-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]

	// Verify timing values are present and consistent.
	if fl.SendMs == nil || fl.WaitMs == nil || fl.ReceiveMs == nil {
		t.Fatalf("timing fields: send=%v wait=%v receive=%v — expected all non-nil",
			fl.SendMs, fl.WaitMs, fl.ReceiveMs)
	}

	// The sum of send + wait + receive should approximately equal duration_ms.
	totalPhasesMs := *fl.SendMs + *fl.WaitMs + *fl.ReceiveMs
	durationMs := fl.Duration.Milliseconds()

	// Allow generous tolerance: the sum may differ from duration due to
	// proxy overhead, connection setup, etc. We just check the sum is
	// within 2x of the total duration and non-negative.
	if totalPhasesMs < 0 {
		t.Errorf("total phases = %d ms, want >= 0", totalPhasesMs)
	}
	if durationMs > 0 && totalPhasesMs > 2*durationMs+100 {
		t.Errorf("total phases (%d ms) significantly exceeds duration (%d ms)",
			totalPhasesMs, durationMs)
	}
}

func TestFlowTiming_HTTPTimingRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start plain HTTP upstream.
	upstream := gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprint(w, "http-timing-ok")
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() { upstream.Serve(ln) }()
	defer upstream.Close()

	upstreamAddr := ln.Addr().String()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)
	proxyListener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := proxyListener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-proxyListener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// HTTP client through the proxy.
	proxyURL, _ := url.Parse("http://" + proxyListener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{Proxy: gohttp.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/http-timing", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.StreamListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	// HTTP flows should also have timing.
	if fl.SendMs == nil {
		t.Error("SendMs is nil for HTTP flow")
	}
	if fl.WaitMs == nil {
		t.Error("WaitMs is nil for HTTP flow")
	}
	if fl.ReceiveMs == nil {
		t.Error("ReceiveMs is nil for HTTP flow")
	}
}

func TestFlowTiming_InHAR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "timing-har-test")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/timing-har", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]

	// Verify flow has timing data.
	if fl.SendMs == nil || fl.WaitMs == nil || fl.ReceiveMs == nil {
		t.Fatalf("timing fields missing: send=%v wait=%v receive=%v",
			fl.SendMs, fl.WaitMs, fl.ReceiveMs)
	}

	// Export as HAR and verify timings are reflected.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Timings == nil {
		t.Fatal("HAR timings is nil")
	}

	// HAR timings should reflect flow timing data (not -1 defaults).
	if entry.Timings.Send < 0 {
		t.Errorf("HAR timings.send = %f, want >= 0", entry.Timings.Send)
	}
	if entry.Timings.Wait < 0 {
		t.Errorf("HAR timings.wait = %f, want >= 0", entry.Timings.Wait)
	}
	if entry.Timings.Receive < 0 {
		t.Errorf("HAR timings.receive = %f, want >= 0", entry.Timings.Receive)
	}

	// HAR timings should match flow timing values.
	if entry.Timings.Send != float64(*fl.SendMs) {
		t.Errorf("HAR timings.send = %f, want %f", entry.Timings.Send, float64(*fl.SendMs))
	}
	if entry.Timings.Wait != float64(*fl.WaitMs) {
		t.Errorf("HAR timings.wait = %f, want %f", entry.Timings.Wait, float64(*fl.WaitMs))
	}
	if entry.Timings.Receive != float64(*fl.ReceiveMs) {
		t.Errorf("HAR timings.receive = %f, want %f", entry.Timings.Receive, float64(*fl.ReceiveMs))
	}
}
