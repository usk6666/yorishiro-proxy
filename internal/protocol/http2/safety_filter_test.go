package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newBlockEngine creates a safety engine with a single block rule matching the given pattern.
func newBlockEngine(t *testing.T, pattern string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{
			ID:      "test-block",
			Name:    "test block rule",
			Pattern: pattern,
			Targets: []string{"body", "url", "query"},
			Action:  "block",
		}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// newLogOnlyEngine creates a safety engine with a single log_only rule.
func newLogOnlyEngine(t *testing.T, pattern string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{
			ID:      "test-logonly",
			Name:    "test log_only rule",
			Pattern: pattern,
			Targets: []string{"body", "url", "query"},
			Action:  "log_only",
		}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestHTTP2SafetyFilter_BlocksMatchingRequest(t *testing.T) {
	// Upstream should never be reached.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		t.Error("upstream should not be reached for blocked requests")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-safety-h2c")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())
	body := "DROP TABLE users"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api", upstream.URL), bytes.NewReader([]byte(body)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Verify 403 response.
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Verify response headers.
	if got := resp.Header.Get("X-Blocked-By"); got != "yorishiro-proxy" {
		t.Errorf("X-Blocked-By = %q, want %q", got, "yorishiro-proxy")
	}
	if got := resp.Header.Get("X-Block-Reason"); got != "safety_filter" {
		t.Errorf("X-Block-Reason = %q, want %q", got, "safety_filter")
	}

	// Verify response body.
	bodyStr := string(respBody)
	for _, want := range []string{`"blocked_by":"safety_filter"`, `"rule":"test-block"`, `"error":"blocked by safety filter"`} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body missing %q: got %s", want, bodyStr)
		}
	}
}

func TestHTTP2SafetyFilter_LogOnlyPassesThrough(t *testing.T) {
	upstreamReached := false
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached = true
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newLogOnlyEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-safety-logonly")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())
	body := "DROP TABLE users"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api", upstream.URL), bytes.NewReader([]byte(body)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached {
		t.Error("upstream was not reached with log_only action")
	}
}

func TestHTTP2SafetyFilter_NoEnginePassesThrough(t *testing.T) {
	upstreamReached := false
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached = true
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// No safety engine set.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-safety-none")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())
	body := "DROP TABLE users"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api", upstream.URL), bytes.NewReader([]byte(body)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached {
		t.Error("upstream was not reached without safety engine")
	}
}
