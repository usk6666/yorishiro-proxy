//go:build e2e

package mcptest_test

import (
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ProxyStart_InterceptAndTransformRules_FromTool exercises
// scenario #6 from R3: proxy_start receives intercept_rules and
// auto_transform via JSON-RPC; live traffic is held by the rule;
// a transform rule rewrites a header on the way out; configure(merge)
// rotates the rule set and the change takes effect.
//
// This is the JSON-RPC wiring proof for intercept_rules / auto_transform —
// the in-memory tests cover the engines individually but never proved
// the full Streamable HTTP round-trip drives the real pipeline.
func TestE2E_ProxyStart_InterceptAndTransformRules_FromTool(t *testing.T) {
	upstreamAddr, upstreamObs := startObservedUpstream(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	proxyAddr := startProxyWithRules(t, h, []map[string]any{
		{
			"id":        "rule-old",
			"enabled":   true,
			"protocol":  "http",
			"direction": "request",
			"http": map[string]any{
				"path_pattern": "^/old/.*",
			},
		},
	}, []map[string]any{
		{
			"id":           "transform-1",
			"enabled":      true,
			"priority":     1,
			"direction":    "request",
			"path_pattern": ".*",
			"action_type":  "set_header",
			"header_name":  "X-Transformed",
			"header_value": "yes",
		},
	})

	// --- (1) Drive a request that matches rule-old; it must hold ---
	t.Run("rule_old_holds_request", func(t *testing.T) {
		client := proxyHTTPClient(t, proxyAddr)
		respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/old/item", upstreamAddr), nil, nil)

		entry := waitForHeldEntry(t, h, 5*time.Second)
		if got := entry["protocol"]; got != "http" {
			t.Fatalf("held entry protocol = %v, want http", got)
		}

		// Release with modify_and_forward — no change to headers, just
		// confirm the held envelope flows through.
		h.MustOK(t, "intercept", map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{
				"intercept_id": entry["id"],
			},
			"http": map[string]any{},
		})

		resp := <-respCh
		if resp.err != nil {
			t.Fatalf("proxied GET /old/item: %v", resp.err)
		}
		if resp.statusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.statusCode)
		}

		// --- Auto-transform proof: upstream observed X-Transformed: yes ---
		got := upstreamObs.lastHeaderValue("X-Transformed")
		if got != "yes" {
			t.Errorf("upstream X-Transformed = %q, want %q", got, "yes")
		}
	})

	// --- (2) Drive a request that does NOT match rule-old; passthrough ---
	t.Run("path_not_matching_passes_through", func(t *testing.T) {
		client := proxyHTTPClient(t, proxyAddr)
		resp := proxiedGet(t, client, fmt.Sprintf("http://%s/keep/it", upstreamAddr))
		if resp.statusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.statusCode)
		}
		// Auto-transform fires regardless of intercept rule.
		if got := upstreamObs.lastHeaderValue("X-Transformed"); got != "yes" {
			t.Errorf("upstream X-Transformed = %q, want %q (auto_transform applies to all)", got, "yes")
		}
	})

	// --- (3) Rotate rules: configure(merge) removes old, adds new ---
	t.Run("merge_rotates_rules", func(t *testing.T) {
		h.MustOK(t, "configure", map[string]any{
			"operation": "merge",
			"intercept_rules": map[string]any{
				"add": []map[string]any{
					{
						"id":        "rule-new",
						"enabled":   true,
						"protocol":  "http",
						"direction": "request",
						"http": map[string]any{
							"path_pattern": "^/new/.*",
						},
					},
				},
				"remove": []string{"rule-old"},
			},
		})

		// Old pattern should no longer hold.
		t.Run("old_pattern_passes_through", func(t *testing.T) {
			client := proxyHTTPClient(t, proxyAddr)
			start := time.Now()
			resp := proxiedGet(t, client, fmt.Sprintf("http://%s/old/item", upstreamAddr))
			if resp.statusCode != 200 {
				t.Fatalf("status = %d, want 200", resp.statusCode)
			}
			// If the request had been held, the response would not have
			// arrived in well under the configured timeout. We use a
			// generous bound (1s) because we want determinism, not a
			// race against the hold-queue timeout.
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Errorf("request took %v; expected fast passthrough", elapsed)
			}
			// And nothing should be queued.
			items := queryHeldItems(t, h)
			for _, it := range items {
				if id, _ := it["id"].(string); id != "" {
					t.Errorf("unexpected held item after rotate: %v", it)
				}
			}
		})

		// New pattern holds.
		t.Run("new_pattern_holds", func(t *testing.T) {
			client := proxyHTTPClient(t, proxyAddr)
			respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/new/item", upstreamAddr), nil, nil)
			entry := waitForHeldEntry(t, h, 5*time.Second)
			h.MustOK(t, "intercept", map[string]any{
				"action": "modify_and_forward",
				"params": map[string]any{
					"intercept_id": entry["id"],
				},
				"http": map[string]any{},
			})
			r := <-respCh
			if r.err != nil {
				t.Fatalf("proxied GET /new/item: %v", r.err)
			}
			if r.statusCode != 200 {
				t.Fatalf("status = %d, want 200", r.statusCode)
			}
		})
	})
}

// startProxyWithRules calls proxy_start with intercept rules and
// auto-transform rules, returning the resolved listen address. It
// t.Fatal's on missing fields.
func startProxyWithRules(t *testing.T, h *mcptest.Harness, intercept []map[string]any, transform []map[string]any) string {
	t.Helper()
	args := map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"intercept_rules": intercept,
		"auto_transform":  transform,
	}
	res := h.MustOK(t, "proxy_start", args)
	addr, ok := res.Decoded["listen_addr"].(string)
	if !ok || addr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %+v", res.Decoded)
	}
	return addr
}

// queryHeldItems lists currently held envelopes via the intercept_queue
// resource. Returns an empty slice when nothing is held.
func queryHeldItems(t *testing.T, h *mcptest.Harness) []map[string]any {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "intercept_queue"})
	rawItems, _ := res.Decoded["items"].([]any)
	out := make([]map[string]any, 0, len(rawItems))
	for _, it := range rawItems {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// waitForHeldEntry polls intercept_queue until at least one entry is
// present. t.Fatal's on timeout.
func waitForHeldEntry(t *testing.T, h *mcptest.Harness, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		items := queryHeldItems(t, h)
		if len(items) > 0 {
			return items[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for held entry within %v", timeout)
	return nil
}

// observedUpstream is a plain HTTP test server that records the headers
// of the most recent request it served. The tests use it to assert that
// auto-transform / intercept modifications survive end-to-end through
// the proxy on the way to the upstream.
type observedUpstream struct {
	mu       atomic.Pointer[gohttp.Header]
	hits     atomic.Int64
	bodyBuf  atomic.Pointer[[]byte]
	server   *gohttp.Server
	listener net.Listener
}

func (o *observedUpstream) lastHeaderValue(name string) string {
	h := o.mu.Load()
	if h == nil {
		return ""
	}
	return h.Get(name)
}

func (o *observedUpstream) hitCount() int64 { return o.hits.Load() }

func (o *observedUpstream) lastBody() []byte {
	bp := o.bodyBuf.Load()
	if bp == nil {
		return nil
	}
	return *bp
}

// startObservedUpstream starts a plain HTTP/1.1 server that records the
// last request's headers and body. Unlike httptest.NewServer the body
// is captured before the response is written; the headers are stored as
// a defensive clone.
func startObservedUpstream(t *testing.T) (string, *observedUpstream) {
	t.Helper()
	obs := &observedUpstream{}
	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		hdr := r.Header.Clone()
		obs.mu.Store(&hdr)
		obs.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		obs.bodyBuf.Store(&body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok path=%s body=%s", r.URL.Path, body)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &gohttp.Server{Handler: handler}
	obs.server = server
	obs.listener = listener
	go server.Serve(listener)
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})
	return listener.Addr().String(), obs
}

// proxyHTTPClient builds an HTTP client that routes through the given
// proxy address. Disabled keep-alive avoids leaking goroutines on test
// teardown.
func proxyHTTPClient(t *testing.T, proxyAddr string) *gohttp.Client {
	t.Helper()
	pURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy:             gohttp.ProxyURL(pURL),
			DisableKeepAlives: true,
		},
		Timeout: 15 * time.Second,
	}
}

// proxiedResponse captures the result of a request issued via
// requestThroughProxy. statusCode is 0 on transport failure.
type proxiedResponse struct {
	statusCode int
	body       []byte
	headers    gohttp.Header
	err        error
}

// requestThroughProxy issues an HTTP request through the proxy in a
// goroutine, returning a channel that receives the response (or error).
// Used when the test needs to interleave the request with intercept
// tooling — the response stays pending until intercept releases it.
func requestThroughProxy(t *testing.T, client *gohttp.Client, method, target string, headers gohttp.Header, body []byte) chan proxiedResponse {
	t.Helper()
	out := make(chan proxiedResponse, 1)
	go func() {
		defer close(out)
		var bodyReader io.Reader
		if body != nil {
			bodyReader = strings.NewReader(string(body))
		}
		req, err := gohttp.NewRequest(method, target, bodyReader)
		if err != nil {
			out <- proxiedResponse{err: fmt.Errorf("new request: %w", err)}
			return
		}
		for k, vv := range headers {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			out <- proxiedResponse{err: err}
			return
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		out <- proxiedResponse{
			statusCode: resp.StatusCode,
			body:       respBody,
			headers:    resp.Header.Clone(),
			err:        err,
		}
	}()
	return out
}

// proxiedGet performs a single proxied GET and returns the response.
// Used for passthrough assertions where no intercept hold is expected.
func proxiedGet(t *testing.T, client *gohttp.Client, target string) proxiedResponse {
	t.Helper()
	respCh := requestThroughProxy(t, client, "GET", target, nil, nil)
	select {
	case r := <-respCh:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for proxied GET %q", target)
		return proxiedResponse{}
	}
}
