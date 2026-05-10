package mcp

// ratelimit_dispatch_test.go — USK-817 regression coverage. Verifies that
// the typed resend / fuzz dispatch loops consult the agent rate limiter
// before each upstream send. Without these checks, AI agents could bypass
// security.set_rate_limits by issuing fuzz variants in quick succession.
//
// The fuzz_http path is the live-bug reproducer (Phase 5 retest P5-18). The
// remaining 7 sites (fuzz_ws / fuzz_grpc / fuzz_raw / resend_http / resend_ws
// / resend_grpc / resend_raw) are covered by a smaller unit-level assertion
// that the shared `waitRateLimit` helper returns nil when the limiter has
// no limits and propagates ctx cancellation when it does.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// startRateLimitEcho returns a hermetic HTTP echo server. Used by the
// fuzz_http pacing regression test.
func startRateLimitEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setupRateLimitFuzzSession spins up an MCP server with the supplied
// RateLimiter wired in. Mirrors setupSecurityRateLimitTestSession but also
// exposes the server to fuzz_http.
func setupRateLimitFuzzSession(t *testing.T, rl *connector.RateLimiter) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	store := newTestStore(t)
	srv := newServer(ctx, nil, store, nil, WithRateLimiter(rl))
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "ratelimit-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// TestFuzzHTTP_RespectsAgentRateLimit is the USK-817 live-bug reproducer.
// Under set_rate_limits { max_requests_per_second: 1 }, running fuzz_http
// with N variants must elapse roughly (N - burst) seconds — not all-at-once.
//
// We use a small N and a relatively high RPS so the lower-bound assertion
// stays well under the unit-tier budget. With rate=10/s and burst=11, 16
// variants must take at least (16-11)/10 = 500ms; we assert >=300ms to
// leave generous headroom for scheduler jitter.
func TestFuzzHTTP_RespectsAgentRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pacing assertion under -short")
	}
	echo := startRateLimitEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{
		MaxRequestsPerSecond: 10,
	})
	cs := setupRateLimitFuzzSession(t, rl)

	const variants = 16
	payloads := make([]string, variants)
	for i := range payloads {
		payloads[i] = "p" + string(rune('a'+i))
	}

	start := time.Now()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/seed",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "raw_query", "payloads": payloads},
			},
			"timeout_ms": 5000,
		},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}

	// Assert the request actually completed all variants.
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out fuzzHTTPResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	if out.CompletedVariants != variants {
		t.Errorf("CompletedVariants = %d, want %d", out.CompletedVariants, variants)
	}

	// Burst absorbs (rate+1)=11 immediate calls; the remaining 5 are paced
	// at 10/s, so elapsed >= 500ms in theory. We assert >=300ms to absorb
	// rate.Limiter's internal scheduling slack while still failing the
	// pre-fix bug (~tens of ms).
	const minElapsed = 300 * time.Millisecond
	if elapsed < minElapsed {
		t.Errorf("fuzz_http elapsed = %v, want >= %v under 10 RPS / %d variants — rate limit appears to be bypassed",
			elapsed, minElapsed, variants)
	}
}

// TestServer_WaitRateLimit_NoOp asserts the shared helper is a no-op when
// no rate limiter is wired (all 8 dispatch sites must remain functional
// when the agent has not configured rate limits, which is the default).
func TestServer_WaitRateLimit_NoOp(t *testing.T) {
	s := &Server{misc: &Misc{}}
	if err := s.waitRateLimit(context.Background(), "example.com"); err != nil {
		t.Errorf("waitRateLimit with nil rateLimiter returned %v, want nil", err)
	}
}

// TestServer_WaitRateLimit_NoLimits asserts the shared helper is a no-op
// when the rate limiter is wired but has no limits configured. This is
// the production default before the agent calls set_rate_limits.
func TestServer_WaitRateLimit_NoLimits(t *testing.T) {
	rl := connector.NewRateLimiter()
	s := &Server{misc: &Misc{rateLimiter: rl}}
	// Even with an already-cancelled ctx, waitRateLimit must not call into
	// rate.Limiter.Wait when no limits are configured.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.waitRateLimit(ctx, "example.com"); err != nil {
		t.Errorf("waitRateLimit with no limits returned %v, want nil", err)
	}
}

// TestServer_WaitRateLimit_PropagatesCtxCancellation asserts the shared
// helper surfaces ctx cancellation as a wrapped error so the dispatch
// loops can return promptly. This is the contract the variant-loop
// `<-ctx.Done()` checks rely on.
func TestServer_WaitRateLimit_PropagatesCtxCancellation(t *testing.T) {
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 1})
	s := &Server{misc: &Misc{rateLimiter: rl}}

	bg := context.Background()
	// Drain the burst (rate=1, burst=2).
	if err := s.waitRateLimit(bg, "example.com"); err != nil {
		t.Fatalf("drain[0]: %v", err)
	}
	if err := s.waitRateLimit(bg, "example.com"); err != nil {
		t.Fatalf("drain[1]: %v", err)
	}

	ctx, cancel := context.WithTimeout(bg, 30*time.Millisecond)
	defer cancel()
	err := s.waitRateLimit(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error from cancelled ctx, got nil")
	}
	// rate.Limiter.Wait surfaces short deadlines either as a wrapped ctx
	// error or as a "would exceed context deadline" sentinel. Either form
	// indicates Wait did not silently allow the request, which is the
	// dispatch-loop contract we care about.
	if !errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(err, context.Canceled) &&
		!strings.Contains(err.Error(), "would exceed context deadline") {
		t.Errorf("error = %v, want ctx cancellation or budget-exhaustion message", err)
	}
}
