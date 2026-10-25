//go:build e2e && !e2e_smoke

package mcp

// resend_cancel_finalize_integration_test.go — USK-1370 coverage: when the
// MCP client cancels a resend_* / fuzz_* call, the go-sdk cancels the
// handler ctx. The Stream RecordStep already created must still receive
// its terminal write (State="error", tags["tag"], tags["error"],
// Duration) instead of staying State="active".
//
// Raw tools are deliberately not covered: with >= 1 chunk received they
// record "complete" on caller cancel (collect-until-timeout semantics).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// startBlockingHTTPServer is an HTTP upstream whose handler signals
// arrived (non-blocking) and then blocks until the test ends, so the
// caller's request is in flight when the test cancels it.
func startBlockingHTTPServer(t *testing.T) (authority string, arrived <-chan struct{}) {
	t.Helper()
	arrivedCh := make(chan struct{}, 16)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrivedCh <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanups run LIFO: release the handlers before srv.Close waits on them.
	t.Cleanup(srv.Close)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	return strings.TrimPrefix(srv.URL, "http://"), arrivedCh
}

// waitOriginStreamsSettled polls until at least one Stream with origin
// exists and none of them is State="active", or the deadline passes. It
// returns the last observed set.
func waitOriginStreamsSettled(t *testing.T, store flow.Store, origin flow.Origin) []*flow.Stream {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		streams, err := store.ListStreams(context.Background(), flow.StreamListOptions{})
		if err != nil {
			t.Fatalf("ListStreams: %v", err)
		}
		var found []*flow.Stream
		active := false
		for _, s := range streams {
			if s.Origin != origin {
				continue
			}
			found = append(found, s)
			if s.State == "active" {
				active = true
			}
		}
		if (len(found) > 0 && !active) || time.Now().After(deadline) {
			return found
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertCancelFinalized checks st was finalised as a failure carrying the
// user's tag, the error text, and a real Duration.
func assertCancelFinalized(t *testing.T, st *flow.Stream, wantTag string) {
	t.Helper()
	if st.State != "error" {
		t.Errorf("Stream %s State = %q, want error (finalize must survive caller cancel; tags=%v)", st.ID, st.State, st.Tags)
	}
	if st.Tags["tag"] != wantTag {
		t.Errorf("Stream %s tags[\"tag\"] = %q, want %q (tags=%v)", st.ID, st.Tags["tag"], wantTag, st.Tags)
	}
	if st.Tags["error"] == "" {
		t.Errorf("Stream %s tags[\"error\"] missing (tags=%v); want the cancellation error text", st.ID, st.Tags)
	}
	if st.Duration <= 0 {
		t.Errorf("Stream %s Duration = %v, want > 0", st.ID, st.Duration)
	}
}

// TestResendHTTP_CallerCancel_FinalizesStream: a caller cancel mid-
// resend_http must still end the Stream as "error" with tag + error tags.
func TestResendHTTP_CallerCancel_FinalizesStream(t *testing.T) {
	cs, store, _, _ := setupResendHTTPSession(t)
	authority, arrived := startBlockingHTTPServer(t)

	callCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-arrived:
			cancel()
		case <-callCtx.Done():
		}
	}()

	_, _ = cs.CallTool(callCtx, &gomcp.CallToolParams{
		Name: "resend_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"tag":        "usk-1370",
			"timeout_ms": 30000,
		},
	})

	streams := waitOriginStreamsSettled(t, store, flow.OriginResend)
	if len(streams) != 1 {
		t.Fatalf("found %d Origin=resend Streams, want 1", len(streams))
	}
	assertCancelFinalized(t, streams[0], "usk-1370")
}

// TestFuzzHTTP_CallerCancel_FinalizesInFlightVariant: a caller cancel
// mid-fuzz_http must finalise the in-flight variant's Stream; no
// Origin=fuzz Stream may remain "active".
func TestFuzzHTTP_CallerCancel_FinalizesInFlightVariant(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)
	authority, arrived := startBlockingHTTPServer(t)

	callCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-arrived:
			cancel()
		case <-callCtx.Done():
		}
	}()

	_, _ = cs.CallTool(callCtx, &gomcp.CallToolParams{
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
				{"path": "path", "payloads": []string{"/v1", "/v2", "/v3"}},
			},
			"tag":        "usk-1370-fuzz",
			"timeout_ms": 30000,
		},
	})

	streams := waitOriginStreamsSettled(t, store, flow.OriginFuzz)
	if len(streams) == 0 {
		t.Fatal("found no Origin=fuzz Streams; want the in-flight variant's Stream")
	}
	for _, st := range streams {
		assertCancelFinalized(t, st, "usk-1370-fuzz")
	}
}
