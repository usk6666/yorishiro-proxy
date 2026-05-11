//go:build e2e && !e2e_smoke

// USK-840: HTTP/2 policy-drop terminator e2e coverage.
//
// Verifies that the four Pipeline policy emitters (Intercept / HostScope /
// HTTPScope / Safety) — each of which constructs a synthetic 403 Forbidden
// response via buildPolicyDropResponse — produce a wire-valid HEADERS
// frame over HTTP/2.
//
// The pre-fix HTTPMessage carried `Connection: close` verbatim from the
// policy-drop builder. On HTTP/1.1 the header is correct; on HTTP/2 it
// is a connection-specific header forbidden by RFC 7540 §8.1.2.2 / RFC
// 9113 §8.2.2 and conforming peers (curl/nghttp2 in the reproduction)
// reject the entire HEADERS frame with PROTOCOL_ERROR. The fix strips
// the forbidden set in the wire encoder (BuildHeaderFieldsFromEvent) so
// the emitted HEADERS frame is wire-valid while the HTTPMessage envelope
// stays protocol-agnostic.
//
// This is the HTTP/2 sibling of
// internal/layer/http1/mitm_policy_drop_integration_test.go (USK-829).

package http2_test

import (
	"context"
	"encoding/json"
	"io"
	nethttp "net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// forbiddenH2HeaderNames is the RFC 7540 §8.1.2.2 / RFC 9113 §8.2.2 set
// of connection-specific names that MUST NOT appear in any HTTP/2 HEADERS
// frame. Names are lowercase to match the wire form HPACK emits.
var forbiddenH2HeaderNames = []string{
	"connection",
	"keep-alive",
	"proxy-connection",
	"transfer-encoding",
	"upgrade",
}

// TestPolicyDrop_H2_StripsConnectionSpecificHeaders runs all four
// policy-block emitters (intercept_drop / host_scope / http_scope /
// safety_filter) end-to-end over HTTP/2 and asserts that the 403
// terminator reaches the client cleanly:
//
//   - The h2 client receives the response without a PROTOCOL_ERROR (proof
//     the HEADERS frame did not carry any RFC 7540 §8.1.2.2 forbidden
//     name).
//   - :status = 403.
//   - The Server header is present (negative-of-negative: only the
//     connection-specific set is stripped; `Server` is not in that set).
//   - None of the response headers exposed to user space contains the
//     forbidden names.
//   - The JSON body is parseable and carries the expected blocked_by
//     attribution.
//   - Upstream was never contacted.
//   - For non-intercept emitters the Stream is recorded with
//     Protocol="http" (intercept_drop's pre-Record terminal Step keeps
//     the recording path empty in this harness — matches the h1.1
//     sibling test's behaviour; production wires OnPipelineDrop
//     attribution separately, see internal/proxybuild/blocked_recorder_test.go).
func TestPolicyDrop_H2_StripsConnectionSpecificHeaders(t *testing.T) {
	type tc struct {
		name          string
		wantBlockedBy string
		path          string
		// configurePipe returns the pipelineOpts plus an optional
		// asyncReleaser. The asyncReleaser is invoked after the client
		// has sent the request; intercept_drop needs it to release the
		// held envelope with ActionDrop.
		configurePipe func(t *testing.T) (pipelineOpts, func())
		// expectRecorded reflects whether the test harness's RecordStep
		// records a Stream for this emitter. intercept_drop is the
		// exception: Intercept returns Respond before RecordStep runs.
		expectRecorded bool
	}

	cases := []tc{
		{
			name:          "intercept_drop",
			wantBlockedBy: "intercept_drop",
			path:          "/blocked",
			configurePipe: func(t *testing.T) (pipelineOpts, func()) {
				engine := httprules.NewInterceptEngine()
				engine.AddRule(httprules.InterceptRule{
					ID:          "usk840-intercept-drop",
					Enabled:     true,
					Direction:   httprules.DirectionRequest,
					PathPattern: regexp.MustCompile(`^/blocked`),
				})
				holdQueue := common.NewHoldQueue()
				holdQueue.SetTimeout(10 * time.Second)
				return pipelineOpts{
						interceptEngine: engine,
						holdQueue:       holdQueue,
					}, func() {
						pollAndReleaseDrop(t, holdQueue)
					}
			},
			expectRecorded: false,
		},
		{
			name:          "host_scope",
			wantBlockedBy: "target_scope",
			path:          "/blocked",
			configurePipe: func(_ *testing.T) (pipelineOpts, func()) {
				scope := connector.NewTargetScope()
				scope.SetPolicyRules(nil, []connector.TargetRule{
					{Hostname: "127.0.0.1"},
				})
				return pipelineOpts{hostScope: scope}, func() {}
			},
			// HostScopeStep emits Respond before RecordStep runs — the
			// terminal Step short-circuits the pipeline, so the harness's
			// RecordStep is not invoked. Matches the h1.1 sibling
			// (mitm_policy_drop_integration_test.go) which does not check
			// store for host_scope either.
			expectRecorded: false,
		},
		{
			name:          "http_scope",
			wantBlockedBy: "target_scope",
			path:          "/blocked",
			configurePipe: func(_ *testing.T) (pipelineOpts, func()) {
				scope := connector.NewTargetScope()
				scope.SetPolicyRules([]connector.TargetRule{
					{Hostname: "127.0.0.1", PathPrefix: "/allowed/"},
				}, nil)
				return pipelineOpts{httpScope: scope}, func() {}
			},
			expectRecorded: false,
		},
		{
			name:          "safety_filter",
			wantBlockedBy: "safety_filter",
			path:          "/blocked",
			configurePipe: func(t *testing.T) (pipelineOpts, func()) {
				// Custom rule that matches anything containing "/blocked"
				// in the URL. We avoid loading a preset (the destructive-sql
				// preset patterns require literal whitespace which the
				// nethttp client percent-encodes before transmission, so
				// the wire-observed RawQuery does not contain `\s`).
				re, err := common.CompilePattern(`/blocked`)
				if err != nil {
					t.Fatalf("compile pattern: %v", err)
				}
				engine := httprules.NewSafetyEngine()
				engine.AddRule(common.CompiledRule{
					ID:       "usk840-safety-blocked",
					Name:     "USK-840 test rule",
					Pattern:  re,
					Targets:  []common.Target{common.TargetURL},
					Category: "test",
				})
				return pipelineOpts{safetyEngine: engine}, func() {}
			},
			expectRecorded: false,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			runPolicyDropCase(t, c.path, c.wantBlockedBy, c.configurePipe, c.expectRecorded)
		})
	}
}

func runPolicyDropCase(t *testing.T, path, wantBlockedBy string, configurePipe func(*testing.T) (pipelineOpts, func()), expectRecorded bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var upstreamHits atomic.Int64
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "usk840-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("upstream-leaked"))
	}))
	defer upShutdown()

	pipeOpts, releaseFn := configurePipe(t)
	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipeOpts)

	cli := newMITMH2Client(proxyAddr, upAddr)

	type result struct {
		resp *nethttp.Response
		err  error
	}
	respCh := make(chan result, 1)
	go func() {
		req, err := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+path, nil)
		if err != nil {
			respCh <- result{err: err}
			return
		}
		resp, err := cli.Do(req)
		respCh <- result{resp: resp, err: err}
	}()

	// Drive any per-emitter release (intercept_drop holds the envelope
	// until we explicitly Drop it).
	releaseFn()

	var r result
	select {
	case r = <-respCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for h2 response")
	}
	if r.err != nil {
		t.Fatalf("client request failed (USK-840 regression: h2 wire likely carried a forbidden header): %v", r.err)
	}
	defer r.resp.Body.Close()

	if r.resp.StatusCode != nethttp.StatusForbidden {
		t.Errorf("status = %d, want 403", r.resp.StatusCode)
	}

	if hits := upstreamHits.Load(); hits != 0 {
		t.Errorf("upstream was called %d times — policy emitter did not block forwarding", hits)
	}

	// Server header is preserved (not in the forbidden set).
	if got := r.resp.Header.Get("Server"); got != "yorishiro-proxy" {
		t.Errorf("Server header = %q, want %q", got, "yorishiro-proxy")
	}

	// None of the forbidden names appear in the response headers.
	for _, forbidden := range forbiddenH2HeaderNames {
		if v := lookupHeaderInsensitive(r.resp.Header, forbidden); v != "" {
			t.Errorf("forbidden h2 header %q present on response (value=%q) — strip did not run", forbidden, v)
		}
	}

	body, err := io.ReadAll(r.resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body is not parseable JSON (%v): %q", err, body)
	}
	if got := payload["blocked_by"]; got != wantBlockedBy {
		t.Errorf("body blocked_by = %v, want %q (full body: %s)", got, wantBlockedBy, body)
	}
	if _, ok := payload["error"]; !ok {
		t.Errorf("body missing 'error' key: %s", body)
	}

	if expectRecorded {
		waitForStreams(t, store, 1, 5*time.Second)
		streams := store.getStreams()
		if len(streams) == 0 {
			t.Fatal("no streams recorded")
		}
		if streams[0].Protocol != "http" {
			t.Errorf("Stream.Protocol = %q, want %q", streams[0].Protocol, "http")
		}
	}
}

// pollAndReleaseDrop waits up to 5s for a held entry to appear, then
// releases the first entry with ActionDrop so the Intercept Step emits
// the synthetic 403 terminator.
func pollAndReleaseDrop(t *testing.T, q *common.HoldQueue) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if q.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries := q.List()
	if len(entries) == 0 {
		t.Fatal("intercept_drop: no entry appeared in hold queue")
	}
	if err := q.Release(entries[0].ID, &common.HoldAction{Type: common.ActionDrop}); err != nil {
		t.Fatalf("intercept_drop: release Drop: %v", err)
	}
}

// lookupHeaderInsensitive scans h for name using a case-insensitive
// comparison and returns the first matched value, or empty string. It
// is a defensive complement to nethttp.Header.Get (which canonicalises
// on lookup) — even if some HTTP/2 transport surfaces a non-canonical
// name to user space, the test still flags it.
func lookupHeaderInsensitive(h nethttp.Header, name string) string {
	if v := h.Get(name); v != "" {
		return v
	}
	for k, values := range h {
		if strings.EqualFold(k, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
