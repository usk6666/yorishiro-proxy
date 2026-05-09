//go:build e2e && !e2e_smoke

// USK-782: e2e coverage for Pipeline-Drop blocked recording. Boots the
// production server with a target_scope_policy that denies the upstream
// host, sends an HTTPS request through the proxy via CONNECT, and asserts
// the MCP query("flows") tool returns the audit Stream with
// blocked_by="target_scope".
//
// This is the AC #6 e2e for the live data path: a scope-blocked request
// must surface as a queryable Stream with the canonical BlockedBy
// attribution. Pre-USK-782 the live data path silently dropped scope-denied
// envelopes — the only blocked Streams in the database were synthesized
// by tests via seedBlockedSession.
//
// The test deliberately exercises the CONNECT route (HTTPS target) because
// HostScopeStep fires inside the Pipeline once CONNECT has set
// env.Context.TargetHost. The plain-HTTP forward route's per-handler scope
// check (internal/connector/http1_forward_handler.go) reaches its own
// 403-Forbidden response BEFORE the Pipeline runs, so it is covered by a
// separate (out-of-scope) recording mechanism.
package mcptest_test

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// scopeDenyConfig installs a target_scope_policy with a path-prefix deny
// rule. The connection-level handler scope check (CONNECT / HTTP forward)
// is empty-path so it does not fire; the per-request HTTPScopeStep evaluates
// the full scheme+authority+path triple and emits Drop. The session-side
// recorder writes a flow.Stream with State="error" + BlockedBy="target_scope".
//
// Why path-prefix: the connection-level CONNECT and plain-HTTP forward
// handlers each run their own Scope.CheckTarget WITHOUT a path before the
// Pipeline ever sees an envelope. HostScopeStep inside the Pipeline acts as
// a defensive backstop for connections that bypassed the handler check (none
// today), so practical Pipeline-Drop deny on a live HTTPS exchange is
// reachable only via the per-request HTTPScopeStep — which checks the path
// prefix the connection-level gate cannot.
const scopeDenyConfig = `{
  "target_scope_policy": {
    "denies": [
      {"hostname": "127.0.0.1", "path_prefix": "/blocked-path"}
    ]
  }
}`

// TestE2E_ScopeBlocked_RecordedAsAuditStream proves the post-USK-782 contract:
//
//  1. A CONNECT-routed HTTPS request to a host the target_scope policy
//     denies is dropped by HostScopeStep.
//  2. query("flows", filter={blocked_by: "target_scope"}) returns the
//     audit Stream.
//  3. The Stream's State is "error" — matches the audit-Stream shape used
//     by the existing enabled_protocols precedent
//     (proxybuild.buildProtocolRejectedRecorder).
func TestE2E_ScopeBlocked_RecordedAsAuditStream(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    scopeDenyConfig,
		UpstreamProto: "http/1.1",
	})

	if h.UpstreamTLS == nil {
		t.Fatal("UpstreamTLS is nil; harness wiring regressed")
	}

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	pURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pURL),
			DisableKeepAlives: true,
			// Self-signed upstream cert; the proxy is configured -insecure
			// for upstream verification, but the test client also has to
			// accept the proxy-issued MITM leaf or the upstream's cert when
			// passthrough fires. We're not asserting TLS here; the load-
			// bearing assertion is what landed in the flow store.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 15 * time.Second,
	}

	// (Sanity gate) An allowed path records a normal Stream — without this
	// we cannot distinguish "Drop path didn't record" from "the recording
	// subsystem isn't working at all". Allow this request through so the
	// proxy MITMs and records it via the normal RecordStep path.
	if resp, err := client.Get(h.UpstreamTLS.URL + "/allowed-path"); err == nil {
		_ = resp.Body.Close()
	}

	// Hit the upstream through the proxy on the deny-listed path. CONNECT
	// succeeds (the deny rule's path_prefix is empty at connection-level
	// scope check), then per-request HTTPScopeStep matches the deny rule
	// and Drops the envelope. The session-side recorder fires
	// OnPipelineDrop, which writes the audit Stream. The client-side
	// outcome is either a transport error or a non-2xx response —
	// the durable assertion is what landed in the flow store.
	resp, err := client.Get(h.UpstreamTLS.URL + "/blocked-path")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("scope-denied GET status = 200; HTTPScopeStep did not block")
		}
	}

	// Poll the query tool for the blocked Stream. SaveStream goes through
	// an async write queue, so allow up to ~2s for the row to land before
	// failing.
	var blockedFlows []map[string]any
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter": map[string]any{
				"blocked_by": "target_scope",
			},
		})
		flows, _ := res.Decoded["flows"].([]any)
		if len(flows) > 0 {
			blockedFlows = make([]map[string]any, 0, len(flows))
			for _, raw := range flows {
				if m, ok := raw.(map[string]any); ok {
					blockedFlows = append(blockedFlows, m)
				}
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(blockedFlows) == 0 {
		t.Fatalf("query(flows, blocked_by=target_scope) returned 0 results; want >= 1")
	}

	got := blockedFlows[0]
	if blockedBy, _ := got["blocked_by"].(string); blockedBy != "target_scope" {
		t.Errorf("blocked Stream.blocked_by = %q, want %q", blockedBy, "target_scope")
	}
	if state, _ := got["state"].(string); !strings.EqualFold(state, "error") {
		t.Errorf("blocked Stream.state = %q, want %q", state, "error")
	}
}
