//go:build e2e

package main

// n9_parity_baseline_test.go — RFC-001 N9 (USK-691)
// Pre-deletion parity baseline for the proxybuild + pluginv2 live
// data path. The hardcoded counts here ARE the snapshot. Any regression
// to recording shape between this commit and N9's mass-delete (USK-697)
// causes this test to fail, surfacing the divergence before legacy
// trees are removed.
//
// Issue body offered "commit a JSON snapshot OR hardcode counts in test
// — choose whichever is easier to operate". Hardcoded is operationally
// simpler: one source of truth, one diff target, no JSON parsing path
// to break. The block below documents the scenario explicitly so a
// USK-697 reviewer knows what regression each assertion guards against.
//
// Scenario: single HTTPS-via-CONNECT GET request through the proxybuild
// Manager with an empty (no-op) pluginv2 plugin loaded — proves the
// boot-time `proxyCfg.Plugins → initPluginV2Engine → LoadPlugins` path
// still parses typed configs after legacy removal, even when the plugin
// registers no hooks.
//
// Expected snapshot:
//
//   streams[Protocol="http"] count: 1
//   streams[Protocol="http"][0].State: "complete"
//   streams[Protocol="http"][0].Scheme: "https"
//   flows for that stream: ≥ 2 (1 "send" + 1 "receive")
//   send flow Method: "GET"
//   receive flow StatusCode: 200
//   both flows: len(RawBytes) > 0  (L4-capable principle, RFC-001 §3.1)
//
// Post-USK-697 parity check: re-run `make test-e2e` after the legacy
// trees are deleted. This file produces identical outcomes if and only
// if the new data path preserves the recorded shape across the removal.

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestN9ParityBaseline_HTTPSCONNECT_RecordingShape exercises the live
// proxybuild + pluginv2 stack with a no-op plugin and asserts the
// recorded Stream + Flow shape against the snapshot documented in this
// file's header. The plugin script is intentionally empty (no
// register_hook calls) — its only purpose is to prove the typed
// `config.Plugins` slice still loads.
func TestN9ParityBaseline_HTTPSCONNECT_RecordingShape(t *testing.T) {
	const pluginName = "n9_parity_noop"
	// No register_hook call: a loaded plugin with zero hooks is the
	// minimum viable proof that the boot-time wiring still works.
	script := `
# usk-691: parity-baseline no-op plugin (no register_hook calls).
_ = 1
`
	lp := setupLiveProxy(t, pluginName, script)
	upstream := startUpstreamHTTPSEcho(t)

	tlsConn := dialMITM(t, lp.addr, upstream.Addr().String())
	req := "GET /n9-parity HTTP/1.1\r\n" +
		"Host: " + upstream.Addr().String() + "\r\n" +
		"User-Agent: usk-691-parity/1.0\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Drain the response fully so the proxy session reaches "complete".
	_, _ = io.Copy(io.Discard, tlsConn)
	tlsConn.Close()

	assertParitySnapshot(t, lp.store)
}

// assertParitySnapshot blocks (with deadline) until at least one
// http stream has reached State="complete" and then validates the
// hardcoded snapshot shape. Polling avoids time.Sleep brittleness when
// the OnComplete callback races the test goroutine.
func assertParitySnapshot(t *testing.T, store *flow.SQLiteStore) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{
			Protocol: "http",
			State:    "complete",
		})
		if err != nil {
			t.Fatalf("ListStreams: %v", err)
		}
		if len(streams) >= 1 {
			validateParityStream(t, ctx, store, streams[0])
			return
		}
		if time.Now().After(deadline) {
			all, _ := store.ListStreams(ctx, flow.StreamListOptions{})
			labels := make([]string, 0, len(all))
			for _, s := range all {
				labels = append(labels, s.Protocol+"/"+s.State)
			}
			t.Fatalf("parity baseline: no http stream reached State=complete in time; saw: [%s]", strings.Join(labels, ", "))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// validateParityStream applies the hardcoded recording-shape assertions
// documented in this file's header.
func validateParityStream(t *testing.T, ctx context.Context, store *flow.SQLiteStore, s *flow.Stream) {
	t.Helper()
	if s.Protocol != "http" {
		t.Errorf("Stream.Protocol = %q, want %q", s.Protocol, "http")
	}
	if s.State != "complete" {
		t.Errorf("Stream.State = %q, want %q", s.State, "complete")
	}
	if s.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want %q", s.Scheme, "https")
	}

	flows, err := store.GetFlows(ctx, s.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(flows) < 2 {
		t.Fatalf("flows for stream %s: count = %d, want >= 2", s.ID, len(flows))
	}

	var sendFlow, recvFlow *flow.Flow
	for _, f := range flows {
		switch f.Direction {
		case "send":
			if sendFlow == nil {
				sendFlow = f
			}
		case "receive":
			if recvFlow == nil {
				recvFlow = f
			}
		}
	}
	if sendFlow == nil {
		t.Fatal("no send flow recorded")
	}
	if recvFlow == nil {
		t.Fatal("no receive flow recorded")
	}
	if len(sendFlow.RawBytes) == 0 {
		t.Error("send flow RawBytes empty (RFC-001 §3.1 wire fidelity violated)")
	}
	if len(recvFlow.RawBytes) == 0 {
		t.Error("receive flow RawBytes empty (RFC-001 §3.1 wire fidelity violated)")
	}
	if sendFlow.Method != "GET" {
		t.Errorf("send Flow.Method = %q, want %q", sendFlow.Method, "GET")
	}
	if recvFlow.StatusCode != 200 {
		t.Errorf("receive Flow.StatusCode = %d, want %d", recvFlow.StatusCode, 200)
	}
}
