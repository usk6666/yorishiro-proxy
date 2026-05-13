//go:build e2e

// Package http1_test extends the HTTP/1.x MITM integration coverage with
// the USK-860 regression guard: after an operator releases a held request
// via modify_and_forward (or release) and the upstream answers normally,
// the diagnostic Stream tag
// intercept_hold_outcome=upstream_closed_after_intercept_release MUST NOT
// be appended. The tag is intended exclusively for the genuine
// "long-held frame caused upstream half-close" symptom that USK-851
// shipped; firing it on a successful end-to-end relay is a cosmetic
// false positive that misleads triage.
//
// This test lives in the smoke tier so the merge gate fails fast on any
// regression that re-broadens the tag's firing condition.
package http1_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// TestHTTPSMITM_InterceptModifyForward_NoEOFTag_WhenResponseRelayed is the
// USK-860 regression guard. It wires the canonical user reproduction:
// request-side intercept rule on /headers, modify_and_forward, upstream
// returns 200 OK with body and Connection: close. The relay completes
// end-to-end and the upstream then closes cleanly. The
// intercept-release tracker still records the release timestamp on the
// Send direction, but because the upstreamToClient relay loop forwarded
// the 200 OK to the client BEFORE upstream EOF, the
// OnInterceptReleaseEOF callback MUST be suppressed.
//
// Pre-USK-860 behaviour (bug): tag fires unconditionally because the
// release stamp is still within the 2-second correlation window when
// upstreamToClientFinish runs.
// Post-USK-860 behaviour (fix): the per-relay-direction relayed gate
// suppresses the callback once at least one envelope was forwarded
// downstream after the matching release.
func TestHTTPSMITM_InterceptModifyForward_NoEOFTag_WhenResponseRelayed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream returns 200 OK with a small body and Connection: close. The
	// close drives the proxy's upstream relay loop into a clean EOF after
	// the response is fully relayed — exactly the path the user reported.
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		body := "ok"
		return []byte(fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\nX-Yorishiro: relayed\r\n\r\n%s",
			len(body), body))
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// Request-side intercept rule covering the request path.
	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "usk860-headers",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`/headers`),
	})
	holdQueue := common.NewHoldQueue()
	releaseTracker := common.NewReleaseTracker()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
		releaseTracker:  releaseTracker,
	})

	// Drive the request through the proxy in a goroutine so we can release
	// the held envelope from the main goroutine.
	respCh := make(chan string, 1)
	go func() {
		rawReq := fmt.Sprintf("GET /headers HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		respCh <- connectAndSendHTTP(t, proxyAddr, target, rawReq)
	}()

	// Poll for the held entry.
	var entries []*common.HeldEntry
	pollDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(pollDeadline) {
		entries = holdQueue.List()
		if len(entries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("no entry appeared in hold queue")
	}
	held := entries[0]

	// Clone + inject X-Yorishiro header for parity with the user's repro.
	modified := held.Envelope.Clone()
	msg, ok := modified.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatal("held envelope message is not *HTTPMessage")
	}
	msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "X-Yorishiro", Value: "by-proxy"})

	// USK-851 production order: the MCP intercept tool stamps the release
	// tracker BEFORE HoldQueue.Release returns. Mirror that order here so
	// the relay observes the marker after Release unblocks the held
	// goroutine.
	releaseTracker.MarkRelease(held.Envelope.StreamID, held.Envelope.Direction, time.Now())
	if err := holdQueue.Release(held.ID, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modified,
	}); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Wait for the client's response read to complete.
	var resp string
	select {
	case resp = <-respCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Wait for upstream + session completion.
	upstreamReqs := getUpstreamReqs()
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Sanity: the response was actually relayed end-to-end. ---
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected 200 OK relayed end-to-end; got %q", resp)
	}
	if !strings.Contains(resp, "X-Yorishiro: relayed") {
		t.Errorf("expected upstream's X-Yorishiro header relayed; resp=%q", resp)
	}
	if !strings.HasSuffix(resp, "ok") {
		t.Errorf("expected response body 'ok'; resp=%q", resp)
	}
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}

	// --- Acceptance: the tag was NOT appended. ---
	if store.hasTag("intercept_hold_outcome", "upstream_closed_after_intercept_release") {
		t.Errorf("USK-860 regression: intercept_hold_outcome tag fired on a successfully-relayed response; tag batches=%d",
			len(store.appendTagBatch))
		for i, batch := range store.appendTagBatch {
			t.Logf("AppendTags[%d] = %v", i, batch)
		}
	}

	// Stream state must reflect a clean exchange.
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream")
	}
	if streams[0].State != "complete" {
		t.Errorf("stream state = %q, want %q", streams[0].State, "complete")
	}
}
