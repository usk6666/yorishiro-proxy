//go:build e2e && !e2e_smoke

// USK-907: SSE parser CR / CRLF terminator interop tests.
//
// WHATWG HTML §9.2.2 ABNF defines the SSE line terminator as
//
//	end-of-line = ( cr lf / cr / lf )
//
// so CR / LF / CRLF are all valid, equivalent line endings. Pre-fix the
// parser used bufio.Scanner's default ScanLines (LF-only with trailing-CR
// strip) and EventBoundaryReader scanned with ReadSlice('\n') — both broke
// for CR-only streams: the entire body collapsed into one giant data: field
// and event boundaries advanced only at EOF. SSE-P5-04 (2026-05-15)
// surfaced the bug against a /p5-bad-cr-style endpoint.
//
// This file pins:
//
//  1. CR-only wire pass-through round-trip (the proxy must not normalise
//     wire bytes — Principle #1) AND correct L7 projection: the recorded
//     SSE message count matches the WHATWG dispatch (one event whose Data
//     joins the three "data:" fields with '\n', dispatched at EOS).
//
//  2. CRLF wire pass-through round-trip + L7 projection (no CR retained in
//     field values).
//
// The test file is exhaustive (e2e && !e2e_smoke) per CLAUDE.md USK-728 —
// it is a low-priority interop guard, not a per-PR merge gate item.
package sse_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// TestSSE_USK907_CROnlyParsesAsOneWHATWGEvent mirrors the SSE-P5-04
// reproduction: an upstream that returns three "data:" fields separated
// by bare CR with no terminating blank line. Per WHATWG §9.2.2 the three
// fields collect into one event whose Data is "a\nb\nc", dispatched at
// EOS. Pre-fix the parser collapsed everything into a single
// data: field whose value retained the embedded CR bytes.
//
// Drives the recording via sse.Wrap directly (mirrors
// TestSSE_DirectChannelThroughPipelineRecordsThreeEvents) so the test
// focuses on the parser/projection contract rather than the http1 → SSE
// swap. The wire-pass-through Principle #1 invariant is verified by the
// existing sse_integration_test.go body of byte-identical RawBytes
// assertions (parser.RawBytes is a record-only canonical reconstruction;
// the wire snapshot lives on Envelope.Raw via the boundary reader).
func TestSSE_USK907_CROnlyParsesAsOneWHATWGEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const streamID = "sse-usk907-cr"
	wire := "data: a\rdata: b\rdata: c\r"

	store := &testStore{}

	seed := makeSSESeedRequest(streamID)
	clientCh := newSeedClientChannel(streamID, seed)

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 1)
	body := strings.NewReader(wire)
	upstreamCh := sse.Wrap(inner, first, body)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &sseUpstreamAdapter{inner: upstreamCh}, nil
	}

	p := buildPipeline(store)

	done := make(chan error, 1)
	go func() {
		done <- session.RunSession(ctx, clientCh, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid != "" {
					_ = store.UpdateStream(cctx, sid, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}()

	// Wait for the post-first-response SSE event to be projected, then
	// close the client to unblock the Send-side goroutine.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recvCount := len(store.flowsByDirection("receive"))
		if recvCount >= 2 { // 1 first-response + 1 SSE event
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = clientCh.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunSession did not return")
	}

	// --- Stream recording ---
	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].Protocol != "sse" {
		t.Errorf("Stream.Protocol = %q, want %q", streams[0].Protocol, "sse")
	}

	// --- Receive flows ---
	recvFlows := store.flowsByDirection("receive")
	// Filter to actual SSE event flows. The first envelope returned by
	// sse.Wrap is the pre-shaped HTTP first-response (Protocol overridden
	// to ProtocolSSE so Metadata["protocol"]="sse" matches it too); we
	// exclude it via the RawBytes starting with "HTTP/".
	var sseFlows []*flow.Flow
	for _, f := range recvFlows {
		if f.Metadata == nil || f.Metadata["protocol"] != "sse" {
			continue
		}
		if strings.HasPrefix(string(f.RawBytes), "HTTP/") {
			continue
		}
		sseFlows = append(sseFlows, f)
	}
	// Per WHATWG dispatch: three "data:" fields with no blank-line
	// boundary collect into ONE event. The pre-USK-907 buggy behaviour
	// would also have produced one event but with Data carrying embedded
	// CR bytes. Assert both the count AND the joined-payload shape.
	if len(sseFlows) != 1 {
		for i, f := range sseFlows {
			t.Logf("sse flow[%d]: body=%q meta=%v", i, string(f.Body), f.Metadata)
		}
		t.Fatalf("got %d SSE event flows, want 1 (WHATWG dispatch joins data: fields)",
			len(sseFlows))
	}
	got := string(sseFlows[0].Body)
	if got != "a\nb\nc" {
		t.Errorf("flow.Body = %q, want %q (WHATWG joins data: fields with '\\n', no CR retained)",
			got, "a\nb\nc")
	}
	if strings.ContainsRune(got, '\r') {
		t.Errorf("flow.Body = %q must not contain CR", got)
	}
}

// TestSSE_USK907_CROnlyEventSeparatorYieldsTwoEvents covers the CR-only
// blank-line boundary: "data: a\r\rdata: b\r\r" must be projected as two
// distinct SSE events, with each event boundary advancing mid-stream
// (not waiting for EOF). This pins the EventBoundaryReader fix.
func TestSSE_USK907_CROnlyEventSeparatorYieldsTwoEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const streamID = "sse-usk907-cr-sep"
	wire := "data: a\r\rdata: b\r\r"

	store := &testStore{}

	seed := makeSSESeedRequest(streamID)
	clientCh := newSeedClientChannel(streamID, seed)

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 1)
	body := strings.NewReader(wire)
	upstreamCh := sse.Wrap(inner, first, body)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &sseUpstreamAdapter{inner: upstreamCh}, nil
	}

	p := buildPipeline(store)

	done := make(chan error, 1)
	go func() {
		done <- session.RunSession(ctx, clientCh, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid != "" {
					_ = store.UpdateStream(cctx, sid, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recvCount := len(store.flowsByDirection("receive"))
		if recvCount >= 3 { // 1 first-response + 2 SSE events
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = clientCh.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunSession did not return")
	}

	// See filter rationale in the previous test.
	var sseFlows []*flow.Flow
	for _, f := range store.flowsByDirection("receive") {
		if f.Metadata == nil || f.Metadata["protocol"] != "sse" {
			continue
		}
		if strings.HasPrefix(string(f.RawBytes), "HTTP/") {
			continue
		}
		sseFlows = append(sseFlows, f)
	}
	if len(sseFlows) != 2 {
		for i, f := range sseFlows {
			t.Logf("sse flow[%d]: body=%q raw=%q", i, string(f.Body), string(f.RawBytes))
		}
		t.Fatalf("got %d SSE event flows, want 2 (CR-CR is a valid event boundary)",
			len(sseFlows))
	}
	if string(sseFlows[0].Body) != "a" {
		t.Errorf("flow[0].Body = %q, want %q", string(sseFlows[0].Body), "a")
	}
	if string(sseFlows[1].Body) != "b" {
		t.Errorf("flow[1].Body = %q, want %q", string(sseFlows[1].Body), "b")
	}
	for i, f := range sseFlows {
		if strings.ContainsRune(string(f.Body), '\r') {
			t.Errorf("flow[%d].Body = %q must not contain CR", i, string(f.Body))
		}
	}
}
