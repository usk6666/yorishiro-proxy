//go:build e2e && !e2e_smoke

// USK-892 SSE per-event TransformEngine / InterceptEngine integration
// suite. These tests run on top of the sseProxyHarness defined in
// usk890_integration_test.go (same package) so they exercise the
// production runUpgradeSSE → driveSSEEventLoop → relaySSEEvent wiring
// for the SSE Layer.
//
// Coverage:
//
//   - TransformEngine.set_data rewrites the client-visible bytes to the
//     canonical `sse.EncodeWireBytes` form for the modified event while
//     unmodified events round-trip raw verbatim (USK-890 invariant).
//   - TransformEngine.drop blocks the client emission entirely
//     (mirrors USK-890 dropEventStep coverage but driven by the engine).
//   - InterceptEngine hold + HoldQueue.Release with a modify_and_forward
//     action delivers the modified event after canonical re-encode,
//     with subsequent unmodified events still raw verbatim.
//   - The exhaustive tier (this file) keeps the suite out of the per-PR
//     merge gate; the smoke tier already enforces USK-890's wire-fidelity
//     invariant separately.
package sse_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
)

// TestSSE_TransformEngine_SetData_ReEncodes asserts the wired SSE
// TransformEngine rewrites the data line and the client receives the
// canonical EncodeWireBytes form (event → id → retry → data ordering).
// Subsequent events that do NOT match are still emitted raw verbatim.
func TestSSE_TransformEngine_SetData_ReEncodes(t *testing.T) {
	transformEngine := sserules.NewTransformEngine()
	r, err := sserules.CompileTransformRule("rewrite", 0, "", "", "", "", nil, nil, nil,
		sserules.TransformSetData, "", "", "REWRITTEN", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	transformEngine.AddRule(*r)

	// First upstream event has data "original" — the engine rewrites it.
	// Second event has data "second"; the engine still matches (DataPattern
	// is empty) so it also rewrites. Use an EventPattern so only the first
	// event is mutated and confirm the unmodified event round-trips raw.
	transformEngine.SetRules(nil)
	r2, err := sserules.CompileTransformRule("rewrite", 0, "", "^target$", "", "", nil, nil, nil,
		sserules.TransformSetData, "", "", "REWRITTEN", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	transformEngine.AddRule(*r2)

	upstreamRaw := "event: target\ndata: original\nid: 1\n\n" + "data: untouched\n\n"
	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		chunkedTE: true,
		upstreamWriter: func(w io.Writer) {
			fmt.Fprintf(w, "%X\r\n%s\r\n", len(upstreamRaw), upstreamRaw)
			_, _ = w.Write([]byte("0\r\n\r\n"))
		},
		pipelineSteps: []pipeline.Step{
			pipeline.NewTransformStep(nil, nil, nil, transformEngine),
		},
	}

	got, _ := h.run()
	// EncodeWireBytes emits event → id → retry → data in canonical order.
	// The rewritten event therefore lands as:
	//     event: target\nid: 1\ndata: REWRITTEN\n\n
	// The second event was not matched so it round-trips raw verbatim.
	want := "event: target\nid: 1\ndata: REWRITTEN\n\n" + "data: untouched\n\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("client wire mismatch\n  got  = %q\n  want = %q", got, want)
	}
}

// TestSSE_TransformEngine_Drop_BlocksEmission asserts a matching
// TransformDrop rule prevents the event from reaching the client.
func TestSSE_TransformEngine_Drop_BlocksEmission(t *testing.T) {
	transformEngine := sserules.NewTransformEngine()
	r, err := sserules.CompileTransformRule("drop", 0, "", "", "", "block", nil, nil, nil,
		sserules.TransformDrop, "", "", "", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	transformEngine.AddRule(*r)

	upstream := []string{
		"data: visible\n\n",
		"data: block-me\n\n", // matches DataPattern=block → dropped
		"data: also visible\n\n",
	}
	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		chunkedTE: true,
		upstreamWriter: func(w io.Writer) {
			for _, e := range upstream {
				fmt.Fprintf(w, "%X\r\n%s\r\n", len(e), e)
			}
			_, _ = w.Write([]byte("0\r\n\r\n"))
		},
		pipelineSteps: []pipeline.Step{
			pipeline.NewTransformStep(nil, nil, nil, transformEngine),
		},
	}

	got, _ := h.run()
	if strings.Contains(string(got), "block-me") {
		t.Errorf("dropped event leaked to client: %q", got)
	}
	if !strings.Contains(string(got), "data: visible") {
		t.Errorf("legitimate event missing from client wire: %q", got)
	}
	if !strings.Contains(string(got), "data: also visible") {
		t.Errorf("legitimate post-drop event missing: %q", got)
	}
}

// TestSSE_InterceptEngine_HoldRelease delivers an event after a manual
// HoldQueue.Release with a modify_and_forward action. The released
// envelope carries a mutated Data field; the session-side
// sseMessageMutated detector picks it up and the client receives the
// canonical EncodeWireBytes form.
func TestSSE_InterceptEngine_HoldRelease(t *testing.T) {
	interceptEngine := sserules.NewInterceptEngine()
	rule, err := sserules.CompileInterceptRule("hold-all", "", "", "", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	interceptEngine.AddRule(*rule)

	queue := common.NewHoldQueue()

	// Release goroutine: when an event lands in the queue, replace its
	// data with "modified" and forward.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			entries := queue.List()
			for _, entry := range entries {
				modified := entry.Envelope.Clone()
				if sm, ok := modified.Message.(*envelope.SSEMessage); ok {
					sm.Data = "modified"
				}
				_ = queue.Release(entry.ID, &common.HoldAction{
					Type:     common.ActionModifyAndForward,
					Modified: modified,
				})
			}
			if len(entries) == 0 {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	upstreamRaw := "data: original\n\n"
	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		chunkedTE: true,
		upstreamWriter: func(w io.Writer) {
			fmt.Fprintf(w, "%X\r\n%s\r\n", len(upstreamRaw), upstreamRaw)
			_, _ = w.Write([]byte("0\r\n\r\n"))
		},
		pipelineSteps: []pipeline.Step{
			pipeline.NewInterceptStep(nil, nil, nil, interceptEngine, queue, nil, nil),
		},
	}

	got, _ := h.run()
	want := "data: modified\n\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("client wire mismatch\n  got  = %q\n  want = %q", got, want)
	}
}
