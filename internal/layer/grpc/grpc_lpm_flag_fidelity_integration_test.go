//go:build e2e && !e2e_smoke

package grpc_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1256 e2e: an LPM whose compressed-flag byte is outside the RFC
// values (0x02 here) must reach the next hop byte-identical and be
// recorded verbatim on the semantic Data row and the grpc-lpm-frame row,
// in both directions. The h2-frame row already carried the true bytes;
// it is asserted as the reference.
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: the RPC completes; the upstream / client
//     observe the exact wire bytes.
//   - Stream recording: the Stream is recorded with Protocol="grpc" and
//     reaches State="complete".
//   - Flow recording + Raw bytes: semantic, grpc-lpm-frame and h2-frame
//     rows carry the wire LPM verbatim.
//
// Fixtures omit grpc-encoding so the Compressed=true payload is surfaced
// as-is (no gunzip).

// semanticDataFlows returns the semantic grpc_event=data rows in dir that
// carry an LPM (the empty END_STREAM marker row is skipped).
func semanticDataFlows(store *testStore, streamID, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.flowsForStream(streamID) {
		if f == nil || f.Direction != dir || f.Metadata["grpc_event"] != "data" {
			continue
		}
		if f.WireLevel != "" && f.WireLevel != flow.WireLevelSemantic {
			continue
		}
		if len(f.RawBytes) == 0 {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitForSemanticDataFlow polls until exactly one LPM-carrying semantic
// Data row is recorded in dir.
func waitForSemanticDataFlow(t *testing.T, store *testStore, streamID, dir string, timeout time.Duration) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fs := semanticDataFlows(store, streamID, dir); len(fs) > 0 {
			if len(fs) != 1 {
				t.Fatalf("%s semantic Data rows = %d, want 1", dir, len(fs))
			}
			return fs[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: no %s semantic Data row for stream %s", dir, streamID)
	return nil
}

// h2FramePayloadConcat returns the h2-frame rows' RawBytes in dir,
// concatenated in recorded order.
func h2FramePayloadConcat(store *testStore, streamID, dir string) []byte {
	var out []byte
	for _, f := range h2FrameFlowsForStream(store, streamID, dir) {
		out = append(out, f.RawBytes...)
	}
	return out
}

// requireLPMRecordedVerbatim asserts the semantic, grpc-lpm-frame and
// h2-frame rows in dir all carry wire.
func requireLPMRecordedVerbatim(t *testing.T, store *testStore, streamID, dir string, wire []byte, body string) {
	t.Helper()
	sem := waitForSemanticDataFlow(t, store, streamID, dir, 5*time.Second)
	if !bytes.Equal(sem.RawBytes, wire) {
		t.Errorf("%s semantic Data RawBytes = %x, want %x (wire bytes verbatim)", dir, sem.RawBytes, wire)
	}
	if got := sem.Metadata["grpc_compressed"]; got != "true" {
		t.Errorf("%s semantic Data grpc_compressed = %q, want true", dir, got)
	}
	if string(sem.Body) != body {
		t.Errorf("%s semantic Data Body = %q, want %q", dir, sem.Body, body)
	}

	lpm := waitForLPMFlows(t, store, streamID, dir, 1, 5*time.Second)
	if len(lpm) != 1 {
		t.Fatalf("%s grpc-lpm-frame rows = %d, want 1", dir, len(lpm))
	}
	if !bytes.Equal(lpm[0].RawBytes, wire) {
		t.Errorf("%s grpc-lpm-frame RawBytes = %x, want %x (wire bytes verbatim)", dir, lpm[0].RawBytes, wire)
	}

	waitForH2FrameFlows(t, store, streamID, dir, 1, 5*time.Second)
	if got := h2FramePayloadConcat(store, streamID, dir); !bytes.Equal(got, wire) {
		t.Errorf("%s h2-frame payloads = %x, want %x", dir, got, wire)
	}
}

// grpcOKResponder writes respWire as the response body followed by a
// grpc-status 0 trailer, after reporting the request body on got.
func grpcOKResponder(got chan<- []byte, respWire []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case got <- b:
		default:
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respWire)
		w.Header().Set("Grpc-Status", "0")
	}
}

// flagFidelityRoundTrip runs one request through the MITM proxy and
// returns what the upstream read, what the client read, the store and
// the recorded gRPC stream.
func flagFidelityRoundTrip(t *testing.T, reqWire, respWire []byte) (upBody, clientBody []byte, store *testStore, st *flow.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	upGot := make(chan []byte, 1)
	upAddr := startRawH2Upstream(t, grpcOKResponder(upGot, respWire))

	ca, issuer := makeCA(t)
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: h2FrameAndLPMRecordOptFn(),
	})

	tr := newTunnelH2Transport(proxyAddr, upAddr)
	t.Cleanup(tr.CloseIdleConnections)

	resp, err := tr.RoundTrip(newGRPCPost(ctx, t, upAddr, bytes.NewReader(reqWire)))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	clientBody, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("client grpc-status trailer = %q, want 0", got)
	}

	select {
	case upBody = <-upGot:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream handler never reported the request body")
	}

	st = firstGRPCStream(t, store, 5*time.Second)
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
	return upBody, clientBody, store, st
}

// T1 + T2: request direction.
func TestGRPCLPMFlagFidelity_Send(t *testing.T) {
	reqWire := append(lpmPrefixBytes(0x02, 3), []byte("abc")...)
	respWire := append(lpmPrefixBytes(0, 2), []byte("ok")...)

	upBody, clientBody, store, st := flagFidelityRoundTrip(t, reqWire, respWire)
	if !bytes.Equal(upBody, reqWire) {
		t.Errorf("upstream request body = %x, want %x (wire bytes verbatim)", upBody, reqWire)
	}
	if !bytes.Equal(clientBody, respWire) {
		t.Errorf("client response body = %x, want %x", clientBody, respWire)
	}
	requireLPMRecordedVerbatim(t, store, st.ID, "send", reqWire, "abc")
}

// T3 + T4: response direction.
func TestGRPCLPMFlagFidelity_Receive(t *testing.T) {
	reqWire := append(lpmPrefixBytes(0, 2), []byte("hi")...)
	respWire := append(lpmPrefixBytes(0x02, 3), []byte("xyz")...)

	upBody, clientBody, store, st := flagFidelityRoundTrip(t, reqWire, respWire)
	if !bytes.Equal(upBody, reqWire) {
		t.Errorf("upstream request body = %x, want %x", upBody, reqWire)
	}
	if !bytes.Equal(clientBody, respWire) {
		t.Errorf("client response body = %x, want %x (wire bytes verbatim)", clientBody, respWire)
	}
	requireLPMRecordedVerbatim(t, store, st.ID, "receive", respWire, "xyz")
}
