//go:build e2e && !e2e_smoke

package grpc_test

import (
	"context"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// TestGRPC_PerStreamRecordCap (USK-802) verifies the RecordStep-side
// per-Stream record cap for gRPC:
//
//  1. Wire forwarding is intact — the gRPC client receives every server
//     streaming message regardless of the cap.
//  2. RecordStep persists at most cap GRPCDataMessage flows per stream.
//  3. The per-Stream truncation tag is stamped exactly once (records_truncated
//     = per_stream_cap_reached) when the cap is first exceeded.
//
// The test layers a tiny WithGRPCMaxMessagesPerStream(cap=3) on the e2e
// suite's standard pipeline so the forward-vs-record split is observable
// against real HPACK + LPM frames.
func TestGRPC_PerStreamRecordCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const (
		serverMessages = 6
		recordCap      = 3
	)

	ca, issuer := makeCA(t)
	srv := &echoServer{
		serverStream: func(req []byte, stream grpc.ServerStream) error {
			for i := 0; i < serverMessages; i++ {
				msg := append([]byte(strconv.Itoa(i)+":"), req...)
				if err := stream.SendMsg(&msg); err != nil {
					return err
				}
			}
			return nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		recordOpts: []pipeline.Option{pipeline.WithGRPCMaxMessagesPerStream(recordCap)},
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	desc := &grpc.StreamDesc{StreamName: echoMethodServerStream, ServerStreams: true}
	cs, err := cc.NewStream(ctx, desc, echoFullMethod(echoMethodServerStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	req := []byte("seed")
	if err := cs.SendMsg(&req); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	recvCount := 0
	for {
		var out []byte
		if err := cs.RecvMsg(&out); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("RecvMsg: %v", err)
		}
		recvCount++
	}
	// (1) Wire forwarding intact — every upstream message reached the
	// client even though the recorder dropped the tail.
	if recvCount != serverMessages {
		t.Errorf("client received %d messages, want %d (cap must not affect forwarding)",
			recvCount, serverMessages)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	// Wait for the End envelope (always recorded; bypasses the cap) so we
	// know the recorder has drained the upstream stream.
	waitForGRPCFlows(t, store, st.ID, "end", "receive", 1, 5*time.Second)
	// (2) The cap is per-Stream and combined across both directions
	// (design review Q5: "One Stream = one RPC = one cap"). The send
	// side contributes 1 data envelope (the unary request); the receive
	// side contributes serverMessages. Together: serverMessages + 1
	// data envelopes observed. With cap=recordCap, RecordStep must
	// persist exactly recordCap of them and drop the rest. Start/End
	// envelopes always record regardless.
	var dataFlows int
	for _, f := range store.flowsForStream(st.ID) {
		if f.Metadata["grpc_event"] == "data" {
			dataFlows++
		}
	}
	if dataFlows != recordCap {
		for i, f := range store.flowsForStream(st.ID) {
			t.Logf("flow[%d] dir=%s seq=%d event=%s id=%s", i, f.Direction, f.Sequence, f.Metadata["grpc_event"], f.ID)
		}
		t.Fatalf("recorded data flows = %d; want %d (combined per-Stream cap)", dataFlows, recordCap)
	}

	// (3) Truncated tag stamped exactly once. The harness testStore
	// captures every UpdateStream call into getUpdates; iterate to count
	// AppendTags entries with the canonical reason.
	tagCount := 0
	for _, u := range store.getUpdates(st.ID) {
		if u.AppendTags["records_truncated"] == "per_stream_cap_reached" {
			tagCount++
		}
	}
	if tagCount != 1 {
		t.Errorf("AppendTags[records_truncated] count = %d, want 1 (one-shot latch)", tagCount)
	}
	waitForStreamState(t, store, st.ID, "complete", 3*time.Second)
}
