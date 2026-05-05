//go:build e2e

// USK-654 — N7 final-gate cross-cutting test for the gRPC Layer.
//
// The N6.7 split (USK-637) decoupled HTTP/2 connection-level WINDOW_UPDATE
// from Pipeline consumption: WINDOW_UPDATE fires at frame-arrival time at
// the Layer level, so a long-held Pipeline Step on stream A cannot stall
// other streams on the same h2 connection. This test verifies that the
// guarantee survives the GRPCLayer wrapper.
//
// Test model:
//
//	1 upstream HTTP/2 connection (one CONNECT, one upH2 Layer)
//	  ├── stream A (BidiStream)   ── Pipeline holds GRPCDataMessage indefinitely
//	  ├── stream B (Unary)        ── completes normally
//	  ├── stream C (ServerStream) ── completes normally
//	  └── stream D (ClientStream) ── completes normally
//
// All 4 RPCs share one *grpc.ClientConn so grpc-go's HTTP/2 transport
// multiplexes them through one CONNECT tunnel onto one upstream h2 conn.
//
// Acceptance: B/C/D each reach Stream.State="complete" within 10s while
// stream A's Pipeline is held.
//
// Issue-text claims intentionally NOT asserted, with rationale:
//   - "BodyBuffer soft cap → stream stall": post-USK-637 the H2 Layer
//     no longer owns a BodyBuffer; the gRPC routing path bypasses
//     httpaggregator entirely and has no aggregate body cap. The only
//     per-stream backpressure is the 32-slot recv chan in the H2 channel,
//     which is internal Layer state and not part of the public Channel
//     contract.
//   - "Hard cap → RST_STREAM": no aggregate body cap exists in this
//     path; the only RST trigger is per-LPM maxMessageSize, which a
//     Pipeline hold does not exercise.
//   - "After hold release, stream A resumes and completes": the harness's
//     bidi handler is an echo loop, so it hangs on RecvMsg while no DATA
//     reaches upstream. Adding a happy-path release-and-complete cycle
//     would require a different bidi handler shape; out of scope for the
//     N7 final gate.

package grpc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
)

// streamForMethod returns the first recorded Stream whose flows carry a
// grpc_method metadata value of method. Polls until timeout.
func streamForMethod(t *testing.T, store *testStore, method string, timeout time.Duration) *flow.Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, st := range store.getStreams() {
			if st.Protocol != "grpc" {
				continue
			}
			for _, fl := range store.flowsForStream(st.ID) {
				if fl.Metadata["grpc_method"] == method {
					return st
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no grpc stream recorded for method=%q within %v", method, timeout)
	return nil
}

// TestGRPC_PipelineHoldDoesNotStallOtherStreams is the N7 final gate.
// Mirrors the N6.7 sibling
// internal/layer/http2/isolation_integration_test.go but drives 4 different
// gRPC RPC kinds through GRPCLayer instead of plain HTTP/2.
func TestGRPC_PipelineHoldDoesNotStallOtherStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)

	// Upstream Echo service:
	//   Unary        : prefix "echo:"
	//   ServerStream : N messages
	//   ClientStream : count of received messages
	//   BidiStream   : echo loop (hangs on RecvMsg if client never sends)
	const serverStreamN = 3
	const clientStreamN = 3
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return append([]byte("echo:"), req...), nil
		},
		serverStream: func(req []byte, stream grpc.ServerStream) error {
			for i := 0; i < serverStreamN; i++ {
				msg := append([]byte(strconv.Itoa(i)+":"), req...)
				if err := stream.SendMsg(&msg); err != nil {
					return err
				}
			}
			return nil
		},
		clientStream: func(stream grpc.ServerStream) ([]byte, error) {
			var got int
			for {
				var msg []byte
				if err := stream.RecvMsg(&msg); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return nil, err
				}
				got++
			}
			return []byte(fmt.Sprintf("got=%d", got)), nil
		},
		bidiStream: func(stream grpc.ServerStream) error {
			for {
				var in []byte
				if err := stream.RecvMsg(&in); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
				out := append([]byte("ack:"), in...)
				if err := stream.SendMsg(&out); err != nil {
					return err
				}
			}
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	// Intercept rule: hold every Send-side GRPCDataMessage on the
	// BidiStream method. The other 3 methods do not match, so their
	// data envelopes traverse the Pipeline without holding.
	engine := grpcrules.NewInterceptEngine()
	engine.SetRules([]grpcrules.InterceptRule{{
		ID:            "hold-bidi-data",
		Enabled:       true,
		Direction:     grpcrules.DirectionSend,
		MethodPattern: regexp.MustCompile(`^` + regexp.QuoteMeta(echoMethodBidiStream) + `$`),
	}})
	queue := common.NewHoldQueue()

	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		intercept: engine,
		queue:     queue,
	})

	// One ClientConn → grpc-go transport multiplexes all RPCs onto one h2
	// connection through the proxy.
	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	// ----------------------------------------------------------------
	// Stream A: BidiStream. Pipeline holds the first GRPCDataMessage on
	// SendMsg indefinitely (until cleanup cancels ctx). The goroutine
	// will not return until cleanup; this is intentional.
	// ----------------------------------------------------------------
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		desc := &grpc.StreamDesc{
			StreamName:    echoMethodBidiStream,
			ServerStreams: true,
			ClientStreams: true,
		}
		cs, err := cc.NewStream(ctx, desc, echoFullMethod(echoMethodBidiStream))
		if err != nil {
			// Context cancelled during cleanup is the expected exit path.
			return
		}
		// Expected to block until ctx is cancelled at cleanup. The hold
		// happens in InterceptStep on the Send-side GRPCDataMessage.
		msg := []byte("held-payload")
		_ = cs.SendMsg(&msg)
		_ = cs.CloseSend()
	}()

	// Give the held bidi stream time to open its h2 stream and reach the
	// hold queue. The grpc-go HTTP/2 handshake plus stream open via the
	// proxy takes longer than the http2 sibling's plain Do() because of
	// CONNECT + TLS + ALPN + h2 preface negotiation.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if queue.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if queue.Len() == 0 {
		t.Fatalf("USK-654: bidi stream A did not reach hold queue within 5s; "+
			"cannot exercise isolation (queue.Len=%d)", queue.Len())
	}

	// ----------------------------------------------------------------
	// Streams B, C, D: must complete on the same h2 connection while A
	// is held. Each runs in its own goroutine with a 10s deadline. If
	// connection-level WINDOW were stalled by stream A's pile-up, these
	// would time out.
	// ----------------------------------------------------------------
	const fastDeadline = 10 * time.Second
	type result struct {
		name string
		err  error
	}
	results := make(chan result, 3)

	// B: Unary
	go func() {
		fastCtx, fastCancel := context.WithTimeout(ctx, fastDeadline)
		defer fastCancel()
		var resp []byte
		req := []byte("B")
		err := cc.Invoke(fastCtx, echoFullMethod(echoMethodUnary), &req, &resp)
		if err == nil && string(resp) != "echo:B" {
			err = fmt.Errorf("Unary resp=%q want %q", resp, "echo:B")
		}
		results <- result{name: "Unary", err: err}
	}()

	// C: ServerStream
	go func() {
		fastCtx, fastCancel := context.WithTimeout(ctx, fastDeadline)
		defer fastCancel()
		desc := &grpc.StreamDesc{StreamName: echoMethodServerStream, ServerStreams: true}
		cs, err := cc.NewStream(fastCtx, desc, echoFullMethod(echoMethodServerStream))
		if err != nil {
			results <- result{name: "ServerStream", err: fmt.Errorf("NewStream: %w", err)}
			return
		}
		req := []byte("C")
		if err := cs.SendMsg(&req); err != nil {
			results <- result{name: "ServerStream", err: fmt.Errorf("SendMsg: %w", err)}
			return
		}
		if err := cs.CloseSend(); err != nil {
			results <- result{name: "ServerStream", err: fmt.Errorf("CloseSend: %w", err)}
			return
		}
		got := 0
		for {
			var out []byte
			rerr := cs.RecvMsg(&out)
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				results <- result{name: "ServerStream", err: fmt.Errorf("RecvMsg: %w", rerr)}
				return
			}
			got++
		}
		if got != serverStreamN {
			results <- result{name: "ServerStream", err: fmt.Errorf("got %d msgs, want %d", got, serverStreamN)}
			return
		}
		results <- result{name: "ServerStream"}
	}()

	// D: ClientStream
	go func() {
		fastCtx, fastCancel := context.WithTimeout(ctx, fastDeadline)
		defer fastCancel()
		desc := &grpc.StreamDesc{StreamName: echoMethodClientStream, ClientStreams: true}
		cs, err := cc.NewStream(fastCtx, desc, echoFullMethod(echoMethodClientStream))
		if err != nil {
			results <- result{name: "ClientStream", err: fmt.Errorf("NewStream: %w", err)}
			return
		}
		for i := 0; i < clientStreamN; i++ {
			msg := []byte(strconv.Itoa(i))
			if err := cs.SendMsg(&msg); err != nil {
				results <- result{name: "ClientStream", err: fmt.Errorf("SendMsg %d: %w", i, err)}
				return
			}
		}
		if err := cs.CloseSend(); err != nil {
			results <- result{name: "ClientStream", err: fmt.Errorf("CloseSend: %w", err)}
			return
		}
		var resp []byte
		if err := cs.RecvMsg(&resp); err != nil {
			results <- result{name: "ClientStream", err: fmt.Errorf("RecvMsg: %w", err)}
			return
		}
		want := fmt.Sprintf("got=%d", clientStreamN)
		if string(resp) != want {
			results <- result{name: "ClientStream", err: fmt.Errorf("resp=%q want %q", resp, want)}
			return
		}
		results <- result{name: "ClientStream"}
	}()

	// Wait for all three fast streams. None may time out.
	for i := 0; i < 3; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				if errors.Is(r.err, context.DeadlineExceeded) ||
					(r.err.Error() != "" && (r.err.Error() == "context deadline exceeded" ||
						containsCtxDeadline(r.err))) {
					t.Fatalf("USK-654 regression: %s did not complete while bidi A is held. "+
						"Pre-USK-637 failure mode: connection-level WINDOW stalled by held streams. "+
						"Post-USK-637: WINDOW_UPDATE fires at frame-arrival, decoupling. err=%v",
						r.name, r.err)
				}
				t.Fatalf("%s returned error: %v", r.name, r.err)
			}
		case <-time.After(fastDeadline + 2*time.Second):
			t.Fatal("USK-654 regression: a fast stream did not complete within deadline; " +
				"connection-level WINDOW appears stalled by held bidi stream A")
		}
	}

	// ----------------------------------------------------------------
	// Recording assertions: B/C/D each have a Stream row with
	// State=complete. Stream A is held; its state is not asserted here
	// (it will reach error/complete only at cleanup, depending on how
	// grpc-go unwinds the cancelled stream).
	// ----------------------------------------------------------------
	stB := streamForMethod(t, store, echoMethodUnary, 5*time.Second)
	stC := streamForMethod(t, store, echoMethodServerStream, 5*time.Second)
	stD := streamForMethod(t, store, echoMethodClientStream, 5*time.Second)

	waitForStreamState(t, store, stB.ID, "complete", 5*time.Second)
	waitForStreamState(t, store, stC.ID, "complete", 5*time.Second)
	waitForStreamState(t, store, stD.ID, "complete", 5*time.Second)

	// ----------------------------------------------------------------
	// Cleanup: clear the hold queue and cancel ctx so the held bidi A
	// goroutine unwinds. Best-effort wait with deadline (matches
	// http2/isolation_integration_test.go cleanup pattern).
	// ----------------------------------------------------------------
	queue.Clear()
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Non-fatal: grpc-go transport teardown after ctx cancel is not
		// always synchronous with the goroutine's return. Mirrors
		// sibling cleanup tolerance.
	}
}

// containsCtxDeadline returns true when err's chain mentions
// "context deadline exceeded". grpc-go often wraps the deadline in a
// status.Error that does not directly satisfy errors.Is(ctx.DeadlineExceeded).
func containsCtxDeadline(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for i := 0; i+25 <= len(s); i++ {
		if s[i:i+25] == "context deadline exceeded" {
			return true
		}
	}
	return false
}
