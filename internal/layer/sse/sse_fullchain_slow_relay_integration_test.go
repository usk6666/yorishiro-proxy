//go:build e2e && !e2e_smoke

package sse_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// slowSSERelayStep delays every post-swap SSE event by a fixed amount. It
// stands in for a loaded machine: runUpgradeSSE installs the SSE adapter
// (ReplaceUpstreamTop) BEFORE driveSSEEventLoop pushes any event through
// the Pipeline and onto the client wire, so slowing the per-event relay
// widens the window between "swap visible" and "events delivered".
type slowSSERelayStep struct {
	delay time.Duration
}

func (s slowSSERelayStep) Process(ctx context.Context, env *envelope.Envelope) pipeline.Result {
	if _, ok := env.Message.(*envelope.SSEMessage); ok {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
		}
	}
	return pipeline.Result{}
}

// TestSSE_FullChainSwapEndToEnd_SlowRelay is the deterministic regression
// guard for USK-1072. It runs the same full http1 → SSE swap as
// TestSSE_FullChainSwapEndToEnd, but with a Step that delays every SSE
// event by 100 ms. A harness that tears the connections down as soon as
// the swap is visible on the stack loses events 2/3 (or all of them):
// observing the swap does not mean the events have been relayed. The
// teardown must wait for the client reader to finish first.
func TestSSE_FullChainSwapEndToEnd_SlowRelay(t *testing.T) {
	clientA, clientB := pipePair()
	defer clientA.Close()
	upstreamA, upstreamB := pipePair()
	defer upstreamB.Close()

	store := &testStore{}

	stack := connector.NewConnectionStack("sse-fullchain-slow-relay-conn")
	clientLayer := http1.New(clientB, "client-stream", envelope.Send,
		http1.WithScheme("https"))
	upstreamLayer := http1.New(upstreamA, "upstream-stream", envelope.Receive,
		http1.WithScheme("https"),
		http1.WithStreamingResponseDetect(http1.IsSSEResponse))
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)

	const event = "event: ping\ndata: %d\nid: %d\nretry: 3000\n\n"
	lastEvent := []byte(fmt.Sprintf(event, 3, 3))

	clientReadDone := make(chan struct{})
	clientReceived := make(chan []byte, 1)
	go func() {
		defer close(clientReadDone)
		_, _ = clientA.Write([]byte("GET /events HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Accept: text/event-stream\r\n" +
			"\r\n"))

		all := make([]byte, 0, 4096)
		buf := make([]byte, 1024)

		// Wait for the 200 OK header block.
		headerDeadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(headerDeadline) {
			_ = clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _ := clientA.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
			}
			if bytes.Contains(all, []byte("\r\n\r\n")) {
				break
			}
		}

		// Browser FIN after the GET; the swap does not depend on it.
		if cw, ok := clientA.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}

		// Drain events until the last one arrives (or the deadline).
		eventDeadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(eventDeadline) {
			_ = clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _ := clientA.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
			}
			if bytes.Contains(all, lastEvent) {
				break
			}
		}
		_ = clientA.SetReadDeadline(time.Time{})
		clientReceived <- all
	}()

	// Server-side: read the request, write 200 + 3 events on the same wire.
	go func() {
		buf := make([]byte, 4096)
		_, _ = upstreamB.Read(buf)

		_, _ = upstreamB.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"\r\n"))
		for i := 1; i <= 3; i++ {
			_, _ = upstreamB.Write([]byte(fmt.Sprintf(event, i, i)))
		}
		time.Sleep(200 * time.Millisecond)
		_ = upstreamB.Close()
	}()

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		ch, ok := <-upstreamLayer.Channels()
		if !ok {
			return nil, errors.New("upstream Channels closed before yielding")
		}
		return ch, nil
	}

	// UpgradeStep MUST run after RecordStep (R1). The slow Step runs last
	// so the event is recorded, then delayed, then written to the client.
	p := pipeline.New(
		pipeline.NewRecordStep(store, slog.Default()),
		session.NewUpgradeStep(),
		slowSSERelayStep{delay: 100 * time.Millisecond},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- session.RunStackSession(ctx, stack, dial, p, session.SessionOptions{
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

	// Wait for the swap to install the SSE adapter on the upstream side.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stack.UpstreamTopmost() != upstreamLayer {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if top := stack.UpstreamTopmost(); top == upstreamLayer {
		t.Errorf("upstream topmost still original http1.Layer; swap did not install SSE adapter")
	}

	// Tear down: close pipes so the recursive RunSession returns.
	_ = clientA.Close()
	_ = upstreamB.Close()
	<-clientReadDone

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunStackSession did not return after teardown")
	}

	// --- Client-side wire receipt ---
	wire := <-clientReceived
	for i := 1; i <= 3; i++ {
		want := fmt.Sprintf(event, i, i)
		if !bytes.Contains(wire, []byte(want)) {
			t.Errorf("client wire missing event %d (%q); wire=%q", i, want, wire)
		}
	}

	// --- Recording shape ---
	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	streamID := streams[0].ID

	if sendFlows := store.flowsByDirection("send"); len(sendFlows) != 1 {
		t.Errorf("got %d send flows, want 1 (the GET)", len(sendFlows))
	}

	var sseFlows, httpFlows []*flow.Flow
	for _, f := range store.flowsByDirection("receive") {
		if f.StreamID != streamID {
			t.Errorf("receive flow on unexpected stream %q (want %q): %+v", f.StreamID, streamID, f)
			continue
		}
		if f.Metadata != nil && f.Metadata["sse_event"] != "" {
			sseFlows = append(sseFlows, f)
		} else {
			httpFlows = append(httpFlows, f)
		}
	}
	if len(sseFlows) != 3 {
		t.Errorf("got %d SSE event flows, want 3", len(sseFlows))
	}
	if len(httpFlows) != 1 {
		t.Errorf("got %d HTTP receive flows, want 1 (no double-recording across swap)", len(httpFlows))
	}
	for i, f := range sseFlows {
		want := fmt.Sprintf("%d", i+1)
		if string(f.Body) != want {
			t.Errorf("SSE flow[%d].Body = %q, want %q", i, f.Body, want)
		}
		if f.Metadata["sse_event"] != "ping" {
			t.Errorf("SSE flow[%d].sse_event = %q, want ping", i, f.Metadata["sse_event"])
		}
	}
}
