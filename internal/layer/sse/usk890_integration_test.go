//go:build e2e && !e2e_smoke

// USK-890 e2e regression suite for runUpgradeSSE's C-event redesign.
//
// These tests live in the exhaustive tier (e2e && !e2e_smoke) — they are
// not part of the per-PR merge gate. The strengthened
// TestSSE_ChunkedTransferEncoding_NoHexPrefix (in sse_integration_test.go,
// plain e2e tag) keeps the smoke-tier guard against the original
// regression. The tests below extend coverage to:
//
//   - Direct-vs-proxy byte-equal round-trip with comments and unknown
//     fields (TestSSE_ChunkedClientWireRoundTripsToDirect).
//   - Pipeline Drop blocks client emission (TestSSE_DropAction_BlocksClientEmission).
//   - Non-chunked TE upstream (Content-Length / Connection: close)
//     forwards events un-wrapped (TestSSE_NonChunkedTE_NoRegression).
//   - Pipeline-modified events re-encode via sse.EncodeWireBytes
//     (TestSSE_ModifiedEvent_ReEncoded).
package sse_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
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

// sseProxyHarness encapsulates the http1 → SSE swap dance used by the
// USK-890 regression tests. Returns the chunked-decoded (when chunkedTE
// is true) or raw client wire body after teardown.
type sseProxyHarness struct {
	t              *testing.T
	upstreamWriter func(net io.Writer)
	upstreamHeader string // full response head (status line + headers + "\r\n")
	chunkedTE      bool   // when true, the test chunked-decodes the client body
	pipelineSteps  []pipeline.Step
}

func (h *sseProxyHarness) run() (clientBody []byte, store *testStore) {
	t := h.t
	t.Helper()

	clientA, clientB := pipePair()
	defer clientA.Close()
	upstreamA, upstreamB := pipePair()
	defer upstreamB.Close()

	store = &testStore{}
	stack := connector.NewConnectionStack("usk890-conn")
	clientLayer := http1.New(clientB, "client-stream", envelope.Send, http1.WithScheme("https"))
	upstreamLayer := http1.New(upstreamA, "upstream-stream", envelope.Receive,
		http1.WithScheme("https"),
		http1.WithStreamingResponseDetect(http1.IsSSEResponse))
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)

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
		if cw, ok := clientA.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		// Drain until upstream closes.
		eventDeadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(eventDeadline) {
			_ = clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _ := clientA.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
			}
			if h.chunkedTE && bytes.HasSuffix(all, []byte("0\r\n\r\n")) {
				break
			}
		}
		_ = clientA.SetReadDeadline(time.Time{})
		clientReceived <- all
	}()

	go func() {
		buf := make([]byte, 4096)
		_, _ = upstreamB.Read(buf)
		_, _ = upstreamB.Write([]byte(h.upstreamHeader))
		h.upstreamWriter(upstreamB)
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

	steps := []pipeline.Step{pipeline.NewRecordStep(store, slog.Default())}
	steps = append(steps, h.pipelineSteps...)
	steps = append(steps, session.NewUpgradeStep())
	p := pipeline.New(steps...)

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

	// Wait for the swap so events flow through the post-swap path
	// before we tear down the connections.
	swapDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(swapDeadline) {
		top := stack.UpstreamTopmost()
		if top != upstreamLayer {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The client goroutine self-terminates after the upstream writer
	// closes upstreamB (which causes the proxy to forward EOF). Wait
	// for that signal before closing the rest of the pipes.
	<-clientReadDone
	_ = clientA.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunStackSession did not return after teardown")
	}

	wire := <-clientReceived
	headerEnd := bytes.Index(wire, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		t.Fatalf("no header terminator in client wire: %q", wire)
	}
	body := wire[headerEnd+4:]
	if !h.chunkedTE {
		return body, store
	}
	decoded, derr := decodeChunkedBody(body)
	if derr != nil {
		t.Fatalf("chunked decode: %v; body=%q", derr, body)
	}
	return decoded, store
}

// TestSSE_ChunkedClientWireRoundTripsToDirect asserts the proxy's client-
// facing wire (chunked-decoded) matches the upstream's body byte-for-byte
// for a stream containing real events, comment lines, and unknown fields.
// This is the strongest wire-fidelity assertion in the suite.
func TestSSE_ChunkedClientWireRoundTripsToDirect(t *testing.T) {
	events := []string{
		"event: ping\ndata: hello\nid: 1\n\n",
		": keepalive\n\n", // comment-only block — must reach client verbatim
		"data: world\n\n",
		"x-custom: ignored\ndata: with-unknown-field\n\n", // unknown field passes through
		"data:tight\n\n",                                  // no space after colon — byte-for-byte round-trip
	}
	upstreamBody := strings.Join(events, "")

	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		chunkedTE: true,
		upstreamWriter: func(w io.Writer) {
			// One chunk per event so chunked framing exercises every
			// event boundary independently.
			for _, e := range events {
				fmt.Fprintf(w, "%X\r\n%s\r\n", len(e), e)
			}
			_, _ = w.Write([]byte("0\r\n\r\n"))
		},
	}

	got, _ := h.run()
	if !bytes.Equal(got, []byte(upstreamBody)) {
		t.Errorf("client wire (chunked-decoded) != upstream body\n  got  = %q\n  want = %q",
			got, upstreamBody)
	}
}

// dropEventStep returns Action=Drop for every SSEMessage envelope. Used
// to assert that runUpgradeSSE blocks client emission when the Pipeline
// drops an event (forward-compatibility for USK-892 auto-replace).
type dropEventStep struct{}

func (dropEventStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if _, ok := env.Message.(*envelope.SSEMessage); ok {
		return pipeline.Result{Action: pipeline.Drop, BlockedBy: "test_drop"}
	}
	return pipeline.Result{}
}

// TestSSE_DropAction_BlocksClientEmission installs a Pipeline step that
// drops every SSEMessage and asserts the proxy does not forward those
// events to the client. The chunked-TE terminator still arrives on
// graceful upstream close, but the decoded body must be empty.
func TestSSE_DropAction_BlocksClientEmission(t *testing.T) {
	events := []string{
		"data: hidden-1\n\n",
		"data: hidden-2\n\n",
	}
	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		chunkedTE: true,
		upstreamWriter: func(w io.Writer) {
			for _, e := range events {
				fmt.Fprintf(w, "%X\r\n%s\r\n", len(e), e)
			}
			_, _ = w.Write([]byte("0\r\n\r\n"))
		},
		pipelineSteps: []pipeline.Step{dropEventStep{}},
	}

	got, _ := h.run()
	if len(got) != 0 {
		t.Errorf("dropped events leaked to client: got=%q", got)
	}
}

// TestSSE_NonChunkedTE_NoRegression asserts non-chunked SSE upstreams
// (Connection: close framing, no Transfer-Encoding header) forward
// events to the client without chunked framing wrapping the body.
func TestSSE_NonChunkedTE_NoRegression(t *testing.T) {
	events := []string{
		"data: a\n\n",
		"data: b\n\n",
	}
	body := strings.Join(events, "")

	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Connection: close\r\n" +
			"\r\n",
		chunkedTE: false,
		upstreamWriter: func(w io.Writer) {
			_, _ = w.Write([]byte(body))
		},
	}

	got, _ := h.run()
	if !bytes.Equal(got, []byte(body)) {
		t.Errorf("non-chunked SSE body mismatch\n  got  = %q\n  want = %q", got, body)
	}
}

// modifySSEStep mutates every SSEMessage's Data field so the C-event
// loop's "mutated → re-encode" branch is exercised end-to-end.
type modifySSEStep struct{}

func (modifySSEStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if msg, ok := env.Message.(*envelope.SSEMessage); ok {
		msg.Data = "modified:" + msg.Data
	}
	return pipeline.Result{}
}

// TestSSE_ModifiedEvent_ReEncoded installs a Pipeline step that mutates
// each event's Data field. The client must receive the re-encoded form
// (sse.EncodeWireBytes output), and the chunked framing must wrap the
// re-encoded payload — not the original raw bytes.
func TestSSE_ModifiedEvent_ReEncoded(t *testing.T) {
	upstreamEvent := "data: original\n\n"
	wantEncoded := "data: modified:original\n\n"

	h := &sseProxyHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		chunkedTE: true,
		upstreamWriter: func(w io.Writer) {
			fmt.Fprintf(w, "%X\r\n%s\r\n", len(upstreamEvent), upstreamEvent)
			_, _ = w.Write([]byte("0\r\n\r\n"))
		},
		pipelineSteps: []pipeline.Step{modifySSEStep{}},
	}

	got, _ := h.run()
	if !bytes.Equal(got, []byte(wantEncoded)) {
		t.Errorf("re-encoded event mismatch\n  got  = %q\n  want = %q", got, wantEncoded)
	}
}
