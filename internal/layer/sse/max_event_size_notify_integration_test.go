//go:build e2e && !e2e_smoke

// USK-905 e2e regression suite for the synthetic event:error notification
// path that runUpgradeSSE emits when an upstream event exceeds the
// configured sse_max_event_size cap.
//
// Pre-USK-905 the proxy closed the response with state=error but the
// client only observed: 200 OK headers, then zero-byte body, then TCP
// close. There was no chunked terminator, no structured signal, and no
// way for the client to distinguish a proxy cap from an upstream abort.
//
// Post-USK-905 the proxy synthesises:
//
//	event: error
//	data: {"reason":"event-too-large","cap":N,"observed":M}
//
// then emits the framing terminator (chunked "0\r\n\r\n" on h1,
// END_STREAM on h2). The synthetic envelope is also recorded as a Flow
// row tagged with sse_anomaly_proxy_event_too_large so analysts can
// distinguish it from a genuine upstream-emitted event:error.
//
// Coverage:
//   - h1: synthetic event delivered to client + chunked terminator emitted.
//   - h1: Stream.State=error, FailureReason=internal_error.
//   - h1: Flow row carries sse_anomaly_proxy_event_too_large metadata.
//   - h1: Pipeline Drop suppresses the synthetic event from the wire BUT
//     the chunked terminator is still emitted (no half-open hang).
package sse_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
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

// sseEventTooLargeHarness drives a chunked-TE SSE upstream that emits
// one oversize event, then captures (a) the client wire bytes, (b) the
// flow.Stream / flow.Flow rows the proxy projected, and (c) the
// terminal error reported via OnComplete. The harness mirrors
// sseProxyHarness in usk890_integration_test.go but adds SSEMaxEventSize
// to SessionOptions and surfaces OnComplete's err to the test.
type sseEventTooLargeHarness struct {
	t              *testing.T
	upstreamHeader string
	upstreamWriter func(w io.Writer)
	maxEventSize   int
	pipelineSteps  []pipeline.Step
}

func (h *sseEventTooLargeHarness) run() (clientBody []byte, store *testStore, completeErr error) {
	t := h.t
	t.Helper()

	clientA, clientB := pipePair()
	defer clientA.Close()
	upstreamA, upstreamB := pipePair()
	defer upstreamB.Close()

	store = &testStore{}
	tagged := &tagStore{testStore: store}

	stack := connector.NewConnectionStack("usk905-conn")
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
		// Read the full response (headers + chunked body + terminator) until
		// either the chunked terminator appears or the proxy closes.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_ = clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := clientA.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
			}
			if bytes.HasSuffix(all, []byte("0\r\n\r\n")) {
				break
			}
			if err != nil {
				// Any non-timeout error means the proxy closed; stop reading.
				if !isTimeoutErr(err) {
					break
				}
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

	var (
		errMu      sync.Mutex
		gotErr     error
		gotErrSeen bool
	)
	captureOnComplete := func(cctx context.Context, sid string, err error) {
		errMu.Lock()
		gotErr = err
		gotErrSeen = true
		errMu.Unlock()
		state := "complete"
		if err != nil && !errors.Is(err, io.EOF) {
			state = "error"
		}
		if sid != "" {
			tags := map[string]string{}
			if state == "error" && err != nil {
				tags["error"] = err.Error()
			}
			_ = tagged.UpdateStream(cctx, sid, flow.StreamUpdate{
				State:         state,
				FailureReason: session.ClassifyError(err),
				AppendTags:    tags,
			})
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- session.RunStackSession(ctx, stack, dial, p, session.SessionOptions{
			SSEMaxEventSize: h.maxEventSize,
			OnComplete:      captureOnComplete,
		})
	}()

	swapDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(swapDeadline) {
		top := stack.UpstreamTopmost()
		if top != upstreamLayer {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
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
	decoded, derr := decodeChunkedBody(body)
	if derr != nil {
		t.Fatalf("chunked decode: %v; body=%q", derr, body)
	}

	errMu.Lock()
	if !gotErrSeen {
		errMu.Unlock()
		t.Fatal("OnComplete was not invoked")
	}
	completeErr = gotErr
	errMu.Unlock()
	return decoded, store, completeErr
}

// isTimeoutErr reports whether err is a deadline-exceeded i/o timeout.
// Used by the harness reader loop to distinguish read-deadline timeouts
// (keep looping) from real EOF / closed-conn errors (stop reading).
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// tagStore extends testStore with AppendTags persistence so the
// USK-905 acceptance tests can assert Stream.Tags["error"] is preserved.
// testStore's UpdateStream intentionally does not implement AppendTags
// (its other consumers do not need it); we extend rather than mutate it
// to keep the sibling test files' contracts stable.
type tagStore struct {
	*testStore
}

func (s *tagStore) UpdateStream(ctx context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.ID == id {
			if update.State != "" {
				st.State = update.State
			}
			if update.FailureReason != "" {
				st.FailureReason = update.FailureReason
			}
			if len(update.AppendTags) > 0 {
				if st.Tags == nil {
					st.Tags = map[string]string{}
				}
				for k, v := range update.AppendTags {
					st.Tags[k] = v
				}
			}
		}
	}
	return nil
}

// TestSSE_EventTooLarge_SyntheticEventNotifiesClient verifies the
// happy-path USK-905 contract: a single oversize event triggers a
// synthetic event:error with the structured JSON payload, the chunked
// terminator is emitted, the flow store records the synthetic envelope
// with the proxy_event_too_large anomaly marker, and OnComplete projects
// state=error + FailureReason=internal_error.
func TestSSE_EventTooLarge_SyntheticEventNotifiesClient(t *testing.T) {
	const cap = 256
	const observed = cap + 64
	huge := strings.Repeat("x", observed)
	upstreamEvent := "data: " + huge + "\n\n"

	h := &sseEventTooLargeHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		maxEventSize: cap,
		upstreamWriter: func(w io.Writer) {
			// One chunk containing the oversize event; we never write the
			// "0\r\n\r\n" terminator from upstream — the proxy must emit
			// its own terminator after the synthetic event.
			fmt.Fprintf(w, "%X\r\n%s\r\n", len(upstreamEvent), upstreamEvent)
		},
	}

	body, store, completeErr := h.run()

	// --- (1) Client wire: synthetic event with JSON payload + clean
	// chunked terminator.
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "event: error\n") {
		t.Errorf("client wire missing synthetic 'event: error' line\n  got = %q", bodyStr)
	}
	dataPrefix := "data: "
	dataIdx := strings.Index(bodyStr, dataPrefix)
	if dataIdx < 0 {
		t.Fatalf("client wire missing synthetic data: line\n  got = %q", bodyStr)
	}
	// Extract the JSON payload (data: { ... }\n).
	payloadStart := dataIdx + len(dataPrefix)
	payloadEnd := strings.IndexByte(bodyStr[payloadStart:], '\n')
	if payloadEnd < 0 {
		t.Fatalf("client wire data: line not newline-terminated\n  got = %q", bodyStr)
	}
	payloadJSON := bodyStr[payloadStart : payloadStart+payloadEnd]
	var got struct {
		Reason   string `json:"reason"`
		Cap      int    `json:"cap"`
		Observed int    `json:"observed"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &got); err != nil {
		t.Fatalf("synthetic event JSON payload did not parse: %v (raw=%q)", err, payloadJSON)
	}
	if got.Reason != "event-too-large" {
		t.Errorf("synthetic event reason = %q, want %q", got.Reason, "event-too-large")
	}
	if got.Cap != cap {
		t.Errorf("synthetic event cap = %d, want %d", got.Cap, cap)
	}
	if got.Observed <= 0 || got.Observed > observed+len("data: ")+len("\n\n") {
		t.Errorf("synthetic event observed = %d (cap=%d, upstream-emitted=%d); want a positive partial-bytes count bounded by upstream event size",
			got.Observed, cap, observed+len("data: ")+len("\n\n"))
	}

	// --- (2) OnComplete: *layer.StreamError with ErrorInternalError.
	if completeErr == nil {
		t.Fatal("OnComplete err was nil; want *layer.StreamError")
	}
	var se *layer.StreamError
	if !errors.As(completeErr, &se) {
		t.Fatalf("OnComplete err = %T (%v); want *layer.StreamError", completeErr, completeErr)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want layer.ErrorInternalError", se.Code)
	}
	if !strings.Contains(se.Error(), "event exceeds maximum size") {
		t.Errorf("StreamError.Error() = %q, want substring %q", se.Error(), "event exceeds maximum size")
	}

	// --- (3) Stream recording: state=error, FailureReason=internal_error,
	// Tags["error"] preserved.
	streams := store.getStreams()
	if len(streams) == 0 {
		t.Fatal("no streams recorded")
	}
	st := streams[0]
	if st.State != "error" {
		t.Errorf("Stream.State = %q, want %q", st.State, "error")
	}
	if st.FailureReason != "internal_error" {
		t.Errorf("Stream.FailureReason = %q, want %q", st.FailureReason, "internal_error")
	}
	if got := st.Tags["error"]; got == "" {
		t.Errorf("Stream.Tags[\"error\"] is empty; want the wrapped StreamError string")
	} else if !strings.Contains(got, "event exceeds maximum size") {
		t.Errorf("Stream.Tags[\"error\"] = %q, want substring %q", got, "event exceeds maximum size")
	}

	// --- (4) Flow recording: at least one Receive flow with the
	// proxy_event_too_large anomaly marker.
	syntheticFlows := 0
	for _, f := range store.flowsByDirection("receive") {
		if f == nil || f.Metadata == nil {
			continue
		}
		if f.Metadata["sse_anomaly_proxy_event_too_large"] != "" {
			syntheticFlows++
			if f.Metadata["sse_event"] != "error" {
				t.Errorf("synthetic flow Metadata[\"sse_event\"] = %q, want %q",
					f.Metadata["sse_event"], "error")
			}
		}
	}
	if syntheticFlows != 1 {
		t.Errorf("got %d Receive flows with sse_anomaly_proxy_event_too_large; want exactly 1", syntheticFlows)
	}
}

// dropSyntheticSSEStep drops the synthetic event:error envelope so the
// USK-905 acceptance test can verify the framing terminator is still
// emitted even when a plugin chooses to suppress the wire write.
type dropSyntheticSSEStep struct{}

func (dropSyntheticSSEStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	msg, ok := env.Message.(*envelope.SSEMessage)
	if !ok {
		return pipeline.Result{}
	}
	for _, a := range msg.Anomalies {
		if a.Type == envelope.AnomalySSEProxyEventTooLarge {
			return pipeline.Result{Action: pipeline.Drop, BlockedBy: "test_drop_synthetic"}
		}
	}
	return pipeline.Result{}
}

// TestSSE_EventTooLarge_PipelineDropStillEmitsTerminator verifies that
// a Pipeline Drop of the synthetic envelope does NOT leave the client
// connection half-open: the chunked terminator must still arrive, and
// the decoded body must be empty. The terminal *layer.StreamError still
// surfaces in OnComplete so projection records state=error.
func TestSSE_EventTooLarge_PipelineDropStillEmitsTerminator(t *testing.T) {
	const cap = 256
	huge := strings.Repeat("x", cap+64)
	upstreamEvent := "data: " + huge + "\n\n"

	h := &sseEventTooLargeHarness{
		t: t,
		upstreamHeader: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",
		maxEventSize: cap,
		upstreamWriter: func(w io.Writer) {
			fmt.Fprintf(w, "%X\r\n%s\r\n", len(upstreamEvent), upstreamEvent)
		},
		pipelineSteps: []pipeline.Step{dropSyntheticSSEStep{}},
	}

	body, _, completeErr := h.run()

	// Body must be empty: the synthetic event was Dropped, no other
	// events were forwarded, and the terminator is implicit in
	// decodeChunkedBody returning at size=0.
	if len(body) != 0 {
		t.Errorf("Pipeline-Drop synthetic event leaked to client wire: got=%q", body)
	}

	// OnComplete still observes the StreamError so projection records
	// the cap-exceed failure even though the wire signal was suppressed.
	var se *layer.StreamError
	if !errors.As(completeErr, &se) {
		t.Fatalf("OnComplete err = %T (%v); want *layer.StreamError even on Pipeline-Drop", completeErr, completeErr)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want layer.ErrorInternalError", se.Code)
	}
}
