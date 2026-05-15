package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-905 h2-path coverage for the synthetic event:error notification
// path. driveSSEEventLoop is shared between runUpgradeSSE (h1,
// chunkedTE=true) and runUpgradeSSEOverH2 (h2, chunkedTE=false). The
// h1-side e2e coverage lives in
// internal/layer/sse/max_event_size_notify_integration_test.go; the
// chunked-terminator branch (finalizeSSEEventLoop emits "0\r\n\r\n")
// is tested there. The h2 branch must NOT emit that terminator on
// the wire — h2 DATA frames carry their own framing and END_STREAM
// is propagated by the deferred cW.Close() in runUpgradeSSEOverH2.
//
// These tests directly invoke driveSSEEventLoop with chunkedTE=false
// (the seam runUpgradeSSEOverH2 uses) so the h2-shaped contract is
// pinned without inheriting the pre-existing TLS-handshake-EOF flake
// of the full sse-over-h2 listener tests.

// sseH2RecordStub captures SaveStream / SaveFlow / UpdateStream calls
// for assertion. It satisfies flow.Writer and intentionally does not
// implement any read interface — the synthetic-event path projects via
// SaveFlow on the cap-exceed envelope.
type sseH2RecordStub struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
	updates []flow.StreamUpdate
}

func (s *sseH2RecordStub) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *st
	s.streams = append(s.streams, &clone)
	return nil
}

func (s *sseH2RecordStub) SaveFlow(_ context.Context, fl *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *fl
	if fl.Metadata != nil {
		clone.Metadata = make(map[string]string, len(fl.Metadata))
		for k, v := range fl.Metadata {
			clone.Metadata[k] = v
		}
	}
	s.flows = append(s.flows, &clone)
	return nil
}

func (s *sseH2RecordStub) UpdateStream(_ context.Context, _ string, u flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, u)
	return nil
}

func (s *sseH2RecordStub) snapshotFlows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// TestDriveSSEEventLoop_H2EventTooLarge_NoChunkedTerminator pins the
// USK-905 h2 contract: when an oversize event hits the boundary reader
// on the h2 path (chunkedTE=false), driveSSEEventLoop must
//   - emit the synthetic event:error wire bytes WITHOUT a chunked
//     hex-length prefix (h2 forbids Transfer-Encoding: chunked per
//     RFC 9113 §8.2.2),
//   - NOT emit the h1 framing terminator "0\r\n\r\n" (the END_STREAM
//     responsibility belongs to runUpgradeSSEOverH2's deferred
//     cW.Close()),
//   - return *layer.StreamError{Code: ErrorInternalError} so
//     OnComplete projects FailureReason="internal_error".
func TestDriveSSEEventLoop_H2EventTooLarge_NoChunkedTerminator(t *testing.T) {
	const capBytes = 256
	huge := strings.Repeat("x", capBytes+64)
	upstream := bytes.NewReader([]byte("data: " + huge + "\n\n"))
	br := sse.NewEventBoundaryReader(upstream, capBytes)

	var clientBuf bytes.Buffer
	store := &sseH2RecordStub{}
	p := pipeline.New(pipeline.NewRecordStep(store, nil))

	nextSeq := 1
	flowCtx := envelope.EnvelopeContext{}
	err := driveSSEEventLoop(
		context.Background(),
		p,
		br,
		&clientBuf,
		false, // h2 path
		"stream-h2-usk905",
		flowCtx,
		&nextSeq,
		capBytes,
	)

	// The seam must surface *layer.StreamError{InternalError}.
	if err == nil {
		t.Fatal("driveSSEEventLoop returned nil; want *layer.StreamError")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("driveSSEEventLoop err = %T (%v); want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want layer.ErrorInternalError", se.Code)
	}
	if !strings.Contains(se.Error(), "event exceeds maximum size") {
		t.Errorf("StreamError.Error() = %q, want substring %q",
			se.Error(), "event exceeds maximum size")
	}

	wire := clientBuf.String()

	// h2 path must NOT emit the chunked terminator. finalizeSSEEventLoop
	// returns nil immediately when chunkedTE=false; END_STREAM is the
	// runUpgradeSSEOverH2 wrapper's responsibility, not the loop's.
	if strings.Contains(wire, "0\r\n\r\n") {
		t.Errorf("h2 driveSSEEventLoop emitted chunked terminator on wire: %q", wire)
	}

	// h2 path must NOT emit a chunked hex-length frame prefix. The
	// synthetic event wire bytes are "event: error\n" + "data: <json>\n"
	// + "\n"; no hex-prefix line is allowed.
	if !strings.HasPrefix(wire, "event: error\n") {
		t.Errorf("h2 wire missing raw event prefix (must NOT be chunked): %q", wire)
	}

	// Structured payload assertion: parse the data: line as JSON and
	// verify the synthetic payload shape.
	dataIdx := strings.Index(wire, "data: ")
	if dataIdx < 0 {
		t.Fatalf("h2 wire missing data: line: %q", wire)
	}
	payloadStart := dataIdx + len("data: ")
	payloadEnd := strings.IndexByte(wire[payloadStart:], '\n')
	if payloadEnd < 0 {
		t.Fatalf("h2 wire data: line not newline-terminated: %q", wire)
	}
	payloadJSON := wire[payloadStart : payloadStart+payloadEnd]
	var got struct {
		Reason   string `json:"reason"`
		Cap      int    `json:"cap"`
		Observed int    `json:"observed"`
	}
	if jerr := json.Unmarshal([]byte(payloadJSON), &got); jerr != nil {
		t.Fatalf("synthetic payload did not parse as JSON: %v (raw=%q)", jerr, payloadJSON)
	}
	if got.Reason != "event-too-large" {
		t.Errorf("synthetic Reason = %q, want %q", got.Reason, "event-too-large")
	}
	if got.Cap != capBytes {
		t.Errorf("synthetic Cap = %d, want %d", got.Cap, capBytes)
	}
	if got.Observed <= 0 {
		t.Errorf("synthetic Observed = %d, want > 0", got.Observed)
	}

	// Wire fidelity guard: the synthetic event must end with the SSE
	// inter-event blank line ("\n\n") so the EventSource client parses
	// it as a complete event rather than waiting for the cap-exceed
	// reason payload to terminate.
	if !strings.HasSuffix(wire, "\n\n") {
		t.Errorf("h2 wire missing SSE event terminator (\\n\\n): %q", wire)
	}

	// RecordStep must have persisted the synthetic envelope as a Flow
	// row carrying the proxy_event_too_large anomaly marker. This is
	// the analyst-visible distinguishing signal between a genuine
	// upstream-emitted event:error and the proxy-synthesised one.
	syntheticFlows := 0
	for _, fl := range store.snapshotFlows() {
		if fl == nil || fl.Metadata == nil {
			continue
		}
		if fl.Metadata["sse_anomaly_proxy_event_too_large"] != "" {
			syntheticFlows++
			if got := fl.Metadata["sse_event"]; got != "error" {
				t.Errorf("synthetic flow Metadata[sse_event] = %q, want %q", got, "error")
			}
		}
	}
	if syntheticFlows != 1 {
		t.Errorf("got %d synthetic-event Flow rows; want exactly 1", syntheticFlows)
	}

	// nextSeq must have advanced by exactly one (the synthetic envelope
	// claims one slot before the loop returns the StreamError).
	if nextSeq != 2 {
		t.Errorf("nextSeq = %d after synthetic emit; want 2 (started at 1, advanced once)", nextSeq)
	}
}

// TestDriveSSEEventLoop_H2EventTooLarge_ClassifyError pins the cross-
// package contract: ClassifyError must map the returned StreamError to
// "internal_error" so OnComplete projection (proxybuild
// buildOnCompleteFunc) records FailureReason consistently with the
// h1 path. Without this, the gRPC-sibling-parity claim in the PR body
// would be h1-only.
func TestDriveSSEEventLoop_H2EventTooLarge_ClassifyError(t *testing.T) {
	const capBytes = 128
	huge := strings.Repeat("y", capBytes*2)
	upstream := bytes.NewReader([]byte("data: " + huge + "\n\n"))
	br := sse.NewEventBoundaryReader(upstream, capBytes)

	nextSeq := 1
	err := driveSSEEventLoop(
		context.Background(),
		pipeline.New(),
		br,
		io.Discard,
		false, // h2 path
		"stream-h2-classify",
		envelope.EnvelopeContext{},
		&nextSeq,
		capBytes,
	)
	if got := ClassifyError(err); got != "internal_error" {
		t.Errorf("ClassifyError(driveSSEEventLoop err) = %q, want %q",
			got, "internal_error")
	}
}
