package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// fkWriter is a flow.Writer double that enforces the two SQLite
// constraints RecordStep must respect: streams.id is UNIQUE, and
// flows.stream_id is a foreign key into streams (a SaveFlow for a Stream
// row that does not exist yet fails, exactly like the real store with
// foreign_keys=ON). saveStreamDelay widens the window between "SaveStream
// started" and "row exists" so a concurrent opener that does not wait for
// the row is caught.
type fkWriter struct {
	saveStreamDelay time.Duration

	mu              sync.Mutex
	streams         map[string]*flow.Stream
	saveStreamCalls int
	flows           []*flow.Flow
	fkErrors        int
	uniqueErrors    int
}

func newFKWriter() *fkWriter {
	return &fkWriter{streams: make(map[string]*flow.Stream)}
}

func (w *fkWriter) SaveStream(_ context.Context, s *flow.Stream) error {
	if w.saveStreamDelay > 0 {
		time.Sleep(w.saveStreamDelay)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.saveStreamCalls++
	if _, ok := w.streams[s.ID]; ok {
		w.uniqueErrors++
		return errors.New("UNIQUE constraint failed: streams.id")
	}
	w.streams[s.ID] = s
	return nil
}

func (w *fkWriter) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (w *fkWriter) SaveFlow(_ context.Context, f *flow.Flow) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.streams[f.StreamID]; !ok {
		w.fkErrors++
		return errors.New("FOREIGN KEY constraint failed")
	}
	w.flows = append(w.flows, f)
	return nil
}

func (w *fkWriter) snapshot() (streams map[string]*flow.Stream, saveStreamCalls int, flows []*flow.Flow, fkErrors, uniqueErrors int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	streams = make(map[string]*flow.Stream, len(w.streams))
	for k, v := range w.streams {
		streams[k] = v
	}
	flows = append([]*flow.Flow(nil), w.flows...)
	return streams, w.saveStreamCalls, flows, w.fkErrors, w.uniqueErrors
}

// rawEnvForTest builds a raw envelope in the shape bytechunk.Channel.Next
// produces (internal/layer/bytechunk/channel.go): Protocol=raw,
// Raw == RawMessage.Bytes, per-direction Sequence, and a Context carrying
// only ReceivedAt. The session rewrites Receive StreamIDs to the client
// Channel's StreamID, so both directions share streamID here.
func rawEnvForTest(streamID string, dir envelope.Direction, seq int, data string) *envelope.Envelope {
	b := []byte(data)
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-" + dir.String() + "-" + string(rune('0'+seq)),
		Sequence:  seq,
		Direction: dir,
		Protocol:  envelope.ProtocolRaw,
		Raw:       b,
		Message:   &envelope.RawMessage{Bytes: b},
		Context:   envelope.EnvelopeContext{ReceivedAt: time.Now()},
	}
}

// TestRecordStep_RawReceiveFirst_CreatesStream pins USK-1216: on a
// server-speaks-first raw stream (SMTP / MySQL / FTP banner) the first
// envelope RecordStep sees is Receive seq 0. It must create the Stream so
// the banner's Flow survives the flows.stream_id FK, and the later client
// Send seq 0 must not create the Stream again.
func TestRecordStep_RawReceiveFirst_CreatesStream(t *testing.T) {
	w := newFKWriter()
	step := NewRecordStep(w, nil)
	ctx := context.Background()

	step.Process(ctx, rawEnvForTest("conn-1/client", envelope.Receive, 0, "220 banner\r\n"))
	step.Process(ctx, rawEnvForTest("conn-1/client", envelope.Send, 0, "EHLO x\r\n"))

	streams, calls, flows, fkErrors, uniqueErrors := w.snapshot()
	if calls != 1 {
		t.Errorf("SaveStream calls = %d, want 1", calls)
	}
	if uniqueErrors != 0 {
		t.Errorf("UNIQUE(streams.id) violations = %d, want 0", uniqueErrors)
	}
	if fkErrors != 0 {
		t.Errorf("flows.stream_id FK violations = %d, want 0 (Receive-first Flow lost)", fkErrors)
	}
	st, ok := streams["conn-1/client"]
	if !ok {
		t.Fatalf("Stream conn-1/client not created; streams=%v", streams)
	}
	if st.Protocol != string(envelope.ProtocolRaw) {
		t.Errorf("Stream.Protocol = %q, want raw", st.Protocol)
	}
	if len(flows) != 2 {
		t.Fatalf("saved flows = %d, want 2", len(flows))
	}
	if flows[0].Direction != "receive" || string(flows[0].RawBytes) != "220 banner\r\n" || flows[0].Sequence != 0 {
		t.Errorf("first flow = dir %q seq %d raw %q, want receive seq 0 %q",
			flows[0].Direction, flows[0].Sequence, flows[0].RawBytes, "220 banner\r\n")
	}
	if flows[1].Direction != "send" || flows[1].Sequence != 0 {
		t.Errorf("second flow = dir %q seq %d, want send seq 0", flows[1].Direction, flows[1].Sequence)
	}
}

// TestRecordStep_RawReceiveFirst_CaptureScope pins the capture_scope
// decision for Receive-first raw streams. A raw envelope carries no
// method / path, and bytechunk stamps no TargetHost / SNI, so the scope
// decision is direction-symmetric: an exclude-only scope keeps the stream
// (nothing can match), an include-by-hostname scope drops it. Before
// USK-1216 the Receive-first envelope hit the fail-closed cache miss and
// the exclude-only case was silently not recorded.
func TestRecordStep_RawReceiveFirst_CaptureScope(t *testing.T) {
	tests := []struct {
		name       string
		includes   []flow.ScopeRule
		excludes   []flow.ScopeRule
		wantStream bool
		wantFlows  int
	}{
		{
			name:       "exclude-only scope records the receive-first stream",
			excludes:   []flow.ScopeRule{{Hostname: "excluded.example"}},
			wantStream: true,
			wantFlows:  2,
		},
		{
			name:       "include-by-hostname scope drops the receive-first stream",
			includes:   []flow.ScopeRule{{Hostname: "included.example"}},
			wantStream: false,
			wantFlows:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newFKWriter()
			step := NewRecordStep(w, nil, WithRecordScope(newRecordScopeForTest(tt.includes, tt.excludes)))
			ctx := context.Background()

			step.Process(ctx, rawEnvForTest("conn-s/client", envelope.Receive, 0, "220 banner\r\n"))
			step.Process(ctx, rawEnvForTest("conn-s/client", envelope.Send, 0, "EHLO x\r\n"))

			streams, _, flows, fkErrors, _ := w.snapshot()
			if _, ok := streams["conn-s/client"]; ok != tt.wantStream {
				t.Errorf("Stream created = %v, want %v", ok, tt.wantStream)
			}
			if len(flows) != tt.wantFlows {
				t.Errorf("saved flows = %d, want %d", len(flows), tt.wantFlows)
			}
			if fkErrors != 0 {
				t.Errorf("flows.stream_id FK violations = %d, want 0", fkErrors)
			}
		})
	}
}

// TestRecordStep_RawConcurrentFirstEnvelopes pins the race between the
// two session goroutines on a raw stream: the client's Send seq 0 and the
// upstream's Receive seq 0 reach RecordStep at the same time on the same
// StreamID. Exactly one SaveStream must run, and neither Flow may be
// saved before the Stream row exists (the loser must wait for the
// winner's SaveStream instead of racing ahead into the FK).
func TestRecordStep_RawConcurrentFirstEnvelopes(t *testing.T) {
	for i := 0; i < 20; i++ {
		w := newFKWriter()
		w.saveStreamDelay = 20 * time.Millisecond
		step := NewRecordStep(w, nil)
		ctx := context.Background()

		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, env := range []*envelope.Envelope{
			rawEnvForTest("conn-race/client", envelope.Send, 0, "EHLO x\r\n"),
			rawEnvForTest("conn-race/client", envelope.Receive, 0, "220 banner\r\n"),
		} {
			wg.Add(1)
			go func(env *envelope.Envelope) {
				defer wg.Done()
				<-start
				step.Process(ctx, env)
			}(env)
		}
		close(start)
		wg.Wait()

		_, calls, flows, fkErrors, uniqueErrors := w.snapshot()
		if calls != 1 || uniqueErrors != 0 {
			t.Fatalf("iteration %d: SaveStream calls = %d (unique violations %d), want exactly 1", i, calls, uniqueErrors)
		}
		if fkErrors != 0 {
			t.Fatalf("iteration %d: flows.stream_id FK violations = %d, want 0 (a Flow was saved before its Stream)", i, fkErrors)
		}
		if len(flows) != 2 {
			t.Fatalf("iteration %d: saved flows = %d, want 2", i, len(flows))
		}
	}
}

// TestRecordStep_NonRawReceiveFirst_Unchanged is a characterization guard
// for the USK-1216 raw-only gate: an HTTP response that arrives with no
// prior request on its StreamID must not create a Stream (with or without
// a capture scope), and a WS Receive on an existing Stream must not save
// the Stream again. Removing the ProtocolRaw gate makes the HTTP cases
// fail.
func TestRecordStep_NonRawReceiveFirst_Unchanged(t *testing.T) {
	httpResp := func(streamID string) *envelope.Envelope {
		return &envelope.Envelope{
			StreamID:  streamID,
			FlowID:    streamID + "-resp",
			Direction: envelope.Receive,
			Sequence:  0,
			Protocol:  envelope.ProtocolHTTP,
			Message:   &envelope.HTTPMessage{Status: 200},
		}
	}

	t.Run("http receive-first without scope creates no stream", func(t *testing.T) {
		w := newFKWriter()
		step := NewRecordStep(w, nil)
		step.Process(context.Background(), httpResp("h-1"))
		_, calls, flows, _, _ := w.snapshot()
		if calls != 0 {
			t.Errorf("SaveStream calls = %d, want 0", calls)
		}
		if len(flows) != 0 {
			t.Errorf("saved flows = %d, want 0", len(flows))
		}
	})

	t.Run("http receive-first under exclude-only scope stays fail-closed", func(t *testing.T) {
		w := newFKWriter()
		step := NewRecordStep(w, nil, WithRecordScope(newRecordScopeForTest(nil, []flow.ScopeRule{{Hostname: "excluded.example"}})))
		step.Process(context.Background(), httpResp("h-2"))
		_, calls, flows, fkErrors, _ := w.snapshot()
		if calls != 0 || len(flows) != 0 || fkErrors != 0 {
			t.Errorf("got SaveStream=%d flows=%d fkErrors=%d, want all 0 (fail-closed)", calls, len(flows), fkErrors)
		}
	})

	t.Run("ws receive on an existing stream does not re-save it", func(t *testing.T) {
		w := newFKWriter()
		step := NewRecordStep(w, nil)
		ctx := context.Background()
		step.Process(ctx, &envelope.Envelope{
			StreamID: "ws-1", FlowID: "ws-1-s0", Direction: envelope.Send, Sequence: 0,
			Protocol: envelope.ProtocolWebSocket,
			Message:  &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hi")},
		})
		step.Process(ctx, &envelope.Envelope{
			StreamID: "ws-1", FlowID: "ws-1-r0", Direction: envelope.Receive, Sequence: 0,
			Protocol: envelope.ProtocolWebSocket,
			Message:  &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("yo")},
		})
		_, calls, flows, fkErrors, _ := w.snapshot()
		if calls != 1 {
			t.Errorf("SaveStream calls = %d, want 1", calls)
		}
		if len(flows) != 2 || fkErrors != 0 {
			t.Errorf("flows = %d fkErrors = %d, want 2 / 0", len(flows), fkErrors)
		}
	})
}
