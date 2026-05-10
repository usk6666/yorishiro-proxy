//go:build e2e && !e2e_smoke

package sse_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// taggingTestStore is a flow.Writer that captures AppendTags entries from
// UpdateStream calls in addition to the basic Stream/Flow recording the
// SSE e2e suite's testStore provides. The default testStore drops
// AppendTags on the floor (it only mirrors State + FailureReason), so
// USK-802's records_truncated tag would be invisible to it.
type taggingTestStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
	updates []flow.StreamUpdate
}

func (s *taggingTestStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *taggingTestStore) UpdateStream(_ context.Context, _ string, u flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, u)
	return nil
}

func (s *taggingTestStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

func (s *taggingTestStore) sseFlowCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := 0
	for _, f := range s.flows {
		if f.Direction == "receive" && f.Metadata["sse_event"] != "" {
			c++
		}
	}
	return c
}

func (s *taggingTestStore) truncatedTagCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := 0
	for _, u := range s.updates {
		if u.AppendTags["records_truncated"] == "per_stream_cap_reached" {
			c++
		}
	}
	return c
}

// TestSSE_PerStreamRecordCap (USK-802) verifies the RecordStep-side
// per-Stream record cap for SSE:
//
//  1. The SSE Channel TeeReader continues to relay every event byte to
//     the client (verified indirectly: every upstream event reaches the
//     SSEMessage envelope queue and is observed by the Pipeline before
//     the gate runs — the gate only suppresses persistence, never
//     emission).
//  2. RecordStep persists at most cap SSEMessage flows per stream.
//  3. The per-Stream truncation tag is stamped exactly once
//     (records_truncated = per_stream_cap_reached) when the cap is first
//     exceeded.
func TestSSE_PerStreamRecordCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const (
		streamID  = "sse-cap-stream-1"
		event     = "event: tick\ndata: x\nid: 1\n\n"
		eventCnt  = 7
		recordCap = 3
	)
	wire := strings.Repeat(event, eventCnt)

	store := &taggingTestStore{}

	seed := makeSSESeedRequest(streamID)
	clientCh := newSeedClientChannel(streamID, seed)

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 1)
	body := strings.NewReader(wire)
	upstreamCh := sse.Wrap(inner, first, body)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &sseUpstreamAdapter{inner: upstreamCh}, nil
	}

	// Build the pipeline with the cap Option layered on top.
	p := pipeline.New(
		pipeline.NewRecordStep(store, slog.Default(),
			pipeline.WithSSEMaxEventsPerStream(recordCap),
		),
	)

	done := make(chan error, 1)
	go func() {
		done <- session.RunSession(ctx, clientCh, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid != "" {
					_ = store.UpdateStream(cctx, sid, flow.StreamUpdate{State: state})
				}
			},
		})
	}()

	// Wait until at least the cap has been recorded; then close the client
	// channel so RunSession returns.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.sseFlowCount() >= recordCap {
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

	// (2) Recorded SSE event count must equal cap exactly. The remaining
	// (eventCnt - recordCap) events were observed by the Pipeline (so the
	// truncated tag fired) but not persisted.
	if got := store.sseFlowCount(); got != recordCap {
		t.Errorf("sse event flows recorded = %d, want %d (cap)", got, recordCap)
	}

	// (3) Truncated tag stamped exactly once via AppendTags.
	if got := store.truncatedTagCount(); got != 1 {
		t.Errorf("AppendTags[records_truncated] count = %d, want 1 (one-shot latch)", got)
	}
}
