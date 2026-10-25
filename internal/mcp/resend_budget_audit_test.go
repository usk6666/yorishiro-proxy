package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// blockedStreamWriterStub is a flow.StreamWriter whose SaveStream always
// fails (the Stream row already exists), forcing recordBlockedStream onto
// its UpdateStream fallback. A non-nil updateErr makes the fallback fail too.
type blockedStreamWriterStub struct {
	updates   []flow.StreamUpdate
	ids       []string
	updateErr error
}

func (w *blockedStreamWriterStub) SaveStream(context.Context, *flow.Stream) error {
	return errors.New("UNIQUE constraint failed: streams.id")
}

func (w *blockedStreamWriterStub) UpdateStream(_ context.Context, id string, u flow.StreamUpdate) error {
	w.ids = append(w.ids, id)
	w.updates = append(w.updates, u)
	return w.updateErr
}

// TestRecordBlockedStream_UpdateFallbackWritesPassedBlockedBy pins that the
// UpdateStream fallback stamps the caller's blocked_by value — not a
// hardcoded "budget" — for every attribution the fuzz / resend helpers use.
func TestRecordBlockedStream_UpdateFallbackWritesPassedBlockedBy(t *testing.T) {
	for _, blockedBy := range []string{
		pipeline.BlockedBySafetyFilter,
		pipeline.BlockedByTargetScope,
		pipeline.BlockedByBudget,
	} {
		t.Run(blockedBy, func(t *testing.T) {
			w := &blockedStreamWriterStub{}
			env := &envelope.Envelope{Protocol: envelope.ProtocolRaw, Message: &envelope.RawMessage{}}
			if !recordBlockedStream(context.Background(), w, env, "sid-1", blockedBy, flow.OriginFuzz) {
				t.Errorf("recordBlockedStream reported not recorded, want recorded via the UpdateStream fallback")
			}
			if len(w.updates) != 1 {
				t.Fatalf("UpdateStream calls = %d, want 1", len(w.updates))
			}
			if w.ids[0] != "sid-1" {
				t.Errorf("UpdateStream id = %q, want sid-1", w.ids[0])
			}
			if got := w.updates[0].BlockedBy; got != blockedBy {
				t.Errorf("fallback BlockedBy = %q, want %q", got, blockedBy)
			}
			if got := w.updates[0].State; got != "error" {
				t.Errorf("fallback State = %q, want error", got)
			}
		})
	}
}

// TestRecordBlockedStream_NothingRecorded pins the "not recorded" report the
// fuzz helpers use to blank row.StreamID (USK-1371).
func TestRecordBlockedStream_NothingRecorded(t *testing.T) {
	env := &envelope.Envelope{Protocol: envelope.ProtocolRaw, Message: &envelope.RawMessage{}}
	if recordBlockedStream(context.Background(), nil, env, "sid-1", pipeline.BlockedBySafetyFilter, flow.OriginFuzz) {
		t.Errorf("nil store: recordBlockedStream reported recorded, want false")
	}
	if recordBlockedStream(context.Background(), &blockedStreamWriterStub{}, env, "", pipeline.BlockedBySafetyFilter, flow.OriginFuzz) {
		t.Errorf("empty streamID: recordBlockedStream reported recorded, want false")
	}

	// SaveStream and the UpdateStream fallback both fail: no Stream row
	// exists under the ID, so the report must be false.
	failing := &blockedStreamWriterStub{updateErr: errors.New("disk I/O error")}
	if recordBlockedStream(context.Background(), failing, env, "sid-1", pipeline.BlockedBySafetyFilter, flow.OriginFuzz) {
		t.Errorf("SaveStream and UpdateStream both failed: recordBlockedStream reported recorded, want false")
	}
	if len(failing.updates) != 1 {
		t.Errorf("UpdateStream calls = %d, want 1 (fallback must be attempted)", len(failing.updates))
	}
}
