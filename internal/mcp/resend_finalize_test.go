package mcp

// resend_finalize_test.go — unit-tier coverage for the USK-789 bug fix.
//
// The bug: resend tools (resend_http / resend_ws / resend_grpc / resend_raw)
// bypass session.RunSession and therefore never trigger the OnComplete
// callback that proxybuild.buildSessionOptions wires for the live data
// path. Streams produced by the resend pipeline's RecordStep used to stay
// pinned at State="active" forever even though the tool returned a
// successful response. finalizeResendStream is the per-call hook every
// resend handler now invokes after runResend* returns, mirroring the
// proxy-path OnComplete semantics:
//
//   - nil err  → State="complete"
//   - err != nil → State="error", FailureReason = session.ClassifyError(err)
//
// These tests pin the helper's contract with a real SQLite store so the
// regression cannot reappear via a refactor that subtly changes the update
// shape (e.g. dropping the "complete" branch or accidentally using a
// FailureReason on the success path).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// seedActiveStream inserts a fresh Stream row in State="active" so the
// finalize call has something to update. Mirrors the shape RecordStep
// produces on the resend path (Origin=resend, no Flows attached because
// the test only exercises the Stream-state transition).
func seedActiveStream(t *testing.T, store flow.Store) string {
	t.Helper()
	id := uuid.NewString()
	st := &flow.Stream{
		ID:       id,
		Protocol: "http",
		State:    "active",
		Origin:   flow.OriginResend,
	}
	if err := store.SaveStream(context.Background(), st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	return id
}

// TestFinalizeResendStream_Success covers the happy path: resend ran
// without error, so the helper must transition State="active" → "complete"
// and leave FailureReason empty.
func TestFinalizeResendStream_Success(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStream(t, store)

	finalizeResendStream(context.Background(), store, id, nil)

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "complete" {
		t.Errorf("State = %q, want %q (USK-789: resend stream must finalise to complete)", got.State, "complete")
	}
	if got.FailureReason != "" {
		t.Errorf("FailureReason = %q, want empty (success path must not classify a failure)", got.FailureReason)
	}
}

// TestFinalizeResendStream_GenericError covers the error path with a
// failure that is not a *layer.StreamError: dial errors, parse errors,
// context cancellations all classify as the empty FailureReason on the
// proxy path (session.ClassifyError returns "" for non-StreamError),
// and the resend helper must mirror that.
func TestFinalizeResendStream_GenericError(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStream(t, store)

	finalizeResendStream(context.Background(), store, id, errors.New("dial: connection refused"))

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "error" {
		t.Errorf("State = %q, want %q (USK-789: resend stream must finalise to error on failure)", got.State, "error")
	}
	if got.FailureReason != "" {
		t.Errorf("FailureReason = %q, want empty (generic non-StreamError must not classify)", got.FailureReason)
	}
}

// TestFinalizeResendStream_StreamError covers the error path with a
// *layer.StreamError. session.ClassifyError extracts the canonical code
// label so analysts can distinguish refused / canceled / aborted on the
// recorded Stream row. The resend helper must surface the same label
// the proxy-path OnComplete does.
func TestFinalizeResendStream_StreamError(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStream(t, store)

	se := &layer.StreamError{Code: layer.ErrorRefused}
	finalizeResendStream(context.Background(), store, id, se)

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "error" {
		t.Errorf("State = %q, want %q", got.State, "error")
	}
	if got.FailureReason != "refused" {
		t.Errorf("FailureReason = %q, want %q (StreamError code must be classified)", got.FailureReason, "refused")
	}
}

// TestFinalizeResendStream_NilStore is a no-op safety check: handlers
// pass s.flowStore.store directly which can be nil for test stacks that
// do not record. The helper must not panic.
func TestFinalizeResendStream_NilStore(t *testing.T) {
	finalizeResendStream(context.Background(), nil, "any", nil)
	finalizeResendStream(context.Background(), nil, "any", errors.New("boom"))
}

// TestFinalizeResendStream_EmptyStreamID is a no-op safety check for
// pathological cases where a resend handler ends up with an empty
// streamID (e.g. an early-validation-fail Drop). The helper must not
// invoke the store at all.
func TestFinalizeResendStream_EmptyStreamID(t *testing.T) {
	store := newTestStore(t)
	finalizeResendStream(context.Background(), store, "", nil)
	finalizeResendStream(context.Background(), store, "", errors.New("boom"))
	// No assertion needed — the test passes if no panic and no error
	// surfaced via t.Fatalf inside the store. A non-empty SaveStream
	// would have created a row; we never created one, so the store
	// remains empty (the SQLite store has no other writes in this
	// test).
}

// seedActiveStreamAt is seedActiveStream with an explicit Timestamp and
// pre-existing Duration, so the finalize Duration stamp can be observed.
// The Timestamp mirrors what RecordStep's createStream stamps
// (time.Now() on the first envelope) — here backdated to simulate a
// resend whose send→receive took that long.
func seedActiveStreamAt(t *testing.T, store flow.Store, ts time.Time, duration time.Duration) string {
	t.Helper()
	id := uuid.NewString()
	st := &flow.Stream{
		ID:        id,
		Protocol:  "http",
		State:     "active",
		Origin:    flow.OriginResend,
		Timestamp: ts,
		Duration:  duration,
	}
	if err := store.SaveStream(context.Background(), st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	return id
}

// TestFinalizeResendStream_StampsDurationFromStreamTimestamp: a resend
// Stream finalised ~1.5s after RecordStep created it must carry
// Duration ≈ 1.5s (USK-1347: resend/fuzz Streams always showed 0).
func TestFinalizeResendStream_StampsDurationFromStreamTimestamp(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStreamAt(t, store, time.Now().Add(-1500*time.Millisecond), 0)

	finalizeResendStream(context.Background(), store, id, nil)

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "complete" {
		t.Errorf("State = %q, want complete", got.State)
	}
	if got.Duration < 1500*time.Millisecond || got.Duration > 1500*time.Millisecond+5*time.Second {
		t.Errorf("Duration = %v, want in [1.5s, 6.5s] (elapsed since Stream.Timestamp)", got.Duration)
	}
}

// TestFinalizeResendStream_ErrorStampsDuration: the error path records
// the real elapsed time too (USK-1347 AC3).
func TestFinalizeResendStream_ErrorStampsDuration(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStreamAt(t, store, time.Now().Add(-1500*time.Millisecond), 0)

	finalizeResendStream(context.Background(), store, id, errors.New("boom"))

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "error" {
		t.Errorf("State = %q, want error", got.State)
	}
	if got.Duration < 1500*time.Millisecond || got.Duration > 1500*time.Millisecond+5*time.Second {
		t.Errorf("Duration = %v, want in [1.5s, 6.5s] (elapsed since Stream.Timestamp)", got.Duration)
	}
}

// TestFinalizeResendStream_ZeroTimestampLeavesDuration: without a
// Timestamp there is nothing to measure from, so the existing Duration
// must survive (zero = "do not update" sentinel of StreamUpdate).
func TestFinalizeResendStream_ZeroTimestampLeavesDuration(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStreamAt(t, store, time.Time{}, 42*time.Millisecond)

	finalizeResendStream(context.Background(), store, id, nil)

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Duration != 42*time.Millisecond {
		t.Errorf("Duration = %v, want 42ms preserved", got.Duration)
	}
}
