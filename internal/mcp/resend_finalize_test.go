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
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
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

	finalizeResendStream(context.Background(), store, id, "", nil)

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

	finalizeResendStream(context.Background(), store, id, "", errors.New("dial: connection refused"))

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
	finalizeResendStream(context.Background(), store, id, "", se)

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
	finalizeResendStream(context.Background(), nil, "any", "", nil)
	finalizeResendStream(context.Background(), nil, "any", "", errors.New("boom"))
}

// TestFinalizeResendStream_EmptyStreamID is a no-op safety check for
// pathological cases where a resend handler ends up with an empty
// streamID (e.g. an early-validation-fail Drop). The helper must not
// invoke the store at all.
func TestFinalizeResendStream_EmptyStreamID(t *testing.T) {
	store := newTestStore(t)
	finalizeResendStream(context.Background(), store, "", "", nil)
	finalizeResendStream(context.Background(), store, "", "", errors.New("boom"))
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

	finalizeResendStream(context.Background(), store, id, "", nil)

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

	finalizeResendStream(context.Background(), store, id, "", errors.New("boom"))

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

	finalizeResendStream(context.Background(), store, id, "", nil)

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Duration != 42*time.Millisecond {
		t.Errorf("Duration = %v, want 42ms preserved", got.Duration)
	}
}

// TestFinalizeResendStream_ErrorRecordsErrorTag: a failed resend / fuzz
// Stream keeps the bare error text in tags["error"], matching the live
// path's OnComplete (USK-1350).
func TestFinalizeResendStream_ErrorRecordsErrorTag(t *testing.T) {
	tests := []struct {
		name   string
		runErr error
	}{
		{name: "generic", runErr: errors.New("dial tcp 127.0.0.1:1: connect: connection refused")},
		{name: "wrapped_eof", runErr: fmt.Errorf("upstream receive: %w", io.EOF)},
		{name: "stream_error", runErr: &layer.StreamError{Code: layer.ErrorRefused}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			id := seedActiveStream(t, store)

			finalizeResendStream(context.Background(), store, id, "", tt.runErr)

			got, err := store.GetStream(context.Background(), id)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			if got.State != "error" {
				t.Errorf("State = %q, want error", got.State)
			}
			if got.Tags["error"] != tt.runErr.Error() {
				t.Errorf("Tags[\"error\"] = %q, want %q", got.Tags["error"], tt.runErr.Error())
			}
		})
	}
}

// TestFinalizeResendStream_SuccessNoErrorTag: a successful finalize must
// not write tags["error"].
func TestFinalizeResendStream_SuccessNoErrorTag(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStream(t, store)

	finalizeResendStream(context.Background(), store, id, "", nil)

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if v, ok := got.Tags["error"]; ok {
		t.Errorf("Tags[\"error\"] = %q present on success; want absent", v)
	}
}

// TestFinalizeResendStream_ErrorPreservesPriorTags: the error tag is
// merged (AppendTags), so tags written earlier by RecordStep survive.
func TestFinalizeResendStream_ErrorPreservesPriorTags(t *testing.T) {
	store := newTestStore(t)
	id := uuid.NewString()
	st := &flow.Stream{
		ID:       id,
		Protocol: "http",
		State:    "active",
		Origin:   flow.OriginResend,
		Tags:     map[string]string{"records_truncated": "true"},
	}
	if err := store.SaveStream(context.Background(), st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	finalizeResendStream(context.Background(), store, id, "", errors.New("boom"))

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Tags["records_truncated"] != "true" {
		t.Errorf("Tags[\"records_truncated\"] = %q, want %q preserved (tags=%v)", got.Tags["records_truncated"], "true", got.Tags)
	}
	if got.Tags["error"] != "boom" {
		t.Errorf("Tags[\"error\"] = %q, want %q (tags=%v)", got.Tags["error"], "boom", got.Tags)
	}
}

// TestFinalizeResendStream_ErrorTagCapped: an oversized error message is
// capped exactly like the live path (flow.TruncateErrorTag), including a
// cut that lands mid-rune.
func TestFinalizeResendStream_ErrorTagCapped(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{name: "ascii", msg: strings.Repeat("a", flow.ErrorTagMaxLen+512)},
		{name: "multibyte", msg: "x" + strings.Repeat("あ", (flow.ErrorTagMaxLen+512)/3)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			id := seedActiveStream(t, store)

			finalizeResendStream(context.Background(), store, id, "", errors.New(tt.msg))

			got, err := store.GetStream(context.Background(), id)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			tag := got.Tags["error"]
			if len(tag) > flow.ErrorTagMaxLen {
				t.Errorf("len(Tags[\"error\"]) = %d, want <= %d", len(tag), flow.ErrorTagMaxLen)
			}
			if !strings.HasSuffix(tag, "...[truncated]") {
				t.Errorf("Tags[\"error\"] lacks the ...[truncated] suffix (len=%d)", len(tag))
			}
			if !utf8.ValidString(tag) {
				t.Errorf("Tags[\"error\"] is not valid UTF-8")
			}
			if want := flow.TruncateErrorTag(tt.msg); tag != want {
				t.Errorf("Tags[\"error\"] differs from flow.TruncateErrorTag(msg) (len %d vs %d)", len(tag), len(want))
			}
		})
	}
}

// seedStreamWithTags inserts an active resend Stream carrying the given
// record-time tags, mirroring TestFinalizeResendStream_ErrorPreservesPriorTags.
func seedStreamWithTags(t *testing.T, store flow.Store, tags map[string]string) string {
	t.Helper()
	id := uuid.NewString()
	st := &flow.Stream{
		ID:       id,
		Protocol: "http",
		State:    "active",
		Origin:   flow.OriginResend,
		Tags:     tags,
	}
	if err := store.SaveStream(context.Background(), st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	return id
}

// TestFinalizeResendStream_UserTag (USK-1362): the user-supplied tag is
// written by finalize on both the success and the error path, merged via
// AppendTags so record-time tags (and tags["error"]) survive alongside it.
func TestFinalizeResendStream_UserTag(t *testing.T) {
	tests := []struct {
		name      string
		runErr    error
		wantState string
		wantError string
	}{
		{name: "success", runErr: nil, wantState: "complete"},
		{name: "error", runErr: errors.New("boom"), wantState: "error", wantError: "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			id := seedStreamWithTags(t, store, map[string]string{"records_truncated": "true"})

			finalizeResendStream(context.Background(), store, id, "t1", tt.runErr)

			got, err := store.GetStream(context.Background(), id)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			if got.State != tt.wantState {
				t.Errorf("State = %q, want %q", got.State, tt.wantState)
			}
			if got.Tags["tag"] != "t1" {
				t.Errorf("Tags[\"tag\"] = %q, want %q (tags=%v)", got.Tags["tag"], "t1", got.Tags)
			}
			if got.Tags["records_truncated"] != "true" {
				t.Errorf("Tags[\"records_truncated\"] = %q, want %q preserved (tags=%v)", got.Tags["records_truncated"], "true", got.Tags)
			}
			if tt.wantError != "" {
				if got.Tags["error"] != tt.wantError {
					t.Errorf("Tags[\"error\"] = %q, want %q (tags=%v)", got.Tags["error"], tt.wantError, got.Tags)
				}
			} else if v, ok := got.Tags["error"]; ok {
				t.Errorf("Tags[\"error\"] = %q present on success; want absent", v)
			}
		})
	}
}

// TestFinalizeResendStream_EmptyUserTagWritesNoTagKey (USK-1362): an empty
// tag must not create a "tag" key on either path, and must leave existing
// tags untouched.
func TestFinalizeResendStream_EmptyUserTagWritesNoTagKey(t *testing.T) {
	tests := []struct {
		name   string
		runErr error
	}{
		{name: "success", runErr: nil},
		{name: "error", runErr: errors.New("boom")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			id := seedStreamWithTags(t, store, map[string]string{"records_truncated": "true"})

			finalizeResendStream(context.Background(), store, id, "", tt.runErr)

			got, err := store.GetStream(context.Background(), id)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			if v, ok := got.Tags["tag"]; ok {
				t.Errorf("Tags[\"tag\"] = %q present with empty tag; want absent", v)
			}
			if got.Tags["records_truncated"] != "true" {
				t.Errorf("Tags[\"records_truncated\"] = %q, want %q preserved (tags=%v)", got.Tags["records_truncated"], "true", got.Tags)
			}
		})
	}
}

// TestFinalizeResendStream_CancelledCallerCtxStillFinalizes (USK-1370): an
// MCP client that cancels a resend / fuzz call cancels the handler ctx the
// finalize write receives. The terminal write — State, FailureReason,
// Duration, tags["tag"], tags["error"] — must still land, as the live
// path's OnComplete does under context.WithoutCancel.
func TestFinalizeResendStream_CancelledCallerCtxStillFinalizes(t *testing.T) {
	store := newTestStore(t)
	id := seedActiveStreamAt(t, store, time.Now().Add(-time.Second), 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finalizeResendStream(ctx, store, id, "usk-1370", fmt.Errorf("resend: %w", context.Canceled))

	got, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "error" {
		t.Errorf("State = %q, want error (finalize must survive caller cancellation)", got.State)
	}
	if got.Tags["tag"] != "usk-1370" {
		t.Errorf("Tags[\"tag\"] = %q, want %q (tags=%v)", got.Tags["tag"], "usk-1370", got.Tags)
	}
	if got.Tags["error"] == "" {
		t.Errorf("Tags[\"error\"] missing (tags=%v); want the error text", got.Tags)
	}
	if got.Duration < time.Second {
		t.Errorf("Duration = %v, want >= 1s (StreamElapsed must also run detached)", got.Duration)
	}
}

// TestFinalizeResendStream_ReturnsAfterStoreClose (USK-1370 criterion 2):
// with cancellation detached, the terminal write must still be bounded.
// After SQLiteStore.Close the writer goroutine is gone, so an enqueued
// write's result never arrives; finalize must give up at its timeout
// rather than block forever.
func TestFinalizeResendStream_ReturnsAfterStoreClose(t *testing.T) {
	// Not flowtest.NewStore: its cleanup Closes the store, and closing a
	// SQLiteStore twice panics.
	store, err := flow.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "s.db"), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	id := seedActiveStream(t, store)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		finalizeResendStreamWithin(context.Background(), 200*time.Millisecond, store, id, "", errors.New("boom"))
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("finalizeResendStream did not return within 15s after store Close; the terminal write is unbounded")
	}
}
