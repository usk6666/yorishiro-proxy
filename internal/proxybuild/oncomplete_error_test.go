package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-797: the live OnComplete callback installed by buildSessionOptions
// must surface stream-level dial errors to BOTH the persisted
// failure_reason column AND tags["error"], without erasing tags written
// earlier in the stream's lifetime.
//
// These tests exercise the exported public symbol surface only by going
// through the same buildSessionOptions hook the production builder
// wires onto every session.RunSession invocation. The session goroutine
// itself is not started — we simulate the terminal callback directly,
// so the test stays deterministic regardless of upstream Layer
// scheduling. The session-level integration (DialFunc returning
// StreamError → ClassifyError reaches OnComplete) is covered by
// internal/session/session_test.go.

func newSQLiteStoreForTest(t *testing.T) *flow.SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "oncomplete-error.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedActiveStreamWithTags(t *testing.T, store *flow.SQLiteStore, id string, tags map[string]string) {
	t.Helper()
	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-1",
		Protocol:  "http",
		Scheme:    "https",
		State:     "active",
		Timestamp: time.Now(),
		Tags:      tags,
	}
	if err := store.SaveStream(context.Background(), st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
}

// TestBuildSessionOptions_OnComplete_DialRefusedSetsFailureReason
// reproduces USK-797's primary scenario: an h2 dial-time
// *layer.StreamError{Code: ErrorRefused} wrapped via
// fmt.Errorf("dial: %w", ...) must land as failure_reason="refused"
// AND tags["error"] containing the wrapped string.
func TestBuildSessionOptions_OnComplete_DialRefusedSetsFailureReason(t *testing.T) {
	store := newSQLiteStoreForTest(t)
	const streamID = "stream-797-dial"
	seedActiveStreamWithTags(t, store, streamID, nil)

	deps := Deps{
		ListenerName: "live",
		FlowStore:    store,
	}
	opts := buildSessionOptions(deps, deps.ListenerName)
	if opts.OnComplete == nil {
		t.Fatal("buildSessionOptions did not install OnComplete with FlowStore set")
	}

	dialErr := fmt.Errorf("dial: %w", &layer.StreamError{
		Code:   layer.ErrorRefused,
		Reason: "layer shutdown",
	})

	opts.OnComplete(context.Background(), streamID, dialErr)

	got, err := store.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "error" {
		t.Errorf("Stream.State = %q, want %q", got.State, "error")
	}
	if got.FailureReason != "refused" {
		t.Errorf("Stream.FailureReason = %q, want %q", got.FailureReason, "refused")
	}
	if got.Tags == nil {
		t.Fatal("Stream.Tags is nil; want tags[\"error\"] populated")
	}
	wantSubstr := "stream error refused"
	if !strings.Contains(got.Tags["error"], wantSubstr) {
		t.Errorf("Tags[\"error\"] = %q, want substring %q", got.Tags["error"], wantSubstr)
	}
}

// TestBuildSessionOptions_OnComplete_PreservesPriorTags ensures the
// AppendTags merge does not clobber tags written by earlier steps
// (RecordStep TLS metadata, USK-790 tls-handshake meta, etc.). The
// CLAUDE.md MITM principle "do not normalize what the wire did not
// normalize" extends to recording: a tag set earlier in the stream's
// lifetime must survive the terminal OnComplete update.
func TestBuildSessionOptions_OnComplete_PreservesPriorTags(t *testing.T) {
	store := newSQLiteStoreForTest(t)
	const streamID = "stream-797-preserve"
	seedActiveStreamWithTags(t, store, streamID, map[string]string{
		"prior":              "kept",
		"tls-handshake-meta": "v1",
	})

	deps := Deps{
		ListenerName: "live",
		FlowStore:    store,
	}
	opts := buildSessionOptions(deps, deps.ListenerName)

	dialErr := fmt.Errorf("dial: %w", &layer.StreamError{Code: layer.ErrorRefused})
	opts.OnComplete(context.Background(), streamID, dialErr)

	got, err := store.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Tags["prior"] != "kept" {
		t.Errorf("Tags[\"prior\"] = %q, want %q (must not be clobbered by OnComplete merge)", got.Tags["prior"], "kept")
	}
	if got.Tags["tls-handshake-meta"] != "v1" {
		t.Errorf("Tags[\"tls-handshake-meta\"] = %q, want %q (must not be clobbered)", got.Tags["tls-handshake-meta"], "v1")
	}
	if got.Tags["error"] == "" {
		t.Error("Tags[\"error\"] is empty; want the err.Error() string")
	}
}

// TestBuildSessionOptions_OnComplete_NilErrLeavesTagsUntouched verifies
// the success path: a clean session exit (err == nil) must NOT add an
// "error" tag and must NOT erase existing tags.
func TestBuildSessionOptions_OnComplete_NilErrLeavesTagsUntouched(t *testing.T) {
	store := newSQLiteStoreForTest(t)
	const streamID = "stream-797-success"
	seedActiveStreamWithTags(t, store, streamID, map[string]string{"prior": "kept"})

	deps := Deps{
		ListenerName: "live",
		FlowStore:    store,
	}
	opts := buildSessionOptions(deps, deps.ListenerName)

	opts.OnComplete(context.Background(), streamID, nil)

	got, err := store.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "complete" {
		t.Errorf("Stream.State = %q, want %q", got.State, "complete")
	}
	if got.FailureReason != "" {
		t.Errorf("Stream.FailureReason = %q, want empty (success path)", got.FailureReason)
	}
	if _, present := got.Tags["error"]; present {
		t.Error("Tags[\"error\"] should be absent on the success path")
	}
	if got.Tags["prior"] != "kept" {
		t.Errorf("Tags[\"prior\"] = %q, want %q (success path must not erase tags)", got.Tags["prior"], "kept")
	}
}

// TestBuildSessionOptions_OnComplete_UnclassifiedErrStillPopulatesTag
// covers the "we didn't recognize the StreamError but still want the
// raw err string" diagnostic case. ClassifyError returns "" for a plain
// errors.New — but operators still need the tag to debug.
func TestBuildSessionOptions_OnComplete_UnclassifiedErrStillPopulatesTag(t *testing.T) {
	store := newSQLiteStoreForTest(t)
	const streamID = "stream-797-unclassified"
	seedActiveStreamWithTags(t, store, streamID, nil)

	deps := Deps{
		ListenerName: "live",
		FlowStore:    store,
	}
	opts := buildSessionOptions(deps, deps.ListenerName)

	opts.OnComplete(context.Background(), streamID, errors.New("something else"))

	got, err := store.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.State != "error" {
		t.Errorf("Stream.State = %q, want %q", got.State, "error")
	}
	if got.FailureReason != "" {
		t.Errorf("Stream.FailureReason = %q, want empty (non-StreamError must not classify)", got.FailureReason)
	}
	if got.Tags["error"] != "something else" {
		t.Errorf("Tags[\"error\"] = %q, want %q (raw err string must be preserved)", got.Tags["error"], "something else")
	}
}

// TestTruncateErrorTag_RespectsCap covers the cap+marker behavior so a
// runaway nested-wrap chain (or a transport-layer error that embeds
// arbitrary attacker-controlled bytes via SNI/Host) cannot blow up the
// stored row.
func TestTruncateErrorTag_RespectsCap(t *testing.T) {
	short := "dial: stream error refused: layer shutdown"
	if got := truncateErrorTag(short); got != short {
		t.Errorf("truncateErrorTag(short) = %q, want %q (under cap → unchanged)", got, short)
	}

	huge := strings.Repeat("a", errorTagMaxLen+512)
	got := truncateErrorTag(huge)
	if len(got) > errorTagMaxLen {
		t.Errorf("len(truncateErrorTag(huge)) = %d, want <= %d", len(got), errorTagMaxLen)
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Errorf("truncateErrorTag(huge) = %q, want suffix %q", got, "...[truncated]")
	}
}
