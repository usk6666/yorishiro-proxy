package proxybuild

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// recordingFlowStore captures SaveStream / UpdateStream calls so tests can
// inspect what the audit recorder wrote. Concurrency-safe because the
// session-side hooks may fire from any goroutine.
type recordingFlowStore struct {
	mu          sync.Mutex
	saved       []*flow.Stream
	saveErrOnce error
	updates     []recordedUpdate
}

type recordedUpdate struct {
	id     string
	update flow.StreamUpdate
}

func (r *recordingFlowStore) SaveStream(_ context.Context, st *flow.Stream) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveErrOnce != nil {
		err := r.saveErrOnce
		r.saveErrOnce = nil
		return err
	}
	// Defensive shallow copy so the test owns the captured value.
	cp := *st
	r.saved = append(r.saved, &cp)
	return nil
}

func (r *recordingFlowStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates = append(r.updates, recordedUpdate{id: id, update: update})
	return nil
}

func (r *recordingFlowStore) SaveFlow(_ context.Context, _ *flow.Flow) error { return nil }

// TestBuildPipelineDropRecorder_NilStore verifies the recorder returns nil
// when no flow.Writer is configured, preserving the silent-close fallback
// path.
func TestBuildPipelineDropRecorder_NilStore(t *testing.T) {
	rec := buildPipelineDropRecorder(nil, "test", silentLogger(), newBlockedStreamSet())
	if rec != nil {
		t.Fatal("expected nil callback when store is nil")
	}
}

// TestBuildPipelineDropRecorder_TargetScope_HTTPMessage verifies the recorder
// writes a Stream with State="error", BlockedBy="target_scope", and Scheme
// projected from the HTTPMessage on a host-scope deny.
func TestBuildPipelineDropRecorder_TargetScope_HTTPMessage(t *testing.T) {
	store := &recordingFlowStore{}
	blocked := newBlockedStreamSet()
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), blocked)
	if rec == nil {
		t.Fatal("expected non-nil recorder")
	}

	env := &envelope.Envelope{
		StreamID: "stream-1",
		Protocol: envelope.ProtocolHTTP,
		Context: envelope.EnvelopeContext{
			ConnID:     "conn-1",
			TargetHost: "evil.com:443",
		},
		Direction: envelope.Send,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "evil.com",
			Path:      "/",
		},
	}

	rec(context.Background(), env, pipeline.BlockedByTargetScope)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	st := store.saved[0]
	if st.ID != "stream-1" {
		t.Errorf("Stream.ID = %q, want %q", st.ID, "stream-1")
	}
	if st.ConnID != "conn-1" {
		t.Errorf("Stream.ConnID = %q, want %q", st.ConnID, "conn-1")
	}
	if st.State != "error" {
		t.Errorf("Stream.State = %q, want %q", st.State, "error")
	}
	if st.BlockedBy != pipeline.BlockedByTargetScope {
		t.Errorf("Stream.BlockedBy = %q, want %q", st.BlockedBy, pipeline.BlockedByTargetScope)
	}
	if st.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want %q (projected from HTTPMessage)", st.Scheme, "https")
	}
	if st.Protocol != string(envelope.ProtocolHTTP) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, string(envelope.ProtocolHTTP))
	}
	if !blocked.contains("stream-1") {
		t.Error("blockedStreamSet should contain stream-1 so OnComplete skips finalisation")
	}
}

// TestBuildPipelineDropRecorder_NoMessage_MinimalStream verifies that the
// recorder writes a minimal Stream when no L7 message is available
// (RawMessage envelope, e.g. raw TCP forward path Drop). The Stream is
// Stream-only with no Flow rows.
func TestBuildPipelineDropRecorder_NoMessage_MinimalStream(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())

	env := &envelope.Envelope{
		StreamID:  "stream-2",
		Protocol:  envelope.ProtocolRaw,
		Direction: envelope.Send,
		Context: envelope.EnvelopeContext{
			ConnID:     "conn-raw",
			TargetHost: "evil.com:1234",
		},
		Message: &envelope.RawMessage{Bytes: []byte{0x01, 0x02}},
	}
	rec(context.Background(), env, pipeline.BlockedByTargetScope)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	st := store.saved[0]
	if st.Scheme != "" {
		t.Errorf("Stream.Scheme = %q, want empty (no HTTPMessage)", st.Scheme)
	}
	if st.Protocol != string(envelope.ProtocolRaw) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, envelope.ProtocolRaw)
	}
	if st.BlockedBy != pipeline.BlockedByTargetScope {
		t.Errorf("Stream.BlockedBy = %q, want %q", st.BlockedBy, pipeline.BlockedByTargetScope)
	}
}

// TestBuildPipelineDropRecorder_EmptyBlockedBy_NoOp verifies the recorder
// silently ignores a Drop with no attribution. Plugin ActionDrop emits
// empty BlockedBy on purpose (USK-782 design scope guards) and must not
// produce an audit row. (The context-cancelled hold path is attributed to
// intercept_cancelled since USK-1193.)
func TestBuildPipelineDropRecorder_EmptyBlockedBy_NoOp(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())
	env := &envelope.Envelope{
		StreamID:  "stream-3",
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}
	rec(context.Background(), env, "")
	if got := len(store.saved); got != 0 {
		t.Errorf("SaveStream count = %d, want 0 (no attribution)", got)
	}
}

// TestBuildPipelineDropRecorder_FallbackToUpdateOnConflict verifies the
// SaveStream → UpdateStream fallback path used for mid-stream Drops
// (streaming gRPC / WS data frame blocked after the stream's first Send
// already created a Stream row).
func TestBuildPipelineDropRecorder_FallbackToUpdateOnConflict(t *testing.T) {
	store := &recordingFlowStore{saveErrOnce: errors.New("UNIQUE constraint failed: streams.id")}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())

	env := &envelope.Envelope{
		StreamID:  "stream-existing",
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   &envelope.HTTPMessage{Method: "POST", Scheme: "https"},
	}
	rec(context.Background(), env, pipeline.BlockedBySafetyFilter)

	if len(store.saved) != 0 {
		t.Errorf("SaveStream should have errored; saved=%d", len(store.saved))
	}
	if len(store.updates) != 1 {
		t.Fatalf("UpdateStream count = %d, want 1 (fallback path)", len(store.updates))
	}
	if got := store.updates[0].update.State; got != "error" {
		t.Errorf("UpdateStream State = %q, want %q", got, "error")
	}
	if got := store.updates[0].update.BlockedBy; got != pipeline.BlockedBySafetyFilter {
		t.Errorf("UpdateStream BlockedBy = %q, want %q", got, pipeline.BlockedBySafetyFilter)
	}
	if got := store.updates[0].id; got != "stream-existing" {
		t.Errorf("UpdateStream id = %q, want %q", got, "stream-existing")
	}
}

// TestBuildPipelineDropRecorder_FallbackRetagsProtocol pins USK-1220: when
// the fallback updates a row that already exists (on HTTP/2 the h2-frame
// overlay recorder creates it with Protocol="http" before the first
// semantic envelope), the blocked envelope's derived protocol is written
// too — under RecordStep.maybeRetagProtocol's rule, so an "http" envelope
// leaves the stored protocol alone. A gRPC-Web Start blocked by a policy
// Step ends the RPC, so no later envelope reaches RecordStep to re-tag it.
func TestBuildPipelineDropRecorder_FallbackRetagsProtocol(t *testing.T) {
	tests := []struct {
		proto envelope.Protocol
		msg   envelope.Message
		want  string
	}{
		{envelope.ProtocolGRPCWeb, &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"}, "grpc-web"},
		{envelope.ProtocolGRPC, &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"}, "grpc"},
		{envelope.ProtocolHTTP, &envelope.HTTPMessage{Method: "POST"}, ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.proto), func(t *testing.T) {
			store := &recordingFlowStore{saveErrOnce: errors.New("UNIQUE constraint failed: streams.id")}
			rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())
			rec(context.Background(), &envelope.Envelope{
				StreamID:  "stream-existing",
				Protocol:  tt.proto,
				Direction: envelope.Send,
				Message:   tt.msg,
			}, pipeline.BlockedByTargetScope)
			if len(store.updates) != 1 {
				t.Fatalf("UpdateStream count = %d, want 1 (fallback path)", len(store.updates))
			}
			if got := store.updates[0].update.Protocol; got != tt.want {
				t.Errorf("UpdateStream Protocol = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBlockedStreamSet_AddContains verifies concurrent-safe membership.
func TestBlockedStreamSet_AddContains(t *testing.T) {
	s := newBlockedStreamSet()
	if s.contains("foo") {
		t.Error("empty set should not contain foo")
	}
	s.add("foo")
	if !s.contains("foo") {
		t.Error("set should contain foo after add")
	}
	// Empty id is a no-op (no panic, no membership).
	s.add("")
	if s.contains("") {
		t.Error("set must not register empty id")
	}
}

// TestBlockedStreamSet_Remove verifies that remove evicts an entry so the
// per-listener set does not grow unboundedly across an attacker-driven
// stream of Pipeline-Drops (USK-782 review fix; CWE-400). After OnComplete
// observes the contains-skip, it calls remove(streamID) so the marker does
// not survive past the session's terminal callback.
func TestBlockedStreamSet_Remove(t *testing.T) {
	s := newBlockedStreamSet()
	s.add("foo")
	s.add("bar")
	if !s.contains("foo") || !s.contains("bar") {
		t.Fatal("setup: expected both foo and bar in set")
	}
	s.remove("foo")
	if s.contains("foo") {
		t.Error("foo should not be in set after remove")
	}
	if !s.contains("bar") {
		t.Error("remove(foo) must not affect bar")
	}
	// Remove of a missing id is a no-op (idempotent).
	s.remove("foo")
	if s.contains("foo") {
		t.Error("idempotent remove should leave set unchanged")
	}
	// Empty id is a no-op (no panic).
	s.remove("")
	if s.contains("") {
		t.Error("remove(\"\") must not affect membership")
	}
}

// TestBuildPipelineDropRecorder_BypassesCaptureScope is the architectural
// guarantee for USK-776 AC #3: a Pipeline-Drop with attribution writes the
// audit Stream regardless of whether RecordStep's capture_scope filter
// would have suppressed it. The mechanism is that OnPipelineDrop fires from
// session-side code BEFORE the Pipeline reaches RecordStep — the
// recorder never consults the RecordScope. This test pins that down by
// observing that the recorder writes the Stream even though no
// RecordScope is plumbed through the recorder constructor at all.
//
// Pre-USK-782, AC #3 was deferred specifically because adding the bypass
// inside RecordStep was awkward (RecordStep doesn't run on Drop short-circuit).
// USK-782 sidesteps that by lifting the recorder out of RecordStep entirely.
func TestBuildPipelineDropRecorder_BypassesCaptureScope(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())

	// Envelope on a host that an in-scope capture_scope filter would
	// exclude (e.g. include={hostname: "trusted.com"} excludes evil.com).
	// The recorder takes no RecordScope argument — capture_scope cannot
	// suppress this write by construction.
	env := &envelope.Envelope{
		StreamID:  "blocked-stream",
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Context: envelope.EnvelopeContext{
			TargetHost: "evil.com:443",
		},
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "evil.com",
			Path:      "/admin",
		},
	}
	rec(context.Background(), env, pipeline.BlockedByTargetScope)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1 (capture_scope bypass)", got)
	}
	if got := store.saved[0].BlockedBy; got != pipeline.BlockedByTargetScope {
		t.Errorf("Stream.BlockedBy = %q, want %q", got, pipeline.BlockedByTargetScope)
	}
}

// readableFlowStore is a recordingFlowStore that also implements
// flow.StreamReader over the set of Stream IDs that already exist, and
// counts every SaveStream attempt (failed ones included) — a failed
// INSERT is what the production store logs as "flow write failed".
type readableFlowStore struct {
	recordingFlowStore
	existing     map[string]bool
	saveAttempts int
}

func (r *readableFlowStore) SaveStream(ctx context.Context, st *flow.Stream) error {
	r.mu.Lock()
	r.saveAttempts++
	exists := r.existing[st.ID]
	r.mu.Unlock()
	if exists {
		return errors.New("insert stream: UNIQUE constraint failed: streams.id")
	}
	return r.recordingFlowStore.SaveStream(ctx, st)
}

func (r *readableFlowStore) GetStream(_ context.Context, id string) (*flow.Stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.existing[id] {
		return &flow.Stream{ID: id}, nil
	}
	return nil, errors.New("stream not found")
}

func (r *readableFlowStore) ListStreams(context.Context, flow.StreamListOptions) ([]*flow.Stream, error) {
	return nil, nil
}

func (r *readableFlowStore) CountStreams(context.Context, flow.StreamListOptions) (int, error) {
	return 0, nil
}

// TestBuildPipelineDropRecorder_PluginDrop_ExistingStream_NoInsert pins
// USK-1393 review F-1: a plugin DROP is recorded by RecordStep before the
// recorder runs, so its Stream row already exists. The recorder must stamp
// it with UpdateStream directly — an INSERT attempt fails on the primary
// key and the store logs a spurious "flow write failed" WARN per DROP.
// The update carries the same fields as the policy-drop fallback.
func TestBuildPipelineDropRecorder_PluginDrop_ExistingStream_NoInsert(t *testing.T) {
	store := &readableFlowStore{existing: map[string]bool{"stream-plugin": true}}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())
	ctx := pipeline.WithBlockAnnotations(context.Background(), map[string]string{"plugin": "p1"})
	rec(ctx, &envelope.Envelope{
		StreamID:  "stream-plugin",
		Protocol:  envelope.ProtocolGRPCWeb,
		Direction: envelope.Send,
		Message:   &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"},
	}, pipeline.BlockedByPlugin)

	if store.saveAttempts != 0 {
		t.Errorf("SaveStream attempts = %d, want 0 (the Stream already exists)", store.saveAttempts)
	}
	if len(store.updates) != 1 {
		t.Fatalf("UpdateStream count = %d, want 1", len(store.updates))
	}
	u := store.updates[0]
	if u.id != "stream-plugin" || u.update.State != "error" || u.update.BlockedBy != pipeline.BlockedByPlugin {
		t.Errorf("UpdateStream = %q %+v, want stream-plugin state=error blocked_by=plugin", u.id, u.update)
	}
	if u.update.Protocol != "grpc-web" {
		t.Errorf("UpdateStream Protocol = %q, want grpc-web (h2-overlay re-tag)", u.update.Protocol)
	}
	if u.update.AppendTags["plugin"] != "p1" {
		t.Errorf("UpdateStream AppendTags = %v, want the plugin tag", u.update.AppendTags)
	}
}

// TestBuildPipelineDropRecorder_PluginDrop_MissingStream_Saves pins that a
// plugin DROP whose Stream row does not exist (no RecordStep wrote one)
// still produces an audit Stream: Stream rows bypass capture_scope.
func TestBuildPipelineDropRecorder_PluginDrop_MissingStream_Saves(t *testing.T) {
	store := &readableFlowStore{existing: map[string]bool{}}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())
	rec(context.Background(), &envelope.Envelope{
		StreamID:  "stream-new",
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   &envelope.HTTPMessage{Method: "GET", Scheme: "https"},
	}, pipeline.BlockedByPlugin)

	if len(store.saved) != 1 {
		t.Fatalf("SaveStream count = %d, want 1", len(store.saved))
	}
	if st := store.saved[0]; st.ID != "stream-new" || st.State != "error" || st.BlockedBy != pipeline.BlockedByPlugin || st.Scheme != "https" {
		t.Errorf("saved Stream = %+v, want stream-new state=error blocked_by=plugin scheme=https", st)
	}
}

// TestBuildPipelineDropRecorder_PolicyDrop_StillSavesFirst pins that the
// policy-drop path is unchanged: SaveStream is tried first even when the
// store can be read.
func TestBuildPipelineDropRecorder_PolicyDrop_StillSavesFirst(t *testing.T) {
	store := &readableFlowStore{existing: map[string]bool{}}
	rec := buildPipelineDropRecorder(store, "live", silentLogger(), newBlockedStreamSet())
	rec(context.Background(), &envelope.Envelope{
		StreamID:  "stream-policy",
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}, pipeline.BlockedByTargetScope)
	if store.saveAttempts != 1 || len(store.saved) != 1 || len(store.updates) != 0 {
		t.Errorf("save attempts=%d saved=%d updates=%d, want 1/1/0", store.saveAttempts, len(store.saved), len(store.updates))
	}
}
