package proxybuild

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// silentLogger returns a logger that drops everything; tests only assert
// builder behavior, not log output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// noopFlowStore is a flow.Writer test double that records nothing.
type noopFlowStore struct{}

func (noopFlowStore) SaveStream(_ context.Context, _ *flow.Stream) error                  { return nil }
func (noopFlowStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error { return nil }
func (noopFlowStore) SaveFlow(_ context.Context, _ *flow.Flow) error                      { return nil }

// newTestDeps returns a Deps populated with the minimum required fields.
// Optional engines are left nil so the canonical Pipeline degrades to
// no-op Steps.
func newTestDeps(t *testing.T) Deps {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("cert.CA.Generate: %v", err)
	}
	return Deps{
		Logger:       silentLogger(),
		ListenerName: "test",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    noopFlowStore{},
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	}
}

// TestBuildLiveStack_Success verifies the happy path: required fields
// supplied, all Stack fields populated, listener accessible without
// engine when PluginV2Engine is nil.
func TestBuildLiveStack_Success(t *testing.T) {
	deps := newTestDeps(t)

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if stack == nil {
		t.Fatal("Stack is nil")
	}
	if stack.Listener == nil {
		t.Error("Stack.Listener is nil")
	}
	if stack.Pipeline == nil {
		t.Error("Stack.Pipeline is nil")
	}
	if stack.WireEncoderRegistry == nil {
		t.Error("Stack.WireEncoderRegistry is nil")
	}
	if stack.BuildConfig == nil {
		t.Error("Stack.BuildConfig is nil")
	}
	if got := stack.Listener.Name(); got != "test" {
		t.Errorf("Listener.Name = %q, want %q", got, "test")
	}
	if got := stack.Listener.PluginV2Engine(); got != nil {
		t.Errorf("Listener.PluginV2Engine = %v, want nil", got)
	}
}

// TestBuildLiveStack_DefaultName ensures an empty ListenerName resolves
// to DefaultListenerName.
func TestBuildLiveStack_DefaultName(t *testing.T) {
	deps := newTestDeps(t)
	deps.ListenerName = ""

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if got := stack.Listener.Name(); got != DefaultListenerName {
		t.Errorf("Listener.Name = %q, want %q", got, DefaultListenerName)
	}
}

// TestBuildLiveStack_PluginV2EngineReachable ensures
// Stack.Listener.PluginV2Engine() returns the engine threaded through Deps,
// satisfying the USK-688 acceptance criterion.
func TestBuildLiveStack_PluginV2EngineReachable(t *testing.T) {
	deps := newTestDeps(t)
	engine := pluginv2.NewEngine(silentLogger())
	deps.PluginV2Engine = engine

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if got := stack.Listener.PluginV2Engine(); got != engine {
		t.Errorf("Listener.PluginV2Engine returned %v, want %v", got, engine)
	}
	if got := stack.PluginV2Engine; got != engine {
		t.Errorf("Stack.PluginV2Engine = %v, want %v", got, engine)
	}
	// Verify the engine was also threaded into BuildConfig so the
	// existing tls.on_handshake hook fires.
	if got := stack.BuildConfig.PluginV2Engine; got != engine {
		t.Errorf("BuildConfig.PluginV2Engine = %v, want %v", got, engine)
	}
}

// TestBuildLiveStack_DefaultEncodersRegistered verifies the default
// WireEncoderRegistry registers the four non-conflicting protocol
// encoders (ws / grpc / grpc-web / sse) plus a route-appropriate HTTP
// encoder. USK-690 finalised the HTTP encoder strategy: the non-h2 (h1)
// registry holds http1.EncodeWireBytes and the h2 registry holds
// httpaggregator.EncodeWireBytes. Both encoders register against
// envelope.ProtocolHTTP and are mutually exclusive in a single registry,
// hence the dual-registry split.
func TestBuildLiveStack_DefaultEncodersRegistered(t *testing.T) {
	deps := newTestDeps(t)
	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	shared := []envelope.Protocol{
		envelope.ProtocolWebSocket,
		envelope.ProtocolGRPC,
		envelope.ProtocolGRPCWeb,
		envelope.ProtocolSSE,
	}
	for _, p := range shared {
		if _, ok := stack.WireEncoderRegistry.Lookup(p); !ok {
			t.Errorf("h1 registry missing encoder for %s", p)
		}
		if _, ok := stack.WireEncoderRegistryH2.Lookup(p); !ok {
			t.Errorf("h2 registry missing encoder for %s", p)
		}
	}
	if _, ok := stack.WireEncoderRegistry.Lookup(envelope.ProtocolHTTP); !ok {
		t.Error("h1 registry must register HTTP encoder (http1.EncodeWireBytes)")
	}
	if _, ok := stack.WireEncoderRegistryH2.Lookup(envelope.ProtocolHTTP); !ok {
		t.Error("h2 registry must register HTTP encoder (httpaggregator.EncodeWireBytes)")
	}
}

// TestBuildLiveStack_CustomRegistryHonored ensures a caller-supplied
// registry is used verbatim instead of the default.
func TestBuildLiveStack_CustomRegistryHonored(t *testing.T) {
	deps := newTestDeps(t)
	custom := pipeline.NewWireEncoderRegistry()
	deps.WireEncoderRegistry = custom

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if stack.WireEncoderRegistry != custom {
		t.Error("Stack.WireEncoderRegistry should match the caller-supplied registry pointer")
	}
}

// TestBuildLiveStack_MissingRequired enumerates each required field and
// confirms BuildLiveStack rejects with a helpful error.
func TestBuildLiveStack_MissingRequired(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Deps)
		want string
	}{
		{
			name: "logger",
			mut:  func(d *Deps) { d.Logger = nil },
			want: "Logger",
		},
		{
			name: "listen_addr",
			mut:  func(d *Deps) { d.ListenAddr = "" },
			want: "ListenAddr",
		},
		{
			name: "build_config",
			mut:  func(d *Deps) { d.BuildConfig = nil },
			want: "BuildConfig",
		},
		{
			name: "build_config_proxy_config",
			mut:  func(d *Deps) { d.BuildConfig.ProxyConfig = nil },
			want: "ProxyConfig",
		},
		{
			name: "build_config_issuer",
			mut:  func(d *Deps) { d.BuildConfig.Issuer = nil },
			want: "Issuer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTestDeps(t)
			tc.mut(&deps)
			_, err := BuildLiveStack(context.Background(), deps)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestBuildLiveStack_MaxConcurrentStreamsPropagates verifies the
// USK-713 H2 stream-concurrency cap is preserved on the BuildConfig
// embedded in the resulting Stack. The actual SETTINGS advertisement
// and REFUSED_STREAM enforcement are exercised at the H2 layer level
// (TestMaxConcurrentStreams_AdvertisedAndEnforced); this test is the
// config → runtime path assertion.
func TestBuildLiveStack_MaxConcurrentStreamsPropagates(t *testing.T) {
	deps := newTestDeps(t)
	deps.BuildConfig.MaxConcurrentStreams = 250

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if stack.BuildConfig == nil {
		t.Fatal("Stack.BuildConfig is nil")
	}
	if got := stack.BuildConfig.MaxConcurrentStreams; got != 250 {
		t.Errorf("Stack.BuildConfig.MaxConcurrentStreams = %d, want 250", got)
	}
}

// TestBuildLiveStack_MaxConcurrentStreamsZeroDefault confirms the
// zero-value sentinel survives BuildLiveStack unchanged so the
// downstream H2 layer can fall back to its compile-time default.
func TestBuildLiveStack_MaxConcurrentStreamsZeroDefault(t *testing.T) {
	deps := newTestDeps(t)
	// Field intentionally left at zero on the freshly-constructed BuildConfig.

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if got := stack.BuildConfig.MaxConcurrentStreams; got != 0 {
		t.Errorf("Stack.BuildConfig.MaxConcurrentStreams = %d, want 0 (sentinel for layer default)", got)
	}
}

var _ = errors.Is // sentinel for future errors.Is assertions on package errors

// fakeStreamStore is a flow.Writer + flow.StreamReader test double used by
// the buildOnCompleteFunc / computeStreamDuration unit tests (USK-885).
// It is sync-safe so subtests can run in parallel without an externally
// observable race.
type fakeStreamStore struct {
	mu      sync.Mutex
	streams map[string]*flow.Stream
	updates map[string][]flow.StreamUpdate
	getErr  error
}

func newFakeStreamStore() *fakeStreamStore {
	return &fakeStreamStore{
		streams: make(map[string]*flow.Stream),
		updates: make(map[string][]flow.StreamUpdate),
	}
}

func (f *fakeStreamStore) SaveStream(_ context.Context, s *flow.Stream) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streams[s.ID] = s
	return nil
}

func (f *fakeStreamStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates[id] = append(f.updates[id], update)
	return nil
}

func (f *fakeStreamStore) SaveFlow(_ context.Context, _ *flow.Flow) error { return nil }

func (f *fakeStreamStore) GetStream(_ context.Context, id string) (*flow.Stream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	st, ok := f.streams[id]
	if !ok {
		return nil, nil
	}
	return st, nil
}

func (f *fakeStreamStore) ListStreams(_ context.Context, _ flow.StreamListOptions) ([]*flow.Stream, error) {
	return nil, nil
}

func (f *fakeStreamStore) CountStreams(_ context.Context, _ flow.StreamListOptions) (int, error) {
	return 0, nil
}

// TestComputeStreamDuration_NilReader verifies the nil-reader guard returns
// zero so a downstream store.UpdateStream call leaves duration_ms untouched.
func TestComputeStreamDuration_NilReader(t *testing.T) {
	if got := computeStreamDuration(context.Background(), nil, "stream-1"); got != 0 {
		t.Errorf("computeStreamDuration(nil) = %v, want 0", got)
	}
}

// TestComputeStreamDuration_GetStreamError verifies a Store error projects
// to zero so partial-failure state does not produce a bogus duration_ms.
func TestComputeStreamDuration_GetStreamError(t *testing.T) {
	store := newFakeStreamStore()
	store.getErr = errors.New("simulated store error")
	if got := computeStreamDuration(context.Background(), store, "stream-1"); got != 0 {
		t.Errorf("computeStreamDuration(error) = %v, want 0", got)
	}
}

// TestComputeStreamDuration_StreamNotFound verifies a missing Stream row
// projects to zero (no UpdateStream-time clobber of an existing duration).
func TestComputeStreamDuration_StreamNotFound(t *testing.T) {
	store := newFakeStreamStore()
	if got := computeStreamDuration(context.Background(), store, "missing"); got != 0 {
		t.Errorf("computeStreamDuration(missing) = %v, want 0", got)
	}
}

// TestComputeStreamDuration_ZeroTimestamp verifies a Stream with a zero
// Timestamp projects to zero rather than a non-deterministic value.
func TestComputeStreamDuration_ZeroTimestamp(t *testing.T) {
	store := newFakeStreamStore()
	store.streams["s1"] = &flow.Stream{ID: "s1"} // Timestamp left zero.
	if got := computeStreamDuration(context.Background(), store, "s1"); got != 0 {
		t.Errorf("computeStreamDuration(zero ts) = %v, want 0", got)
	}
}

// TestComputeStreamDuration_FutureTimestamp verifies the defensive d <= 0
// guard catches clock skew / future timestamps and returns zero so the
// caller does not record a negative duration.
func TestComputeStreamDuration_FutureTimestamp(t *testing.T) {
	store := newFakeStreamStore()
	store.streams["s1"] = &flow.Stream{ID: "s1", Timestamp: time.Now().Add(1 * time.Hour)}
	if got := computeStreamDuration(context.Background(), store, "s1"); got != 0 {
		t.Errorf("computeStreamDuration(future ts) = %v, want 0", got)
	}
}

// TestComputeStreamDuration_HappyPath verifies the production case: a
// Stream with a past Timestamp yields a strictly positive Duration.
func TestComputeStreamDuration_HappyPath(t *testing.T) {
	store := newFakeStreamStore()
	store.streams["s1"] = &flow.Stream{ID: "s1", Timestamp: time.Now().Add(-50 * time.Millisecond)}
	got := computeStreamDuration(context.Background(), store, "s1")
	if got <= 0 {
		t.Errorf("computeStreamDuration(past ts) = %v, want > 0", got)
	}
	if got > time.Second {
		t.Errorf("computeStreamDuration(past 50ms) = %v, want roughly 50ms (sanity ceiling 1s)", got)
	}
}

// TestBuildOnCompleteFunc_EmptyStreamID verifies the no-op guard for an
// empty StreamID. RunSession can return without producing any envelope
// (e.g. dial failure before any read); the OnComplete must not produce a
// spurious UpdateStream call.
func TestBuildOnCompleteFunc_EmptyStreamID(t *testing.T) {
	store := newFakeStreamStore()
	blocked := newBlockedStreamSet()
	fn := buildOnCompleteFunc(store, blocked)
	fn(context.Background(), "", nil)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.updates) != 0 {
		t.Errorf("UpdateStream called for empty streamID; updates=%v, want none", store.updates)
	}
}

// TestBuildOnCompleteFunc_BlockedStreamSkippedAndEvicted verifies the
// USK-782 audit-recorder coordination: a Stream that the audit path
// already finalised is not re-finalised by OnComplete, and the marker is
// evicted from the per-listener set (CWE-400 leak guard).
func TestBuildOnCompleteFunc_BlockedStreamSkippedAndEvicted(t *testing.T) {
	store := newFakeStreamStore()
	blocked := newBlockedStreamSet()
	blocked.add("s1")
	fn := buildOnCompleteFunc(store, blocked)
	fn(context.Background(), "s1", nil)
	store.mu.Lock()
	if len(store.updates["s1"]) != 0 {
		t.Errorf("UpdateStream called on blocked stream; updates=%v, want none", store.updates["s1"])
	}
	store.mu.Unlock()
	if blocked.contains("s1") {
		t.Error("blockedStreamSet still contains s1; OnComplete must evict after consumption")
	}
}

// TestBuildOnCompleteFunc_HappyPathComplete verifies the canonical
// USK-885 success projection: nil err → state=complete, Duration
// populated from the Stream's Timestamp.
func TestBuildOnCompleteFunc_HappyPathComplete(t *testing.T) {
	store := newFakeStreamStore()
	store.streams["s1"] = &flow.Stream{ID: "s1", Timestamp: time.Now().Add(-100 * time.Millisecond)}
	blocked := newBlockedStreamSet()
	fn := buildOnCompleteFunc(store, blocked)
	fn(context.Background(), "s1", nil)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.updates["s1"]) != 1 {
		t.Fatalf("UpdateStream call count = %d, want 1", len(store.updates["s1"]))
	}
	up := store.updates["s1"][0]
	if up.State != "complete" {
		t.Errorf("State = %q, want %q", up.State, "complete")
	}
	if up.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", up.Duration)
	}
	if up.AppendTags != nil {
		t.Errorf("AppendTags = %v, want nil on success", up.AppendTags)
	}
}

// TestBuildOnCompleteFunc_EOFTreatedAsComplete verifies io.EOF is
// classified as a graceful terminator (state=complete), not an error.
// The Issue acceptance gate "client/upstream どちらが close しても
// state=complete" depends on this projection.
func TestBuildOnCompleteFunc_EOFTreatedAsComplete(t *testing.T) {
	store := newFakeStreamStore()
	store.streams["s1"] = &flow.Stream{ID: "s1", Timestamp: time.Now().Add(-10 * time.Millisecond)}
	blocked := newBlockedStreamSet()
	fn := buildOnCompleteFunc(store, blocked)
	fn(context.Background(), "s1", io.EOF)
	store.mu.Lock()
	defer store.mu.Unlock()
	up := store.updates["s1"][0]
	if up.State != "complete" {
		t.Errorf("State = %q on io.EOF, want %q", up.State, "complete")
	}
	if up.AppendTags != nil {
		t.Errorf("AppendTags = %v on io.EOF, want nil (no error tag for EOF)", up.AppendTags)
	}
}

// TestBuildOnCompleteFunc_NonEOFErrorProjectsToError verifies non-EOF
// errors classify as state=error with the AppendTags["error"] entry from
// USK-797. The Duration must still be populated so analysts can see the
// stream's lifespan even when it terminated abnormally.
func TestBuildOnCompleteFunc_NonEOFErrorProjectsToError(t *testing.T) {
	store := newFakeStreamStore()
	store.streams["s1"] = &flow.Stream{ID: "s1", Timestamp: time.Now().Add(-10 * time.Millisecond)}
	blocked := newBlockedStreamSet()
	fn := buildOnCompleteFunc(store, blocked)
	fn(context.Background(), "s1", errors.New("simulated transport error"))
	store.mu.Lock()
	defer store.mu.Unlock()
	up := store.updates["s1"][0]
	if up.State != "error" {
		t.Errorf("State = %q on non-EOF err, want %q", up.State, "error")
	}
	if up.Duration <= 0 {
		t.Errorf("Duration = %v on error path, want > 0 (analysts need lifespan even for errors)", up.Duration)
	}
	if up.AppendTags == nil || up.AppendTags["error"] == "" {
		t.Errorf("AppendTags[error] = %v, want non-empty err string", up.AppendTags)
	}
}

// TestBuildOnCompleteFunc_WriterOnlyStoreNoDuration verifies that a Store
// that only implements flow.Writer (no StreamReader) falls through to
// Duration=0 silently. This keeps the test-double contract intact for
// existing flow.Writer-only test stores in the repository.
func TestBuildOnCompleteFunc_WriterOnlyStoreNoDuration(t *testing.T) {
	// noopFlowStore (defined earlier in this file) implements only
	// flow.Writer, not flow.StreamReader.
	store := noopFlowStore{}
	blocked := newBlockedStreamSet()
	fn := buildOnCompleteFunc(store, blocked)
	// No assertions on the StreamUpdate fields since noopFlowStore
	// drops everything; the goal here is purely to verify that the
	// closure does not panic and does not type-assert into a nil
	// reader incorrectly.
	fn(context.Background(), "s1", nil)
}
