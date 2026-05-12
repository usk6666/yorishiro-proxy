package proxybuild

import (
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// passthroughRecordingStore is a Writer that captures every SaveStream /
// UpdateStream / SaveFlow call so the unit tests can assert what the
// passthrough recorder persisted.
type passthroughRecordingStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	updates []recordedUpdate
	flows   []*flow.Flow
}

func (s *passthroughRecordingStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	if st.ConnInfo != nil {
		ciCopy := *st.ConnInfo
		cp.ConnInfo = &ciCopy
	}
	if st.Tags != nil {
		tagsCopy := make(map[string]string, len(st.Tags))
		for k, v := range st.Tags {
			tagsCopy[k] = v
		}
		cp.Tags = tagsCopy
	}
	s.streams = append(s.streams, &cp)
	return nil
}

func (s *passthroughRecordingStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, recordedUpdate{id: id, update: update})
	return nil
}

func (s *passthroughRecordingStore) SaveFlow(_ context.Context, fl *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *fl
	if fl.Metadata != nil {
		md := make(map[string]string, len(fl.Metadata))
		for k, v := range fl.Metadata {
			md[k] = v
		}
		cp.Metadata = md
	}
	s.flows = append(s.flows, &cp)
	return nil
}

func (s *passthroughRecordingStore) snapshot() (streams []*flow.Stream, updates []recordedUpdate, flows []*flow.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*flow.Stream(nil), s.streams...),
		append([]recordedUpdate(nil), s.updates...),
		append([]*flow.Flow(nil), s.flows...)
}

func TestNewPassthroughRecorder_NilStoreReturnsNil(t *testing.T) {
	if got := newPassthroughRecorder(nil, "live", silentLogger(), nil); got != nil {
		t.Errorf("expected nil observer when store is nil, got %T", got)
	}
}

func TestPassthroughRecorder_OnStartOnComplete_Tunneled(t *testing.T) {
	store := &passthroughRecordingStore{}
	r := newPassthroughRecorder(store, "live", silentLogger(), nil)
	if r == nil {
		t.Fatal("expected non-nil recorder")
	}

	ctx := context.Background()
	obs := connector.PassthroughObservation{
		SNI:          "example.com",
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.0.2.1:55555",
		UpstreamAddr: "93.184.216.34:443",
	}
	r.OnStart(ctx, obs)

	streams, updates, flows := store.snapshot()
	if len(streams) != 1 {
		t.Fatalf("OnStart streams = %d, want 1", len(streams))
	}
	st := streams[0]
	if st.Protocol != string(envelope.ProtocolTLSHandshake) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, envelope.ProtocolTLSHandshake)
	}
	if st.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want https", st.Scheme)
	}
	if st.State != "active" {
		t.Errorf("Stream.State = %q, want active", st.State)
	}
	if st.Origin != flow.OriginProxy {
		t.Errorf("Stream.Origin = %q, want %q", st.Origin, flow.OriginProxy)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != "192.0.2.1:55555" || st.ConnInfo.ServerAddr != "93.184.216.34:443" {
		t.Errorf("Stream.ConnInfo = %+v", st.ConnInfo)
	}
	if len(updates) != 0 {
		t.Errorf("OnStart should not write any UpdateStream, got %d", len(updates))
	}
	if len(flows) != 0 {
		t.Errorf("OnStart should not write any Flow, got %d", len(flows))
	}

	// OnComplete with a successful tunnel.
	final := obs
	final.BytesClientToUpstream = 1024
	final.BytesUpstreamToClient = 4096
	final.Outcome = envelope.TLSHandshakeOutcomeTunneled
	r.OnComplete(ctx, final)

	streams, updates, flows = store.snapshot()
	if len(streams) != 1 {
		t.Errorf("Stream count after OnComplete = %d, want 1", len(streams))
	}
	if len(updates) != 1 {
		t.Fatalf("UpdateStream count = %d, want 1", len(updates))
	}
	upd := updates[0]
	if upd.id != st.ID {
		t.Errorf("Update.id = %q, want %q", upd.id, st.ID)
	}
	if upd.update.State != "complete" {
		t.Errorf("Update.State = %q, want complete", upd.update.State)
	}
	if upd.update.FailureReason != "" {
		t.Errorf("Update.FailureReason = %q, want empty", upd.update.FailureReason)
	}
	if upd.update.Duration <= 0 {
		t.Errorf("Update.Duration = %v, want positive", upd.update.Duration)
	}

	if len(flows) != 1 {
		t.Fatalf("Flow count = %d, want 1", len(flows))
	}
	fl := flows[0]
	if fl.StreamID != st.ID {
		t.Errorf("Flow.StreamID = %q, want %q", fl.StreamID, st.ID)
	}
	if fl.Direction != "send" {
		t.Errorf("Flow.Direction = %q, want send", fl.Direction)
	}
	if fl.Sequence != 0 {
		t.Errorf("Flow.Sequence = %d, want 0", fl.Sequence)
	}
	if fl.Metadata["sni"] != "example.com" {
		t.Errorf("Flow.Metadata[sni] = %q, want example.com", fl.Metadata["sni"])
	}
	if fl.Metadata["local_addr"] != "127.0.0.1:8080" {
		t.Errorf("Flow.Metadata[local_addr] = %q", fl.Metadata["local_addr"])
	}
	if fl.Metadata["remote_addr"] != "192.0.2.1:55555" {
		t.Errorf("Flow.Metadata[remote_addr] = %q", fl.Metadata["remote_addr"])
	}
	if fl.Metadata["upstream_addr"] != "93.184.216.34:443" {
		t.Errorf("Flow.Metadata[upstream_addr] = %q", fl.Metadata["upstream_addr"])
	}
	if fl.Metadata["bytes_client_to_upstream"] != "1024" {
		t.Errorf("Flow.Metadata[bytes_client_to_upstream] = %q, want 1024", fl.Metadata["bytes_client_to_upstream"])
	}
	if fl.Metadata["bytes_upstream_to_client"] != "4096" {
		t.Errorf("Flow.Metadata[bytes_upstream_to_client] = %q, want 4096", fl.Metadata["bytes_upstream_to_client"])
	}
	if fl.Metadata["outcome"] != envelope.TLSHandshakeOutcomeTunneled {
		t.Errorf("Flow.Metadata[outcome] = %q, want %q", fl.Metadata["outcome"], envelope.TLSHandshakeOutcomeTunneled)
	}
	if _, ok := fl.Metadata["error"]; ok {
		t.Errorf("Flow.Metadata[error] should be absent for tunneled outcome, got %q", fl.Metadata["error"])
	}
}

func TestPassthroughRecorder_OnComplete_RelayError(t *testing.T) {
	store := &passthroughRecordingStore{}
	r := newPassthroughRecorder(store, "live", silentLogger(), nil)
	ctx := context.Background()

	obs := connector.PassthroughObservation{
		SNI:          "example.com",
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.0.2.1:55555",
		UpstreamAddr: "93.184.216.34:443",
	}
	r.OnStart(ctx, obs)

	failed := obs
	failed.BytesClientToUpstream = 100
	failed.BytesUpstreamToClient = 200
	failed.Outcome = envelope.TLSHandshakeOutcomeFailed
	failed.ErrorReason = "io.Copy: broken pipe"
	r.OnComplete(ctx, failed)

	_, updates, flows := store.snapshot()
	if len(updates) != 1 {
		t.Fatalf("UpdateStream count = %d, want 1", len(updates))
	}
	if updates[0].update.State != "error" {
		t.Errorf("State = %q, want error", updates[0].update.State)
	}
	if updates[0].update.FailureReason != "passthrough_relay_error" {
		t.Errorf("FailureReason = %q, want passthrough_relay_error", updates[0].update.FailureReason)
	}

	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	if flows[0].Metadata["outcome"] != envelope.TLSHandshakeOutcomeFailed {
		t.Errorf("outcome = %q, want %q", flows[0].Metadata["outcome"], envelope.TLSHandshakeOutcomeFailed)
	}
	if flows[0].Metadata["error"] != "io.Copy: broken pipe" {
		t.Errorf("error metadata = %q", flows[0].Metadata["error"])
	}
}

func TestPassthroughRecorder_OnComplete_DialFailureWithoutOnStart(t *testing.T) {
	store := &passthroughRecordingStore{}
	r := newPassthroughRecorder(store, "live", silentLogger(), nil)
	ctx := context.Background()

	// OnStart is not called — upstream dial failed before that point.
	failed := connector.PassthroughObservation{
		LocalAddr:   "127.0.0.1:8080",
		RemoteAddr:  "192.0.2.1:55555",
		Outcome:     envelope.TLSHandshakeOutcomeFailed,
		ErrorReason: "dial tcp 198.51.100.4:443: connect: connection refused",
	}
	r.OnComplete(ctx, failed)

	streams, updates, flows := store.snapshot()
	if len(streams) != 1 {
		t.Fatalf("Streams = %d, want 1", len(streams))
	}
	if streams[0].State != "error" {
		t.Errorf("State = %q, want error", streams[0].State)
	}
	if streams[0].FailureReason != "passthrough_dial_failed" {
		t.Errorf("FailureReason = %q, want passthrough_dial_failed", streams[0].FailureReason)
	}
	if streams[0].Tags["error"] == "" {
		t.Errorf("expected Tags[error] to carry dial reason")
	}
	if len(updates) != 0 {
		t.Errorf("UpdateStream count = %d, want 0 (initial Stream is state=error)", len(updates))
	}
	if len(flows) != 1 {
		t.Errorf("flows = %d, want 1", len(flows))
	}
}

func TestPassthroughRecorder_RecordScopeFiltersOutOfScope(t *testing.T) {
	store := &passthroughRecordingStore{}
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: "in-scope.example"}}, nil)
	r := newPassthroughRecorder(store, "live", silentLogger(), scope)
	ctx := context.Background()

	// Out-of-scope target — no Stream should be persisted.
	obs := connector.PassthroughObservation{
		SNI:          "out-of-scope.example",
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.0.2.1:55555",
		UpstreamAddr: "out-of-scope.example:443",
		TargetHost:   "out-of-scope.example",
	}
	r.OnStart(ctx, obs)
	final := obs
	final.Outcome = envelope.TLSHandshakeOutcomeTunneled
	r.OnComplete(ctx, final)

	streams, updates, flows := store.snapshot()
	if len(streams) != 0 || len(updates) != 0 || len(flows) != 0 {
		t.Errorf("out-of-scope passthrough should not be recorded, got streams=%d updates=%d flows=%d",
			len(streams), len(updates), len(flows))
	}

	// In-scope target — Stream should be persisted.
	in := connector.PassthroughObservation{
		SNI:          "in-scope.example",
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.0.2.1:55556",
		UpstreamAddr: "in-scope.example:443",
		TargetHost:   "in-scope.example",
	}
	r.OnStart(ctx, in)
	finalIn := in
	finalIn.Outcome = envelope.TLSHandshakeOutcomeTunneled
	r.OnComplete(ctx, finalIn)

	streams, _, flows = store.snapshot()
	if len(streams) != 1 {
		t.Errorf("in-scope passthrough should record 1 Stream, got %d", len(streams))
	}
	if len(flows) != 1 {
		t.Errorf("in-scope passthrough should record 1 Flow, got %d", len(flows))
	}
}

// TestPassthroughRecorder_RecordScopeMatchesHostnameWhenUpstreamIsIP is the
// USK-845 regression test: pre-fix, the recorder seeded the scope envelope's
// Context.TargetHost from obs.UpstreamAddr (a resolved IP literal), which
// short-circuited scopeHostnameFromContext's TargetHost → SNI fallback in
// flow/record_scope.go. With the fix, obs.TargetHost carries the CONNECT /
// SOCKS5 target hostname and the include rule matches even when the dialed
// upstream is reachable only by IP. Track F §F-1 footgun (2026-05-13).
func TestPassthroughRecorder_RecordScopeMatchesHostnameWhenUpstreamIsIP(t *testing.T) {
	store := &passthroughRecordingStore{}
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: "httpbin.org"}}, nil)
	r := newPassthroughRecorder(store, "live", silentLogger(), scope)
	ctx := context.Background()

	// Mirror Track F §F-1 wire reality: client sent CONNECT httpbin.org:443,
	// the proxy resolved it to a public IP, and the SNI peek confirmed the
	// hostname. UpstreamAddr is the IP-shaped 4-tuple half — pre-fix this
	// alone reached the matcher and the include rule never fired.
	obs := connector.PassthroughObservation{
		SNI:          "httpbin.org",
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.0.2.1:55557",
		UpstreamAddr: "1.2.3.4:443",
		TargetHost:   "httpbin.org",
	}
	r.OnStart(ctx, obs)
	final := obs
	final.BytesClientToUpstream = 512
	final.BytesUpstreamToClient = 2048
	final.Outcome = envelope.TLSHandshakeOutcomeTunneled
	r.OnComplete(ctx, final)

	streams, updates, flows := store.snapshot()
	if len(streams) != 1 {
		t.Fatalf("expected 1 Stream for IP-shaped UpstreamAddr + hostname TargetHost; got %d", len(streams))
	}
	if len(updates) != 1 {
		t.Errorf("expected 1 UpdateStream finalisation, got %d", len(updates))
	}
	if len(flows) != 1 {
		t.Errorf("expected 1 audit Flow, got %d", len(flows))
	}
	if streams[0].ConnInfo == nil || streams[0].ConnInfo.ServerAddr != "1.2.3.4:443" {
		t.Errorf("Stream.ConnInfo.ServerAddr = %+v, want 1.2.3.4:443 (raw upstream preserved)", streams[0].ConnInfo)
	}
}

// TestPassthroughRecorder_RecordScopeFallsBackToSNI guards the
// defence-in-depth path: even when obs.TargetHost is empty (e.g., an
// observation built by hand or a future peek-before-dial code path), the
// matcher should still match through Context.TLS.SNI populated from
// obs.SNI. This locks in the USK-845 design Q3 decision.
func TestPassthroughRecorder_RecordScopeFallsBackToSNI(t *testing.T) {
	store := &passthroughRecordingStore{}
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: "httpbin.org"}}, nil)
	r := newPassthroughRecorder(store, "live", silentLogger(), scope)
	ctx := context.Background()

	obs := connector.PassthroughObservation{
		SNI:          "httpbin.org",
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.0.2.1:55558",
		UpstreamAddr: "1.2.3.4:443",
		// TargetHost intentionally empty.
	}
	r.OnStart(ctx, obs)
	final := obs
	final.Outcome = envelope.TLSHandshakeOutcomeTunneled
	r.OnComplete(ctx, final)

	streams, _, flows := store.snapshot()
	if len(streams) != 1 {
		t.Errorf("SNI fallback should record 1 Stream; got %d", len(streams))
	}
	if len(flows) != 1 {
		t.Errorf("SNI fallback should record 1 Flow; got %d", len(flows))
	}
}
