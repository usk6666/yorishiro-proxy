package proxybuild

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/time/rate"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1142: unit coverage for the Manager-level capacity-rejection
// aggregator. RejectInfo values are synthetic here because the aggregator
// is pure bookkeeping; the producers (FullListener, TCP forward) are
// covered by internal/connector/full_listener_reject_test.go, the wiring
// test below, and the mcptest e2e.

func connectReject(i int, target string) connector.RejectInfo {
	return connector.RejectInfo{
		Listener:       "default",
		RemoteAddr:     fmt.Sprintf("127.0.0.1:%d", 40000+i),
		DetectedKind:   connector.ProtocolHTTPConnect,
		Method:         "CONNECT",
		Target:         target,
		WroteResponse:  true,
		MaxConnections: 1,
		At:             time.Date(2026, 10, 16, 0, 0, i, 0, time.UTC),
	}
}

// savedStreams returns a copy of the streams captured by the recording
// store.
func (r *recordingFlowStore) savedStreams() []*flow.Stream {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*flow.Stream, len(r.saved))
	copy(out, r.saved)
	return out
}

// recentAt returns snap.Recent[i], failing the test when the ring is too
// short.
func recentAt(t *testing.T, snap ConnectionRejectionsSnapshot, i int) ConnectionRejectionEntry {
	t.Helper()
	if len(snap.Recent) <= i {
		t.Fatalf("len(Recent) = %d, want > %d", len(snap.Recent), i)
	}
	return snap.Recent[i]
}

func waitForStreams(t *testing.T, store *recordingFlowStore, n int) []*flow.Stream {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := store.savedStreams(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return store.savedStreams()
}

func TestConnectionRejections_SnapshotCountsAndRing(t *testing.T) {
	c := NewConnectionRejections(ConnectionRejectionsConfig{Logger: silentLogger()})
	t.Cleanup(c.Close)

	kinds := []connector.ProtocolKind{
		connector.ProtocolHTTP1,
		connector.ProtocolHTTPConnect,
		connector.ProtocolSOCKS5,
		connector.ProtocolHTTP2,
		connector.ProtocolTCP,
		connector.ProtocolUnknown,
	}
	const n = 100
	for i := 0; i < n; i++ {
		info := connectReject(i, fmt.Sprintf("host-%d.example:443", i))
		info.DetectedKind = kinds[i%len(kinds)]
		c.Record(info)
	}

	snap := c.Snapshot()
	if snap.Total != n {
		t.Errorf("Total = %d, want %d", snap.Total, n)
	}
	bk := snap.ByKind
	if sum := bk.HTTP1 + bk.Connect + bk.SOCKS5 + bk.HTTP2 + bk.TCP + bk.Unknown; sum != n {
		t.Errorf("sum(ByKind) = %d, want %d (%+v)", sum, n, bk)
	}
	if bk.Connect != 17 || bk.Unknown != 16 {
		t.Errorf("ByKind = %+v, want connect=17 unknown=16", bk)
	}
	if len(snap.Recent) != connectionRejectionsRingSize {
		t.Fatalf("len(Recent) = %d, want %d", len(snap.Recent), connectionRejectionsRingSize)
	}
	if got, want := snap.Recent[0].RemoteAddr, fmt.Sprintf("127.0.0.1:%d", 40000+n-1); got != want {
		t.Errorf("Recent[0].RemoteAddr = %q, want newest %q", got, want)
	}
	if got, want := snap.Recent[len(snap.Recent)-1].RemoteAddr, fmt.Sprintf("127.0.0.1:%d", 40000+n-connectionRejectionsRingSize); got != want {
		t.Errorf("Recent[last].RemoteAddr = %q, want %q", got, want)
	}
	wantLast := time.Date(2026, 10, 16, 0, 0, n-1, 0, time.UTC).Format(time.RFC3339Nano)
	if snap.LastAt != wantLast {
		t.Errorf("LastAt = %q, want %q", snap.LastAt, wantLast)
	}
	newest := snap.Recent[0]
	if newest.DetectedKind == "" || newest.Listener != "default" || newest.MaxConnections != 1 || !newest.Wrote503 {
		t.Errorf("Recent[0] = %+v, want detected_kind set, listener=default, max_connections=1, wrote_503=true", newest)
	}
	// Without a store nothing is recorded, and that is not "unrecorded"
	// (recording is disabled, not shed).
	if newest.Recorded {
		t.Errorf("Recent[0].Recorded = true with no store")
	}
}

func TestConnectionRejections_KindLabels(t *testing.T) {
	c := NewConnectionRejections(ConnectionRejectionsConfig{Logger: silentLogger()})
	t.Cleanup(c.Close)
	want := map[connector.ProtocolKind]string{
		connector.ProtocolHTTP1:       "http1",
		connector.ProtocolHTTPConnect: "connect",
		connector.ProtocolSOCKS5:      "socks5",
		connector.ProtocolHTTP2:       "http2",
		connector.ProtocolTCP:         "tcp",
		connector.ProtocolUnknown:     "unknown",
	}
	for kind, label := range want {
		info := connectReject(0, "")
		info.DetectedKind = kind
		c.Record(info)
		if got := recentAt(t, c.Snapshot(), 0).DetectedKind; got != label {
			t.Errorf("kind %v: detected_kind = %q, want %q", kind, got, label)
		}
	}
}

func TestConnectionRejections_ConcurrentRecordAndSnapshot(t *testing.T) {
	c := NewConnectionRejections(ConnectionRejectionsConfig{Logger: silentLogger()})
	t.Cleanup(c.Close)

	const workers, per = 8, 200
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				snap := c.Snapshot()
				if len(snap.Recent) > connectionRejectionsRingSize {
					t.Errorf("len(Recent) = %d exceeds ring size", len(snap.Recent))
					return
				}
			}
		}
	}()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.Record(connectReject(w*per+i, "x.example:443"))
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	readers.Wait()

	if got := c.Snapshot().Total; got != workers*per {
		t.Errorf("Total = %d, want %d", got, workers*per)
	}
}

func TestConnectionRejections_RecordsAuditStream(t *testing.T) {
	store := &recordingFlowStore{}
	c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Logger: silentLogger()})
	t.Cleanup(c.Close)

	c.Record(connectReject(1, "ExAmPlE.com:443"))

	streams := waitForStreams(t, store, 1)
	if len(streams) != 1 {
		t.Fatalf("saved streams = %d, want 1", len(streams))
	}
	st := streams[0]
	if st.State != "error" {
		t.Errorf("State = %q, want error", st.State)
	}
	if pipeline.BlockedByCapacity != "capacity" {
		t.Errorf("pipeline.BlockedByCapacity = %q, want the MCP filter value capacity", pipeline.BlockedByCapacity)
	}
	if st.BlockedBy != pipeline.BlockedByCapacity {
		t.Errorf("BlockedBy = %q, want %q", st.BlockedBy, pipeline.BlockedByCapacity)
	}
	if !strings.Contains(st.FailureReason, "max_connections=1") {
		t.Errorf("FailureReason = %q, want it to name max_connections=1", st.FailureReason)
	}
	if st.Protocol != "http" {
		t.Errorf("Protocol = %q, want http for CONNECT", st.Protocol)
	}
	if st.ConnInfo == nil || st.ConnInfo.ServerAddr != "ExAmPlE.com:443" || st.ConnInfo.ClientAddr != "127.0.0.1:40001" {
		t.Errorf("ConnInfo = %+v, want ServerAddr=ExAmPlE.com:443 ClientAddr=127.0.0.1:40001", st.ConnInfo)
	}
	if st.Tags["target"] != "ExAmPlE.com:443" || st.Tags["detected_kind"] != "connect" || st.Tags["listener"] != "default" {
		t.Errorf("Tags = %v, want target/detected_kind/listener", st.Tags)
	}
	if snap := c.Snapshot(); !recentAt(t, snap, 0).Recorded || snap.Unrecorded != 0 {
		t.Errorf("snapshot recorded=%v unrecorded=%d, want true/0", recentAt(t, snap, 0).Recorded, snap.Unrecorded)
	}
}

func TestConnectionRejections_HTTP1AbsoluteFormServerAddr(t *testing.T) {
	store := &recordingFlowStore{}
	c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Logger: silentLogger()})
	t.Cleanup(c.Close)

	info := connectReject(2, "http://Ads.Example:8080/slot?id=1")
	info.DetectedKind = connector.ProtocolHTTP1
	info.Method = "GET"
	c.Record(info)

	streams := waitForStreams(t, store, 1)
	if len(streams) != 1 {
		t.Fatalf("saved streams = %d, want 1", len(streams))
	}
	st := streams[0]
	if st.ConnInfo == nil || st.ConnInfo.ServerAddr != "Ads.Example:8080" {
		t.Errorf("ConnInfo = %+v, want ServerAddr = authority of the absolute-form target", st.ConnInfo)
	}
	if st.Tags["target"] != "http://Ads.Example:8080/slot?id=1" {
		t.Errorf("Tags[target] = %q, want verbatim request-target", st.Tags["target"])
	}
	if st.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", st.Protocol)
	}
}

func TestConnectionRejections_NonHTTPRecordedAsRaw(t *testing.T) {
	store := &recordingFlowStore{}
	c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Logger: silentLogger()})
	t.Cleanup(c.Close)

	info := connectReject(3, "")
	info.DetectedKind = connector.ProtocolSOCKS5
	info.Method = ""
	info.WroteResponse = false
	c.Record(info)

	streams := waitForStreams(t, store, 1)
	if len(streams) != 1 {
		t.Fatalf("saved streams = %d, want 1 (no-target rejections are still recorded)", len(streams))
	}
	if streams[0].Protocol != "raw" {
		t.Errorf("Protocol = %q, want raw", streams[0].Protocol)
	}
	if streams[0].ConnInfo == nil || streams[0].ConnInfo.ServerAddr != "" {
		t.Errorf("ConnInfo = %+v, want empty ServerAddr", streams[0].ConnInfo)
	}
}

// TestConnectionRejections_RateCap: with a burst of 5 and a negligible
// refill, 20 rejections write at most 5 Streams; the rest are counted as
// unrecorded and flagged on their ring entries.
func TestConnectionRejections_RateCap(t *testing.T) {
	store := &recordingFlowStore{}
	c := NewConnectionRejections(ConnectionRejectionsConfig{
		Store:       store,
		Logger:      silentLogger(),
		RecordRate:  rate.Every(time.Hour),
		RecordBurst: 5,
	})
	t.Cleanup(c.Close)

	const n = 20
	for i := 0; i < n; i++ {
		c.Record(connectReject(i, "flood.example:443"))
	}
	waitForStreams(t, store, 5)
	// Give a straggler write a moment to (wrongly) appear.
	time.Sleep(50 * time.Millisecond)
	streams := store.savedStreams()
	if len(streams) != 5 {
		t.Errorf("saved streams = %d, want 5 (burst)", len(streams))
	}
	snap := c.Snapshot()
	if snap.Unrecorded != int64(n-len(streams)) {
		t.Errorf("Unrecorded = %d, want %d", snap.Unrecorded, n-len(streams))
	}
	recorded := 0
	for _, e := range snap.Recent {
		if e.Recorded {
			recorded++
		}
	}
	if recorded != 5 {
		t.Errorf("ring entries with recorded=true = %d, want 5", recorded)
	}
}

// blockingFlowStore blocks every SaveStream until release is closed or the
// call's context is done.
type blockingFlowStore struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingFlowStore() *blockingFlowStore {
	return &blockingFlowStore{entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *blockingFlowStore) SaveStream(ctx context.Context, _ *flow.Stream) error {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *blockingFlowStore) UpdateStream(context.Context, string, flow.StreamUpdate) error {
	return nil
}
func (s *blockingFlowStore) SaveFlow(context.Context, *flow.Flow) error { return nil }

// TestConnectionRejections_FullQueueDoesNotBlock: a stalled store must
// never block the reject path; overflow is counted as unrecorded.
func TestConnectionRejections_FullQueueDoesNotBlock(t *testing.T) {
	store := newBlockingFlowStore()
	c := NewConnectionRejections(ConnectionRejectionsConfig{
		Store:       store,
		Logger:      silentLogger(),
		RecordRate:  rate.Inf,
		RecordBurst: 1000,
		QueueSize:   2,
	})
	t.Cleanup(func() {
		close(store.release)
		c.Close()
	})

	c.Record(connectReject(0, "slow.example:443"))
	select {
	case <-store.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recorder never called SaveStream")
	}

	const n = 50
	start := time.Now()
	for i := 1; i <= n; i++ {
		c.Record(connectReject(i, "slow.example:443"))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("%d Record calls with a stalled store took %v; Record must not block", n, elapsed)
	}
	// One in flight + QueueSize queued; everything else is shed.
	if got, want := c.Snapshot().Unrecorded, int64(n-2); got != want {
		t.Errorf("Unrecorded = %d, want %d", got, want)
	}
}

// TestConnectionRejections_CaptureScope: an out-of-scope target is counted
// in status but not written; an in-scope target is written.
func TestConnectionRejections_CaptureScope(t *testing.T) {
	store := &recordingFlowStore{}
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: "a.example"}}, nil)
	c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Scope: scope, Logger: silentLogger()})
	t.Cleanup(c.Close)

	c.Record(connectReject(1, "b.example:443"))
	c.Record(connectReject(2, "a.example:443"))

	waitForStreams(t, store, 1)
	time.Sleep(50 * time.Millisecond)
	streams := store.savedStreams()
	if len(streams) != 1 {
		t.Fatalf("saved streams = %d, want 1 (in-scope only)", len(streams))
	}
	if got := streams[0].ConnInfo.ServerAddr; got != "a.example:443" {
		t.Errorf("recorded ServerAddr = %q, want a.example:443", got)
	}
	snap := c.Snapshot()
	if snap.Total != 2 {
		t.Errorf("Total = %d, want 2 (out-of-scope still counted)", snap.Total)
	}
	if snap.OutOfScope != 1 {
		t.Errorf("OutOfScope = %d, want 1", snap.OutOfScope)
	}
	if snap.Unrecorded != 0 {
		t.Errorf("Unrecorded = %d, want 0 (scope skips are not shed writes)", snap.Unrecorded)
	}
	if recentAt(t, snap, 1).Recorded {
		t.Errorf("out-of-scope entry has recorded=true")
	}
}

// TestConnectionRejections_CloseStopsRecorder: Close returns promptly even
// while a write is in flight, and no recorder goroutine survives it.
func TestConnectionRejections_CloseStopsRecorder(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	store := newBlockingFlowStore()
	c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Logger: silentLogger()})
	c.Record(connectReject(0, "slow.example:443"))
	c.Record(connectReject(1, "slow.example:443"))
	select {
	case <-store.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recorder never called SaveStream")
	}

	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return while a write was in flight")
	}
	// Close is idempotent and Record after Close neither panics nor
	// restarts the recorder.
	c.Close()
	c.Record(connectReject(2, "late.example:443"))
	if got := c.Snapshot().Total; got != 3 {
		t.Errorf("Total = %d, want 3", got)
	}
}

// TestConnectionRejections_NoAuthorityUnderHostnameExclude (USK-1142
// review S-1): an HTTP/1.x origin-form rejection carries no authority, so
// no hostname rule can match it. Under an exclude rule that constrains
// Hostname the target may belong to an excluded host, so the rejection
// fails closed (out_of_scope, nothing persisted) instead of writing its
// path/query to the store. With no hostname-bearing exclude rule the audit
// Stream is still written.
func TestConnectionRejections_NoAuthorityUnderHostnameExclude(t *testing.T) {
	originForm := func(i int) connector.RejectInfo {
		info := connectReject(i, "/secret?token=x")
		info.DetectedKind = connector.ProtocolHTTP1
		info.Method = "GET"
		return info
	}
	cases := []struct {
		name           string
		excludes       []flow.ScopeRule
		wantSaved      bool
		wantOutOfScope int64
	}{
		{name: "hostname exclude fails closed", excludes: []flow.ScopeRule{{Hostname: "secret.example"}}, wantSaved: false, wantOutOfScope: 1},
		{name: "hostname+path exclude fails closed", excludes: []flow.ScopeRule{{Hostname: "secret.example", URLPrefix: "/secret"}}, wantSaved: false, wantOutOfScope: 1},
		{name: "empty scope still records", excludes: nil, wantSaved: true, wantOutOfScope: 0},
		{name: "path-only exclude still records", excludes: []flow.ScopeRule{{URLPrefix: "/admin"}}, wantSaved: true, wantOutOfScope: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &recordingFlowStore{}
			scope := flow.NewRecordScope()
			scope.SetRules(nil, tc.excludes)
			c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Scope: scope, Logger: silentLogger()})
			t.Cleanup(c.Close)

			c.Record(originForm(1))
			// Sentinel with an authority no exclude rule matches. The single
			// recorder is FIFO, so once the sentinel is saved the origin-form
			// record has either been saved already or was never queued.
			c.Record(connectReject(2, "other.example:443"))

			want := 1
			if tc.wantSaved {
				want = 2
			}
			streams := waitForStreams(t, store, want)
			if len(streams) != want {
				t.Fatalf("saved streams = %d, want %d", len(streams), want)
			}
			sawTarget := false
			for _, st := range streams {
				if st.Tags["target"] == "/secret?token=x" {
					sawTarget = true
				}
			}
			if sawTarget != tc.wantSaved {
				t.Errorf("origin-form target persisted = %v, want %v", sawTarget, tc.wantSaved)
			}
			snap := c.Snapshot()
			if snap.OutOfScope != tc.wantOutOfScope {
				t.Errorf("OutOfScope = %d, want %d", snap.OutOfScope, tc.wantOutOfScope)
			}
			if snap.Total != 2 {
				t.Errorf("Total = %d, want 2", snap.Total)
			}
			if got := recentAt(t, snap, 1).Recorded; got != tc.wantSaved {
				t.Errorf("origin-form entry recorded = %v, want %v", got, tc.wantSaved)
			}
		})
	}
}
