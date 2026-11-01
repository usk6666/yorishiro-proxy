package flow

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- helpers ---------------------------------------------------------------

// sinkTestStore opens a migrated store whose Close the test may call
// itself; the cleanup closes it only if the test did not.
type sinkTestStore struct {
	*SQLiteStore
	once sync.Once
}

func (s *sinkTestStore) close(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		if err := s.SQLiteStore.Close(); err != nil {
			t.Errorf("store Close: %v", err)
		}
	})
}

func newSinkTestStore(t *testing.T) *sinkTestStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sink.db")
	copyTestStoreTemplate(t, dbPath)
	st, err := NewSQLiteStore(context.Background(), dbPath, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	s := &sinkTestStore{SQLiteStore: st}
	t.Cleanup(func() { s.close(t) })
	return s
}

// newObservedFileStore returns a store with a file sink in a fresh
// directory attached, plus that directory.
func newObservedFileStore(t *testing.T, cfg SinkConfig) (*sinkTestStore, *Sink, string) {
	t.Helper()
	store := newSinkTestStore(t)
	if cfg.Dir == "" {
		cfg.Dir = filepath.Join(t.TempDir(), "sink")
	}
	sink, err := NewFileSink(cfg, store, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	store.SetCommitObserver(sink)
	return store, sink, cfg.Dir
}

// sinkFiles returns the sink's files in consumption order: rotated files
// by name, then the active flows.jsonl.
func sinkFiles(t *testing.T, dir string) []string {
	t.Helper()
	rotated, err := filepath.Glob(filepath.Join(dir, "flows-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sort.Strings(rotated)
	active := filepath.Join(dir, "flows.jsonl")
	if _, err := os.Stat(active); err == nil {
		rotated = append(rotated, active)
	}
	return rotated
}

func readFileLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 64<<20)
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		t.Errorf("%s does not end with a newline: a line was split", path)
	}
	return out
}

func readSinkRecords(t *testing.T, dir string) []*ExportRecord {
	t.Helper()
	var recs []*ExportRecord
	for _, f := range sinkFiles(t, dir) {
		for _, line := range readFileLines(t, f) {
			var rec ExportRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				t.Fatalf("%s: invalid JSON line %q: %v", f, line, err)
			}
			recs = append(recs, &rec)
		}
	}
	return recs
}

func sinkEvents(recs []*ExportRecord) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Event
	}
	return out
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

var sinkTestTS = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func sinkTestStream(id string) *Stream {
	return &Stream{
		ID:           id,
		ConnID:       "conn-" + id,
		Protocol:     "http",
		Scheme:       "https",
		State:        "active",
		Timestamp:    sinkTestTS,
		Tags:         map[string]string{"a": "1"},
		ListenerName: "default",
		ConnInfo:     &ConnectionInfo{ClientAddr: "127.0.0.1:5000", ServerAddr: "127.0.0.1:443"},
	}
}

func sinkTestFlow(streamID string, seq int, dir string, body []byte) *Flow {
	return &Flow{
		StreamID:  streamID,
		Sequence:  seq,
		Direction: dir,
		Timestamp: sinkTestTS.Add(time.Duration(seq+1) * time.Millisecond),
		Headers:   map[string][]string{"X-Seq": {dir}},
		Body:      body,
		RawBytes:  append([]byte("RAW "), body...),
	}
}

// blockingLineWriter blocks every WriteLine until release is closed and
// records what it was given.
type blockingLineWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	lines   [][]byte
	closed  bool
}

func newBlockingLineWriter() *blockingLineWriter {
	return &blockingLineWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *blockingLineWriter) WriteLine(line []byte) error {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, append([]byte(nil), line...))
	return nil
}

func (w *blockingLineWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *blockingLineWriter) records(t *testing.T) []*ExportRecord {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*ExportRecord, 0, len(w.lines))
	for _, l := range w.lines {
		var rec ExportRecord
		if err := json.Unmarshal(l, &rec); err != nil {
			t.Fatalf("invalid JSON line %q: %v", l, err)
		}
		out = append(out, &rec)
	}
	return out
}

// --- Test Plan #1 ----------------------------------------------------------

// TestSink_EmitsCommittedWritesInOrder: SaveStream → SaveFlow ×2 →
// UpdateStream(AppendTags, State=complete) produce stream_created,
// flow_saved ×2, stream_updated in that order, each carrying the stored
// record; the final snapshot has the merged tags and the new state.
func TestSink_EmitsCommittedWritesInOrder(t *testing.T) {
	ctx := context.Background()
	store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true})

	st := sinkTestStream("sink-order-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	send := sinkTestFlow(st.ID, 0, "send", []byte("request-body"))
	recv := sinkTestFlow(st.ID, 1, "receive", []byte("response-body"))
	for _, f := range []*Flow{send, recv} {
		if err := store.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
	}
	if err := store.UpdateStream(ctx, st.ID, StreamUpdate{State: "complete", AppendTags: map[string]string{"b": "2"}}); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}

	// What the store holds, in export form.
	var wantFlows []*ExportFlow
	for _, f := range []*Flow{send, recv} {
		stored, err := store.GetFlow(ctx, f.ID)
		if err != nil {
			t.Fatalf("GetFlow: %v", err)
		}
		wantFlows = append(wantFlows, flowsToExport([]*Flow{stored}, true)[0])
	}
	storedStream, err := store.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	wantFinal := streamToExport(storedStream)

	store.close(t)

	recs := readSinkRecords(t, dir)
	want := []string{"stream_created", "flow_saved", "flow_saved", "stream_updated"}
	if got := sinkEvents(recs); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	runID := recs[0].RunID
	if runID == "" {
		t.Errorf("run_id is empty")
	}
	for i, r := range recs {
		if r.Version != ExportFormatVersion {
			t.Errorf("line %d: version = %q, want %q", i, r.Version, ExportFormatVersion)
		}
		if r.Seq != uint64(i+1) {
			t.Errorf("line %d: seq = %d, want %d", i, r.Seq, i+1)
		}
		if r.RunID != runID {
			t.Errorf("line %d: run_id = %q, want %q", i, r.RunID, runID)
		}
		if _, err := time.Parse(time.RFC3339Nano, r.EmittedAt); err != nil {
			t.Errorf("line %d: emitted_at %q: %v", i, r.EmittedAt, err)
		}
		if r.Stream == nil || r.Stream.ID != st.ID {
			t.Fatalf("line %d: stream = %+v, want id %s", i, r.Stream, st.ID)
		}
	}
	if n := len(recs[0].Flows); n != 0 {
		t.Errorf("stream_created carries %d flows, want 0", n)
	}
	for i, wf := range wantFlows {
		r := recs[1+i]
		if len(r.Flows) != 1 {
			t.Fatalf("flow_saved line %d carries %d flows, want 1", 1+i, len(r.Flows))
		}
		if got, want := jsonOf(t, r.Flows[0]), jsonOf(t, wf); got != want {
			t.Errorf("flow_saved line %d flow =\n%s\nwant (stored record)\n%s", 1+i, got, want)
		}
	}
	if body, _ := base64.StdEncoding.DecodeString(recs[1].Flows[0].Body); string(body) != "request-body" {
		t.Errorf("send body = %q, want request-body", body)
	}
	if got, want := jsonOf(t, recs[3].Stream), jsonOf(t, wantFinal); got != want {
		t.Errorf("stream_updated snapshot =\n%s\nwant (stored record)\n%s", got, want)
	}
	if recs[3].Stream.State != "complete" || !reflect.DeepEqual(recs[3].Stream.Tags, map[string]string{"a": "1", "b": "2"}) {
		t.Errorf("final snapshot state=%q tags=%v, want complete with merged tags", recs[3].Stream.State, recs[3].Stream.Tags)
	}
}

// --- Test Plan #2 ----------------------------------------------------------

// TestSink_FailedWritesEmitNothing: writes that do not commit produce no
// line.
func TestSink_FailedWritesEmitNothing(t *testing.T) {
	ctx := context.Background()
	store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true})

	st := sinkTestStream("sink-fail-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	// Duplicate primary key.
	if err := store.SaveStream(ctx, sinkTestStream(st.ID)); err == nil {
		t.Fatalf("duplicate SaveStream succeeded")
	}
	// Foreign-key violation: the stream does not exist.
	if err := store.SaveFlow(ctx, sinkTestFlow("no-such-stream", 0, "send", []byte("x"))); err == nil {
		t.Fatalf("SaveFlow on a missing stream succeeded")
	}
	// Rejected update.
	if err := store.UpdateStream(ctx, st.ID, StreamUpdate{Tags: map[string]string{"x": "1"}, AppendTags: map[string]string{"y": "2"}}); err == nil {
		t.Fatalf("UpdateStream with Tags and AppendTags succeeded")
	}
	// Update of a stream that does not exist changes no row.
	if err := store.UpdateStream(ctx, "no-such-stream", StreamUpdate{State: "complete"}); err != nil {
		t.Fatalf("UpdateStream(missing): %v", err)
	}
	store.close(t)

	recs := readSinkRecords(t, dir)
	if got, want := sinkEvents(recs), []string{"stream_created"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v (only the committed SaveStream)", got, want)
	}
}

// --- Test Plan #3 ----------------------------------------------------------

// TestSink_BlockedWriterNeverBlocksStoreWrites: while the sink's writer is
// stuck, SaveFlow keeps returning promptly, the excess is counted as
// dropped, and once the writer recovers a gap line covering exactly the
// dropped sequence numbers precedes the next event.
func TestSink_BlockedWriterNeverBlocksStoreWrites(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	ctx := context.Background()
	store := newSinkTestStore(t)
	w := newBlockingLineWriter()
	sink := newSink(SinkConfig{Dir: "test", IncludeBodies: true, QueueMaxEvents: 2, QueueMaxBytes: DefaultSinkQueueMaxBytes}, store, w, testutil.DiscardLogger())
	store.SetCommitObserver(sink)

	st := sinkTestStream("sink-block-1")
	if err := store.SaveStream(ctx, st); err != nil { // seq 1: taken by the worker, which blocks
		t.Fatalf("SaveStream: %v", err)
	}
	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("sink worker never reached the writer")
	}

	const n = 10 // seq 2..11: two fit in the queue, eight are dropped
	start := time.Now()
	for i := 0; i < n; i++ {
		before := time.Now()
		if err := store.SaveFlow(ctx, sinkTestFlow(st.ID, i, "send", []byte("payload"))); err != nil {
			t.Fatalf("SaveFlow %d: %v", i, err)
		}
		if d := time.Since(before); d > time.Second {
			t.Fatalf("SaveFlow %d took %v while the sink was blocked", i, d)
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("%d SaveFlow calls took %v while the sink was blocked", n, d)
	}
	stats := sink.Stats()
	if stats.DroppedEvents != 8 {
		t.Fatalf("dropped_events = %d, want 8", stats.DroppedEvents)
	}
	if stats.DroppedBytes <= 0 {
		t.Errorf("dropped_bytes = %d, want > 0", stats.DroppedBytes)
	}

	close(w.release)
	if err := store.SaveFlow(ctx, sinkTestFlow(st.ID, n, "send", []byte("after"))); err != nil { // seq 12
		t.Fatalf("SaveFlow after release: %v", err)
	}
	store.close(t)

	recs := w.records(t)
	gotEvents := sinkEvents(recs)
	wantEvents := []string{"stream_created", "flow_saved", "flow_saved", "gap", "flow_saved"}
	if !reflect.DeepEqual(gotEvents, wantEvents) {
		t.Fatalf("events = %v, want %v", gotEvents, wantEvents)
	}
	for i, wantSeq := range []uint64{1, 2, 3} {
		if recs[i].Seq != wantSeq {
			t.Errorf("line %d seq = %d, want %d", i, recs[i].Seq, wantSeq)
		}
	}
	gap := recs[3].Gap
	if gap == nil {
		t.Fatalf("gap line has no gap object: %+v", recs[3])
	}
	if gap.FirstSeq != 4 || gap.LastSeq != 11 || gap.Dropped != 8 {
		t.Errorf("gap = %+v, want first_seq 4, last_seq 11, dropped 8", gap)
	}
	if recs[3].Stream != nil {
		t.Errorf("gap line carries a stream: %+v", recs[3].Stream)
	}
	if recs[4].Seq != 12 {
		t.Errorf("event after gap seq = %d, want 12", recs[4].Seq)
	}
	if got := sink.Stats(); got.Emitted != 4 {
		t.Errorf("emitted = %d, want 4", got.Emitted)
	}
	if err := goleak.Find(ignore); err != nil {
		t.Errorf("goroutine leak after Close: %v", err)
	}
}

// --- Test Plan #4 ----------------------------------------------------------

// TestSink_OversizeEventWrittenMetadataOnly: an event larger than the
// queue's byte bound is written without body / raw bytes but with their
// sizes and SHA-256, instead of being dropped.
func TestSink_OversizeEventWrittenMetadataOnly(t *testing.T) {
	ctx := context.Background()
	store, sink, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true, QueueMaxBytes: 1024})

	st := sinkTestStream("sink-big-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	big := bytes.Repeat([]byte("B"), 4096)
	bigFlow := sinkTestFlow(st.ID, 0, "send", big)
	if err := store.SaveFlow(ctx, bigFlow); err != nil {
		t.Fatalf("SaveFlow(big): %v", err)
	}
	small := sinkTestFlow(st.ID, 1, "receive", []byte("small"))
	if err := store.SaveFlow(ctx, small); err != nil {
		t.Fatalf("SaveFlow(small): %v", err)
	}
	store.close(t)

	recs := readSinkRecords(t, dir)
	if got, want := sinkEvents(recs), []string{"stream_created", "flow_saved", "flow_saved"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v (oversize event must not be dropped)", got, want)
	}
	ef := recs[1].Flows[0]
	if ef.ID != bigFlow.ID {
		t.Fatalf("flow id = %s, want %s", ef.ID, bigFlow.ID)
	}
	if ef.Body != "" || ef.RawBytes != "" {
		t.Errorf("oversize flow still carries body (%d chars) / raw_bytes (%d chars)", len(ef.Body), len(ef.RawBytes))
	}
	bodySum := sha256.Sum256(big)
	rawSum := sha256.Sum256(bigFlow.RawBytes)
	if !ef.BodyOmitted || ef.BodySize == nil || *ef.BodySize != int64(len(big)) || ef.BodySHA256 != hex.EncodeToString(bodySum[:]) {
		t.Errorf("body omission = (%v, %v, %q), want (true, %d, %x)", ef.BodyOmitted, ef.BodySize, ef.BodySHA256, len(big), bodySum)
	}
	if !ef.RawBytesOmitted || ef.RawBytesSize == nil || *ef.RawBytesSize != int64(len(bigFlow.RawBytes)) || ef.RawBytesSHA256 != hex.EncodeToString(rawSum[:]) {
		t.Errorf("raw omission = (%v, %v, %q), want (true, %d, %x)", ef.RawBytesOmitted, ef.RawBytesSize, ef.RawBytesSHA256, len(bigFlow.RawBytes), rawSum)
	}
	sm := recs[2].Flows[0]
	if sm.BodyOmitted || sm.RawBytesOmitted || sm.Body != base64.StdEncoding.EncodeToString([]byte("small")) {
		t.Errorf("small flow altered: %+v", sm)
	}
	if d := sink.Stats().DroppedEvents; d != 0 {
		t.Errorf("dropped_events = %d, want 0", d)
	}
}

// TestSink_IncludeBodiesFalseOmitsPayloads: include_bodies=false writes
// metadata only, like export_flows include_bodies=false.
func TestSink_IncludeBodiesFalseOmitsPayloads(t *testing.T) {
	ctx := context.Background()
	store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: false})
	st := sinkTestStream("sink-nobody-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, sinkTestFlow(st.ID, 0, "send", []byte("secret"))); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	store.close(t)
	recs := readSinkRecords(t, dir)
	if len(recs) != 2 || len(recs[1].Flows) != 1 {
		t.Fatalf("records = %d, want 2 with one flow", len(recs))
	}
	if f := recs[1].Flows[0]; f.Body != "" || f.RawBytes != "" || f.BodyOmitted {
		t.Errorf("flow = %+v, want no body / raw_bytes and no omission marker", f)
	}
}

// TestSink_WireLevelFilter: the default semantic filter leaves overlay
// rows out without spending sequence numbers on them; "" (all) keeps them.
func TestSink_WireLevelFilter(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wireLevel string
		wantFlows int
	}{
		{"semantic", WireLevelSemantic, 1},
		{"all", "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true, WireLevel: tc.wireLevel})
			st := sinkTestStream("sink-wl-" + tc.name)
			if err := store.SaveStream(ctx, st); err != nil {
				t.Fatalf("SaveStream: %v", err)
			}
			sem := sinkTestFlow(st.ID, 0, "send", []byte("sem"))
			frame := sinkTestFlow(st.ID, 0, "send", []byte("frame"))
			frame.WireLevel = WireLevelH2Frame
			for _, f := range []*Flow{frame, sem} {
				if err := store.SaveFlow(ctx, f); err != nil {
					t.Fatalf("SaveFlow: %v", err)
				}
			}
			store.close(t)
			recs := readSinkRecords(t, dir)
			if got := len(recs) - 1; got != tc.wantFlows {
				t.Fatalf("flow lines = %d, want %d (%v)", got, tc.wantFlows, sinkEvents(recs))
			}
			for i, r := range recs {
				if r.Seq != uint64(i+1) {
					t.Errorf("line %d seq = %d, want %d (filtered rows must not leave seq holes)", i, r.Seq, i+1)
				}
			}
		})
	}
}

// --- Test Plan #5 ----------------------------------------------------------

// TestFileSink_RotatesAtMaxFileBytes: the active file is renamed once the
// next line would push it past max_file_bytes; no line spans files and
// sequence numbers continue across files.
func TestFileSink_RotatesAtMaxFileBytes(t *testing.T) {
	ctx := context.Background()
	const maxBytes = 2048
	store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true, MaxFileBytes: maxBytes})
	st := sinkTestStream("sink-rot-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	const flows = 20
	for i := 0; i < flows; i++ {
		if err := store.SaveFlow(ctx, sinkTestFlow(st.ID, i, "send", bytes.Repeat([]byte{'x'}, 200))); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
	}
	store.close(t)

	files := sinkFiles(t, dir)
	if len(files) < 3 {
		t.Fatalf("files = %v, want at least two rotated files plus flows.jsonl", files)
	}
	var seqs []uint64
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := readFileLines(t, f)
		if len(lines) == 0 && filepath.Base(f) != "flows.jsonl" {
			t.Errorf("rotated file %s is empty", f)
		}
		if info.Size() > maxBytes && len(lines) > 1 {
			t.Errorf("%s is %d bytes (> %d) with %d lines", f, info.Size(), maxBytes, len(lines))
		}
		for _, l := range lines {
			var rec ExportRecord
			if err := json.Unmarshal(l, &rec); err != nil {
				t.Fatalf("%s: split or invalid line %q: %v", f, l, err)
			}
			seqs = append(seqs, rec.Seq)
		}
	}
	if len(seqs) != flows+1 {
		t.Fatalf("lines = %d, want %d", len(seqs), flows+1)
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seq sequence across files = %v, want 1..%d", seqs, flows+1)
		}
	}
	for _, f := range files[:len(files)-1] {
		if !strings.HasPrefix(filepath.Base(f), "flows-") {
			t.Errorf("rotated file name %s does not start with flows-", f)
		}
	}
}

// TestFileSink_MaxFilesPrunesOldest: with max_files set, only that many
// rotated files are kept; the oldest go first.
func TestFileSink_MaxFilesPrunesOldest(t *testing.T) {
	ctx := context.Background()
	store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true, MaxFileBytes: 1024, MaxFiles: 2})
	st := sinkTestStream("sink-prune-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	const flows = 20
	for i := 0; i < flows; i++ {
		if err := store.SaveFlow(ctx, sinkTestFlow(st.ID, i, "send", bytes.Repeat([]byte{'y'}, 300))); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
	}
	store.close(t)
	rotated, _ := filepath.Glob(filepath.Join(dir, "flows-*.jsonl"))
	if len(rotated) != 2 {
		t.Fatalf("rotated files = %v, want exactly 2", rotated)
	}
	recs := readSinkRecords(t, dir)
	if len(recs) == 0 || recs[len(recs)-1].Seq != flows+1 {
		t.Fatalf("newest record missing after pruning: %v", sinkEvents(recs))
	}
	if recs[0].Seq == 1 {
		t.Errorf("oldest file was kept (first seq is 1)")
	}
}

// TestFileSink_ExistingActiveFileRotatedAway: a flows.jsonl left by an
// earlier run (possibly ending in a partial line after a crash) is
// renamed before the new run writes, so lines of two runs never share a
// file and a torn line never merges with a new one.
func TestFileSink_ExistingActiveFileRotatedAway(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	torn := []byte(`{"version":"1","event":"flow_saved","seq":9,"stre`)
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), torn, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, _, _ := newObservedFileStore(t, SinkConfig{Dir: dir, IncludeBodies: true})
	if err := store.SaveStream(ctx, sinkTestStream("sink-reopen-1")); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	store.close(t)

	rotated, _ := filepath.Glob(filepath.Join(dir, "flows-*.jsonl"))
	if len(rotated) != 1 {
		t.Fatalf("rotated files = %v, want the previous run's file", rotated)
	}
	if got, _ := os.ReadFile(rotated[0]); !bytes.Equal(got, torn) {
		t.Errorf("previous file content = %q, want it unchanged", got)
	}
	lines := readFileLines(t, filepath.Join(dir, "flows.jsonl"))
	if len(lines) != 1 {
		t.Fatalf("flows.jsonl lines = %d, want 1", len(lines))
	}
}

// --- Test Plan #6 ----------------------------------------------------------

// slowLineWriter delays each line, so events are still queued when Close
// starts.
type slowLineWriter struct {
	mu    sync.Mutex
	lines [][]byte
}

func (w *slowLineWriter) WriteLine(line []byte) error {
	time.Sleep(2 * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, append([]byte(nil), line...))
	return nil
}

func (w *slowLineWriter) Close() error { return nil }

// TestSink_CloseFlushesQueueBeforeDBClose: store Close delivers every
// queued event — including writes made by OnClose hooks and drained by
// the writer goroutine — while the database can still be read, and leaves
// no goroutine behind.
func TestSink_CloseFlushesQueueBeforeDBClose(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	ctx := context.Background()
	store := newSinkTestStore(t)
	w := &slowLineWriter{}
	sink := newSink(SinkConfig{Dir: "test", IncludeBodies: true}, store, w, testutil.DiscardLogger())
	store.SetCommitObserver(sink)

	st := sinkTestStream("sink-close-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	const n = 50
	for i := 0; i < n; i++ {
		if err := store.SaveFlow(ctx, sinkTestFlow(st.ID, i, "send", []byte("q"))); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
	}
	hookFlow := sinkTestFlow(st.ID, n, "receive", []byte("from-hook"))
	store.OnClose(func() {
		if err := store.SaveFlow(ctx, hookFlow); err != nil {
			t.Errorf("SaveFlow from OnClose hook: %v", err)
		}
	})
	store.close(t)

	w.mu.Lock()
	lines := len(w.lines)
	var last []byte
	if lines > 0 {
		last = w.lines[lines-1]
	}
	w.mu.Unlock()
	if lines != n+2 {
		t.Fatalf("lines after Close = %d, want %d", lines, n+2)
	}
	var rec ExportRecord
	if err := json.Unmarshal(last, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Flows) != 1 || rec.Flows[0].ID != hookFlow.ID {
		t.Errorf("last line = %s, want the OnClose hook's flow", last)
	}
	if e := sink.Stats().WriteErrors; e != 0 {
		t.Errorf("write_errors = %d, want 0 (snapshots read after db close?)", e)
	}
	if err := goleak.Find(ignore); err != nil {
		t.Errorf("goroutine leak after Close: %v", err)
	}
}

// --- Test Plan #8 ----------------------------------------------------------

// TestImportMerge_ReproducesSinkFileAndIsIdempotent: importing a sink
// file with on_conflict=merge rebuilds the stream (final snapshot) and
// all its flows; importing it a second time changes nothing.
func TestImportMerge_ReproducesSinkFileAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	src, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true})
	st := sinkTestStream("8d1b3c6e-1f9a-4f53-9a51-0f4f3b2a1c01")
	if err := src.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	send := sinkTestFlow(st.ID, 0, "send", []byte("req"))
	recv := sinkTestFlow(st.ID, 1, "receive", []byte("resp"))
	for _, f := range []*Flow{send, recv} {
		if err := src.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
	}
	if err := src.UpdateStream(ctx, st.ID, StreamUpdate{State: "complete", AppendTags: map[string]string{"b": "2"}, Duration: 30 * time.Millisecond}); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}
	wantStream, err := src.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantFlows, err := src.GetFlows(ctx, st.ID, FlowListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	src.close(t)

	var data []byte
	for _, f := range sinkFiles(t, dir) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}

	dst := newTestStore(t)
	for round := 1; round <= 2; round++ {
		res, err := ImportStreams(ctx, dst, bytes.NewReader(data), ImportOptions{OnConflict: ConflictMerge, ValidateIDs: true})
		if err != nil {
			t.Fatalf("round %d ImportStreams: %v", round, err)
		}
		if res.Errors != 0 {
			t.Fatalf("round %d import errors: %+v", round, res.ErrorDetails)
		}
		gotStream, err := dst.GetStream(ctx, st.ID)
		if err != nil {
			t.Fatalf("round %d GetStream: %v", round, err)
		}
		if got, want := jsonOf(t, streamToExport(gotStream)), jsonOf(t, streamToExport(wantStream)); got != want {
			t.Errorf("round %d stream =\n%s\nwant\n%s", round, got, want)
		}
		gotFlows, err := dst.GetFlows(ctx, st.ID, FlowListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := jsonOf(t, flowsToExport(gotFlows, true)), jsonOf(t, flowsToExport(wantFlows, true)); got != want {
			t.Errorf("round %d flows =\n%s\nwant\n%s", round, got, want)
		}
	}
}

// TestImportMerge_RejectsForeignFlowStreamID: a merge line whose flow
// names a different stream than the line's stream is an error, not a
// silent insert into another stream.
func TestImportMerge_RejectsForeignFlowStreamID(t *testing.T) {
	ctx := context.Background()
	other := "6f0e2a7b-3c1d-4e5f-8a9b-0c1d2e3f4a5b"
	line := `{"version":"1","event":"flow_saved","seq":2,"stream":{"id":"1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d","conn_id":"c","protocol":"http","state":"active","timestamp":"2026-11-01T12:00:00Z","duration_ms":0},` +
		`"flows":[{"id":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","stream_id":"` + other + `","sequence":0,"direction":"send","timestamp":"2026-11-01T12:00:00Z","body_truncated":false}]}` + "\n"
	dst := newTestStore(t)
	res, err := ImportStreams(ctx, dst, strings.NewReader(line), ImportOptions{OnConflict: ConflictMerge, ValidateIDs: true})
	if err != nil {
		t.Fatalf("ImportStreams: %v", err)
	}
	if res.Errors != 1 {
		t.Fatalf("errors = %d, want 1 (flow stream_id mismatch)", res.Errors)
	}
	if fl, _ := dst.GetFlows(ctx, other, FlowListOptions{}); len(fl) != 0 {
		t.Errorf("flow was inserted under the foreign stream %s", other)
	}
}

// TestImport_SkipsGapLines: gap lines carry no stream; every policy skips
// them without counting an error.
func TestImport_SkipsGapLines(t *testing.T) {
	ctx := context.Background()
	gap := `{"version":"1","event":"gap","run_id":"r","emitted_at":"2026-11-01T12:00:00Z","flows":null,"gap":{"dropped":3,"dropped_bytes":10,"first_seq":4,"last_seq":6}}` + "\n"
	for _, p := range []ConflictPolicy{ConflictSkip, ConflictReplace, ConflictMerge} {
		res, err := ImportStreams(ctx, newTestStore(t), strings.NewReader(gap), ImportOptions{OnConflict: p})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if res.Errors != 0 || res.Imported != 0 {
			t.Errorf("%s: result = %+v, want nothing imported and no error", p, res)
		}
	}
}

// --- Test Plan #9 ----------------------------------------------------------

// TestSink_ImportedRowsNotEmitted: rows written by ImportStreams are not
// streamed to the sink; live writes on the same store still are.
func TestSink_ImportedRowsNotEmitted(t *testing.T) {
	ctx := context.Background()

	// Build an export from an unobserved store.
	srcStore := newTestStore(t)
	makeTestSession(t, srcStore, "imp-1", "http", "https://example.com/a", sinkTestTS, []byte("body"))
	var buf bytes.Buffer
	if _, err := ExportStreams(ctx, srcStore, &buf, ExportOptions{IncludeBodies: true}); err != nil {
		t.Fatalf("ExportStreams: %v", err)
	}
	exported := buf.Bytes()

	store, _, dir := newObservedFileStore(t, SinkConfig{IncludeBodies: true})
	for _, p := range []ConflictPolicy{ConflictSkip, ConflictReplace, ConflictMerge} {
		if _, err := ImportStreams(ctx, store, bytes.NewReader(exported), ImportOptions{OnConflict: p}); err != nil {
			t.Fatalf("ImportStreams(%s): %v", p, err)
		}
	}
	live := sinkTestStream("live-after-import")
	if err := store.SaveStream(ctx, live); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	store.close(t)

	recs := readSinkRecords(t, dir)
	if len(recs) != 1 || recs[0].Stream == nil || recs[0].Stream.ID != live.ID {
		ids := make([]string, 0, len(recs))
		for _, r := range recs {
			if r.Stream != nil {
				ids = append(ids, r.Event+":"+r.Stream.ID)
			}
		}
		t.Fatalf("sink lines = %v, want only the live stream %s", ids, live.ID)
	}
}

// TestSQLiteStore_FlowSinkStats reports the attached sink's counters.
func TestSQLiteStore_FlowSinkStats(t *testing.T) {
	store := newSinkTestStore(t)
	if _, ok := store.FlowSinkStats(); ok {
		t.Fatalf("FlowSinkStats ok without a sink")
	}
	dir := filepath.Join(t.TempDir(), "sink")
	sink, err := NewFileSink(SinkConfig{Dir: dir, IncludeBodies: true}, store, testutil.DiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	store.SetCommitObserver(sink)
	if err := store.SaveStream(context.Background(), sinkTestStream("stats-1")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		stats, ok := store.FlowSinkStats()
		if !ok {
			t.Fatalf("FlowSinkStats not ok with a sink attached")
		}
		if stats.Emitted == 1 {
			if stats.Dir != dir || stats.RunID == "" {
				t.Errorf("stats = %+v, want dir %s and a run id", stats, dir)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("emitted = %d, want 1", stats.Emitted)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
