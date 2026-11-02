package flow

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestSink_IncludeBodiesFalseQueueDoesNotRetainBodies: with
// include_bodies=false a queued flow_saved event is not charged against
// queue_max_bytes, so it must not keep the recorded body / raw bytes
// alive either - otherwise queue_max_events large bodies are pinned
// while the writer is slow. The caller's Flow is left untouched.
func TestSink_IncludeBodiesFalseQueueDoesNotRetainBodies(t *testing.T) {
	ctx := context.Background()
	store := newSinkTestStore(t)
	st := sinkTestStream("sink-nobody-retain-1")
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	w := newBlockingLineWriter()
	sink := newSink(SinkConfig{Dir: "test", IncludeBodies: false, QueueMaxEvents: 8}, store, w, testutil.DiscardLogger())
	t.Cleanup(func() { _ = sink.Close() })

	sink.StreamCommitted(st.ID, true) // taken by the worker, which blocks
	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("sink worker never reached the writer")
	}

	body := bytes.Repeat([]byte("B"), 1<<20)
	f := sinkTestFlow(st.ID, 0, "send", body)
	f.ID = "flow-nobody-retain-1"
	rawLen := len(f.RawBytes)
	sink.FlowCommitted(f)

	var it sinkItem
	select {
	case it = <-sink.queue:
	case <-time.After(5 * time.Second):
		t.Fatalf("flow_saved event was not queued")
	}
	close(w.release)

	if it.flow == nil {
		t.Fatalf("queued item has no flow")
	}
	if it.flow.Body != nil || it.flow.RawBytes != nil {
		t.Errorf("queued item retains body (%d bytes) / raw bytes (%d bytes) with include_bodies=false",
			len(it.flow.Body), len(it.flow.RawBytes))
	}
	if it.flow.ID != f.ID || it.flow.StreamID != f.StreamID {
		t.Errorf("queued flow = (%s, %s), want (%s, %s)", it.flow.ID, it.flow.StreamID, f.ID, f.StreamID)
	}
	if len(f.Body) != len(body) || len(f.RawBytes) != rawLen {
		t.Errorf("caller's Flow was modified: body %d / raw %d bytes, want %d / %d",
			len(f.Body), len(f.RawBytes), len(body), rawLen)
	}
}

// TestFileSink_ShortWriteLeavesNoTornLine: a write that fails part-way
// (e.g. ENOSPC) must not leave a fragment the next line is appended to.
func TestFileSink_ShortWriteLeavesNoTornLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	w, err := openFileSinkWriter(dir, DefaultSinkMaxFileBytes, 0, false)
	if err != nil {
		t.Fatalf("openFileSinkWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.WriteLine([]byte(`{"n":1}`)); err != nil {
		t.Fatalf("WriteLine 1: %v", err)
	}
	w.writeFile = func(f *os.File, b []byte) (int, error) {
		n, _ := f.Write(b[:len(b)/2])
		return n, syscall.ENOSPC
	}
	if err := w.WriteLine([]byte(`{"n":2,"pad":"xxxxxxxxxxxxxxxx"}`)); err == nil {
		t.Fatalf("WriteLine 2: want an error from the short write")
	}
	w.writeFile = nil
	if err := w.WriteLine([]byte(`{"n":3}`)); err != nil {
		t.Fatalf("WriteLine 3: %v", err)
	}

	var all []byte
	for _, f := range sinkFiles(t, dir) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	if want := "{\"n\":1}\n{\"n\":3}\n"; string(all) != want {
		t.Errorf("sink content = %q, want %q", all, want)
	}
	if fi, err := os.Stat(filepath.Join(dir, sinkActiveFileName)); err == nil && fi.Size() != w.size {
		t.Errorf("tracked size = %d, file size = %d", w.size, fi.Size())
	}
}

// TestImport_RawBytesOmittedMarksTruncated: a sink line that left only
// oversize raw bytes out imports with the flow marked body_truncated,
// like an omitted body.
func TestImport_RawBytesOmittedMarksTruncated(t *testing.T) {
	size := int64(4096)
	f, err := exportToFlow(&ExportFlow{
		ID:              "f1",
		StreamID:        "s1",
		Direction:       "send",
		Timestamp:       sinkTestTS.Format(time.RFC3339Nano),
		RawBytesOmitted: true,
		RawBytesSize:    &size,
		RawBytesSHA256:  "00",
	})
	if err != nil {
		t.Fatalf("exportToFlow: %v", err)
	}
	if !f.BodyTruncated {
		t.Errorf("BodyTruncated = false, want true for an omitted raw_bytes payload")
	}
}

// TestFileSink_RefusesSymlinkedActiveFile: a flows.jsonl planted as a
// symlink must not redirect the recording to the link target.
func TestFileSink_RefusesSymlinkedActiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "sink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, sinkActiveFileName)); err != nil {
		t.Fatal(err)
	}
	w, err := openFileSinkWriter(dir, DefaultSinkMaxFileBytes, 0, false)
	if err == nil {
		_ = w.WriteLine([]byte(`{"n":1}`))
		_ = w.Close()
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Errorf("sink wrote %q through the symlink to %s", b, target)
	}
}

// TestFileSink_TightensPreexistingModes: a pre-existing flows.jsonl with
// a looser mode is made 0600, and a group/other-accessible directory is
// reported.
func TestFileSink_TightensPreexistingModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := filepath.Join(t.TempDir(), "sink")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(dir, sinkActiveFileName)
	if err := os.WriteFile(active, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(active, 0o644); err != nil {
		t.Fatal(err)
	}
	capture, logger := testutil.NewCaptureLogger()
	sink, err := NewFileSink(SinkConfig{Dir: dir}, newSinkTestStore(t), logger)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer func() { _ = sink.Close() }()
	fi, err := os.Stat(active)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("flows.jsonl mode = %o, want 600", got)
	}
	if !capture.Contains("flow sink directory") {
		t.Errorf("no warning about the group/other-accessible directory; log = %q", capture.Output())
	}
}
