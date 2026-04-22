package bodybuf_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// TestWriteBytesRoundTrip covers requirements (1) and (2): Write →
// Bytes round-trip in memory mode and file mode. Table-driven.
func TestWriteBytesRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fileMod bool
		initial []byte
		writes  [][]byte
	}{
		{
			name:    "memory empty seed then writes",
			fileMod: false,
			initial: nil,
			writes:  [][]byte{[]byte("hello "), []byte("world")},
		},
		{
			name:    "memory seeded then appended",
			fileMod: false,
			initial: []byte("seed:"),
			writes:  [][]byte{[]byte("abc"), []byte("def")},
		},
		{
			name:    "file mode single write",
			fileMod: true,
			writes:  [][]byte{[]byte("single-chunk body")},
		},
		{
			name:    "file mode multiple writes",
			fileMod: true,
			writes:  [][]byte{[]byte("alpha "), []byte("beta "), []byte("gamma")},
		},
		{
			name:    "file mode empty body",
			fileMod: true,
			writes:  nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf *bodybuf.BodyBuffer
			var want []byte
			if tc.fileMod {
				var err error
				buf, err = bodybuf.NewFile(t.TempDir(), "yorishiro-body", 1<<20)
				if err != nil {
					t.Fatalf("NewFile: %v", err)
				}
			} else {
				buf = bodybuf.NewMemory(tc.initial)
				want = append(want, tc.initial...)
			}
			defer func() {
				if err := buf.Release(); err != nil {
					t.Fatalf("Release: %v", err)
				}
			}()

			for i, w := range tc.writes {
				n, err := buf.Write(w)
				if err != nil {
					t.Fatalf("Write[%d]: %v", i, err)
				}
				if n != len(w) {
					t.Fatalf("Write[%d] n=%d want %d", i, n, len(w))
				}
				want = append(want, w...)
			}

			got, err := buf.Bytes(context.Background())
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Bytes mismatch: got %q want %q", got, want)
			}
			if got, want := buf.Len(), int64(len(want)); got != want {
				t.Fatalf("Len=%d want %d", got, want)
			}
		})
	}
}

// TestReaderStreaming covers requirement (3): Reader consumes full
// contents in both modes.
func TestReaderStreaming(t *testing.T) {
	t.Parallel()

	payload := []byte("the quick brown fox jumps over the lazy dog")

	tests := []struct {
		name    string
		fileMod bool
	}{
		{name: "memory", fileMod: false},
		{name: "file", fileMod: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf *bodybuf.BodyBuffer
			if tc.fileMod {
				var err error
				buf, err = bodybuf.NewFile(t.TempDir(), "yorishiro-body", 1<<20)
				if err != nil {
					t.Fatalf("NewFile: %v", err)
				}
				if _, err := buf.Write(payload); err != nil {
					t.Fatalf("Write: %v", err)
				}
			} else {
				buf = bodybuf.NewMemory(payload)
			}
			t.Cleanup(func() { _ = buf.Release() })

			rc, err := buf.Reader()
			if err != nil {
				t.Fatalf("Reader: %v", err)
			}
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if cerr := rc.Close(); cerr != nil {
				t.Fatalf("Close: %v", cerr)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %q want %q", got, payload)
			}
		})
	}
}

// TestRetainReleaseRefcount covers requirements (4) and (5): 3× Retain
// then 4 Releases total (the constructor's 1 + 3 Retains) → refcount
// hits zero → temp file removed.
func TestRetainReleaseRefcount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	buf, err := bodybuf.NewFile(dir, "yorishiro-body", 1<<20)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if _, err := buf.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Capture the path via a directory-scan trick: the temp file is the
	// only file in dir that has our prefix.
	path := findTempFile(t, dir, "yorishiro-body")

	// 3 Retains → refCount becomes 4 (1 from constructor + 3).
	buf.Retain()
	buf.Retain()
	buf.Retain()

	// First 3 Releases should be non-terminal.
	for i := 0; i < 3; i++ {
		if err := buf.Release(); err != nil {
			t.Fatalf("non-terminal Release[%d]: %v", i, err)
		}
		// File must still exist while refcount > 0.
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("temp file vanished before final Release: %v", err)
		}
	}

	// Final Release → cleanup.
	if err := buf.Release(); err != nil {
		t.Fatalf("final Release: %v", err)
	}

	// File must be gone.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temp file still present after final Release: err=%v", err)
	}
}

// TestMaxSizeExceeded covers requirement (6): maxSize exceeded on
// Write returns ErrMaxSizeExceeded, the temp file is removed, and the
// buffer is dead (subsequent Release returns nil, subsequent Write
// returns a write-after-release error).
func TestMaxSizeExceeded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const maxSize = 10
	buf, err := bodybuf.NewFile(dir, "yorishiro-body", maxSize)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	path := findTempFile(t, dir, "yorishiro-body")

	// First 10 bytes: OK.
	if _, err := buf.Write([]byte("0123456789")); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	// 11th byte: exceeds.
	n, werr := buf.Write([]byte("X"))
	if !errors.Is(werr, bodybuf.ErrMaxSizeExceeded) {
		t.Fatalf("want ErrMaxSizeExceeded, got n=%d err=%v", n, werr)
	}
	if n != 0 {
		t.Fatalf("want n=0 on ErrMaxSizeExceeded, got %d", n)
	}

	// Temp file must be gone immediately.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temp file still present after ErrMaxSizeExceeded: err=%v", err)
	}

	// Subsequent Write: write-after-release error (not panic).
	if _, err := buf.Write([]byte("Y")); err == nil || !strings.Contains(err.Error(), "write after release") {
		t.Fatalf("want write-after-release error, got %v", err)
	}

	// Subsequent Release: returns nil.
	if err := buf.Release(); err != nil {
		t.Fatalf("Release after teardown: %v", err)
	}
}

// TestPromoteToFile covers requirement (7): NewMemory → PromoteToFile
// flips IsFileBacked, Bytes returns the original data, Reader returns
// the original data.
func TestPromoteToFile(t *testing.T) {
	t.Parallel()

	payload := []byte("in-memory-seed-data")
	buf := bodybuf.NewMemory(payload)
	t.Cleanup(func() { _ = buf.Release() })

	if buf.IsFileBacked() {
		t.Fatalf("fresh memory buffer must not be file-backed")
	}

	dir := t.TempDir()
	if err := buf.PromoteToFile(dir, "yorishiro-body", 1<<20); err != nil {
		t.Fatalf("PromoteToFile: %v", err)
	}
	if !buf.IsFileBacked() {
		t.Fatalf("buffer not file-backed after PromoteToFile")
	}

	got, err := buf.Bytes(context.Background())
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Bytes mismatch: got %q want %q", got, payload)
	}

	rc, err := buf.Reader()
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	via, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = rc.Close()
	if !bytes.Equal(via, payload) {
		t.Fatalf("Reader payload mismatch: got %q want %q", via, payload)
	}

	// Further writes should land in the file.
	extra := []byte("-extra")
	if _, err := buf.Write(extra); err != nil {
		t.Fatalf("Write after promote: %v", err)
	}
	got, err = buf.Bytes(context.Background())
	if err != nil {
		t.Fatalf("Bytes after append: %v", err)
	}
	want := append(append([]byte(nil), payload...), extra...)
	if !bytes.Equal(got, want) {
		t.Fatalf("post-append Bytes mismatch: got %q want %q", got, want)
	}
}

// TestPromoteToFileFailure covers requirement (8): PromoteToFile to a
// nonexistent directory → error, IsFileBacked stays false, data still
// readable via Bytes.
func TestPromoteToFileFailure(t *testing.T) {
	t.Parallel()

	payload := []byte("preserved-across-promote-failure")
	buf := bodybuf.NewMemory(payload)
	t.Cleanup(func() { _ = buf.Release() })

	// A path that is guaranteed not to exist: a subpath of t.TempDir
	// that we do not create.
	missing := filepath.Join(t.TempDir(), "does-not-exist-dir")

	if err := buf.PromoteToFile(missing, "yorishiro-body", 1<<20); err == nil {
		t.Fatalf("want PromoteToFile error on missing dir, got nil")
	}
	if buf.IsFileBacked() {
		t.Fatalf("IsFileBacked must remain false after failed PromoteToFile")
	}

	// Data must be intact.
	got, err := buf.Bytes(context.Background())
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Bytes mismatch after failed promote: got %q want %q", got, payload)
	}
}

// TestConcurrentRetainRelease covers requirement (9): 100 goroutines
// ×× Retain+Release under -race; final Release closes cleanly.
func TestConcurrentRetainRelease(t *testing.T) {
	t.Parallel()

	const goroutines = 100
	dir := t.TempDir()
	buf, err := bodybuf.NewFile(dir, "yorishiro-body", 1<<20)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if _, err := buf.Write([]byte("concurrent-payload")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	path := findTempFile(t, dir, "yorishiro-body")

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			buf.Retain()
			if err := buf.Release(); err != nil {
				t.Errorf("worker Release: %v", err)
			}
		}()
	}
	wg.Wait()

	// refCount should still be 1 (the constructor's). One more Release
	// closes the buffer.
	if err := buf.Release(); err != nil {
		t.Fatalf("final Release: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temp file not removed after final Release: err=%v", err)
	}
}

// TestBytesContextCancel covers requirement (10): ctx cancel mid-Bytes
// in file mode returns ctx.Err(). Uses a multi-MiB body and cancels
// the ctx after a short delay; the Bytes loop checks ctx.Err() at the
// top of each 32 KiB chunk iteration.
func TestBytesContextCancel(t *testing.T) {
	t.Parallel()

	// 8 MiB: large enough that a reasonable sleep interleaves at least
	// one chunk read before ctx fires.
	const payloadSize = 8 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	buf, err := bodybuf.NewFile(t.TempDir(), "yorishiro-body", int64(payloadSize+1))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	t.Cleanup(func() { _ = buf.Release() })
	if _, err := buf.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel almost immediately, before Bytes has a chance to read
	// anything: since the loop checks ctx.Err() at the top of each
	// iteration, the very first check inside the loop will bail.
	cancel()

	if _, err := buf.Bytes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestBytesContextDeadline covers a variant of requirement (10) where
// the ctx fires via deadline while Bytes is mid-loop. This exercises
// the in-loop ctx.Err() check specifically (rather than the entry
// check).
func TestBytesContextDeadline(t *testing.T) {
	t.Parallel()

	const payloadSize = 8 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	buf, err := bodybuf.NewFile(t.TempDir(), "yorishiro-body", int64(payloadSize+1))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	t.Cleanup(func() { _ = buf.Release() })
	if _, err := buf.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	// Sleep to guarantee the deadline has passed before we enter Bytes.
	time.Sleep(5 * time.Millisecond)

	_, err = buf.Bytes(ctx)
	if err == nil {
		t.Fatalf("want ctx error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("want ctx error, got %v", err)
	}
}

// TestReaderCloseDoesNotAffectRefcount covers requirement (11):
// closing a returned ReadCloser leaves the BodyBuffer alive.
func TestReaderCloseDoesNotAffectRefcount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fileMod bool
	}{
		{name: "memory", fileMod: false},
		{name: "file", fileMod: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			payload := []byte("alive-after-reader-close")
			var buf *bodybuf.BodyBuffer
			if tc.fileMod {
				var err error
				buf, err = bodybuf.NewFile(t.TempDir(), "yorishiro-body", 1<<20)
				if err != nil {
					t.Fatalf("NewFile: %v", err)
				}
				if _, err := buf.Write(payload); err != nil {
					t.Fatalf("Write: %v", err)
				}
			} else {
				buf = bodybuf.NewMemory(payload)
			}
			t.Cleanup(func() { _ = buf.Release() })

			rc, err := buf.Reader()
			if err != nil {
				t.Fatalf("Reader: %v", err)
			}
			if _, err := io.ReadAll(rc); err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if err := rc.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// BodyBuffer must still be usable.
			if got := buf.Len(); got != int64(len(payload)) {
				t.Fatalf("Len after Reader Close: got %d want %d", got, len(payload))
			}
			got, err := buf.Bytes(context.Background())
			if err != nil {
				t.Fatalf("Bytes after Reader Close: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("Bytes mismatch: got %q want %q", got, payload)
			}
		})
	}
}

// TestDoubleReleasePanics covers requirement (12): a Release on an
// already-zero refcount panics with the documented message.
func TestDoubleReleasePanics(t *testing.T) {
	t.Parallel()

	buf := bodybuf.NewMemory([]byte("x"))
	// First Release drops refcount 1 → 0 and performs cleanup.
	if err := buf.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("want panic from double Release, got nothing")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("want string panic, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "release called on zero refcount") {
			t.Fatalf("unexpected panic message: %q", msg)
		}
	}()
	// Second Release: refcount would go to -1 → panic.
	_ = buf.Release()
}

// TestWriteAfterReleaseErrors covers requirement (13): Write after
// Release returns an error (not a panic).
func TestWriteAfterReleaseErrors(t *testing.T) {
	t.Parallel()

	buf := bodybuf.NewMemory(nil)
	if err := buf.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	n, err := buf.Write([]byte("late"))
	if err == nil {
		t.Fatalf("want error from Write after Release, got nil")
	}
	if !strings.Contains(err.Error(), "write after release") {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("want n=0, got %d", n)
	}
}

// TestTempFilePermissions verifies the 0o600 mode required by the
// design. Sanity check sibling to internal/mcp/manage_tool.go:366.
func TestTempFilePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	buf, err := bodybuf.NewFile(dir, "yorishiro-body", 1<<20)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	t.Cleanup(func() { _ = buf.Release() })

	path := findTempFile(t, dir, "yorishiro-body")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("temp file mode = %o, want 0600", mode)
	}
}

// findTempFile returns the absolute path of the single file in dir
// whose name starts with prefix. Used by tests to assert existence /
// absence without threading the path back through the API.
func findTempFile(t *testing.T, dir, prefix string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var found string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			if found != "" {
				t.Fatalf("multiple temp files in %s: %s and %s", dir, found, e.Name())
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	if found == "" {
		t.Fatalf("no temp file with prefix %q in %s", prefix, dir)
	}
	return found
}
