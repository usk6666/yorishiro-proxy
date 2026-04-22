package bodybuf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// ErrMaxSizeExceeded is returned from Write when an accepted write would
// push the total buffered size above the buffer's maxSize. Callers at
// the Channel boundary may wrap this into a layer-specific error type
// (e.g. layer.StreamError); this package does not perform that wrap to
// avoid a layering inversion.
var ErrMaxSizeExceeded = errors.New("bodybuf: body exceeds max size")

// readChunkSize is the size of each read issued by Bytes when the
// buffer is file-backed. 32 KiB is large enough to amortize syscall
// overhead and small enough to let ctx cancellation interrupt a large
// read within a bounded amount of time.
const readChunkSize = 32 * 1024

// BodyBuffer is a reference-counted accessor over either an in-memory
// []byte or a temp-file-backed scratch store for a single message
// body. See package doc for full semantics.
type BodyBuffer struct {
	mu       sync.Mutex   // guards bytes, file, path, size, released
	refCount atomic.Int32 // refcount; zero-transition triggers cleanup

	bytes    []byte   // memory mode storage; nil in file mode
	file     *os.File // file mode write handle; closed by cleanup
	path     string   // file mode path; empty in memory mode
	size     int64    // total bytes successfully written
	maxSize  int64    // cap on size; 0 means unlimited
	released bool     // true after final Release or error-path cleanup
}

// NewMemory creates an in-memory BodyBuffer seeded with a copy of b.
// The returned buffer has refCount=1; the caller is the first owner.
// maxSize is left at the package's "unlimited" sentinel (0) because
// NewMemory is intended for callers that already hold the full payload
// in memory; size is pre-validated by the caller.
func NewMemory(b []byte) *BodyBuffer {
	buf := &BodyBuffer{
		bytes: append([]byte(nil), b...),
		size:  int64(len(b)),
	}
	buf.refCount.Store(1)
	return buf
}

// NewFile creates a file-backed BodyBuffer with an empty temp file in
// dir (os.CreateTemp dir semantics: empty string means os.TempDir) and
// the given prefix. maxSize > 0 caps the total size of subsequent
// writes; maxSize == 0 means "unlimited".
//
// The returned buffer has refCount=1; the caller is the first owner.
// The underlying temp file is chmod'd to 0o600 explicitly so that the
// default umask does not leak read access to other users.
func NewFile(dir, prefix string, maxSize int64) (*BodyBuffer, error) {
	tmp, err := os.CreateTemp(dir, prefix+"-*")
	if err != nil {
		return nil, fmt.Errorf("bodybuf: create temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		// Best-effort cleanup: close and remove the partially created file.
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("bodybuf: chmod temp file: %w", err)
	}
	buf := &BodyBuffer{
		file:    tmp,
		path:    tmp.Name(),
		maxSize: maxSize,
	}
	buf.refCount.Store(1)
	return buf, nil
}

// Write appends p to the buffer. Write is single-writer-by-contract:
// the Layer assembler that owns the buffer during assembly is the only
// goroutine permitted to call Write or PromoteToFile.
//
// If the write would cause the total size to exceed maxSize, Write
// returns (0, ErrMaxSizeExceeded) without performing a partial write.
// On that failure the buffer is marked dead: its temp file is closed
// and removed, subsequent Write calls return a "write after release"
// error, and subsequent Release calls return nil.
//
// Write after Release returns an error rather than panicking because
// this is data-path code where the writer may race with a
// caller-initiated cleanup.
func (b *BodyBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.released {
		return 0, errors.New("bodybuf: write after release")
	}

	if b.maxSize > 0 && b.size+int64(len(p)) > b.maxSize {
		// Mark dead and tear down any file state before returning.
		b.teardownLocked()
		return 0, ErrMaxSizeExceeded
	}

	if b.file != nil {
		n, err := b.file.Write(p)
		b.size += int64(n)
		if err != nil {
			return n, fmt.Errorf("bodybuf: write: %w", err)
		}
		return n, nil
	}

	b.bytes = append(b.bytes, p...)
	b.size += int64(len(p))
	return len(p), nil
}

// PromoteToFile switches an in-memory buffer to file-backed storage.
// Any already-buffered bytes are flushed to the newly created temp
// file, and future writes target that file. PromoteToFile is a no-op
// if the buffer is already file-backed.
//
// If CreateTemp fails, the buffer remains in bytes mode and the
// existing in-memory data is preserved. If flushing the in-memory
// bytes to the new temp file fails mid-write, the partial temp file is
// closed and removed, and the buffer likewise remains in bytes mode.
//
// Like Write, PromoteToFile is single-writer-by-contract.
func (b *BodyBuffer) PromoteToFile(dir, prefix string, maxSize int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.released {
		return errors.New("bodybuf: promote after release")
	}
	if b.file != nil {
		// Already file-backed; nothing to do. Do not re-apply maxSize;
		// the caller that created the file mode owns that invariant.
		return nil
	}

	tmp, err := os.CreateTemp(dir, prefix+"-*")
	if err != nil {
		return fmt.Errorf("bodybuf: promote: create temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("bodybuf: promote: chmod temp file: %w", err)
	}

	if len(b.bytes) > 0 {
		if _, werr := tmp.Write(b.bytes); werr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("bodybuf: promote: flush in-memory bytes: %w", werr)
		}
	}

	// Commit the switch. Keep size unchanged (same bytes, different storage).
	b.file = tmp
	b.path = tmp.Name()
	b.bytes = nil
	b.maxSize = maxSize
	return nil
}

// Len returns the number of bytes that have been successfully written
// to the buffer. Under the single-writer contract, the returned value
// equals the final body length once the pipeline begins reading.
func (b *BodyBuffer) Len() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}

// IsFileBacked reports whether the buffer currently stores its data in
// a temp file. The transition memory → file is one-way.
func (b *BodyBuffer) IsFileBacked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.file != nil
}

// Bytes returns a copy of the full body. The returned slice is safe for
// the caller to mutate; modifying it does not affect subsequent
// Bytes/Reader calls.
//
// For file-backed buffers, Bytes performs a fresh os.Open of the temp
// file and reads it in 32 KiB chunks, honoring ctx cancellation between
// chunks.
func (b *BodyBuffer) Bytes(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.released {
		return nil, errors.New("bodybuf: bytes after release")
	}

	if b.file == nil {
		// Defensive copy so callers cannot mutate our internal slice.
		return append([]byte(nil), b.bytes...), nil
	}

	// File mode: fresh open so our read offset is independent of the
	// append-only write handle (b.file).
	f, err := os.Open(b.path)
	if err != nil {
		return nil, fmt.Errorf("bodybuf: open for read: %w", err)
	}
	defer f.Close()

	// Cap via io.LimitReader as defense-in-depth. Write already enforces
	// the cap, but an unexpected writer or FS surprise should not let
	// Bytes return unbounded data.
	var lr io.Reader = f
	if b.maxSize > 0 {
		lr = io.LimitReader(f, b.maxSize+1)
	}

	out := make([]byte, 0, b.size)
	chunk := make([]byte, readChunkSize)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, rerr := lr.Read(chunk)
		if n > 0 {
			out = append(out, chunk[:n]...)
			if b.maxSize > 0 && int64(len(out)) > b.maxSize {
				return nil, ErrMaxSizeExceeded
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, fmt.Errorf("bodybuf: read: %w", rerr)
		}
	}
	return out, nil
}

// Reader returns an io.ReadCloser over the body. Callers are expected
// to Close the returned reader when done; closing only releases the
// caller's file descriptor (in file mode), it does NOT affect the
// BodyBuffer's refcount.
//
// Multiple concurrent Readers are permitted; each call performs a fresh
// os.Open in file mode, so readers have independent seek offsets. In
// memory mode the returned reader wraps a bytes.Reader over the
// internal slice; callers must treat the contents as read-only.
func (b *BodyBuffer) Reader() (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.released {
		return nil, errors.New("bodybuf: reader after release")
	}

	if b.file == nil {
		return io.NopCloser(bytes.NewReader(b.bytes)), nil
	}

	f, err := os.Open(b.path)
	if err != nil {
		return nil, fmt.Errorf("bodybuf: open for read: %w", err)
	}
	return f, nil
}

// Retain atomically increments the refcount. It is safe to call
// concurrently with Release and readers, but not with Write or
// PromoteToFile.
func (b *BodyBuffer) Retain() {
	b.refCount.Add(1)
}

// Release atomically decrements the refcount. When the refcount
// transitions to zero, Release closes the write handle (if any) and
// removes the temp file (if any). Release is idempotent only in the
// sense that it is permitted to call exactly as many times as Retain
// plus the one owned by the constructor; a decrement below zero
// panics, matching sync.WaitGroup.Done().
//
// If an error-path teardown (e.g. maxSize exceeded) already removed
// the backing file, subsequent Release calls return nil.
//
// The returned error reflects only the terminal os.Remove failure.
// Non-terminal (non-zero-transition) releases always return nil.
func (b *BodyBuffer) Release() error {
	n := b.refCount.Add(-1)
	if n < 0 {
		panic("bodybuf: release called on zero refcount")
	}
	if n > 0 {
		return nil
	}

	// Final release: cleanup under the mutex.
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.released {
		// Error-path teardown already ran (e.g. ErrMaxSizeExceeded on
		// Write). Nothing to do.
		return nil
	}

	return b.teardownLocked()
}

// teardownLocked closes the write handle, removes the temp file, and
// marks the buffer dead. It returns the error from os.Remove (if any)
// so that the caller (Release) can surface it. Called with b.mu held.
//
// teardownLocked is idempotent: a buffer can be released (via
// ErrMaxSizeExceeded) at Write time; a later Release then short-
// circuits because b.released is already true.
func (b *BodyBuffer) teardownLocked() error {
	if b.released {
		return nil
	}
	b.released = true

	var closeErr error
	if b.file != nil {
		closeErr = b.file.Close()
		b.file = nil
	}

	var removeErr error
	if b.path != "" {
		if rerr := os.Remove(b.path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			removeErr = rerr
		}
		b.path = ""
	}

	// Drop the in-memory slice so that GC can reclaim it promptly.
	b.bytes = nil

	if removeErr != nil {
		return fmt.Errorf("bodybuf: remove temp file: %w", removeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("bodybuf: close temp file: %w", closeErr)
	}
	return nil
}
