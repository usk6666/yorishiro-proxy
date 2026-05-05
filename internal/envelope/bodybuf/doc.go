// Package bodybuf provides BodyBuffer, a reference-counted accessor that
// unifies in-memory []byte storage and temporary-file-backed storage for
// message bodies assembled by Layer implementations.
//
// BodyBuffer lives beneath the envelope layer so that HTTPMessage (and
// other Layer-specific message types) can embed it without creating an
// import cycle. The package deliberately avoids importing
// internal/envelope and internal/layer; any error-to-layer bridging
// (e.g. wrapping ErrMaxSizeExceeded into layer.StreamError) is performed
// by the Channel boundary that consumes BodyBuffer.
//
// # Memory vs file mode
//
// A BodyBuffer starts in one of two modes:
//
//   - NewMemory([]byte) creates a buffer that stores the body in a []byte.
//   - NewFile(dir, prefix, maxSize) creates a buffer whose writes are
//     streamed to a freshly created temp file (mode 0o600).
//
// An in-memory buffer may be promoted to file-backed storage via
// PromoteToFile. The transition is one-way: once file-backed, a
// BodyBuffer never demotes back to []byte. PromoteToFile is provided so
// that a Layer assembler (e.g. HTTP/2 DATA-frame aggregation) can spill
// to disk when it observes that the accumulated body has exceeded a
// threshold set by config.BodySpillThreshold.
//
// # Refcount semantics
//
// Construction returns a buffer with refCount=1. The constructor is the
// first owner. Retain atomically increments the refcount. Release
// atomically decrements it; the final Release (refCount reaches zero)
// performs cleanup: the underlying file (if any) is closed and removed.
// A subsequent Release on an already-zero refcount panics, matching the
// convention used by sync.WaitGroup.Done(): this indicates a
// programming error, not attacker input.
//
// # Single-writer contract
//
// Write and PromoteToFile are intended to be called from a single
// goroutine — the Layer assembler that owns the BodyBuffer during
// assembly. After assembly completes, the assembler hands the buffer
// off to the pipeline/rules path via a mechanism that provides a
// happens-before edge (e.g. a channel send). From that point onward,
// readers (Bytes, Reader, Retain, Release) may run concurrently with
// each other but must not overlap with further Write or PromoteToFile
// calls.
//
// Internally, an atomic.Int32 tracks the refcount so that Retain never
// requires the mutex. A sync.Mutex guards the mutable storage fields
// (bytes, file handle, path, size, released flag) so that readers can
// run concurrently with Release's zero-transition cleanup without
// racing on those fields.
//
// # Error handling
//
// ErrMaxSizeExceeded is returned from Write when an accepted write
// would push the total buffered size above maxSize. When Write fails
// this way, the BodyBuffer is marked dead: its temp file (if any) is
// removed immediately, subsequent Write calls return a "write after
// release" error, and subsequent Release calls return nil. The
// Layer/Channel that receives this error is expected to wrap it into
// the appropriate layer-specific error (for example
// layer.StreamError), but that translation is outside this package.
//
// # What this package does not do
//
//   - It does not fsync. Body bodies are scratch data; durability is
//     not required. Temp files are expected to live only as long as
//     the containing Stream.
//   - It does not cap concurrent Reader() calls. Each call performs a
//     fresh os.Open so that readers are seek-independent.
//   - It does not expose a Seal() or freeze API. Readers rely on the
//     documented single-writer contract instead.
package bodybuf
