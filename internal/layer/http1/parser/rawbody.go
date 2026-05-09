package parser

import (
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// rawBodySpillConfig carries the disk-spill knobs that the channel layer
// installs on a body reader after parsing but before draining. The parser
// itself never reads these fields directly; they are applied at the first
// call to bodyCaptureSink.write.
//
// USK-772: introduced so chunked / identity body capture can survive bodies
// larger than MaxRawCaptureSize without losing wire fidelity. The default
// zero-value behavior (memory only, capped at MaxRawCaptureSize) preserves
// USK-769 semantics for any caller that does not configure spill.
type rawBodySpillConfig struct {
	// dir is the directory used for the spill temp file. Empty means use
	// os.TempDir() (matched by bodybuf.NewFile / PromoteToFile semantics).
	dir string
	// prefix is the temp-file prefix. Empty means no spill is permitted —
	// the sink stays memory-only and is bounded by MaxRawCaptureSize.
	prefix string
	// threshold is the in-memory byte count above which the sink promotes
	// to a disk-backed bodybuf. Zero means "spill on first byte" (rarely
	// useful in production; mostly for tests).
	threshold int64
	// maxSize is the absolute cap on captured bytes. Writes beyond this
	// flip truncated=true and stop accumulating. Zero means "use the
	// memory-only MaxRawCaptureSize cap" — i.e., the USK-769 behavior.
	maxSize int64
}

// bodyCaptureSink accumulates the on-wire body bytes for one HTTP/1.x message
// (chunk framing for chunked TE, identity bytes otherwise). It supports two
// storage modes:
//
//   - Memory-only (the default): writes accumulate in memBuf up to
//     MaxRawCaptureSize. Past the cap, additional writes are dropped and
//     truncated flips to true. This matches the USK-769 behavior used by any
//     caller that does not enable spill.
//   - Memory-then-spill: when spill.prefix is non-empty AND the accumulated
//     size would exceed spill.threshold, the sink promotes to a disk-backed
//     bodybuf.BodyBuffer (via NewFile + initial Write of the in-memory bytes).
//     Subsequent writes append to the file. The absolute cap moves to
//     spill.maxSize; the bodybuf maxSize enforces it at write time.
//
// Truncation semantics:
//   - In memory-only mode: truncated=true means the captured bytes are a
//     prefix of MaxRawCaptureSize.
//   - In spill mode: truncated=true means the body exceeded spill.maxSize.
//     The spill.maxSize cap applies to the FULL body (memory prefix + file
//     contents). The bodybuf returns ErrMaxSizeExceeded which we translate
//     into truncated=true.
//
// The sink is single-writer-by-contract: the dechunkedReader / identityBody
// Reader is the only goroutine that calls write during drain.
type bodyCaptureSink struct {
	memBuf    []byte
	truncated bool
	spill     rawBodySpillConfig
	bb        *bodybuf.BodyBuffer // non-nil after promote
	// failedToPromote, when true, indicates a previous write attempt to
	// promote-to-file failed and we have permanently fallen back to the
	// memory-only path. Subsequent writes therefore obey the
	// MaxRawCaptureSize cap.
	failedToPromote bool
}

// newBodyCaptureSink returns a sink in memory-only mode. enableSpill must be
// called separately to switch to disk-backed mode.
func newBodyCaptureSink() *bodyCaptureSink {
	return &bodyCaptureSink{}
}

// enableSpill installs the disk-spill knobs. Call before the first write.
// Calling on a sink that already received writes is permitted — accumulated
// memory bytes count toward the threshold check on the next write.
func (s *bodyCaptureSink) enableSpill(cfg rawBodySpillConfig) {
	s.spill = cfg
}

// write appends p to the sink. If spill is enabled and the accumulated size
// would cross threshold, the sink first promotes to a bodybuf-backed file.
// Truncation past maxSize (memory cap or spill cap) sets truncated=true and
// drops further bytes.
func (s *bodyCaptureSink) write(p []byte) {
	if s == nil || s.truncated {
		return
	}
	if len(p) == 0 {
		return
	}

	// File-backed branch.
	if s.bb != nil {
		// bodybuf enforces maxSize internally; capture truncation if it
		// trips. A truncated capture cannot recover, so we tear down the
		// file (bodybuf does this on ErrMaxSizeExceeded) and stop
		// accumulating.
		if _, err := s.bb.Write(p); err != nil {
			s.truncated = true
			s.bb = nil
		}
		return
	}

	// Memory branch. Decide whether to promote to file before writing.
	if s.canSpill() {
		newSize := int64(len(s.memBuf)) + int64(len(p))
		if newSize > s.spill.threshold {
			if err := s.promoteToFile(); err == nil {
				if _, werr := s.bb.Write(p); werr != nil {
					s.truncated = true
					s.bb = nil
				}
				return
			}
			// promote failed — fall through to memory write capped by
			// MaxRawCaptureSize. failedToPromote prevents repeated attempts.
		}
		// Below threshold (or promote failed): append to memory but
		// observe maxSize cap.
		s.writeMemoryWithCap(p, s.spill.maxSize)
		return
	}

	// No spill configured: memory-only with MaxRawCaptureSize cap.
	s.writeMemoryWithCap(p, MaxRawCaptureSize)
}

// canSpill reports whether disk-spill mode is active and a file has not yet
// been promoted (or a previous promotion failed).
func (s *bodyCaptureSink) canSpill() bool {
	return s.spill.prefix != "" && !s.failedToPromote
}

// writeMemoryWithCap appends p to memBuf, observing cap. If cap is zero the
// MaxRawCaptureSize default is used.
func (s *bodyCaptureSink) writeMemoryWithCap(p []byte, cap int64) {
	if cap <= 0 {
		cap = MaxRawCaptureSize
	}
	remaining := cap - int64(len(s.memBuf))
	if remaining <= 0 {
		s.truncated = true
		return
	}
	if int64(len(p)) > remaining {
		s.memBuf = append(s.memBuf, p[:remaining]...)
		s.truncated = true
		return
	}
	s.memBuf = append(s.memBuf, p...)
}

// promoteToFile creates a bodybuf-backed temp file and flushes the
// accumulated in-memory bytes into it. After success, s.bb is non-nil and
// s.memBuf is cleared so the file is the single source of truth.
func (s *bodyCaptureSink) promoteToFile() error {
	bb, err := bodybuf.NewFile(s.spill.dir, s.spill.prefix, s.spill.maxSize)
	if err != nil {
		s.failedToPromote = true
		return err
	}
	if len(s.memBuf) > 0 {
		if _, werr := bb.Write(s.memBuf); werr != nil {
			// On flush failure release the new bodybuf and stay memory.
			_ = bb.Release()
			s.failedToPromote = true
			return werr
		}
	}
	s.bb = bb
	s.memBuf = nil
	return nil
}

// bytes returns the captured memory bytes. Returns nil when the sink is
// file-backed (caller should consume buffer instead) or empty.
func (s *bodyCaptureSink) bytes() []byte {
	if s == nil || s.bb != nil {
		return nil
	}
	if len(s.memBuf) == 0 {
		return nil
	}
	out := make([]byte, len(s.memBuf))
	copy(out, s.memBuf)
	return out
}

// buffer returns the disk-backed bodybuf (nil when the sink is memory-only).
// Ownership: the bodybuf carries one Retain from NewFile; the consumer is
// responsible for matching that Retain with a terminal Release once the
// envelope's lifetime is complete.
func (s *bodyCaptureSink) buffer() *bodybuf.BodyBuffer {
	if s == nil {
		return nil
	}
	return s.bb
}

// isTruncated reports whether the sink hit its byte cap and dropped bytes.
func (s *bodyCaptureSink) isTruncated() bool {
	if s == nil {
		return false
	}
	return s.truncated
}
