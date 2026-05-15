package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// hexVal returns the numeric value of a hex digit, or -1 for invalid digits.
func hexVal(c rune) int64 {
	switch {
	case '0' <= c && c <= '9':
		return int64(c - '0')
	case 'a' <= c && c <= 'f':
		return int64(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int64(c-'A') + 10
	default:
		return -1
	}
}

// stripLineTerminator removes exactly one trailing CRLF or LF from b.
func stripLineTerminator(b []byte) []byte {
	end := len(b)
	if end > 0 && b[end-1] == '\n' {
		end--
		if end > 0 && b[end-1] == '\r' {
			end--
		}
	}
	return b[:end]
}

// trimHexString trims leading/trailing spaces and tabs (HTTP OWS) from a hex
// size string. It intentionally does NOT trim control characters such as CR,
// so that embedded CRs in malformed chunk-size lines are preserved and
// detected as invalid hex digits downstream.
func trimHexString(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
}

// DechunkBody decodes raw chunked Transfer-Encoding bytes into the plain body.
// It strips chunk size lines, chunk extensions, trailers, and the terminal
// chunk, returning only the concatenated chunk data.
//
// If the input is not valid chunked encoding, it returns the input as-is.
// This is intentionally lenient to avoid data loss on malformed bodies.
func DechunkBody(raw []byte) []byte {
	r := bufio.NewReader(bytes.NewReader(raw))
	var decoded bytes.Buffer

	for {
		// Read chunk size line.
		sizeLine, err := r.ReadSlice('\n')
		if err != nil && err != io.EOF {
			// Not valid chunked encoding; return original.
			if err == bufio.ErrBufferFull {
				return raw
			}
			return raw
		}

		lineNoEOL := stripLineTerminator(sizeLine)
		sizeStr := string(lineNoEOL)
		if idx := bytes.IndexByte(lineNoEOL, ';'); idx >= 0 {
			sizeStr = string(lineNoEOL[:idx])
		}
		sizeStr = trimHexString(sizeStr)

		if sizeStr == "" {
			// Not valid chunked encoding.
			return raw
		}

		// Terminal chunk.
		if sizeStr == "0" {
			break
		}

		// Parse hex size.
		var size int64
		for _, c := range sizeStr {
			d := hexVal(c)
			if d < 0 {
				return raw
			}
			if size > (1<<63-1)/16 {
				return raw
			}
			size = size*16 + int64(d)
		}

		// Read chunk data.
		if size > 0 {
			n, copyErr := io.CopyN(&decoded, r, size)
			if copyErr != nil || n != size {
				return raw
			}
		}

		// Read trailing CRLF after chunk data.
		var crlf [2]byte
		if _, crlfErr := io.ReadFull(r, crlf[:]); crlfErr != nil {
			return raw
		}
	}

	return decoded.Bytes()
}

// IsChunked reports whether the headers include a Transfer-Encoding header
// with a "chunked" token.
func IsChunked(headers RawHeaders) bool {
	for _, te := range headers.Values("Transfer-Encoding") {
		if hasChunkedTE(te) {
			return true
		}
	}
	return false
}

// dechunkedReader reads a chunked Transfer-Encoding stream and returns only
// the decoded payload data (stripping chunk size lines and the terminal chunk).
// Unlike rawChunkedReader it does not preserve wire format and has no memory
// cap beyond the caller's read buffer.
//
// Chunked trailers (per RFC 7230 §4.1.2) are parsed, not discarded. After the
// reader returns io.EOF, Trailers() and TrailerAnomalies() surface the parsed
// trailer section. The dechunkedReader satisfies TrailerProvider.
//
// USK-769: dechunkedReader also captures the on-wire body bytes (chunk
// framing, chunk-size hex, extensions, trailing CRLFs, terminal "0" chunk,
// and trailer section) into a bodyCaptureSink so opaque pass-through send
// paths can re-emit the body byte-for-byte. Capture is bounded by
// MaxRawCaptureSize in memory-only mode, or by maxSize when USK-772
// disk-spill is configured via EnableRawBodySpill. Truncation flips
// rawBodyTruncated. The dechunkedReader satisfies RawBodyProvider once the
// body has been fully drained.
//
// USK-895: when a per-chunk record callback is installed (via
// SetChunkRecordCallback), the reader emits one callback per chunk
// boundary on the SSE-over-h1-chunked streaming detach path. The callback
// receives the full chunk wire bytes — chunk-size line (including any
// chunk-extension and terminating CRLF) + chunk-data + trailing CRLF —
// captured into chunkBuf during decode. The terminal "0\r\n…\r\n"
// chunk (with any trailer section) is emitted as its own callback. The
// callback fires AFTER the chunk has been fully read from the wire so
// the recorder snapshot reflects the bytes the proxy actually observed.
type dechunkedReader struct {
	r                *bufio.Reader
	remaining        int64 // bytes remaining in the current chunk
	done             bool
	err              error
	trailers         RawHeaders
	trailerAnomalies []Anomaly

	// rawCapture accumulates the on-wire body bytes (chunk framing + data +
	// trailers). Read from RawBody() (memory) or RawBodyBuffer() (spilled)
	// after drain.
	rawCapture *bodyCaptureSink

	// USK-895 per-chunk record callback.
	// chunkCallback fires once per chunk boundary with the full chunk wire
	// bytes accumulated in chunkBuf. nil disables the per-chunk path.
	chunkCallback func(chunkRaw []byte)
	// chunkBuf accumulates the current chunk's wire bytes (size-line +
	// payload + trailing CRLF). Reset between chunks. Only allocated when
	// chunkCallback is non-nil to keep the no-callback hot path zero-cost.
	chunkBuf []byte
	// chunkOverCap, when true, indicates the current chunk's wire size has
	// exceeded chunkMaxBytes and the callback for THIS chunk will be
	// suppressed (defensive against a malicious upstream sending a 4 GiB
	// single chunk — see USK-893 fitness check Principle #5). Reset at the
	// next chunk boundary.
	chunkOverCap bool
	// chunkMaxBytes caps the wire bytes captured for a single chunk-record
	// callback. Zero means MaxRawCaptureSize at write time. Threaded via
	// SetChunkRecordCallback; under-cap chunks accumulate verbatim into
	// chunkBuf; over-cap chunks are dropped with chunkOverCap=true.
	chunkMaxBytes int64
}

// newDechunkedReader returns a dechunkedReader bounded by the package-default
// MaxRawCaptureSize. Used by tests/fuzz harnesses; production callers thread
// their per-channel cap via newDechunkedReaderWithCap.
func newDechunkedReader(r *bufio.Reader) *dechunkedReader {
	return newDechunkedReaderWithCap(r, 0)
}

// newDechunkedReaderWithCap mirrors newDechunkedReader but seeds the body
// capture sink with memoryCap. Zero memoryCap falls back to
// MaxRawCaptureSize at write time.
func newDechunkedReaderWithCap(r *bufio.Reader, memoryCap int64) *dechunkedReader {
	return &dechunkedReader{r: r, rawCapture: newBodyCaptureSinkWithCap(memoryCap)}
}

// SetChunkRecordCallback installs the per-chunk record callback (USK-895).
// The callback fires once per chunk boundary (including the terminal zero-
// size chunk + trailer section, emitted as its own callback) with the full
// chunk wire bytes: chunk-size line + chunk-extension + chunk-data +
// trailing CRLF.
//
// maxBytes caps the wire bytes captured for a single chunk-record callback
// (defensive against a malicious upstream sending an oversized single
// chunk — Principle #5 / USK-893 fitness check). Zero means the package
// default (MaxRawCaptureSize). If a chunk's wire bytes exceed maxBytes the
// callback is skipped for THAT chunk; subsequent under-cap chunks still
// fire normally.
//
// Call before the first Read so the chunkBuf accumulator is populated for
// every chunk. Calling on a reader that already drained chunks is permitted
// but only chunks read after the call are observed.
//
// Passing a nil cb is equivalent to never having installed the option:
// the reader behaves identically to the pre-USK-895 contract and the hot
// path stays zero-cost (chunkBuf is not allocated).
func (dr *dechunkedReader) SetChunkRecordCallback(cb func(chunkRaw []byte), maxBytes int64) {
	if dr == nil {
		return
	}
	dr.chunkCallback = cb
	dr.chunkMaxBytes = maxBytes
	if cb != nil && dr.chunkBuf == nil {
		// Reserve a modest initial capacity. Typical SSE chunks are well
		// under 1 KiB; the grow loop handles the rest. Keeping this small
		// avoids burning memory for non-callback paths.
		dr.chunkBuf = make([]byte, 0, 256)
	}
}

// captureChunkBytes appends p to chunkBuf observing chunkMaxBytes. When
// the buffer would exceed the cap the buffer is reset to nil and
// chunkOverCap is latched so the deferred callback at the chunk boundary
// is suppressed. Called from readChunkSizeLine, readChunkData, and
// consumeTrailers under chunkCallback != nil only.
func (dr *dechunkedReader) captureChunkBytes(p []byte) {
	if dr.chunkCallback == nil || dr.chunkOverCap || len(p) == 0 {
		return
	}
	cap := dr.chunkMaxBytes
	if cap <= 0 {
		cap = MaxRawCaptureSize
	}
	if int64(len(dr.chunkBuf))+int64(len(p)) > cap {
		dr.chunkOverCap = true
		// Drop the partial buffer — a partial chunk record would mislead
		// an analyst (they'd see a truncated wire view without explicit
		// truncation metadata). Skip the chunk record entirely. The full
		// chunked body still surfaces via the broader rawCapture path
		// when MaxRawCaptureSize permits.
		dr.chunkBuf = dr.chunkBuf[:0]
		return
	}
	dr.chunkBuf = append(dr.chunkBuf, p...)
}

// emitChunkRecord fires the per-chunk record callback (USK-895) with the
// accumulated chunk wire bytes and resets the buffer for the next chunk.
// Called at the trailing-CRLF boundary of each chunk (and once after the
// terminal "0" chunk + trailer section).
func (dr *dechunkedReader) emitChunkRecord() {
	if dr.chunkCallback == nil {
		return
	}
	if !dr.chunkOverCap && len(dr.chunkBuf) > 0 {
		// Defensive copy: the callback runs synchronously but the
		// recorder may stash the slice on an envelope that outlives this
		// goroutine's chunkBuf reuse.
		out := make([]byte, len(dr.chunkBuf))
		copy(out, dr.chunkBuf)
		dr.chunkCallback(out)
	}
	// Reset for the next chunk regardless of cap-hit / empty.
	dr.chunkBuf = dr.chunkBuf[:0]
	dr.chunkOverCap = false
}

// EnableRawBodySpill installs the disk-spill knobs on the body capture sink.
// Call before the first Read to allow chunked bodies above threshold to be
// captured to a temp file rather than truncated at MaxRawCaptureSize.
func (dr *dechunkedReader) EnableRawBodySpill(dir, prefix string, threshold, maxSize int64) {
	if dr == nil || dr.rawCapture == nil {
		return
	}
	dr.rawCapture.enableSpill(rawBodySpillConfig{
		dir:       dir,
		prefix:    prefix,
		threshold: threshold,
		maxSize:   maxSize,
	})
}

// Trailers returns the parsed chunked trailers in wire order. Call after the
// reader has returned io.EOF; before that the result is nil/empty.
func (dr *dechunkedReader) Trailers() RawHeaders { return dr.trailers }

// TrailerAnomalies returns anomalies observed while parsing the trailer
// section (pseudo-header, forbidden header, obs-fold, injection).
func (dr *dechunkedReader) TrailerAnomalies() []Anomaly { return dr.trailerAnomalies }

// RawBody returns the on-wire body bytes captured during dechunking when the
// body fit in memory. Returns nil when the sink spilled to disk (use
// RawBodyBuffer for the disk-backed path). Call after the reader has
// returned io.EOF.
func (dr *dechunkedReader) RawBody() []byte {
	if dr.rawCapture == nil {
		return nil
	}
	return dr.rawCapture.bytes()
}

// RawBodyBuffer returns the disk-backed bodybuf when the chunked body crossed
// the spill threshold during capture. Returns nil otherwise (use RawBody for
// the memory path). The bodybuf carries one outstanding Retain at this
// point; the caller assumes ownership.
func (dr *dechunkedReader) RawBodyBuffer() *bodybuf.BodyBuffer {
	if dr.rawCapture == nil {
		return nil
	}
	return dr.rawCapture.buffer()
}

// RawBodyTruncated reports whether captured RawBody was capped (at
// MaxRawCaptureSize for memory mode, or maxSize for spill mode).
func (dr *dechunkedReader) RawBodyTruncated() bool {
	if dr.rawCapture == nil {
		return false
	}
	return dr.rawCapture.isTruncated()
}

// Read implements io.Reader. It returns decoded chunk data without markers.
func (dr *dechunkedReader) Read(p []byte) (int, error) {
	if dr.done || dr.err != nil {
		if dr.err != nil {
			return 0, dr.err
		}
		return 0, io.EOF
	}

	for {
		// If we have remaining data in the current chunk, read from it.
		if dr.remaining > 0 {
			return dr.readChunkData(p)
		}

		// Read the next chunk header and set dr.remaining.
		// Returns io.EOF when the terminal chunk is reached.
		if err := dr.nextChunk(); err != nil {
			return 0, err
		}
	}
}

// readChunkData reads up to len(p) bytes from the current chunk.
func (dr *dechunkedReader) readChunkData(p []byte) (int, error) {
	toRead := int64(len(p))
	if toRead > dr.remaining {
		toRead = dr.remaining
	}
	n, err := dr.r.Read(p[:toRead])
	dr.remaining -= int64(n)
	if n > 0 {
		dr.rawCapture.write(p[:n])
		dr.captureChunkBytes(p[:n])
	}
	if err != nil {
		dr.err = err
		return n, err
	}
	// If the chunk is fully read, consume the trailing CRLF.
	if dr.remaining == 0 {
		var crlf [2]byte
		if _, crlfErr := io.ReadFull(dr.r, crlf[:]); crlfErr != nil {
			dr.err = crlfErr
			return n, crlfErr
		}
		dr.rawCapture.write(crlf[:])
		dr.captureChunkBytes(crlf[:])
		// USK-895: emit the per-chunk record callback at the trailing
		// CRLF boundary, AFTER the chunk has been fully observed on the
		// wire. The callback fires synchronously on the consumer's read
		// goroutine — the contract documented on SetChunkRecordCallback
		// requires non-blocking.
		dr.emitChunkRecord()
	}
	return n, nil
}

// nextChunk reads the next chunk-size line and sets dr.remaining.
// Returns io.EOF when the terminal chunk ("0") is reached.
func (dr *dechunkedReader) nextChunk() error {
	sizeStr, err := dr.readChunkSizeLine()
	if err != nil {
		dr.err = err
		return err
	}

	// Terminal chunk.
	if sizeStr == "0" {
		dr.consumeTrailers()
		dr.done = true
		// USK-895: emit the per-chunk record callback for the terminal
		// "0\r\n…\r\n" chunk (including any trailer section). This is the
		// boundary an analyst needs to see "the stream closed gracefully"
		// vs. "the stream was cut off mid-chunk".
		dr.emitChunkRecord()
		// Propagate trailer-parse failures (e.g., oversize, malformed section)
		// to the body reader consumer instead of silently masking them with EOF.
		if dr.err != nil {
			return dr.err
		}
		return io.EOF
	}

	size, parseErr := parseHexSize(sizeStr)
	if parseErr != nil {
		dr.err = parseErr
		return parseErr
	}
	dr.remaining = size
	return nil
}

// maxChunkSizeLineLen is the hard cap on chunk-size line length.
// A chunk-size line contains hex digits plus an optional extension; 4 KiB is
// far more than any legitimate implementation would send.
const maxChunkSizeLineLen = 4096

// readChunkSizeLine reads a chunk-size line, handling bufio.ErrBufferFull
// for very long lines, and returns the trimmed hex size string.
//
// The full line (including chunk extensions and the terminating CRLF) is
// captured into dr.rawCapture for byte-for-byte wire fidelity.
func (dr *dechunkedReader) readChunkSizeLine() (string, error) {
	line, lineErr := dr.r.ReadSlice('\n')
	if lineErr != nil && lineErr != bufio.ErrBufferFull {
		// Capture whatever was read (may be empty on hard EOF) for diagnostic
		// purposes — analysts see the partial wire bytes via RawBody.
		if len(line) > 0 {
			dr.rawCapture.write(line)
			dr.captureChunkBytes(line)
		}
		return "", lineErr
	}
	for lineErr == bufio.ErrBufferFull {
		if len(line) > maxChunkSizeLineLen {
			dr.rawCapture.write(line[:maxChunkSizeLineLen])
			dr.captureChunkBytes(line[:maxChunkSizeLineLen])
			return "", fmt.Errorf("chunk-size line exceeds maximum length %d", maxChunkSizeLineLen)
		}
		var extra []byte
		extra, lineErr = dr.r.ReadSlice('\n')
		line = append(line, extra...)
	}
	if len(line) > maxChunkSizeLineLen {
		dr.rawCapture.write(line[:maxChunkSizeLineLen])
		dr.captureChunkBytes(line[:maxChunkSizeLineLen])
		return "", fmt.Errorf("chunk-size line exceeds maximum length %d", maxChunkSizeLineLen)
	}

	dr.rawCapture.write(line)
	dr.captureChunkBytes(line)

	lineNoEOL := stripLineTerminator(line)
	sizeStr := string(lineNoEOL)
	if idx := bytes.IndexByte(lineNoEOL, ';'); idx >= 0 {
		sizeStr = string(lineNoEOL[:idx])
	}
	sizeStr = trimHexString(sizeStr)

	if sizeStr == "" {
		return "", io.ErrUnexpectedEOF
	}
	return sizeStr, nil
}

// consumeTrailers parses chunked trailer lines until the blank line terminator.
// Parsed trailers are stored on dr.trailers for later retrieval via Trailers().
// Pseudo-header and RFC 7230 §4.1.2 forbidden-header names are recorded as
// anomalies but kept in the Trailers slice (wire fidelity: do not drop).
// Total trailer bytes are capped at maxHeaderSize to bound attacker-controlled
// input.
//
// The trailer section bytes (each line + terminating blank line) are also
// captured into dr.rawCapture so opaque pass-through send paths re-emit them
// verbatim alongside the chunk framing. USK-895: when a per-chunk record
// callback is installed, the trailer section also feeds the terminal
// "0\r\n…\r\n" chunk-record buffer via a tee sink.
func (dr *dechunkedReader) consumeTrailers() {
	sink := dr.trailerCaptureSink()
	trailers, anomalies, err := parseHeaderLines(dr.r, sink, maxHeaderSize)
	if err != nil {
		// Preserve whatever was successfully parsed for diagnostics even when
		// the section overflows or a read fails.
		dr.trailers = trailers
		dr.trailerAnomalies = anomalies
		dr.err = fmt.Errorf("chunked trailers: %w", err)
		return
	}
	anomalies = append(anomalies, scanTrailerAnomalies(trailers)...)
	dr.trailers = trailers
	dr.trailerAnomalies = anomalies
}

// trailerCaptureSink returns the rawSink passed to parseHeaderLines when
// reading the chunked trailer section. When a chunk-record callback is
// installed (USK-895) the sink is a tee that writes to both rawCapture
// (full-body wire bytes) and chunkBuf (terminal chunk-record). Otherwise
// it is rawCapture directly so the no-callback hot path matches the
// pre-USK-895 contract exactly.
func (dr *dechunkedReader) trailerCaptureSink() rawSink {
	if dr.chunkCallback == nil {
		return dr.rawCapture
	}
	return &teeRawSink{
		primary:    dr.rawCapture,
		chunkWrite: dr.captureChunkBytes,
	}
}

// teeRawSink is a rawSink that forwards every write to primary and also
// to chunkWrite. Used by dechunkedReader.trailerCaptureSink so the chunk-
// record buffer accumulates the trailer section bytes alongside the
// full-body capture sink.
type teeRawSink struct {
	primary    *bodyCaptureSink
	chunkWrite func([]byte)
}

func (t *teeRawSink) write(p []byte) {
	if t.primary != nil {
		t.primary.write(p)
	}
	if t.chunkWrite != nil {
		t.chunkWrite(p)
	}
}

// forbiddenTrailerHeaders enumerates the RFC 7230 §4.1.2 framing/routing
// subset whose appearance in a chunked trailer is a smuggling indicator.
var forbiddenTrailerHeaders = []string{
	"Transfer-Encoding",
	"Content-Length",
	"Host",
	"Trailer",
}

// scanTrailerAnomalies classifies semantically invalid trailer names. The
// offending headers remain in the RawHeaders slice so that MITM analysts see
// the wire as-observed; this helper only produces diagnostic Anomalies.
//
// HTTP/1 has no pseudo-header concept, so a line beginning with ':' (e.g.,
// ":authority: foo") is parsed by parseHeaderLines as an empty-Name header
// because the split happens on the first colon. Empty Name therefore signals
// an H2-style pseudo-header smuggling attempt or other malformed name.
func scanTrailerAnomalies(trailers RawHeaders) []Anomaly {
	var anomalies []Anomaly
	for _, h := range trailers {
		if h.Name == "" || strings.HasPrefix(h.Name, ":") {
			anomalies = append(anomalies, Anomaly{
				Type:   AnomalyTrailerPseudoHeader,
				Detail: fmt.Sprintf("pseudo-header-like trailer (empty or :-prefixed name, value=%q)", h.Value),
			})
			continue
		}
		for _, forbidden := range forbiddenTrailerHeaders {
			if strings.EqualFold(h.Name, forbidden) {
				anomalies = append(anomalies, Anomaly{
					Type:   AnomalyTrailerForbidden,
					Detail: fmt.Sprintf("framing/routing header not allowed in trailer (RFC 7230 §4.1.2): %q", h.Name),
				})
				break
			}
		}
	}
	return anomalies
}

// parseHexSize parses a hex chunk size string with overflow protection.
func parseHexSize(sizeStr string) (int64, error) {
	var size int64
	for _, c := range sizeStr {
		d := hexVal(c)
		if d < 0 {
			return 0, fmt.Errorf("invalid chunk size: %q", sizeStr)
		}
		if size > (1<<63-1)/16 {
			return 0, fmt.Errorf("chunk size overflow")
		}
		size = size*16 + int64(d)
	}
	return size, nil
}
