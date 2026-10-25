package ws

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
)

// deflateParams holds the negotiated permessage-deflate parameters for one
// direction (client-to-server or server-to-client).
type deflateParams struct {
	// enabled indicates whether permessage-deflate was negotiated.
	enabled bool

	// contextTakeover indicates whether the compressor/decompressor context
	// is preserved across messages. When true, decompressed output is accumulated
	// as a dictionary and passed to subsequent messages via flate.NewReaderDict
	// to maintain the LZ77 sliding window.
	// When false (no_context_takeover), a fresh reader is created per message.
	contextTakeover bool

	// windowBits is the LZ77 window size (8-15). Default is 15 per RFC 7692.
	windowBits int
}

// maxDictSize is the maximum LZ77 sliding window size (32 KB) used for
// context takeover. The DEFLATE specification limits back-references to 32768
// bytes, so only the last 32 KB of decompressed output are relevant as
// dictionary context for subsequent messages.
const maxDictSize = 32768

// maxCompressedPayloadSize is a hard upper bound on the compressed payload size
// accepted by the permessage-deflate decompressor. It is derived from
// maxFramePayloadSize (the WebSocket frame payload cap) to maintain a single
// source of truth and prevent oversized allocations from attacker-controlled data.
const maxCompressedPayloadSize = maxFramePayloadSize

// deflateState manages the decompression state for one relay direction.
//
// For contextTakeover=false (no_context_takeover), a fresh flate.Reader is
// created per message — each message is independently compressed.
//
// For contextTakeover=true (the RFC 7692 default), each message is decompressed
// with flate.NewReaderDict using the accumulated decompressed output (last 32 KB)
// as the dictionary. This provides the LZ77 sliding window context that the
// compressor references in subsequent messages.
//
// Concurrency: each public method (compress, decompress, close) acquires
// the embedded mu for the duration of the call. The mutex is defense-in-
// depth (USK-867): the session-level wsSendSerializer already serialises
// Send-direction calls into Channel.Send for the upstream-facing Channel,
// and Next/Send on a single Channel reference disjoint *deflateState
// instances (clientDS vs serverDS). Adding the internal lock removes the
// reliance on those external invariants — a future caller path that
// bypasses the session serialiser, or a test/diagnostic harness that
// calls compress + decompress from goroutines, can no longer corrupt the
// LZ77 dictionary mid-operation.
type deflateState struct {
	// mu guards params and dict against concurrent compress/decompress/close
	// calls. Held for the full duration of each public method to keep the
	// flate.Reader / flate.Writer construction and the post-decode dict
	// update inside one critical section.
	mu sync.Mutex

	params deflateParams

	// dict holds the accumulated decompressed output (last maxDictSize bytes)
	// used as the dictionary for context takeover mode.
	dict []byte
}

// newDeflateState creates a new deflateState for the given parameters.
func newDeflateState(params deflateParams) *deflateState {
	return &deflateState{params: params}
}

// flateTrailer is the 4-byte trailer appended to permessage-deflate payloads
// before decompression, as specified in RFC 7692 Section 7.2.2.
var flateTrailer = []byte{0x00, 0x00, 0xff, 0xff}

// checkAllocationOverflow checks whether adding trailerLen to payloadLen
// would overflow int, which would cause a runtime panic in make().
func checkAllocationOverflow(payloadLen, trailerLen int) error {
	if payloadLen > math.MaxInt-trailerLen {
		return fmt.Errorf("deflate decompress: allocation size overflow (%d + %d bytes)", payloadLen, trailerLen)
	}
	return nil
}

// inflateResult is the outcome of decompressing one permessage-deflate
// message (USK-1321).
type inflateResult struct {
	// payload is the decompressed message, at most maxSize bytes.
	payload []byte

	// truncated reports that the decompressed message exceeded maxSize
	// and payload holds only its first maxSize bytes.
	truncated bool

	// fullSize is the full decompressed size when it is known (always
	// for a whole message; for a truncated one only under context
	// takeover, where the rest is inflated to keep the window in step).
	// -1 when unknown.
	fullSize int64

	// windowBefore / windowAfter are copies of the LZ77 window before and
	// after this message. Populated only for a truncated message under
	// context takeover; the Send side uses them to forward the received
	// frame verbatim while keeping its compressor window in step.
	windowBefore []byte
	windowAfter  []byte
}

// decompress decompresses a permessage-deflate payload and returns at most
// maxSize bytes of it. See inflate.
func (ds *deflateState) decompress(payload []byte, maxSize int64) ([]byte, error) {
	res, err := ds.inflate(payload, maxSize)
	if err != nil {
		return nil, err
	}
	return res.payload, nil
}

// inflate decompresses a permessage-deflate payload.
// Per RFC 7692 Section 7.2.2, the 4-byte trailer (0x00 0x00 0xFF 0xFF) must be
// appended before decompression.
//
// maxSize limits the decompressed output that is returned, to bound memory
// against decompression bombs. A message that decompresses past maxSize is
// reported as truncated with its first maxSize bytes. Under context
// takeover the rest of the message is still inflated (output discarded
// except the trailing 32 KiB) so the window matches the peer's compressor
// for the messages that follow (RFC 7692 §7.2.2 / §8.1); memory stays
// bounded at maxSize + maxDictSize.
//
// Concurrency: acquires ds.mu for the full duration of the call so the
// internal dict update is atomic with respect to any concurrent compress
// / decompress / close on the same *deflateState (USK-867 defense-in-depth).
func (ds *deflateState) inflate(payload []byte, maxSize int64) (inflateResult, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if len(payload) == 0 {
		return inflateResult{payload: payload, fullSize: 0}, nil
	}

	// Enforce a hard upper bound on the compressed payload size to avoid
	// pathological allocations and satisfy static analysis that this value
	// cannot be arbitrarily large.
	if int64(len(payload)) > maxCompressedPayloadSize {
		return inflateResult{}, fmt.Errorf("deflate decompress: compressed payload too large: %d > %d", len(payload), maxCompressedPayloadSize)
	}

	// Guard against integer overflow when computing the allocation size
	// for make([]byte, len(payload)+len(flateTrailer)).
	if err := checkAllocationOverflow(len(payload), len(flateTrailer)); err != nil {
		return inflateResult{}, err
	}

	// Append the DEFLATE trailer per RFC 7692 Section 7.2.2.
	src := make([]byte, len(payload)+len(flateTrailer))
	copy(src, payload)
	copy(src[len(payload):], flateTrailer)

	if ds.params.contextTakeover {
		return ds.decompressWithContext(src, maxSize)
	}
	return ds.decompressFresh(src, maxSize)
}

// decompressFresh creates a new flate reader for each message. Used when
// no_context_takeover is negotiated — each message is independently
// compressed, so an over-cap message is not inflated past maxSize+1 and
// its full size stays unknown.
func (ds *deflateState) decompressFresh(src []byte, maxSize int64) (inflateResult, error) {
	reader := flate.NewReader(bytes.NewReader(src))
	defer reader.Close()

	decoded, truncated, err := ds.readDecompressed(reader, maxSize)
	if err != nil {
		return inflateResult{}, err
	}
	if truncated {
		return inflateResult{payload: decoded[:maxSize], truncated: true, fullSize: -1}, nil
	}
	return inflateResult{payload: decoded, fullSize: int64(len(decoded))}, nil
}

// decompressWithContext creates a new flate reader per message, providing the
// accumulated decompressed output as a dictionary via flate.NewReaderDict.
// This preserves the LZ77 sliding window context across messages without
// needing to keep a single reader alive (which is problematic because Go's
// flate reader caches errors permanently).
//
// A message that decompresses past maxSize is inflated to its end anyway:
// the output beyond maxSize is discarded except for the trailing window, so
// the dictionary always reflects the FULL plaintext the peer's compressor
// saw (USK-1321). Resetting the dictionary instead would desynchronise
// every later back-referencing message.
func (ds *deflateState) decompressWithContext(src []byte, maxSize int64) (inflateResult, error) {
	var reader io.ReadCloser
	if len(ds.dict) > 0 {
		reader = flate.NewReaderDict(bytes.NewReader(src), ds.dict)
	} else {
		reader = flate.NewReader(bytes.NewReader(src))
	}
	defer reader.Close()

	decoded, truncated, err := ds.readDecompressed(reader, maxSize)
	if err != nil {
		return inflateResult{}, err
	}
	if !truncated {
		ds.dict = appendWindow(ds.dict, decoded)
		return inflateResult{payload: decoded, fullSize: int64(len(decoded))}, nil
	}

	// decoded holds maxSize+1 bytes; inflate the remainder into the window.
	window, rest, err := drainIntoWindow(reader, appendWindow(ds.dict, decoded))
	if err != nil {
		return inflateResult{}, err
	}
	res := inflateResult{
		payload:      decoded[:maxSize],
		truncated:    true,
		fullSize:     int64(len(decoded)) + rest,
		windowBefore: cloneBytes(ds.dict),
		windowAfter:  cloneBytes(window),
	}
	ds.dict = window
	return res, nil
}

// readDecompressed reads decompressed data from a flate reader up to
// maxSize+1 bytes. permessage-deflate streams lack a BFINAL block, so
// io.ErrUnexpectedEOF is expected and treated as success when data was read.
// truncated reports that more than maxSize bytes were available; decoded
// then holds maxSize+1 bytes and the reader is positioned after them.
func (ds *deflateState) readDecompressed(reader io.Reader, maxSize int64) (decoded []byte, truncated bool, err error) {
	decoded, err = io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			if len(decoded) == 0 {
				return nil, false, fmt.Errorf("deflate decompress: %w", err)
			}
		} else {
			return nil, false, fmt.Errorf("deflate decompress: %w", err)
		}
	}
	return decoded, int64(len(decoded)) > maxSize, nil
}

// drainIntoWindow inflates the rest of a message from reader, discarding
// the output except for the trailing maxDictSize bytes, which it appends to
// window. It returns the updated window and the number of bytes inflated.
// Memory is bounded by one maxDictSize read buffer plus the window.
func drainIntoWindow(reader io.Reader, window []byte) ([]byte, int64, error) {
	buf := make([]byte, maxDictSize)
	var n int64
	for {
		k, err := reader.Read(buf)
		if k > 0 {
			window = appendWindow(window, buf[:k])
			n += int64(k)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return window, n, nil
			}
			return nil, n, fmt.Errorf("deflate decompress: %w", err)
		}
	}
}

// appendWindow returns the last maxDictSize bytes of window+data as a new
// slice. Neither argument is modified, so a slice handed out earlier (an
// inflateResult window snapshot) never changes underneath its holder.
func appendWindow(window, data []byte) []byte {
	if len(data) >= maxDictSize {
		out := make([]byte, maxDictSize)
		copy(out, data[len(data)-maxDictSize:])
		return out
	}
	if keep := maxDictSize - len(data); len(window) > keep {
		window = window[len(window)-keep:]
	}
	out := make([]byte, 0, len(window)+len(data))
	out = append(out, window...)
	return append(out, data...)
}

// windowMatches reports whether this state's LZ77 window equals want over
// the bytes the negotiated window size lets a compressor reference
// (2^windowBits, at most maxDictSize). Used before forwarding a received
// compressed frame verbatim under context takeover: the frame's
// back-references only resolve on the peer if the two windows agree.
func (ds *deflateState) windowMatches(want []byte) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	span := maxDictSize
	if wb := ds.params.windowBits; wb >= 8 && wb < 15 {
		span = 1 << wb
	}
	return bytes.Equal(windowSuffix(ds.dict, span), windowSuffix(want, span))
}

func windowSuffix(b []byte, span int) []byte {
	if len(b) > span {
		return b[len(b)-span:]
	}
	return b
}

// setWindow replaces this state's LZ77 window with a copy of window. Used
// after a received compressed frame was forwarded verbatim, so the next
// compress call references exactly what the peer's inflater now holds.
func (ds *deflateState) setWindow(window []byte) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.dict = cloneBytes(window)
}

// compress compresses a permessage-deflate payload for the Send direction.
// Per RFC 7692 Section 7.2.1, the compressed output must end with an empty
// DEFLATE block whose BTYPE=00 and BFINAL=0 ("00 00 FF FF" after byte
// alignment), and those 4 trailer octets MUST be stripped before
// transmission. BFINAL=0 is critical for context-takeover peers (e.g. Node
// ws / zlib) that hold a single persistent inflater across frames: a
// BFINAL=1 terminator would mark the stream as finished and prevent any
// subsequent frame from being decoded (root cause of USK-867 prior to this
// fix).
//
// We achieve this by calling flate.Writer.Flush (Z_SYNC_FLUSH) rather than
// Close: Flush emits a stored empty block with BFINAL=0, whereas Close
// emits one with BFINAL=1. The trailing 4 bytes are verified and stripped
// per the RFC.
//
// When ds.params.contextTakeover is true and a non-empty dictionary has been
// accumulated from prior messages, the writer is initialized with
// flate.NewWriterDict so the LZ77 sliding window matches the peer's
// decompressor state. After a successful encode, the dictionary is updated
// with the original (uncompressed) payload bytes — capped at maxDictSize.
//
// maxSize bounds the allowed compressed output size. A non-positive maxSize
// falls back to maxFramePayloadSize (16 MiB).
//
// Concurrency: acquires ds.mu for the full duration of the call so the
// internal dict update is atomic with respect to any concurrent compress
// / decompress / close on the same *deflateState (USK-867 defense-in-depth).
func (ds *deflateState) compress(payload []byte, maxSize int64) ([]byte, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if maxSize <= 0 {
		maxSize = maxFramePayloadSize
	}
	if len(payload) == 0 {
		return payload, nil
	}

	var buf bytes.Buffer
	var w *flate.Writer
	var err error
	if ds.params.contextTakeover && len(ds.dict) > 0 {
		w, err = flate.NewWriterDict(&buf, flate.DefaultCompression, ds.dict)
	} else {
		w, err = flate.NewWriter(&buf, flate.DefaultCompression)
	}
	if err != nil {
		return nil, fmt.Errorf("deflate compress: new writer: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return nil, fmt.Errorf("deflate compress: write: %w", err)
	}
	// Flush (Z_SYNC_FLUSH) emits an empty stored block with BFINAL=0 followed
	// by the 4-byte trailer, leaving the stream open for the peer's
	// persistent inflater. Do NOT call Close here: that would emit BFINAL=1
	// and terminate the peer's inflater after the first frame.
	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("deflate compress: flush: %w", err)
	}

	out := buf.Bytes()
	// Strip the RFC 7692 §7.2.1 trailer (the 4-byte sync-flush tail of the
	// empty BFINAL=0 stored block that flate.Writer emits on Flush). Verify
	// before stripping so we do not silently corrupt malformed output from a
	// future flate.Writer.
	if len(out) < len(flateTrailer) || !bytes.Equal(out[len(out)-len(flateTrailer):], flateTrailer) {
		return nil, fmt.Errorf("deflate compress: missing RFC 7692 trailer")
	}
	out = out[:len(out)-len(flateTrailer)]

	if int64(len(out)) > maxSize {
		return nil, fmt.Errorf("deflate compress: output too large: %d > %d", len(out), maxSize)
	}

	// Update the per-direction dictionary with the original input bytes.
	// The LZ77 window size is capped at maxDictSize.
	if ds.params.contextTakeover {
		ds.dict = appendWindow(ds.dict, payload)
	}

	return out, nil
}

// close releases the decompression resources. Each message creates and closes
// its own flate reader, so this only needs to clear the accumulated dictionary.
//
// Concurrency: acquires ds.mu so the dict clear is atomic with respect to
// any in-flight compress / decompress (USK-867 defense-in-depth).
func (ds *deflateState) close() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.dict = nil
}

// parseDeflateExtension parses the Sec-WebSocket-Extensions header value for
// permessage-deflate parameters. Returns (clientParams, serverParams) which
// control decompression for the client-to-server and server-to-client directions.
//
// Per RFC 7692:
//   - server_no_context_takeover: server will not use context takeover
//   - client_no_context_takeover: client will not use context takeover
//   - server_max_window_bits: server LZ77 window size
//   - client_max_window_bits: client LZ77 window size
func parseDeflateExtension(extensionHeader string) (client deflateParams, server deflateParams) {
	if extensionHeader == "" {
		return
	}

	// Split on comma to handle multiple extensions; find permessage-deflate.
	for _, ext := range strings.Split(extensionHeader, ",") {
		ext = strings.TrimSpace(ext)
		parts := strings.Split(ext, ";")
		name := strings.TrimSpace(parts[0])
		if name != "permessage-deflate" {
			continue
		}

		// Found permessage-deflate. Parse parameters.
		client, server = applyDeflateParams(parts[1:])
		return
	}

	return
}

// applyDeflateParams initializes deflateParams from the parameter tokens
// of a permessage-deflate extension value.
func applyDeflateParams(params []string) (client deflateParams, server deflateParams) {
	client = deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	server = deflateParams{enabled: true, contextTakeover: true, windowBits: 15}

	for _, param := range params {
		kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
		key := strings.TrimSpace(kv[0])

		switch key {
		case "server_no_context_takeover":
			server.contextTakeover = false
		case "client_no_context_takeover":
			client.contextTakeover = false
		case "server_max_window_bits":
			server.windowBits = parseWindowBits(kv, server.windowBits)
		case "client_max_window_bits":
			client.windowBits = parseWindowBits(kv, client.windowBits)
		}
	}
	return
}

// parseWindowBits extracts a window bits value from a key=value pair.
// Returns defaultVal if the value is missing or out of range (8-15).
func parseWindowBits(kv []string, defaultVal int) int {
	if len(kv) != 2 {
		return defaultVal
	}
	v, err := strconv.Atoi(strings.TrimSpace(kv[1]))
	if err != nil || v < 8 || v > 15 {
		return defaultVal
	}
	return v
}
