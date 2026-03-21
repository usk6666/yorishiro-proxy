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

// deflateState manages the decompression state for one relay direction.
//
// For contextTakeover=false (no_context_takeover), a fresh flate.Reader is
// created per message — each message is independently compressed.
//
// For contextTakeover=true (the RFC 7692 default), each message is decompressed
// with flate.NewReaderDict using the accumulated decompressed output (last 32 KB)
// as the dictionary. This provides the LZ77 sliding window context that the
// compressor references in subsequent messages.
type deflateState struct {
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

// decompress decompresses a permessage-deflate payload.
// Per RFC 7692 Section 7.2.2, the 4-byte trailer (0x00 0x00 0xFF 0xFF) must be
// appended before decompression.
//
// maxSize limits the decompressed output size to prevent decompression bombs.
func (ds *deflateState) decompress(payload []byte, maxSize int64) ([]byte, error) {
	if len(payload) == 0 {
		return payload, nil
	}

	// Guard against integer overflow when computing the allocation size
	// for make([]byte, len(payload)+len(flateTrailer)).
	if err := checkAllocationOverflow(len(payload), len(flateTrailer)); err != nil {
		return nil, err
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
// no_context_takeover is negotiated — each message is independently compressed.
func (ds *deflateState) decompressFresh(src []byte, maxSize int64) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(src))
	defer reader.Close()

	decoded, _, err := ds.readDecompressed(reader, maxSize)
	return decoded, err
}

// decompressWithContext creates a new flate reader per message, providing the
// accumulated decompressed output as a dictionary via flate.NewReaderDict.
// This preserves the LZ77 sliding window context across messages without
// needing to keep a single reader alive (which is problematic because Go's
// flate reader caches errors permanently).
func (ds *deflateState) decompressWithContext(src []byte, maxSize int64) ([]byte, error) {
	var reader io.ReadCloser
	if len(ds.dict) > 0 {
		reader = flate.NewReaderDict(bytes.NewReader(src), ds.dict)
	} else {
		reader = flate.NewReader(bytes.NewReader(src))
	}
	defer reader.Close()

	decoded, truncated, err := ds.readDecompressed(reader, maxSize)
	if err != nil {
		return nil, err
	}

	// If maxSize truncation occurred, the dictionary would be inconsistent with
	// the peer's compressor state (LZ77 window desync). Reset the dictionary to
	// avoid silently producing incorrect decompression for subsequent messages.
	if truncated {
		ds.dict = nil
		return decoded, nil
	}

	// Update the dictionary with the decompressed output for subsequent messages.
	ds.dict = append(ds.dict, decoded...)
	if len(ds.dict) > maxDictSize {
		start := len(ds.dict) - maxDictSize
		newDict := make([]byte, maxDictSize)
		copy(newDict, ds.dict[start:])
		ds.dict = newDict
	}

	return decoded, nil
}

// readDecompressed reads decompressed data from a flate reader up to maxSize.
// permessage-deflate streams lack a BFINAL block, so io.ErrUnexpectedEOF is
// expected and treated as success when data was read.
// The returned truncated flag indicates whether the output was limited by maxSize.
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
	if int64(len(decoded)) > maxSize {
		decoded = decoded[:maxSize]
		truncated = true
	}

	return decoded, truncated, nil
}

// close releases the decompression resources. Each message creates and closes
// its own flate reader, so this only needs to clear the accumulated dictionary.
func (ds *deflateState) close() {
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
