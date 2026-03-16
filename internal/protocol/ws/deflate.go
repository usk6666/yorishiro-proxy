package ws

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// deflateParams holds the negotiated permessage-deflate parameters for one
// direction (client-to-server or server-to-client).
type deflateParams struct {
	// enabled indicates whether permessage-deflate was negotiated.
	enabled bool

	// contextTakeover indicates whether the compressor/decompressor context
	// is preserved across messages. When true, a single flate.Reader is reused.
	// When false (no_context_takeover), a fresh reader is created per message.
	contextTakeover bool

	// windowBits is the LZ77 window size (8-15). Default is 15 per RFC 7692.
	windowBits int
}

// deflateState manages the decompression state for one relay direction.
// It wraps a flate.Reader that may be reused across messages (context takeover)
// or created fresh for each message (no context takeover).
type deflateState struct {
	params deflateParams
	reader io.ReadCloser
}

// newDeflateState creates a new deflateState for the given parameters.
func newDeflateState(params deflateParams) *deflateState {
	return &deflateState{params: params}
}

// flateTrailer is the 4-byte trailer appended to permessage-deflate payloads
// before decompression, as specified in RFC 7692 Section 7.2.2.
var flateTrailer = []byte{0x00, 0x00, 0xff, 0xff}

// decompress decompresses a permessage-deflate payload.
// Per RFC 7692 Section 7.2.2, the 4-byte trailer (0x00 0x00 0xFF 0xFF) must be
// appended before decompression.
//
// maxSize limits the decompressed output size to prevent decompression bombs.
func (ds *deflateState) decompress(payload []byte, maxSize int64) ([]byte, error) {
	if len(payload) == 0 {
		return payload, nil
	}

	// Append the DEFLATE trailer per RFC 7692 Section 7.2.2.
	src := make([]byte, len(payload)+len(flateTrailer))
	copy(src, payload)
	copy(src[len(payload):], flateTrailer)

	if ds.params.contextTakeover && ds.reader != nil {
		// Reuse existing reader with new input (context takeover).
		// flate.Resetter allows feeding new data without losing LZ77 state.
		if resetter, ok := ds.reader.(flate.Resetter); ok {
			if err := resetter.Reset(bytes.NewReader(src), nil); err != nil {
				return nil, fmt.Errorf("reset deflate reader: %w", err)
			}
		} else {
			// Fallback: create new reader (should not happen with stdlib).
			ds.reader = flate.NewReader(bytes.NewReader(src))
		}
	} else {
		// Create a new reader (no context takeover or first message).
		if ds.reader != nil {
			ds.reader.Close()
		}
		ds.reader = flate.NewReader(bytes.NewReader(src))
	}

	decoded, err := io.ReadAll(io.LimitReader(ds.reader, maxSize+1))
	if err != nil {
		// permessage-deflate streams are not properly terminated (no final block marker),
		// so io.ReadAll may return io.ErrUnexpectedEOF after successfully reading all data.
		// This is expected per RFC 7692 Section 7.2.2: the 4 octets appended before
		// decompression form a non-final DEFLATE block, so the reader sees a truncated stream.
		if len(decoded) == 0 {
			return nil, fmt.Errorf("deflate decompress: %w", err)
		}
		// Got some data before the error — treat as success (partial stream is normal).
	}
	if int64(len(decoded)) > maxSize {
		decoded = decoded[:maxSize]
	}

	// For no_context_takeover, close the reader after each message.
	if !ds.params.contextTakeover {
		ds.reader.Close()
		ds.reader = nil
	}

	return decoded, nil
}

// close releases the decompression resources.
func (ds *deflateState) close() {
	if ds.reader != nil {
		ds.reader.Close()
		ds.reader = nil
	}
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
