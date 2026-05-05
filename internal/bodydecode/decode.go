// Package bodydecode decodes HTTP Content-Encoding (gzip / deflate / br /
// zstd) bodies for the MCP query observation interface.
//
// This is a control-plane helper used only by internal/mcp/ when serializing
// stored flow bodies to AI agents. The data path (internal/layer/, parser,
// recorder, resend) MUST NOT use this package: storage and resend keep wire
// fidelity by preserving the original compressed bytes (CLAUDE.md MITM
// principle #1: "do not normalize what the wire did not normalize").
//
// Failures (unknown codec, malformed input, size cap exceeded, multi-codec
// chain) never panic and never fabricate data — they return the original
// body unchanged plus a typed Anomaly so the caller can surface the failure
// as metadata while preserving wire bytes for downstream tools.
package bodydecode

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// DefaultMaxDecodedSize caps the decoded body emitted to MCP clients.
// 16 MiB matches the WebSocket per-frame cap and is large enough for any
// realistic single-flow inspection while bounding zip-bomb expansion.
const DefaultMaxDecodedSize int64 = 16 << 20

// Anomaly classifies a decode failure or rejection. The original body is
// returned alongside the anomaly so the caller can keep the wire bytes
// intact in the response.
type Anomaly struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
}

// Anomaly type constants. These are stable strings exposed via the MCP
// response schema; renaming is a breaking change.
const (
	// AnomalyUnknownEncoding is reported when Content-Encoding names a codec
	// the decoder does not implement (e.g. "snappy", "compress").
	AnomalyUnknownEncoding = "unknown_encoding"

	// AnomalyMalformed is reported when the codec accepted the encoding name
	// but the body bytes failed to decode (corrupt header, truncated stream,
	// invalid checksum).
	AnomalyMalformed = "malformed"

	// AnomalySizeExceeded is reported when the decoded output exceeds the
	// caller-supplied maxSize cap (zip-bomb defense).
	AnomalySizeExceeded = "size_exceeded"

	// AnomalyChainRejected is reported when Content-Encoding lists more than
	// one codec ("gzip, br"). Chain handling is deferred — the original
	// compressed bytes are returned with this anomaly so callers can flag the
	// flow without losing data.
	AnomalyChainRejected = "chain_rejected"
)

// Decode attempts to decode body using the codec named by contentEncoding
// (the raw Content-Encoding header value).
//
// Return contract:
//   - applied == "" && anomaly == nil — identity / empty CE / empty body.
//     `out` is `body` (no copy made).
//   - applied != "" && anomaly == nil — decode succeeded. `out` is the
//     plaintext bytes. `applied` is the lower-case codec name (e.g. "gzip").
//   - anomaly != nil — decode rejected or failed. `out` is the original
//     `body` unchanged; `applied` is "". Caller surfaces the anomaly as
//     metadata and renders the original (compressed) body.
//
// maxSize <= 0 disables the size cap.
func Decode(body []byte, contentEncoding string, maxSize int64) (out []byte, applied string, anomaly *Anomaly) {
	enc := strings.TrimSpace(contentEncoding)
	if enc == "" || strings.EqualFold(enc, "identity") || len(body) == 0 {
		return body, "", nil
	}

	// Reject codec chains (e.g. "gzip, br"). Real-world chained CE on
	// responses is essentially never seen; a chain_rejected anomaly is
	// preferable to a partial decode that hides which step failed.
	if strings.Contains(enc, ",") {
		return body, "", &Anomaly{Type: AnomalyChainRejected, Detail: "multi-codec Content-Encoding not supported: " + enc}
	}

	codec := strings.ToLower(enc)
	switch codec {
	case "gzip", "x-gzip":
		return decodeWith(body, "gzip", maxSize, openGzip)
	case "deflate":
		return decodeWith(body, "deflate", maxSize, openDeflate)
	case "br":
		return decodeWith(body, "br", maxSize, openBrotli)
	case "zstd":
		return decodeWith(body, "zstd", maxSize, openZstdWithCap(maxSize))
	default:
		return body, "", &Anomaly{Type: AnomalyUnknownEncoding, Detail: enc}
	}
}

// codecOpener constructs a streaming reader for one codec.
type codecOpener func(r io.Reader) (io.ReadCloser, error)

// decodeWith runs `opener(body)` then reads up to maxSize+1 bytes via
// io.LimitedReader. Reading one byte past the cap lets us distinguish
// "exact fit" from "would have produced more", at zero memory cost.
func decodeWith(body []byte, applied string, maxSize int64, opener codecOpener) ([]byte, string, *Anomaly) {
	rc, err := opener(bytes.NewReader(body))
	if err != nil {
		return body, "", &Anomaly{Type: AnomalyMalformed, Detail: applied + ": " + err.Error()}
	}
	defer rc.Close()

	var reader io.Reader = rc
	if maxSize > 0 {
		reader = &io.LimitedReader{R: rc, N: maxSize + 1}
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		return body, "", &Anomaly{Type: AnomalyMalformed, Detail: applied + ": " + err.Error()}
	}
	if maxSize > 0 && int64(len(out)) > maxSize {
		return body, "", &Anomaly{Type: AnomalySizeExceeded, Detail: fmt.Sprintf("%s: decoded size exceeds %d bytes", applied, maxSize)}
	}
	return out, applied, nil
}

func openGzip(r io.Reader) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return zr, nil
}

func openDeflate(r io.Reader) (io.ReadCloser, error) {
	return flate.NewReader(r), nil
}

func openBrotli(r io.Reader) (io.ReadCloser, error) {
	return io.NopCloser(brotli.NewReader(r)), nil
}

// openZstdWithCap returns a codecOpener that bounds zstd's internal decoder
// memory (window/dict allocation) to maxSize bytes. This mirrors the sibling
// pattern in internal/encoding/protobuf/compress.go and is defense-in-depth:
// io.LimitedReader in decodeWith already caps the read side, but passing the
// cap into zstd ensures the decoder itself cannot allocate more than maxSize
// internally if a future refactor bypasses the LimitedReader wrapper.
//
// When maxSize <= 0 (cap disabled), the option is omitted so zstd uses its
// own default — passing 0 to WithDecoderMaxMemory is not equivalent to
// "disabled" across library versions.
func openZstdWithCap(maxSize int64) codecOpener {
	return func(r io.Reader) (io.ReadCloser, error) {
		var zr *zstd.Decoder
		var err error
		if maxSize > 0 {
			zr, err = zstd.NewReader(r, zstd.WithDecoderMaxMemory(uint64(maxSize)))
		} else {
			zr, err = zstd.NewReader(r)
		}
		if err != nil {
			return nil, err
		}
		return &zstdReadCloser{zr}, nil
	}
}

// zstdReadCloser adapts *zstd.Decoder.Close() (which returns no error) to
// io.Closer.
type zstdReadCloser struct {
	*zstd.Decoder
}

func (z *zstdReadCloser) Close() error {
	z.Decoder.Close()
	return nil
}
