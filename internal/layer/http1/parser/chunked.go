package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
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
type dechunkedReader struct {
	r                *bufio.Reader
	remaining        int64 // bytes remaining in the current chunk
	done             bool
	err              error
	trailers         RawHeaders
	trailerAnomalies []Anomaly
}

func newDechunkedReader(r *bufio.Reader) *dechunkedReader {
	return &dechunkedReader{r: r}
}

// Trailers returns the parsed chunked trailers in wire order. Call after the
// reader has returned io.EOF; before that the result is nil/empty.
func (dr *dechunkedReader) Trailers() RawHeaders { return dr.trailers }

// TrailerAnomalies returns anomalies observed while parsing the trailer
// section (pseudo-header, forbidden header, obs-fold, injection).
func (dr *dechunkedReader) TrailerAnomalies() []Anomaly { return dr.trailerAnomalies }

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
func (dr *dechunkedReader) readChunkSizeLine() (string, error) {
	line, lineErr := dr.r.ReadSlice('\n')
	if lineErr != nil && lineErr != bufio.ErrBufferFull {
		return "", lineErr
	}
	for lineErr == bufio.ErrBufferFull {
		if len(line) > maxChunkSizeLineLen {
			return "", fmt.Errorf("chunk-size line exceeds maximum length %d", maxChunkSizeLineLen)
		}
		var extra []byte
		extra, lineErr = dr.r.ReadSlice('\n')
		line = append(line, extra...)
	}
	if len(line) > maxChunkSizeLineLen {
		return "", fmt.Errorf("chunk-size line exceeds maximum length %d", maxChunkSizeLineLen)
	}

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
func (dr *dechunkedReader) consumeTrailers() {
	trailers, anomalies, err := parseHeaderLines(dr.r, nil, maxHeaderSize)
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
