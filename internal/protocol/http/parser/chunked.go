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
// the decoded payload data (stripping chunk size lines, trailers, and the
// terminal chunk). Unlike rawChunkedReader it does not preserve wire format
// and has no memory cap beyond the caller's read buffer.
type dechunkedReader struct {
	r         *bufio.Reader
	remaining int64 // bytes remaining in the current chunk
	done      bool
	err       error
}

func newDechunkedReader(r *bufio.Reader) *dechunkedReader {
	return &dechunkedReader{r: r}
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

// readChunkSizeLine reads a chunk-size line, handling bufio.ErrBufferFull
// for very long lines, and returns the trimmed hex size string.
func (dr *dechunkedReader) readChunkSizeLine() (string, error) {
	line, lineErr := dr.r.ReadSlice('\n')
	if lineErr != nil && lineErr != bufio.ErrBufferFull {
		return "", lineErr
	}
	for lineErr == bufio.ErrBufferFull {
		var extra []byte
		extra, lineErr = dr.r.ReadSlice('\n')
		line = append(line, extra...)
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

// consumeTrailers reads and discards trailer lines until a blank line.
func (dr *dechunkedReader) consumeTrailers() {
	for {
		trailer, tErr := dr.r.ReadSlice('\n')
		if tErr != nil && tErr != bufio.ErrBufferFull {
			break
		}
		for tErr == bufio.ErrBufferFull {
			var extra []byte
			extra, tErr = dr.r.ReadSlice('\n')
			trailer = append(trailer, extra...)
		}
		trimmed := bytes.TrimRight(trailer, "\r\n")
		if len(trimmed) == 0 {
			break
		}
	}
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
