package parser

import (
	"bufio"
	"bytes"
	"io"
)

// rawChunkedReader streams a chunked Transfer-Encoding body WITHOUT decoding.
// It reads the entire chunked body (all chunks including size lines, chunk data,
// trailers, and the final CRLF) and returns the raw bytes as-is.
//
// The reader terminates after reading the "0\r\n" terminal chunk and its
// trailing headers + CRLF. Any trailers present after the terminal chunk
// are included in the output.
type rawChunkedReader struct {
	r    *bufio.Reader
	done bool
	buf  bytes.Buffer
	err  error
}

func newRawChunkedReader(r *bufio.Reader) *rawChunkedReader {
	return &rawChunkedReader{r: r}
}

// Read implements io.Reader. It reads raw chunked data without decoding.
// On the first call, it reads the entire chunked body into an internal buffer,
// then serves subsequent reads from that buffer.
func (cr *rawChunkedReader) Read(p []byte) (int, error) {
	if cr.err != nil && cr.buf.Len() == 0 {
		return 0, cr.err
	}

	if !cr.done {
		cr.readAll()
		cr.done = true
	}

	n, err := cr.buf.Read(p)
	if err == io.EOF && cr.err != nil {
		return n, cr.err
	}
	return n, err
}

// readAll consumes the chunked body from the underlying reader.
// It reads chunk-size lines and chunk data, preserving the raw wire format.
func (cr *rawChunkedReader) readAll() {
	for {
		// Read chunk size line (e.g., "1a\r\n" or "0\r\n").
		sizeLine, err := cr.r.ReadSlice('\n')
		cr.buf.Write(sizeLine)
		if err != nil {
			cr.err = err
			return
		}

		// Parse the chunk size (hex before any chunk-ext).
		sizeStr := string(bytes.TrimRight(sizeLine, "\r\n"))
		if idx := bytes.IndexByte(sizeLine, ';'); idx >= 0 {
			sizeStr = string(sizeLine[:idx])
		}
		sizeStr = trimHexString(sizeStr)

		// Terminal chunk: "0\r\n"
		if sizeStr == "0" || sizeStr == "" {
			// Read trailers until blank line.
			cr.readTrailers()
			return
		}

		// Parse hex size.
		var size int64
		for _, c := range sizeStr {
			d := hexVal(c)
			if d < 0 {
				// Invalid hex — stop reading.
				cr.err = io.ErrUnexpectedEOF
				return
			}
			size = size*16 + int64(d)
		}

		// Read chunk data + trailing CRLF.
		toRead := size + 2 // +2 for CRLF after chunk data
		if err := cr.copyN(toRead); err != nil {
			return
		}
	}
}

// readTrailers reads trailer headers (or just the terminating CRLF).
func (cr *rawChunkedReader) readTrailers() {
	for {
		line, err := cr.r.ReadSlice('\n')
		cr.buf.Write(line)
		if err != nil {
			cr.err = err
			return
		}
		// Blank line ends the trailers.
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			return
		}
	}
}

// copyN copies exactly n bytes from the underlying reader to the buffer.
func (cr *rawChunkedReader) copyN(n int64) error {
	_, err := io.CopyN(&cr.buf, cr.r, n)
	if err != nil {
		cr.err = err
	}
	return err
}

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

// trimHexString trims leading/trailing whitespace from a hex size string.
func trimHexString(s string) string {
	return bytes.NewBuffer(bytes.TrimSpace([]byte(s))).String()
}
