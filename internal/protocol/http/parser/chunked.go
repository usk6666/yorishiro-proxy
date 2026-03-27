package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// maxChunkedBodySize limits the total raw chunked body to prevent OOM.
// Set equal to maxRawCaptureSize for consistency.
const maxChunkedBodySize = maxRawCaptureSize

// rawChunkedReader buffers a chunked Transfer-Encoding body WITHOUT decoding.
// On the first Read call, it reads and buffers the entire chunked body
// (all chunks including size lines, chunk data, trailers, and the final CRLF)
// up to maxChunkedBodySize. Subsequent Read calls serve data from the buffer.
//
// The reader terminates after reading the "0\r\n" terminal chunk and its
// trailing headers + CRLF. Any trailers present after the terminal chunk
// are included in the output.
//
// The total buffered size is capped at maxChunkedBodySize to prevent OOM.
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
		// Loop to handle bufio.ErrBufferFull when the line exceeds the bufio buffer.
		var sizeLine []byte
		for {
			fragment, err := cr.r.ReadSlice('\n')
			// Check size BEFORE appending/writing to prevent large allocations.
			if len(sizeLine)+len(fragment) > maxChunkedBodySize || cr.buf.Len()+len(fragment) > maxChunkedBodySize {
				cr.err = fmt.Errorf("chunk size line exceeds maximum length")
				return
			}
			sizeLine = append(sizeLine, fragment...)
			cr.buf.Write(fragment)
			if err == nil {
				break
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			// Any other error is fatal.
			cr.err = err
			return
		}

		// Parse the chunk size (hex before any chunk-ext).
		sizeStr := string(bytes.TrimRight(sizeLine, "\r\n"))
		if idx := bytes.IndexByte(sizeLine, ';'); idx >= 0 {
			sizeStr = string(sizeLine[:idx])
		}
		sizeStr = trimHexString(sizeStr)

		// Empty chunk-size line is a protocol violation.
		if sizeStr == "" {
			cr.err = io.ErrUnexpectedEOF
			return
		}

		// Terminal chunk: "0\r\n"
		if sizeStr == "0" {
			// Read trailers until blank line.
			cr.readTrailers()
			return
		}

		// Parse hex size with overflow protection.
		var size int64
		for _, c := range sizeStr {
			d := hexVal(c)
			if d < 0 {
				// Invalid hex — stop reading.
				cr.err = io.ErrUnexpectedEOF
				return
			}
			// Guard against int64 overflow.
			if size > (1<<63-1)/16 {
				cr.err = fmt.Errorf("chunk size overflow")
				return
			}
			size = size*16 + int64(d)
		}

		// Enforce memory limit on total buffered body.
		// Account for the trailing CRLF that copyN reads after chunk data.
		const chunkCRLFOverhead = int64(2)
		if int64(cr.buf.Len())+size+chunkCRLFOverhead > int64(maxChunkedBodySize) {
			cr.err = fmt.Errorf("chunked body exceeds maximum size %d", maxChunkedBodySize)
			return
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
		// Loop to handle bufio.ErrBufferFull for long trailer lines.
		var line []byte
		for {
			fragment, err := cr.r.ReadSlice('\n')
			// Enforce size limit before growing the line slice to prevent
			// large allocations from a single oversized ReadSlice fragment.
			if cr.buf.Len()+len(line)+len(fragment) > maxChunkedBodySize {
				cr.err = fmt.Errorf("chunked body exceeds maximum size %d", maxChunkedBodySize)
				return
			}
			line = append(line, fragment...)
			if err == nil {
				break
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			// Any other error: write what we have and return.
			cr.buf.Write(line)
			cr.err = err
			return
		}
		cr.buf.Write(line)
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
	return string(bytes.TrimSpace([]byte(s)))
}
