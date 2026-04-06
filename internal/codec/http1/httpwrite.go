package http1

import (
	"bufio"
	"fmt"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// maxRawCaptureSize limits the size of raw bytes captured in serialization.
// Matches the parser and handler limits.
const maxRawCaptureSize = 2 << 20 // 2 MiB

// WriteRawResponse writes a parser.RawResponse to a net.Conn. The body bytes
// are provided separately because resp.Body may have been consumed.
//
// When autoContentLength is true (default for non-intercept paths),
// Content-Length is recalculated to match the actual body length and
// Transfer-Encoding is removed. When false (intercept with flag disabled),
// headers are preserved as-is to allow intentional CL/TE mismatches.
func WriteRawResponse(conn net.Conn, resp *parser.RawResponse, body []byte, autoContentLength bool) error {
	w := bufio.NewWriter(conn)

	if _, err := fmt.Fprintf(w, "%s\r\n", BuildStatusLine(resp)); err != nil {
		return err
	}

	if err := WriteResponseHeaders(w, resp.Headers, len(body), autoContentLength); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "\r\n"); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Flush()
}

// BuildStatusLine constructs the HTTP status line, preserving the original
// reason phrase from resp.Status when available.
func BuildStatusLine(resp *parser.RawResponse) string {
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if resp.Status != "" {
		return fmt.Sprintf("%s %s", proto, resp.Status)
	}
	text := httputil.StatusText(resp.StatusCode)
	if text == "" {
		text = "Unknown"
	}
	return fmt.Sprintf("%s %d %s", proto, resp.StatusCode, text)
}

// WriteResponseHeaders writes response headers. When autoContentLength is true,
// Content-Length is replaced with the actual body length and Transfer-Encoding
// is removed (default behavior). When false, all headers are written as-is,
// preserving any intentional CL/TE mismatches set by the pentester.
func WriteResponseHeaders(w *bufio.Writer, headers parser.RawHeaders, bodyLen int, autoContentLength bool) error {
	if !autoContentLength {
		// Passthrough mode: write headers exactly as-is.
		for _, h := range headers {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", h.Name, h.Value); err != nil {
				return err
			}
		}
		return nil
	}

	wroteContentLength := false
	for _, h := range headers {
		lower := toLower(h.Name)
		if lower == "transfer-encoding" {
			continue
		}
		if lower == "content-length" {
			if !wroteContentLength {
				if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n", bodyLen); err != nil {
					return err
				}
				wroteContentLength = true
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s: %s\r\n", h.Name, h.Value); err != nil {
			return err
		}
	}
	if !wroteContentLength {
		if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n", bodyLen); err != nil {
			return err
		}
	}
	return nil
}

// WriteRawResponseHeaders writes the HTTP response status line and headers
// to the client connection without buffering the body. This is used for
// streaming protocols (SSE, WebSocket upgrade) where the body is forwarded
// separately.
func WriteRawResponseHeaders(conn net.Conn, resp *parser.RawResponse) error {
	w := bufio.NewWriter(conn)

	if _, err := fmt.Fprintf(w, "%s\r\n", BuildStatusLine(resp)); err != nil {
		return err
	}
	for _, h := range resp.Headers {
		if _, err := fmt.Fprintf(w, "%s: %s\r\n", h.Name, h.Value); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

// toLower is a simple ASCII lowercase helper for header names.
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// SerializeRawResponseBytes reconstructs raw HTTP response bytes from a
// parser.RawResponse and body. This preserves the status line, headers,
// and body in wire format for flow recording.
func SerializeRawResponseBytes(resp *parser.RawResponse, body []byte) []byte {
	if resp == nil {
		return nil
	}

	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}

	// Build status line preserving the original reason phrase when available.
	var statusLine string
	if resp.Status != "" {
		statusLine = fmt.Sprintf("%s %s\r\n", proto, resp.Status)
	} else {
		text := httputil.StatusText(resp.StatusCode)
		if text == "" {
			text = "Unknown"
		}
		statusLine = fmt.Sprintf("%s %d %s\r\n", proto, resp.StatusCode, text)
	}

	// Estimate buffer size.
	size := len(statusLine)
	for _, h := range resp.Headers {
		size += len(h.Name) + len(h.Value) + 4
	}
	size += 2 + len(body)

	buf := make([]byte, 0, size)
	buf = append(buf, statusLine...)
	for _, h := range resp.Headers {
		buf = append(buf, h.Name...)
		buf = append(buf, ": "...)
		buf = append(buf, h.Value...)
		buf = append(buf, "\r\n"...)
	}
	buf = append(buf, "\r\n"...)

	remaining := maxRawCaptureSize - len(buf)
	if len(body) <= remaining {
		buf = append(buf, body...)
	} else if remaining > 0 {
		buf = append(buf, body[:remaining]...)
	}

	return buf
}
