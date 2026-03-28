package http

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// writeHTTPError writes a minimal HTTP error response to the connection.
// This replaces httputil.WriteHTTPError calls to avoid importing net/http.
func writeHTTPError(conn net.Conn, code int, logger *slog.Logger) {
	text := statusText(code)
	if text == "" {
		text = "Unknown"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code, text)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write error response", "status", code, "error", err)
	}
}

// writeRawResponse writes a parser.RawResponse to a net.Conn. The body bytes
// are provided separately because resp.Body may have been consumed.
//
// This replaces the old writeResponse(conn, *gohttp.Response, body) function
// and writeResponseToClient.
func writeRawResponse(conn net.Conn, resp *parser.RawResponse, body []byte) error {
	w := bufio.NewWriter(conn)

	if _, err := fmt.Fprintf(w, "%s\r\n", buildStatusLine(resp)); err != nil {
		return err
	}

	if err := writeResponseHeaders(w, resp.Headers, len(body)); err != nil {
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

// buildStatusLine constructs the HTTP status line, preserving the original
// reason phrase from resp.Status when available.
func buildStatusLine(resp *parser.RawResponse) string {
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if resp.Status != "" {
		return fmt.Sprintf("%s %s", proto, resp.Status)
	}
	text := statusText(resp.StatusCode)
	if text == "" {
		text = "Unknown"
	}
	return fmt.Sprintf("%s %d %s", proto, resp.StatusCode, text)
}

// writeResponseHeaders writes response headers, replacing Content-Length with
// the actual body length and removing Transfer-Encoding.
func writeResponseHeaders(w *bufio.Writer, headers parser.RawHeaders, bodyLen int) error {
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

// writeSSERawResponseHeaders writes the HTTP response status line and headers
// to the client connection without buffering the body. This allows the client
// to begin processing SSE events as they arrive.
func writeSSERawResponseHeaders(conn net.Conn, resp *parser.RawResponse) error {
	w := bufio.NewWriter(conn)

	if _, err := fmt.Fprintf(w, "%s\r\n", buildStatusLine(resp)); err != nil {
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

// toLower is a simple ASCII lowercase helper to avoid importing strings
// for a single use. For header names this is sufficient since HTTP header
// names are ASCII.
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

// serializeRawResponseBytes reconstructs raw HTTP response bytes from a
// parser.RawResponse and body. This preserves the status line, headers,
// and body in wire format for flow recording.
func serializeRawResponseBytes(resp *parser.RawResponse, body []byte) []byte {
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
		text := statusText(resp.StatusCode)
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
